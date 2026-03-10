package workos

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/workos/workos-go/v6/pkg/usermanagement"
)

func authFailedMessage(reason string) string {
	msg := "Authentication failed"
	if strings.TrimSpace(os.Getenv("VANGO_DEV")) == "1" && strings.TrimSpace(reason) != "" {
		msg += ": " + reason
	}
	return msg
}

func setAuthNoStoreHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

func generateState() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

type unverifiedAccessTokenClaims struct {
	Issuer   string          `json:"iss"`
	Audience json.RawMessage `json:"aud"`
}

func accessTokenDebugClaims(token string) (string, string) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) < 2 {
		return "", ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", ""
	}
	var claims unverifiedAccessTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", ""
	}
	return claims.Issuer, strings.TrimSpace(string(claims.Audience))
}

func (c *Client) SignInHandler(w http.ResponseWriter, r *http.Request) {
	setAuthNoStoreHeaders(w)

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	state := generateState()
	if state == "" {
		http.Error(w, "Failed to generate sign-in URL", http.StatusInternalServerError)
		return
	}
	setStateCookie(w, state, c.cfg)

	authURL, err := c.um.GetAuthorizationURL(usermanagement.GetAuthorizationURLOpts{
		ClientID:    c.cfg.ClientID,
		RedirectURI: c.cfg.RedirectURI,
		State:       state,
		Provider:    "authkit",
	})
	if err != nil || authURL == nil {
		http.Error(w, "Failed to generate sign-in URL", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, authURL.String(), http.StatusTemporaryRedirect)
}

func (c *Client) SignUpHandler(w http.ResponseWriter, r *http.Request) {
	setAuthNoStoreHeaders(w)

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	state := generateState()
	if state == "" {
		http.Error(w, "Failed to generate sign-up URL", http.StatusInternalServerError)
		return
	}
	setStateCookie(w, state, c.cfg)

	authURL, err := c.um.GetAuthorizationURL(usermanagement.GetAuthorizationURLOpts{
		ClientID:    c.cfg.ClientID,
		RedirectURI: c.cfg.RedirectURI,
		State:       state,
		Provider:    "authkit",
		ScreenHint:  usermanagement.SignUp,
	})
	if err != nil || authURL == nil {
		http.Error(w, "Failed to generate sign-up URL", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, authURL.String(), http.StatusTemporaryRedirect)
}

func (c *Client) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	setAuthNoStoreHeaders(w)

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	errParam := r.URL.Query().Get("error")

	if errParam != "" {
		http.Error(w, "Authentication error", http.StatusBadRequest)
		return
	}
	if code == "" {
		http.Error(w, "Missing authorization code", http.StatusBadRequest)
		return
	}
	if !validateStateCookie(r, state, c.cfg) {
		http.Error(w, "Invalid state parameter", http.StatusForbidden)
		return
	}
	clearStateCookie(w, c.cfg)

	authResp, err := c.um.AuthenticateWithCode(r.Context(), usermanagement.AuthenticateWithCodeOpts{
		ClientID: c.cfg.ClientID,
		Code:     code,
	})
	if err != nil {
		slog.Warn("workos callback code exchange failed", "error", err)
		http.Error(w, authFailedMessage("code exchange failed"), http.StatusUnauthorized)
		return
	}
	// Refresh token is required because middleware uses it to rotate expired access tokens.
	if strings.TrimSpace(authResp.RefreshToken) == "" {
		slog.Warn("workos callback missing refresh token")
		http.Error(w, authFailedMessage("missing refresh token"), http.StatusUnauthorized)
		return
	}
	claims, err := c.VerifyAccessToken(r.Context(), authResp.AccessToken)
	if err != nil {
		if strings.TrimSpace(os.Getenv("VANGO_DEV")) == "1" {
			rawIssuer, rawAudience := accessTokenDebugClaims(authResp.AccessToken)
			slog.Warn("workos callback token debug",
				"configured_issuer", c.cfg.JWTIssuer,
				"configured_audience", c.cfg.JWTAudience,
				"token_issuer", rawIssuer,
				"token_audience", rawAudience,
			)
		}
		slog.Warn("workos callback access token verification failed", "error", err)
		http.Error(w, authFailedMessage("access token verification failed ("+err.Error()+")"), http.StatusUnauthorized)
		return
	}

	identity := &Identity{
		UserID:       authResp.User.ID,
		Email:        authResp.User.Email,
		Name:         strings.TrimSpace(authResp.User.FirstName + " " + authResp.User.LastName),
		OrgID:        claims.OrgID,
		Roles:        claims.Roles,
		Permissions:  claims.Permissions,
		Entitlements: claims.Entitlements,
		SessionID:    claims.SessionID,
		ExpiresAt:    claims.ExpiresAt,
		AuthMethod:   string(authResp.AuthenticationMethod),
	}
	if identity.Name == "" {
		identity.Name = identity.Email
	}
	if identity.OrgID == "" {
		identity.OrgID = authResp.OrganizationID
	}

	if err := setSessionCookie(w, &cookieSession{
		AccessToken:  authResp.AccessToken,
		RefreshToken: authResp.RefreshToken,
		OrgID:        identity.OrgID,
		IdentityHint: identity,
	}, c.cfg); err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	returnTo := r.URL.Query().Get("return_to")
	if returnTo == "" || !isSafeRedirect(returnTo, c.cfg.BaseURL) {
		returnTo = "/"
	}
	http.Redirect(w, r, returnTo, http.StatusTemporaryRedirect)
}

func isSafeRedirect(returnTo, baseURL string) bool {
	if returnTo == "" {
		return false
	}
	u, err := url.Parse(returnTo)
	if err != nil {
		return false
	}
	if u.IsAbs() {
		base, err := url.Parse(baseURL)
		if err != nil || base == nil {
			return false
		}
		return u.Scheme == base.Scheme && strings.EqualFold(u.Host, base.Host)
	}
	return strings.HasPrefix(returnTo, "/") && !strings.HasPrefix(returnTo, "//")
}

func (c *Client) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	setAuthNoStoreHeaders(w)

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cookieSess, _ := readSessionCookie(r, c.cfg)
	clearSessionCookie(w, c.cfg)

	sessionID := ""
	if cookieSess != nil && cookieSess.IdentityHint != nil && cookieSess.IdentityHint.SessionID != "" {
		sessionID = cookieSess.IdentityHint.SessionID
	} else if cookieSess != nil && cookieSess.AccessToken != "" {
		if claims, err := c.VerifyAccessToken(r.Context(), cookieSess.AccessToken); err == nil && claims != nil {
			sessionID = claims.SessionID
		}
	}

	if sessionID != "" {
		_ = c.RevokeSession(r.Context(), sessionID)
		signedOutURL := strings.TrimRight(c.cfg.BaseURL, "/") + c.cfg.SignOutRedirectURI
		logoutURL, err := c.um.GetLogoutURL(usermanagement.GetLogoutURLOpts{
			SessionID: sessionID,
			ReturnTo:  signedOutURL,
		})
		if err == nil && logoutURL != nil {
			http.Redirect(w, r, logoutURL.String(), http.StatusSeeOther)
			return
		}
	}

	http.Redirect(w, r, c.cfg.SignOutRedirectURI, http.StatusSeeOther)
}

func (c *Client) SignedOutHandler(w http.ResponseWriter, r *http.Request) {
	setAuthNoStoreHeaders(w)

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	returnTo := r.URL.Query().Get("return_to")
	if returnTo == "" || !isSafeRedirect(returnTo, c.cfg.BaseURL) {
		returnTo = "/"
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(signedOutHTML(returnTo)))
}

// signedOutHTML renders the post-logout landing page. The JS route is fixed to
// /auth/signed-out.js (same-origin, no inline script), while the HTML page route
// itself is configured via Config.SignOutRedirectURI.
func signedOutHTML(returnTo string) string {
	rt := html.EscapeString(returnTo)
	return fmt.Sprintf(`<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="workos-return-to" content="%s">
    <title>Signed out</title>
    <script src="/auth/signed-out.js" defer></script>
  </head>
  <body></body>
</html>`, rt)
}

func (c *Client) SignedOutScriptHandler(w http.ResponseWriter, r *http.Request) {
	setAuthNoStoreHeaders(w)

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(signedOutJS))
}

const signedOutJS = `(function () {
  function meta(name) {
    var el = document.querySelector('meta[name="' + name + '"]');
    return el && el.content ? el.content : "";
  }

  var channel = "vango:auth";
  var payload = { type: "logout", reason: 0 };
  var redirectTo = meta("workos-return-to") || "/";

  try {
    if (typeof BroadcastChannel !== "undefined") {
      var bc = new BroadcastChannel(channel);
      bc.postMessage(payload);
      bc.close();
    } else if (typeof localStorage !== "undefined") {
      var key = "__vango_auth_" + channel;
      localStorage.setItem(key, JSON.stringify({ payload: payload, ts: Date.now() }));
      localStorage.removeItem(key);
    }
  } catch (err) {}

  try {
    if (typeof sessionStorage !== "undefined") {
      sessionStorage.removeItem("__vango_session_id");
      sessionStorage.removeItem("__vango_last_seq");
    }
  } catch (err) {}

  try {
    window.location.replace(redirectTo);
  } catch (err) {
    window.location.replace("/");
  }
})();`

func (c *Client) RegisterAuthHandlers(mux *http.ServeMux, csrfMw func(http.Handler) http.Handler) {
	if csrfMw == nil {
		panic("workos: csrf middleware is required for /auth/logout; pass app.Server().CSRFMiddleware()")
	}

	// Canonical signed-out landing path comes from config.
	signOutPath := strings.TrimSpace(c.cfg.SignOutRedirectURI)
	if signOutPath == "" {
		signOutPath = "/auth/signed-out"
	}

	mux.HandleFunc("/auth/signin", c.SignInHandler)
	mux.HandleFunc("/auth/signup", c.SignUpHandler)
	mux.HandleFunc("/auth/callback", c.CallbackHandler)
	// Logout must be CSRF-protected at registration time.
	mux.Handle("/auth/logout", csrfMw(http.HandlerFunc(c.LogoutHandler)))
	mux.HandleFunc(signOutPath, c.SignedOutHandler)
	// Backward-compatibility alias for existing integrations that still link to
	// /auth/signed-out when SignOutRedirectURI is customized.
	if signOutPath != "/auth/signed-out" {
		mux.HandleFunc("/auth/signed-out", c.SignedOutHandler)
	}
	// Script path stays fixed and same-origin.
	mux.HandleFunc("/auth/signed-out.js", c.SignedOutScriptHandler)
}
