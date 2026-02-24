package workos

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"

	"github.com/workos/workos-go/v6/pkg/usermanagement"
)

func generateState() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

func (c *Client) SignInHandler(w http.ResponseWriter, r *http.Request) {
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
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}
	claims, err := c.VerifyAccessToken(r.Context(), authResp.AccessToken)
	if err != nil {
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
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
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cookieSess, _ := readSessionCookie(r, c.cfg)
	clearSessionCookie(w, c.cfg)
	w.Header().Set("Cache-Control", "no-store")

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
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	returnTo := r.URL.Query().Get("return_to")
	if returnTo == "" || !isSafeRedirect(returnTo, c.cfg.BaseURL) {
		returnTo = "/"
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(signedOutHTML(returnTo)))
}

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

func (c *Client) SignedOutScriptHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
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
		csrfMw = func(next http.Handler) http.Handler { return next }
	}

	mux.HandleFunc("/auth/signin", c.SignInHandler)
	mux.HandleFunc("/auth/signup", c.SignUpHandler)
	mux.HandleFunc("/auth/callback", c.CallbackHandler)
	mux.Handle("/auth/logout", csrfMw(http.HandlerFunc(c.LogoutHandler)))
	mux.HandleFunc("/auth/signed-out", c.SignedOutHandler)
	mux.HandleFunc("/auth/signed-out.js", c.SignedOutScriptHandler)
}
