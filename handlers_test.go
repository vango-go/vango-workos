package workos

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/workos/workos-go/v6/pkg/common"
	"github.com/workos/workos-go/v6/pkg/usermanagement"
)

func newHandlerClient(t *testing.T, um *fakeUMClient) *Client {
	t.Helper()
	c, err := New(validConfig())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	c.um = um
	return c
}

func mustFindCookie(t *testing.T, cookies []*http.Cookie, name string) *http.Cookie {
	t.Helper()
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("cookie %q not found", name)
	return nil
}

func addSessionCookie(t *testing.T, req *http.Request, cfg Config, sess *cookieSession) {
	t.Helper()
	w := httptest.NewRecorder()
	if err := setSessionCookie(w, sess, cfg); err != nil {
		t.Fatalf("setSessionCookie() error = %v", err)
	}
	req.AddCookie(mustFindCookie(t, w.Result().Cookies(), cfg.CookieName))
}

func TestSignInHandler(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		var captured usermanagement.GetAuthorizationURLOpts
		client := newHandlerClient(t, &fakeUMClient{
			getAuthorizationURLFunc: func(opts usermanagement.GetAuthorizationURLOpts) (*url.URL, error) {
				captured = opts
				return url.Parse("https://auth.workos.com/sso?state=" + opts.State)
			},
		})

		req := httptest.NewRequest(http.MethodGet, "http://example.test/auth/signin", nil)
		w := httptest.NewRecorder()
		client.SignInHandler(w, req)
		resp := w.Result()

		if resp.StatusCode != http.StatusTemporaryRedirect {
			t.Fatalf("StatusCode = %d, want %d", resp.StatusCode, http.StatusTemporaryRedirect)
		}

		stateCookie := mustFindCookie(t, resp.Cookies(), stateCookieName)
		if stateCookie.Value == "" {
			t.Fatal("expected non-empty state cookie")
		}
		if captured.Provider != "authkit" {
			t.Fatalf("Provider = %q, want %q", captured.Provider, "authkit")
		}
		if captured.State != stateCookie.Value {
			t.Fatalf("captured.State = %q, cookie state = %q", captured.State, stateCookie.Value)
		}
		if captured.ClientID != client.cfg.ClientID {
			t.Fatalf("ClientID = %q, want %q", captured.ClientID, client.cfg.ClientID)
		}
		if captured.RedirectURI != client.cfg.RedirectURI {
			t.Fatalf("RedirectURI = %q, want %q", captured.RedirectURI, client.cfg.RedirectURI)
		}
	})

	t.Run("method not allowed", func(t *testing.T) {
		client := newHandlerClient(t, &fakeUMClient{})

		req := httptest.NewRequest(http.MethodPost, "http://example.test/auth/signin", nil)
		w := httptest.NewRecorder()
		client.SignInHandler(w, req)
		resp := w.Result()

		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("StatusCode = %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
		}
	})

	t.Run("upstream failure", func(t *testing.T) {
		client := newHandlerClient(t, &fakeUMClient{
			getAuthorizationURLFunc: func(usermanagement.GetAuthorizationURLOpts) (*url.URL, error) {
				return nil, errors.New("boom")
			},
		})

		req := httptest.NewRequest(http.MethodGet, "http://example.test/auth/signin", nil)
		w := httptest.NewRecorder()
		client.SignInHandler(w, req)
		resp := w.Result()

		if resp.StatusCode != http.StatusInternalServerError {
			t.Fatalf("StatusCode = %d, want %d", resp.StatusCode, http.StatusInternalServerError)
		}
	})
}

func TestSignUpHandler(t *testing.T) {
	var captured usermanagement.GetAuthorizationURLOpts
	client := newHandlerClient(t, &fakeUMClient{
		getAuthorizationURLFunc: func(opts usermanagement.GetAuthorizationURLOpts) (*url.URL, error) {
			captured = opts
			return url.Parse("https://auth.workos.com/sso?state=" + opts.State)
		},
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.test/auth/signup", nil)
	w := httptest.NewRecorder()
	client.SignUpHandler(w, req)
	resp := w.Result()

	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("StatusCode = %d, want %d", resp.StatusCode, http.StatusTemporaryRedirect)
	}

	stateCookie := mustFindCookie(t, resp.Cookies(), stateCookieName)
	if stateCookie.Value == "" {
		t.Fatal("expected non-empty state cookie")
	}
	if captured.Provider != "authkit" {
		t.Fatalf("Provider = %q, want %q", captured.Provider, "authkit")
	}
	if captured.ScreenHint != usermanagement.SignUp {
		t.Fatalf("ScreenHint = %q, want %q", captured.ScreenHint, usermanagement.SignUp)
	}
	if captured.State != stateCookie.Value {
		t.Fatalf("captured.State = %q, cookie state = %q", captured.State, stateCookie.Value)
	}
}

func TestCallbackHandler_ValidationAndSanitization(t *testing.T) {
	client := newHandlerClient(t, &fakeUMClient{})

	t.Run("method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "http://example.test/auth/callback?code=abc&state=s1", nil)
		req.AddCookie(&http.Cookie{Name: stateCookieName, Value: "s1"})
		w := httptest.NewRecorder()

		client.CallbackHandler(w, req)
		resp := w.Result()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("StatusCode = %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
		}
	})

	t.Run("missing code", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.test/auth/callback?state=s1", nil)
		req.AddCookie(&http.Cookie{Name: stateCookieName, Value: "s1"})
		w := httptest.NewRecorder()

		client.CallbackHandler(w, req)
		resp := w.Result()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("StatusCode = %d, want %d", resp.StatusCode, http.StatusBadRequest)
		}
		body := w.Body.String()
		if !strings.Contains(body, "Missing authorization code") {
			t.Fatalf("body = %q", body)
		}
	})

	t.Run("invalid state", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.test/auth/callback?code=abc&state=want", nil)
		req.AddCookie(&http.Cookie{Name: stateCookieName, Value: "different"})
		w := httptest.NewRecorder()

		client.CallbackHandler(w, req)
		resp := w.Result()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("StatusCode = %d, want %d", resp.StatusCode, http.StatusForbidden)
		}
	})

	t.Run("generic error does not echo params", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.test/auth/callback?error=access_denied&error_description=secret_description&code=code_secret&state=state_secret", nil)
		w := httptest.NewRecorder()

		client.CallbackHandler(w, req)
		resp := w.Result()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("StatusCode = %d, want %d", resp.StatusCode, http.StatusBadRequest)
		}
		body := w.Body.String()
		if !strings.Contains(body, "Authentication error") {
			t.Fatalf("body = %q", body)
		}
		if strings.Contains(body, "access_denied") || strings.Contains(body, "secret_description") || strings.Contains(body, "code_secret") || strings.Contains(body, "state_secret") {
			t.Fatalf("unexpected callback query reflection in body %q", body)
		}
		assertNoSecretLeak(t, body, "code_secret", "state_secret", "secret_description")
	})
}

func TestCallbackHandler_SuccessAndRedirectRules(t *testing.T) {
	key := mustRSAKey(t)
	claims := baseClaims()
	claims.OrgID = ""
	claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(5 * time.Minute))
	claims.Role = "member"
	claims.Roles = []string{"admin"}
	claims.Permissions = []string{"projects:read"}
	claims.Entitlements = []string{"feature:pro"}
	accessToken := signRS256Token(t, key, "kid-1", claims)

	client, ts := newJWTTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jwkDoc{Keys: []jwkKey{rsaJWK(t, &key.PublicKey, "kid-1")}})
	})
	defer ts.Close()

	client.um = &fakeUMClient{
		authenticateWithCodeFunc: func(_ context.Context, opts usermanagement.AuthenticateWithCodeOpts) (usermanagement.AuthenticateResponse, error) {
			if opts.ClientID != client.cfg.ClientID {
				t.Fatalf("ClientID = %q, want %q", opts.ClientID, client.cfg.ClientID)
			}
			if opts.Code == "" {
				t.Fatal("expected non-empty code")
			}
			return usermanagement.AuthenticateResponse{
				User: common.User{
					ID:        claims.Subject,
					FirstName: "",
					LastName:  "",
					Email:     "alice@example.com",
				},
				OrganizationID:       "org_from_auth_resp",
				AccessToken:          accessToken,
				RefreshToken:         "refresh_next_123",
				AuthenticationMethod: usermanagement.Password,
			}, nil
		},
	}

	tests := []struct {
		name     string
		returnTo string
		wantLoc  string
	}{
		{name: "relative allowed", returnTo: "/ok", wantLoc: "/ok"},
		{name: "double slash blocked", returnTo: "//evil.com", wantLoc: "/"},
		{name: "external absolute blocked", returnTo: "https://evil.com/pwn", wantLoc: "/"},
		{name: "same-origin absolute allowed", returnTo: "https://app.example.com/dashboard", wantLoc: "https://app.example.com/dashboard"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://example.test/auth/callback?code=code_123&state=state_123&return_to="+url.QueryEscape(tt.returnTo), nil)
			req.AddCookie(&http.Cookie{Name: stateCookieName, Value: "state_123"})
			w := httptest.NewRecorder()

			client.CallbackHandler(w, req)
			resp := w.Result()

			if resp.StatusCode != http.StatusTemporaryRedirect {
				t.Fatalf("StatusCode = %d, want %d", resp.StatusCode, http.StatusTemporaryRedirect)
			}
			if got := resp.Header.Get("Location"); got != tt.wantLoc {
				t.Fatalf("Location = %q, want %q", got, tt.wantLoc)
			}

			setCookies := resp.Header.Values("Set-Cookie")
			joined := strings.Join(setCookies, "\n")
			if !strings.Contains(joined, stateCookieName) || !strings.Contains(joined, "Max-Age=0") {
				t.Fatalf("state clear cookie missing; Set-Cookie headers: %q", joined)
			}
			if !strings.Contains(joined, client.cfg.CookieName) {
				t.Fatalf("session cookie missing; Set-Cookie headers: %q", joined)
			}

			cookie := mustFindCookie(t, resp.Cookies(), client.cfg.CookieName)
			verifyReq := httptest.NewRequest(http.MethodGet, "http://example.test/verify", nil)
			verifyReq.AddCookie(cookie)
			sess, err := readSessionCookie(verifyReq, client.cfg)
			if err != nil {
				t.Fatalf("readSessionCookie() error = %v", err)
			}
			if sess == nil || sess.IdentityHint == nil {
				t.Fatal("expected identity hint in cookie")
			}
			if sess.IdentityHint.UserID != claims.Subject {
				t.Fatalf("UserID = %q, want %q", sess.IdentityHint.UserID, claims.Subject)
			}
			if sess.IdentityHint.Name != "alice@example.com" {
				t.Fatalf("Name = %q, want %q", sess.IdentityHint.Name, "alice@example.com")
			}
			if sess.IdentityHint.OrgID != "org_from_auth_resp" {
				t.Fatalf("OrgID = %q, want %q", sess.IdentityHint.OrgID, "org_from_auth_resp")
			}
			if len(sess.IdentityHint.Roles) != 2 || sess.IdentityHint.Roles[0] != "member" || sess.IdentityHint.Roles[1] != "admin" {
				t.Fatalf("Roles = %#v", sess.IdentityHint.Roles)
			}
			if sess.IdentityHint.AuthMethod != string(usermanagement.Password) {
				t.Fatalf("AuthMethod = %q", sess.IdentityHint.AuthMethod)
			}
		})
	}
}

func TestLogoutHandler(t *testing.T) {
	t.Run("method gated", func(t *testing.T) {
		client := newHandlerClient(t, &fakeUMClient{})
		req := httptest.NewRequest(http.MethodGet, "http://example.test/auth/logout", nil)
		w := httptest.NewRecorder()
		client.LogoutHandler(w, req)
		if w.Result().StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("StatusCode = %d, want %d", w.Result().StatusCode, http.StatusMethodNotAllowed)
		}
	})

	t.Run("known session uses workos logout URL and revokes", func(t *testing.T) {
		var revokedSessionID string
		var logoutOpts usermanagement.GetLogoutURLOpts
		client := newHandlerClient(t, &fakeUMClient{
			revokeSessionFunc: func(_ context.Context, opts usermanagement.RevokeSessionOpts) error {
				revokedSessionID = opts.SessionID
				return nil
			},
			getLogoutURLFunc: func(opts usermanagement.GetLogoutURLOpts) (*url.URL, error) {
				logoutOpts = opts
				return url.Parse("https://api.workos.com/user_management/sessions/logout?session_id=sess_123")
			},
		})

		req := httptest.NewRequest(http.MethodPost, "http://example.test/auth/logout", nil)
		addSessionCookie(t, req, client.cfg, &cookieSession{
			AccessToken:  "token_unused_for_this_test",
			RefreshToken: "refresh_unused",
			IdentityHint: &Identity{SessionID: "sess_123"},
		})
		w := httptest.NewRecorder()

		client.LogoutHandler(w, req)
		resp := w.Result()

		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("StatusCode = %d, want %d", resp.StatusCode, http.StatusSeeOther)
		}
		if got := resp.Header.Get("Location"); !strings.Contains(got, "session_id=sess_123") {
			t.Fatalf("Location = %q", got)
		}
		if revokedSessionID != "sess_123" {
			t.Fatalf("revokedSessionID = %q, want %q", revokedSessionID, "sess_123")
		}
		if logoutOpts.SessionID != "sess_123" {
			t.Fatalf("logoutOpts.SessionID = %q, want %q", logoutOpts.SessionID, "sess_123")
		}
		if logoutOpts.ReturnTo != "https://app.example.com/auth/signed-out" {
			t.Fatalf("logoutOpts.ReturnTo = %q, want %q", logoutOpts.ReturnTo, "https://app.example.com/auth/signed-out")
		}
		if got := resp.Header.Get("Cache-Control"); got != "no-store" {
			t.Fatalf("Cache-Control = %q, want %q", got, "no-store")
		}
		if !strings.Contains(strings.Join(resp.Header.Values("Set-Cookie"), "\n"), client.cfg.CookieName) {
			t.Fatalf("expected session clear cookie in Set-Cookie headers: %v", resp.Header.Values("Set-Cookie"))
		}
	})

	t.Run("falls back to local signout when logout URL unavailable", func(t *testing.T) {
		client := newHandlerClient(t, &fakeUMClient{
			revokeSessionFunc: func(_ context.Context, _ usermanagement.RevokeSessionOpts) error { return nil },
			getLogoutURLFunc: func(usermanagement.GetLogoutURLOpts) (*url.URL, error) {
				return nil, errors.New("cannot build logout url")
			},
		})

		req := httptest.NewRequest(http.MethodPost, "http://example.test/auth/logout", nil)
		addSessionCookie(t, req, client.cfg, &cookieSession{
			AccessToken:  "token_unused_for_this_test",
			RefreshToken: "refresh_unused",
			IdentityHint: &Identity{SessionID: "sess_999"},
		})
		w := httptest.NewRecorder()
		client.LogoutHandler(w, req)
		resp := w.Result()

		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("StatusCode = %d, want %d", resp.StatusCode, http.StatusSeeOther)
		}
		if got := resp.Header.Get("Location"); got != "/auth/signed-out" {
			t.Fatalf("Location = %q, want %q", got, "/auth/signed-out")
		}
	})
}

func TestSignedOutHandlers(t *testing.T) {
	client := newHandlerClient(t, &fakeUMClient{})

	t.Run("signed out page", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.test/auth/signed-out?return_to="+url.QueryEscape(`/next"onload="x`), nil)
		w := httptest.NewRecorder()
		client.SignedOutHandler(w, req)
		resp := w.Result()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("StatusCode = %d, want %d", resp.StatusCode, http.StatusOK)
		}
		if got := resp.Header.Get("Cache-Control"); got != "no-store" {
			t.Fatalf("Cache-Control = %q, want %q", got, "no-store")
		}
		if got := resp.Header.Get("Content-Type"); got != "text/html; charset=utf-8" {
			t.Fatalf("Content-Type = %q", got)
		}
		body := w.Body.String()
		if !strings.Contains(body, `<script src="/auth/signed-out.js" defer></script>`) {
			t.Fatalf("body = %q", body)
		}
		if !strings.Contains(body, "/next&#34;onload=&#34;x") {
			t.Fatalf("expected escaped return_to in body, got %q", body)
		}
	})

	t.Run("signed out page method gated", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "http://example.test/auth/signed-out", nil)
		w := httptest.NewRecorder()
		client.SignedOutHandler(w, req)
		if w.Result().StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("StatusCode = %d, want %d", w.Result().StatusCode, http.StatusMethodNotAllowed)
		}
	})

	t.Run("signed out script", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.test/auth/signed-out.js", nil)
		w := httptest.NewRecorder()
		client.SignedOutScriptHandler(w, req)
		resp := w.Result()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("StatusCode = %d, want %d", resp.StatusCode, http.StatusOK)
		}
		if got := resp.Header.Get("Cache-Control"); got != "no-store" {
			t.Fatalf("Cache-Control = %q, want %q", got, "no-store")
		}
		if got := resp.Header.Get("Content-Type"); got != "application/javascript; charset=utf-8" {
			t.Fatalf("Content-Type = %q", got)
		}
		body := w.Body.String()
		if !strings.Contains(body, "BroadcastChannel") || !strings.Contains(body, "__vango_session_id") {
			t.Fatalf("script body missing expected behavior snippets")
		}
	})

	t.Run("signed out script method gated", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "http://example.test/auth/signed-out.js", nil)
		w := httptest.NewRecorder()
		client.SignedOutScriptHandler(w, req)
		if w.Result().StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("StatusCode = %d, want %d", w.Result().StatusCode, http.StatusMethodNotAllowed)
		}
	})
}

func TestRegisterAuthHandlers(t *testing.T) {
	client := newHandlerClient(t, &fakeUMClient{
		getAuthorizationURLFunc: func(opts usermanagement.GetAuthorizationURLOpts) (*url.URL, error) {
			return url.Parse("https://auth.workos.com/sso?state=" + opts.State)
		},
	})

	t.Run("csrf wrapper applied to logout", func(t *testing.T) {
		mux := http.NewServeMux()
		var wrapped bool
		csrf := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				wrapped = true
				w.Header().Set("X-CSRF-Wrapped", "1")
				next.ServeHTTP(w, r)
			})
		}

		client.RegisterAuthHandlers(mux, csrf)
		req := httptest.NewRequest(http.MethodPost, "http://example.test/auth/logout", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if !wrapped {
			t.Fatal("expected csrf wrapper to execute")
		}
		if got := w.Result().Header.Get("X-CSRF-Wrapped"); got != "1" {
			t.Fatalf("X-CSRF-Wrapped = %q", got)
		}
		if w.Result().StatusCode != http.StatusSeeOther {
			t.Fatalf("StatusCode = %d, want %d", w.Result().StatusCode, http.StatusSeeOther)
		}
	})

	t.Run("nil csrf middleware is tolerated", func(t *testing.T) {
		mux := http.NewServeMux()
		client.RegisterAuthHandlers(mux, nil)
		req := httptest.NewRequest(http.MethodGet, "http://example.test/auth/signin", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Result().StatusCode != http.StatusTemporaryRedirect {
			t.Fatalf("StatusCode = %d, want %d", w.Result().StatusCode, http.StatusTemporaryRedirect)
		}
	})
}
