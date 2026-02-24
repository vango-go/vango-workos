package workos

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/vango-go/vango"
	"github.com/workos/workos-go/v6/pkg/usermanagement"
)

func newMiddlewareClientWithJWKS(t *testing.T, jwksHandler http.HandlerFunc, cfgMutators ...func(*Config)) (*Client, *httptest.Server) {
	t.Helper()

	ts := httptest.NewServer(jwksHandler)
	cfg := validConfig()
	cfg.JWKSURL = ts.URL
	cfg.JWKSCacheDuration = time.Hour
	cfg.JWTAudience = "client_test_audience"
	cfg.JWTIssuer = "https://api.workos.com"
	for _, fn := range cfgMutators {
		fn(&cfg)
	}

	c, err := New(cfg)
	if err != nil {
		ts.Close()
		t.Fatalf("New() error = %v", err)
	}
	return c, ts
}

func setCookieOnRequest(t *testing.T, req *http.Request, cfg Config, sess *cookieSession) {
	t.Helper()
	w := httptest.NewRecorder()
	if err := setSessionCookie(w, sess, cfg); err != nil {
		t.Fatalf("setSessionCookie() error = %v", err)
	}
	res := w.Result()
	req.AddCookie(mustFindCookie(t, res.Cookies(), cfg.CookieName))
}

func TestMiddleware_NoCookiePassThrough(t *testing.T) {
	client, ts := newMiddlewareClientWithJWKS(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jwkDoc{})
	})
	defer ts.Close()

	var gotUser any
	var nextCalled bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		gotUser = vango.UserFromContext(r.Context())
		w.WriteHeader(http.StatusAccepted)
	})

	h := client.Middleware()(next)
	req := httptest.NewRequest(http.MethodGet, "http://example.test/private", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if !nextCalled {
		t.Fatal("next handler was not called")
	}
	if gotUser != nil {
		t.Fatalf("user = %#v, want nil", gotUser)
	}
	if w.Result().StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", w.Result().StatusCode, http.StatusAccepted)
	}
	if got := len(w.Result().Header.Values("Set-Cookie")); got != 0 {
		t.Fatalf("unexpected Set-Cookie headers: %v", w.Result().Header.Values("Set-Cookie"))
	}
}

func TestMiddleware_ValidCookieAttachesIdentity(t *testing.T) {
	key := mustRSAKey(t)
	claims := baseClaims()
	claims.Email = "claims@example.com"
	claims.Name = "Claims User"
	claims.OrgID = "org_claims"
	claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(10 * time.Minute))
	token := signRS256Token(t, key, "kid-1", claims)

	client, ts := newMiddlewareClientWithJWKS(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jwkDoc{Keys: []jwkKey{rsaJWK(t, &key.PublicKey, "kid-1")}})
	})
	defer ts.Close()

	req := httptest.NewRequest(http.MethodGet, "http://example.test/private", nil)
	setCookieOnRequest(t, req, client.cfg, &cookieSession{
		AccessToken:  token,
		RefreshToken: "refresh_1",
		IdentityHint: &Identity{
			UserID:    "user_hint",
			Email:     "hint@example.com",
			Name:      "Hint User",
			OrgID:     "org_hint",
			SessionID: "sess_hint",
		},
	})

	var gotIdentity *Identity
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := vango.UserFromContext(r.Context())
		i, _ := u.(*Identity)
		gotIdentity = i
		w.WriteHeader(http.StatusNoContent)
	})
	h := client.Middleware()(next)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if gotIdentity == nil {
		t.Fatal("expected identity in context")
	}
	if gotIdentity.UserID != claims.Subject {
		t.Fatalf("UserID = %q, want %q", gotIdentity.UserID, claims.Subject)
	}
	if gotIdentity.Email != claims.Email {
		t.Fatalf("Email = %q, want %q", gotIdentity.Email, claims.Email)
	}
	if gotIdentity.Name != claims.Name {
		t.Fatalf("Name = %q, want %q", gotIdentity.Name, claims.Name)
	}
	if gotIdentity.OrgID != claims.OrgID {
		t.Fatalf("OrgID = %q, want %q", gotIdentity.OrgID, claims.OrgID)
	}
	if gotIdentity.SessionID != claims.SID {
		t.Fatalf("SessionID = %q, want %q", gotIdentity.SessionID, claims.SID)
	}
	if got := len(w.Result().Header.Values("Set-Cookie")); got != 0 {
		t.Fatalf("unexpected cookie rewrite: %v", w.Result().Header.Values("Set-Cookie"))
	}
}

func TestMiddleware_InvalidCookieClearsAndPassesThrough(t *testing.T) {
	client, ts := newMiddlewareClientWithJWKS(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jwkDoc{})
	})
	defer ts.Close()

	req := httptest.NewRequest(http.MethodGet, "http://example.test/private", nil)
	req.AddCookie(&http.Cookie{Name: client.cfg.CookieName, Value: "not-valid-cookie"})

	var gotUser any
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser = vango.UserFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	h := client.Middleware()(next)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if gotUser != nil {
		t.Fatalf("user = %#v, want nil", gotUser)
	}
	setCookies := w.Result().Header.Values("Set-Cookie")
	if len(setCookies) == 0 {
		t.Fatal("expected clear cookie header")
	}
	joined := setCookies[0]
	if !(strings.Contains(joined, "Max-Age=0") || strings.Contains(joined, "Max-Age=-1")) {
		t.Fatalf("expected cookie clear Max-Age header, got: %v", setCookies)
	}
}

func TestMiddleware_ExpiredRefreshEnabledSuccess(t *testing.T) {
	key := mustRSAKey(t)
	expiredClaims := baseClaims()
	expiredClaims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-5 * time.Second))
	expiredToken := signRS256Token(t, key, "kid-1", expiredClaims)

	refreshedClaims := baseClaims()
	refreshedClaims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(10 * time.Minute))
	refreshedClaims.Email = "refreshed@example.com"
	refreshedToken := signRS256Token(t, key, "kid-1", refreshedClaims)

	var refreshCalls int32
	client, ts := newMiddlewareClientWithJWKS(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jwkDoc{Keys: []jwkKey{rsaJWK(t, &key.PublicKey, "kid-1")}})
	})
	defer ts.Close()

	client.um = &fakeUMClient{
		authenticateWithRefreshTokenFunc: func(_ context.Context, _ usermanagement.AuthenticateWithRefreshTokenOpts) (usermanagement.RefreshAuthenticationResponse, error) {
			atomic.AddInt32(&refreshCalls, 1)
			return usermanagement.RefreshAuthenticationResponse{
				AccessToken:  refreshedToken,
				RefreshToken: "refresh_rotated_2",
			}, nil
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.test/private", nil)
	setCookieOnRequest(t, req, client.cfg, &cookieSession{
		AccessToken:  expiredToken,
		RefreshToken: "refresh_old_1",
	})

	var gotIdentity *Identity
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := vango.UserFromContext(r.Context())
		gotIdentity, _ = u.(*Identity)
		w.WriteHeader(http.StatusOK)
	})
	h := client.Middleware()(next)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if got := atomic.LoadInt32(&refreshCalls); got != 1 {
		t.Fatalf("refresh calls = %d, want 1", got)
	}
	if gotIdentity == nil {
		t.Fatal("expected identity after refresh")
	}
	if gotIdentity.Email != "refreshed@example.com" {
		t.Fatalf("Email = %q, want %q", gotIdentity.Email, "refreshed@example.com")
	}
	setCookies := w.Result().Header.Values("Set-Cookie")
	if len(setCookies) == 0 {
		t.Fatal("expected cookie rewrite after refresh")
	}
}

func TestMiddleware_ExpiredRefreshDisabledClears(t *testing.T) {
	key := mustRSAKey(t)
	claims := baseClaims()
	claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-5 * time.Second))
	token := signRS256Token(t, key, "kid-1", claims)

	client, ts := newMiddlewareClientWithJWKS(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jwkDoc{Keys: []jwkKey{rsaJWK(t, &key.PublicKey, "kid-1")}})
	}, func(cfg *Config) {
		cfg.DisableRefreshInMiddleware = true
	})
	defer ts.Close()

	req := httptest.NewRequest(http.MethodGet, "http://example.test/private", nil)
	setCookieOnRequest(t, req, client.cfg, &cookieSession{
		AccessToken:  token,
		RefreshToken: "refresh_1",
	})

	var gotUser any
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser = vango.UserFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	h := client.Middleware()(next)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if gotUser != nil {
		t.Fatalf("user = %#v, want nil", gotUser)
	}
	if len(w.Result().Header.Values("Set-Cookie")) == 0 {
		t.Fatal("expected clear cookie header")
	}
}

func TestMiddleware_ExpiredMissingRefreshTokenClears(t *testing.T) {
	key := mustRSAKey(t)
	claims := baseClaims()
	claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-5 * time.Second))
	token := signRS256Token(t, key, "kid-1", claims)

	client, ts := newMiddlewareClientWithJWKS(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jwkDoc{Keys: []jwkKey{rsaJWK(t, &key.PublicKey, "kid-1")}})
	})
	defer ts.Close()

	req := httptest.NewRequest(http.MethodGet, "http://example.test/private", nil)
	setCookieOnRequest(t, req, client.cfg, &cookieSession{
		AccessToken: token,
	})

	var gotUser any
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser = vango.UserFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	h := client.Middleware()(next)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if gotUser != nil {
		t.Fatalf("user = %#v, want nil", gotUser)
	}
	if len(w.Result().Header.Values("Set-Cookie")) == 0 {
		t.Fatal("expected clear cookie header")
	}
}

func TestMiddleware_ExpiredRefreshFailureClears(t *testing.T) {
	key := mustRSAKey(t)
	claims := baseClaims()
	claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-5 * time.Second))
	token := signRS256Token(t, key, "kid-1", claims)

	client, ts := newMiddlewareClientWithJWKS(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jwkDoc{Keys: []jwkKey{rsaJWK(t, &key.PublicKey, "kid-1")}})
	})
	defer ts.Close()

	var refreshCalls int32
	client.um = &fakeUMClient{
		authenticateWithRefreshTokenFunc: func(context.Context, usermanagement.AuthenticateWithRefreshTokenOpts) (usermanagement.RefreshAuthenticationResponse, error) {
			atomic.AddInt32(&refreshCalls, 1)
			return usermanagement.RefreshAuthenticationResponse{}, errors.New("refresh failed with refresh_token=secret")
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.test/private", nil)
	setCookieOnRequest(t, req, client.cfg, &cookieSession{
		AccessToken:  token,
		RefreshToken: "refresh_secret",
	})

	var gotUser any
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser = vango.UserFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	h := client.Middleware()(next)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if gotUser != nil {
		t.Fatalf("user = %#v, want nil", gotUser)
	}
	if got := atomic.LoadInt32(&refreshCalls); got != 1 {
		t.Fatalf("refresh calls = %d, want 1", got)
	}
	if len(w.Result().Header.Values("Set-Cookie")) == 0 {
		t.Fatal("expected clear cookie header")
	}
	assertNoSecretLeak(t, w.Body.String(), "refresh_secret")
}

func TestMiddleware_RefreshSuccessReverifyFailureClears(t *testing.T) {
	keyGood := mustRSAKey(t)
	keyOther := mustRSAKey(t)

	expiredClaims := baseClaims()
	expiredClaims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-5 * time.Second))
	expiredToken := signRS256Token(t, keyGood, "kid-good", expiredClaims)

	refreshedClaims := baseClaims()
	refreshedClaims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(10 * time.Minute))
	// Sign with a key that JWKS won't publish.
	refreshedToken := signRS256Token(t, keyOther, "kid-other", refreshedClaims)

	client, ts := newMiddlewareClientWithJWKS(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jwkDoc{Keys: []jwkKey{rsaJWK(t, &keyGood.PublicKey, "kid-good")}})
	})
	defer ts.Close()

	client.um = &fakeUMClient{
		authenticateWithRefreshTokenFunc: func(context.Context, usermanagement.AuthenticateWithRefreshTokenOpts) (usermanagement.RefreshAuthenticationResponse, error) {
			return usermanagement.RefreshAuthenticationResponse{
				AccessToken:  refreshedToken,
				RefreshToken: "refresh_rotated",
			}, nil
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.test/private", nil)
	setCookieOnRequest(t, req, client.cfg, &cookieSession{
		AccessToken:  expiredToken,
		RefreshToken: "refresh_old",
	})

	var gotUser any
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser = vango.UserFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	h := client.Middleware()(next)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if gotUser != nil {
		t.Fatalf("user = %#v, want nil", gotUser)
	}
	if len(w.Result().Header.Values("Set-Cookie")) == 0 {
		t.Fatal("expected clear cookie header")
	}
}

func TestMiddleware_IdentityHintFallback(t *testing.T) {
	key := mustRSAKey(t)
	claims := baseClaims()
	claims.Email = ""
	claims.Name = ""
	claims.OrgID = ""
	claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(10 * time.Minute))
	token := signRS256Token(t, key, "kid-1", claims)

	client, ts := newMiddlewareClientWithJWKS(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jwkDoc{Keys: []jwkKey{rsaJWK(t, &key.PublicKey, "kid-1")}})
	})
	defer ts.Close()

	req := httptest.NewRequest(http.MethodGet, "http://example.test/private", nil)
	setCookieOnRequest(t, req, client.cfg, &cookieSession{
		AccessToken:  token,
		RefreshToken: "refresh_1",
		IdentityHint: &Identity{
			Email: "hint@example.com",
			Name:  "Hint User",
			OrgID: "org_hint",
		},
	})

	var gotIdentity *Identity
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := vango.UserFromContext(r.Context())
		gotIdentity, _ = u.(*Identity)
		w.WriteHeader(http.StatusOK)
	})
	h := client.Middleware()(next)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if gotIdentity == nil {
		t.Fatal("expected identity in context")
	}
	if gotIdentity.Email != "hint@example.com" {
		t.Fatalf("Email = %q, want %q", gotIdentity.Email, "hint@example.com")
	}
	if gotIdentity.Name != "Hint User" {
		t.Fatalf("Name = %q, want %q", gotIdentity.Name, "Hint User")
	}
	if gotIdentity.OrgID != "org_hint" {
		t.Fatalf("OrgID = %q, want %q", gotIdentity.OrgID, "org_hint")
	}
	// Roles should still come from claims, not hint.
	if len(gotIdentity.Roles) == 0 || gotIdentity.Roles[0] != claims.Role {
		t.Fatalf("Roles = %#v", gotIdentity.Roles)
	}
}

func TestMiddleware_NotRouteProtection(t *testing.T) {
	client, ts := newMiddlewareClientWithJWKS(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jwkDoc{})
	})
	defer ts.Close()

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("handled by downstream"))
	})
	h := client.Middleware()(next)

	req := httptest.NewRequest(http.MethodGet, "http://example.test/private", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Result().StatusCode != http.StatusTeapot {
		t.Fatalf("status = %d, want %d", w.Result().StatusCode, http.StatusTeapot)
	}
	if body := w.Body.String(); !strings.Contains(body, "handled by downstream") {
		t.Fatalf("body = %q", body)
	}
}

func TestMiddleware_ConcurrentRefreshSingleFlight(t *testing.T) {
	key := mustRSAKey(t)
	expiredClaims := baseClaims()
	expiredClaims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-5 * time.Second))
	expiredToken := signRS256Token(t, key, "kid-1", expiredClaims)

	refreshedClaims := baseClaims()
	refreshedClaims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(10 * time.Minute))
	refreshedToken := signRS256Token(t, key, "kid-1", refreshedClaims)

	var refreshCalls int32
	client, ts := newMiddlewareClientWithJWKS(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jwkDoc{Keys: []jwkKey{rsaJWK(t, &key.PublicKey, "kid-1")}})
	})
	defer ts.Close()

	client.um = &fakeUMClient{
		authenticateWithRefreshTokenFunc: func(_ context.Context, _ usermanagement.AuthenticateWithRefreshTokenOpts) (usermanagement.RefreshAuthenticationResponse, error) {
			atomic.AddInt32(&refreshCalls, 1)
			time.Sleep(20 * time.Millisecond)
			return usermanagement.RefreshAuthenticationResponse{
				AccessToken:  refreshedToken,
				RefreshToken: "refresh_rotated",
			}, nil
		},
	}

	h := client.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u := vango.UserFromContext(r.Context()); u == nil {
			t.Error("expected identity in context")
		}
		w.WriteHeader(http.StatusOK)
	}))

	templateReq := httptest.NewRequest(http.MethodGet, "http://example.test/private", nil)
	setCookieOnRequest(t, templateReq, client.cfg, &cookieSession{
		AccessToken:  expiredToken,
		RefreshToken: "refresh_shared",
	})
	sharedCookie := templateReq.Cookies()[0]

	const concurrent = 2
	var wg sync.WaitGroup
	wg.Add(concurrent)
	errCh := make(chan error, concurrent)

	for i := 0; i < concurrent; i++ {
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "http://example.test/private", nil)
			req.AddCookie(sharedCookie)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Result().StatusCode != http.StatusOK {
				errCh <- errors.New("unexpected non-200 status")
			}
		}()
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatalf("request error: %v", err)
		}
	}
	if got := atomic.LoadInt32(&refreshCalls); got != 1 {
		t.Fatalf("refresh calls = %d, want 1", got)
	}
}
