package workos

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testCookieConfig() Config {
	return Config{
		CookieName:     "__vango_workos_session",
		CookieSecret:   "0123456789abcdef0123456789abcdef",
		CookieSecure:   true,
		CookieSameSite: "lax",
		CookieMaxAge:   7 * 24 * time.Hour,
	}
}

func TestStateCookieSetValidateClear(t *testing.T) {
	cfg := testCookieConfig()
	rec := httptest.NewRecorder()
	setStateCookie(rec, "state-123", cfg)

	resp := rec.Result()
	cookies := resp.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookie count = %d, want 1", len(cookies))
	}
	c := cookies[0]
	if c.Name != stateCookieName {
		t.Fatalf("state cookie name = %q", c.Name)
	}
	if c.Value != "state-123" {
		t.Fatalf("state cookie value = %q", c.Value)
	}
	if !c.HttpOnly {
		t.Fatal("state cookie should be HttpOnly")
	}
	if !c.Secure {
		t.Fatal("state cookie should be Secure")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Fatalf("state cookie sameSite = %v", c.SameSite)
	}
	if c.MaxAge != int(stateCookieMaxAge.Seconds()) {
		t.Fatalf("state cookie maxAge = %d", c.MaxAge)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(c)
	if !validateStateCookie(req, "state-123", cfg) {
		t.Fatal("state cookie should validate")
	}
	if validateStateCookie(req, "state-xxx", cfg) {
		t.Fatal("state cookie should fail for mismatched value")
	}

	rec2 := httptest.NewRecorder()
	clearStateCookie(rec2, cfg)
	cleared := rec2.Result().Cookies()[0]
	if cleared.MaxAge != -1 {
		t.Fatalf("cleared state cookie maxAge = %d", cleared.MaxAge)
	}
}

func TestSessionCookieRoundTrip(t *testing.T) {
	cfg := testCookieConfig()
	sess := &cookieSession{AccessToken: "at-1", RefreshToken: "rt-1", IdentityHint: &Identity{UserID: "u1"}}

	rec := httptest.NewRecorder()
	if err := setSessionCookie(rec, sess, cfg); err != nil {
		t.Fatalf("setSessionCookie error = %v", err)
	}
	if sess.V != 1 {
		t.Fatalf("session version = %d", sess.V)
	}
	if sess.IssuedAtUnix == 0 {
		t.Fatal("session issuedAt should be set")
	}

	cookie := rec.Result().Cookies()[0]
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)

	got, err := readSessionCookie(req, cfg)
	if err != nil {
		t.Fatalf("readSessionCookie error = %v", err)
	}
	if got.AccessToken != "at-1" || got.RefreshToken != "rt-1" {
		t.Fatalf("unexpected tokens after roundtrip")
	}
	if got.IdentityHint == nil || got.IdentityHint.UserID != "u1" {
		t.Fatalf("identity hint mismatch: %+v", got.IdentityHint)
	}
}

func TestOpenCookieSessionRejectsWrongAADAndSecret(t *testing.T) {
	cfg := testCookieConfig()
	sess := &cookieSession{AccessToken: "at", RefreshToken: "rt"}
	sealed, err := sealCookieSession(sess, cfg.CookieSecret, cfg.CookieName)
	if err != nil {
		t.Fatalf("sealCookieSession error = %v", err)
	}

	if _, err := openCookieSession(sealed, cfg.CookieSecret, "different_cookie_name"); err == nil {
		t.Fatal("expected error for wrong AAD")
	}
	if _, err := openCookieSession(sealed, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", cfg.CookieName); err == nil {
		t.Fatal("expected error for wrong secret")
	}
}

func TestReadSessionCookieFallbackSecret(t *testing.T) {
	cfg := testCookieConfig()
	fallback := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	cfg.CookieSecretFallbacks = []string{fallback}

	sess := &cookieSession{AccessToken: "at-fb", RefreshToken: "rt-fb"}
	sealed, err := sealCookieSession(sess, fallback, cfg.CookieName)
	if err != nil {
		t.Fatalf("sealCookieSession error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: cfg.CookieName, Value: sealed})

	got, err := readSessionCookie(req, cfg)
	if err != nil {
		t.Fatalf("readSessionCookie error = %v", err)
	}
	if got.AccessToken != "at-fb" {
		t.Fatalf("AccessToken = %q", got.AccessToken)
	}
}

func TestOpenCookieSessionMalformedPayloads(t *testing.T) {
	cfg := testCookieConfig()

	if _, err := openCookieSession("***not-base64***", cfg.CookieSecret, cfg.CookieName); err == nil {
		t.Fatal("expected invalid base64 error")
	}

	tooShort := "AQ"
	if _, err := openCookieSession(tooShort, cfg.CookieSecret, cfg.CookieName); err == nil {
		t.Fatal("expected invalid payload error")
	}
}

func TestClearSessionCookie(t *testing.T) {
	cfg := testCookieConfig()
	rec := httptest.NewRecorder()
	clearSessionCookie(rec, cfg)
	c := rec.Result().Cookies()[0]
	if c.Name != cfg.CookieName {
		t.Fatalf("cookie name = %q", c.Name)
	}
	if c.MaxAge != -1 {
		t.Fatalf("cookie maxAge = %d", c.MaxAge)
	}
}

func TestCookieErrorStringsDoNotLeakTokens(t *testing.T) {
	cfg := testCookieConfig()
	sess := &cookieSession{AccessToken: "secret_access_token_123", RefreshToken: "secret_refresh_token_123"}

	sealed, err := sealCookieSession(sess, cfg.CookieSecret, cfg.CookieName)
	if err != nil {
		t.Fatalf("sealCookieSession error = %v", err)
	}

	_, err = openCookieSession(sealed, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", cfg.CookieName)
	if err == nil {
		t.Fatal("expected decryption error")
	}
	assertNoSecretLeak(t, err.Error(), "secret_access_token_123", "secret_refresh_token_123", sealed)

	_, err = readSessionCookie(httptest.NewRequest(http.MethodGet, "/", nil), cfg)
	if err == nil {
		t.Fatal("expected missing cookie error")
	}
	assertNoSecretLeak(t, err.Error(), "secret_access_token_123", "secret_refresh_token_123")

	_, err = openCookieSession(strings.Repeat("a", 10), cfg.CookieSecret, cfg.CookieName)
	if err == nil {
		t.Fatal("expected decode error")
	}
	assertNoSecretLeak(t, err.Error(), "secret_access_token_123", "secret_refresh_token_123")
}

func TestCookieSameSiteNoneForcesSecure(t *testing.T) {
	cfg := testCookieConfig()
	cfg.CookieSecure = false
	cfg.CookieSameSite = "none"

	rec := httptest.NewRecorder()
	setStateCookie(rec, "state-123", cfg)
	stateCookie := rec.Result().Cookies()[0]
	if !stateCookie.Secure {
		t.Fatal("state cookie should force Secure when SameSite=None")
	}

	rec = httptest.NewRecorder()
	if err := setSessionCookie(rec, &cookieSession{AccessToken: "at", RefreshToken: "rt"}, cfg); err != nil {
		t.Fatalf("setSessionCookie error = %v", err)
	}
	sessionCookie := rec.Result().Cookies()[0]
	if !sessionCookie.Secure {
		t.Fatal("session cookie should force Secure when SameSite=None")
	}
}
