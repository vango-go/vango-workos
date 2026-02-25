package workos

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func newTestClientForJWKS(t *testing.T, jwksURL string) *Client {
	t.Helper()

	cfg := Config{
		APIKey:            "sk_test_abcdefghijklmnopqrstuvwxyz123456",
		ClientID:          "client_test_123456",
		RedirectURI:       "https://app.example.com/auth/callback",
		CookieSecret:      "0123456789abcdef0123456789abcdef",
		BaseURL:           "https://app.example.com",
		JWKSURL:           jwksURL,
		JWKSCacheDuration: time.Hour,
		JWTAudience:       "client_test_audience",
		JWTIssuer:         "https://api.workos.com",
	}

	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return c
}

func rsaJWK(t *testing.T, pub *rsa.PublicKey, kid string) jwkKey {
	t.Helper()

	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	return jwkKey{Kty: "RSA", Kid: kid, N: n, E: e, Alg: "RS256", Use: "sig"}
}

func TestGetJWKS_CachesWithinTTL(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	var hits int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		_ = json.NewEncoder(w).Encode(jwkDoc{Keys: []jwkKey{rsaJWK(t, &key.PublicKey, "kid-1")}})
	}))
	defer ts.Close()

	client := newTestClientForJWKS(t, ts.URL)

	if _, err := client.getJWKS(context.Background(), false); err != nil {
		t.Fatalf("getJWKS #1 error = %v", err)
	}
	if _, err := client.getJWKS(context.Background(), false); err != nil {
		t.Fatalf("getJWKS #2 error = %v", err)
	}

	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("JWKS HTTP hits = %d, want 1", got)
	}
}

func TestGetJWKS_ForceRefresh(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	var hits int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		_ = json.NewEncoder(w).Encode(jwkDoc{Keys: []jwkKey{rsaJWK(t, &key.PublicKey, "kid-1")}})
	}))
	defer ts.Close()

	client := newTestClientForJWKS(t, ts.URL)

	if _, err := client.getJWKS(context.Background(), false); err != nil {
		t.Fatalf("getJWKS false error = %v", err)
	}
	if _, err := client.getJWKS(context.Background(), true); err != nil {
		t.Fatalf("getJWKS true error = %v", err)
	}

	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Fatalf("JWKS HTTP hits = %d, want 2", got)
	}
}

func TestGetJWKS_Non2xx(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	client := newTestClientForJWKS(t, ts.URL)
	_, err := client.getJWKS(context.Background(), false)
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "workos: jwks fetch failed" {
		t.Fatalf("error = %q, want %q", err.Error(), "workos: jwks fetch failed")
	}
	if !errors.Is(err, ErrJWKSUnavailable) {
		t.Fatal("expected ErrJWKSUnavailable")
	}
}

func TestGetJWKS_InvalidJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("{"))
	}))
	defer ts.Close()

	client := newTestClientForJWKS(t, ts.URL)
	_, err := client.getJWKS(context.Background(), false)
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "workos: jwks decode failed" {
		t.Fatalf("error = %q, want %q", err.Error(), "workos: jwks decode failed")
	}
	var safeErr *SafeError
	if ok := errors.As(err, &safeErr); !ok {
		t.Fatal("expected SafeError")
	}
	if !errors.Is(err, ErrJWKSUnavailable) {
		t.Fatal("expected ErrJWKSUnavailable")
	}
}

func TestGetJWKS_IgnoresInvalidKeys(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jwkDoc{Keys: []jwkKey{
			{Kty: "EC", Kid: "ec-key", N: "abc", E: "AQAB"},
			{Kty: "RSA", Kid: "", N: "abc", E: "AQAB"},
			{Kty: "RSA", Kid: "bad-n", N: "!!!", E: "AQAB"},
			{Kty: "RSA", Kid: "bad-e", N: base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()), E: "!!!"},
			rsaJWK(t, &key.PublicKey, "good-key"),
		}})
	}))
	defer ts.Close()

	client := newTestClientForJWKS(t, ts.URL)
	cache, err := client.getJWKS(context.Background(), false)
	if err != nil {
		t.Fatalf("getJWKS error = %v", err)
	}

	if len(cache.keys) != 1 {
		t.Fatalf("parsed keys = %d, want 1", len(cache.keys))
	}
	if cache.keys["good-key"] == nil {
		t.Fatal("expected good-key to be present")
	}
}

func TestGetJWKS_RespectsConfiguredTimeout(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		time.Sleep(250 * time.Millisecond)
	}))
	defer ts.Close()

	cfg := Config{
		APIKey:            "sk_test_abcdefghijklmnopqrstuvwxyz123456",
		ClientID:          "client_test_123456",
		RedirectURI:       "https://app.example.com/auth/callback",
		CookieSecret:      "0123456789abcdef0123456789abcdef",
		BaseURL:           "https://app.example.com",
		JWKSURL:           ts.URL,
		JWKSCacheDuration: time.Hour,
		JWKSFetchTimeout:  40 * time.Millisecond,
		JWTAudience:       "client_test_audience",
		JWTIssuer:         "https://api.workos.com",
	}

	client, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	start := time.Now()
	_, err = client.getJWKS(context.Background(), true)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	elapsed := time.Since(start)
	if elapsed > 220*time.Millisecond {
		t.Fatalf("getJWKS took too long: %v", elapsed)
	}
	if !errors.Is(err, ErrJWKSUnavailable) {
		t.Fatal("expected ErrJWKSUnavailable")
	}
}
