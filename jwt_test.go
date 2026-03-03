package workos

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func mustRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	return key
}

func signRS256Token(t *testing.T, privateKey *rsa.PrivateKey, kid string, claims rawAccessTokenClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(privateKey)
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}
	return signed
}

func signHS256Token(t *testing.T, kid string, claims rawAccessTokenClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tok.Header["kid"] = kid
	signed, err := tok.SignedString([]byte("hs-secret"))
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}
	return signed
}

func baseClaims() rawAccessTokenClaims {
	return rawAccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user_123",
			Issuer:    "https://api.workos.com",
			Audience:  jwt.ClaimStrings{"client_test_audience"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		},
		SID:          "sess_123",
		Email:        "user@example.com",
		Name:         "User Example",
		OrgID:        "org_123",
		Role:         "member",
		Roles:        []string{"admin"},
		Permissions:  []string{"projects:read"},
		Entitlements: []string{"feature:alpha"},
	}
}

func newJWTTestClient(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	ts := httptest.NewServer(handler)
	client := newTestClientForJWKS(t, ts.URL)
	return client, ts
}

func TestVerifyAccessToken_Success(t *testing.T) {
	key := mustRSAKey(t)
	claims := baseClaims()
	token := signRS256Token(t, key, "kid-1", claims)

	client, ts := newJWTTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jwkDoc{Keys: []jwkKey{rsaJWK(t, &key.PublicKey, "kid-1")}})
	})
	defer ts.Close()

	got, err := client.VerifyAccessToken(context.Background(), token)
	if err != nil {
		t.Fatalf("VerifyAccessToken() error = %v", err)
	}

	if got.UserID != claims.Subject {
		t.Fatalf("UserID = %q, want %q", got.UserID, claims.Subject)
	}
	if got.SessionID != claims.SID {
		t.Fatalf("SessionID = %q, want %q", got.SessionID, claims.SID)
	}
	if got.Email != claims.Email {
		t.Fatalf("Email = %q, want %q", got.Email, claims.Email)
	}
	if got.Name != claims.Name {
		t.Fatalf("Name = %q, want %q", got.Name, claims.Name)
	}
	if got.OrgID != claims.OrgID {
		t.Fatalf("OrgID = %q, want %q", got.OrgID, claims.OrgID)
	}
	if len(got.Roles) != 2 || got.Roles[0] != "member" || got.Roles[1] != "admin" {
		t.Fatalf("Roles = %#v", got.Roles)
	}
	if got.Audience != "client_test_audience" {
		t.Fatalf("Audience = %q", got.Audience)
	}
	if got.Issuer != claims.Issuer {
		t.Fatalf("Issuer = %q", got.Issuer)
	}
}

func TestVerifyAccessToken_EmptyToken(t *testing.T) {
	client, ts := newJWTTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	defer ts.Close()

	_, err := client.VerifyAccessToken(context.Background(), "")
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "workos: access token required" {
		t.Fatalf("error = %q", err.Error())
	}
	if !errors.Is(err, ErrAccessTokenInvalid) {
		t.Fatal("expected ErrAccessTokenInvalid")
	}
}

func TestVerifyAccessToken_InvalidIssuer(t *testing.T) {
	key := mustRSAKey(t)
	claims := baseClaims()
	claims.Issuer = "https://wrong-issuer.example.com"
	token := signRS256Token(t, key, "kid-1", claims)

	client, ts := newJWTTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jwkDoc{Keys: []jwkKey{rsaJWK(t, &key.PublicKey, "kid-1")}})
	})
	defer ts.Close()

	_, err := client.VerifyAccessToken(context.Background(), token)
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "workos: invalid token issuer" {
		t.Fatalf("error = %q", err.Error())
	}
	if !errors.Is(err, ErrAccessTokenInvalid) {
		t.Fatal("expected ErrAccessTokenInvalid")
	}
}

func TestVerifyAccessToken_InvalidAudience(t *testing.T) {
	key := mustRSAKey(t)
	claims := baseClaims()
	claims.Audience = jwt.ClaimStrings{"some-other-aud"}
	token := signRS256Token(t, key, "kid-1", claims)

	client, ts := newJWTTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jwkDoc{Keys: []jwkKey{rsaJWK(t, &key.PublicKey, "kid-1")}})
	})
	defer ts.Close()

	_, err := client.VerifyAccessToken(context.Background(), token)
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "workos: invalid token audience" {
		t.Fatalf("error = %q", err.Error())
	}
	if !errors.Is(err, ErrAccessTokenInvalid) {
		t.Fatal("expected ErrAccessTokenInvalid")
	}
}

func TestVerifyAccessToken_MissingSubOrSID(t *testing.T) {
	key := mustRSAKey(t)

	t.Run("missing sub", func(t *testing.T) {
		claims := baseClaims()
		claims.Subject = ""
		token := signRS256Token(t, key, "kid-1", claims)

		client, ts := newJWTTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(jwkDoc{Keys: []jwkKey{rsaJWK(t, &key.PublicKey, "kid-1")}})
		})
		defer ts.Close()

		_, err := client.VerifyAccessToken(context.Background(), token)
		if err == nil {
			t.Fatal("expected error")
		}
		if err.Error() != "workos: invalid token claims" {
			t.Fatalf("error = %q", err.Error())
		}
		if !errors.Is(err, ErrAccessTokenInvalid) {
			t.Fatal("expected ErrAccessTokenInvalid")
		}
	})

	t.Run("missing sid", func(t *testing.T) {
		claims := baseClaims()
		claims.SID = ""
		token := signRS256Token(t, key, "kid-1", claims)

		client, ts := newJWTTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(jwkDoc{Keys: []jwkKey{rsaJWK(t, &key.PublicKey, "kid-1")}})
		})
		defer ts.Close()

		_, err := client.VerifyAccessToken(context.Background(), token)
		if err == nil {
			t.Fatal("expected error")
		}
		if err.Error() != "workos: invalid token claims" {
			t.Fatalf("error = %q", err.Error())
		}
		if !errors.Is(err, ErrAccessTokenInvalid) {
			t.Fatal("expected ErrAccessTokenInvalid")
		}
	})
}

func TestVerifyAccessToken_MissingExp_ReturnsInvalidClaims(t *testing.T) {
	key := mustRSAKey(t)
	claims := baseClaims()
	claims.ExpiresAt = nil
	token := signRS256Token(t, key, "kid-1", claims)

	client, ts := newJWTTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jwkDoc{Keys: []jwkKey{rsaJWK(t, &key.PublicKey, "kid-1")}})
	})
	defer ts.Close()

	_, err := client.VerifyAccessToken(context.Background(), token)
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "workos: invalid token claims" {
		t.Fatalf("error = %q", err.Error())
	}
	if !errors.Is(err, ErrAccessTokenInvalid) {
		t.Fatal("expected ErrAccessTokenInvalid")
	}
	assertNoSecretLeak(t, err.Error(), token)
}

func TestVerifyAccessToken_ExpiredTokenOutsideLeeway(t *testing.T) {
	key := mustRSAKey(t)
	claims := baseClaims()
	claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-2 * time.Minute))
	token := signRS256Token(t, key, "kid-1", claims)

	client, ts := newJWTTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jwkDoc{Keys: []jwkKey{rsaJWK(t, &key.PublicKey, "kid-1")}})
	})
	defer ts.Close()

	_, err := client.VerifyAccessToken(context.Background(), token)
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "workos: invalid access token" {
		t.Fatalf("error = %q", err.Error())
	}
	if !errors.Is(err, ErrAccessTokenExpired) {
		t.Fatal("expected ErrAccessTokenExpired")
	}
}

func TestVerifyAccessToken_UnexpectedAlg(t *testing.T) {
	claims := baseClaims()
	token := signHS256Token(t, "kid-1", claims)

	key := mustRSAKey(t)
	client, ts := newJWTTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jwkDoc{Keys: []jwkKey{rsaJWK(t, &key.PublicKey, "kid-1")}})
	})
	defer ts.Close()

	_, err := client.VerifyAccessToken(context.Background(), token)
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "workos: unexpected jwt alg" {
		t.Fatalf("error = %q", err.Error())
	}
	if !errors.Is(err, ErrAccessTokenInvalid) {
		t.Fatal("expected ErrAccessTokenInvalid")
	}
}

func TestVerifyAccessToken_UnknownKidTriggersSingleForcedRefresh(t *testing.T) {
	keyA := mustRSAKey(t)
	keyB := mustRSAKey(t)

	claims := baseClaims()
	token := signRS256Token(t, keyB, "kid-b", claims)

	var hits int32
	client, ts := newJWTTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		hit := atomic.AddInt32(&hits, 1)
		if hit == 1 {
			_ = json.NewEncoder(w).Encode(jwkDoc{Keys: []jwkKey{rsaJWK(t, &keyA.PublicKey, "kid-a")}})
			return
		}
		_ = json.NewEncoder(w).Encode(jwkDoc{Keys: []jwkKey{rsaJWK(t, &keyB.PublicKey, "kid-b")}})
	})
	defer ts.Close()

	_, err := client.VerifyAccessToken(context.Background(), token)
	if err != nil {
		t.Fatalf("VerifyAccessToken() error = %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Fatalf("JWKS hits = %d, want 2", got)
	}
}

func TestVerifyAccessToken_UnknownKidAfterRefreshFails(t *testing.T) {
	keyA := mustRSAKey(t)
	keyB := mustRSAKey(t)

	claims := baseClaims()
	token := signRS256Token(t, keyB, "kid-b", claims)

	client, ts := newJWTTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jwkDoc{Keys: []jwkKey{rsaJWK(t, &keyA.PublicKey, "kid-a")}})
	})
	defer ts.Close()

	_, err := client.VerifyAccessToken(context.Background(), token)
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "workos: unknown jwt kid" {
		t.Fatalf("error = %q", err.Error())
	}
	if !errors.Is(err, ErrAccessTokenInvalid) {
		t.Fatal("expected ErrAccessTokenInvalid")
	}
}

func TestVerifyAccessToken_DoesNotLeakTokenInError(t *testing.T) {
	key := mustRSAKey(t)
	claims := baseClaims()
	claims.Audience = jwt.ClaimStrings{"wrong"}
	token := signRS256Token(t, key, "kid-1", claims)

	client, ts := newJWTTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jwkDoc{Keys: []jwkKey{rsaJWK(t, &key.PublicKey, "kid-1")}})
	})
	defer ts.Close()

	_, err := client.VerifyAccessToken(context.Background(), token)
	if err == nil {
		t.Fatal("expected error")
	}
	assertNoSecretLeak(t, err.Error(), token)
	if errors.Is(err, errJWTUnknownKID) {
		t.Fatal("unexpected sentinel leak")
	}
}
