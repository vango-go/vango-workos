package workos

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/workos/workos-go/v6/pkg/usermanagement"
)

func TestRefreshTokens_SingleFlight(t *testing.T) {
	key := mustRSAKey(t)
	claims := baseClaims()
	claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(5 * time.Minute))
	accessToken := signRS256Token(t, key, "kid-1", claims)

	var upstreamCalls int32
	um := &fakeUMClient{
		authenticateWithRefreshTokenFunc: func(_ context.Context, opts usermanagement.AuthenticateWithRefreshTokenOpts) (usermanagement.RefreshAuthenticationResponse, error) {
			atomic.AddInt32(&upstreamCalls, 1)
			if opts.ClientID != "client_test_123456" {
				t.Fatalf("ClientID = %q, want %q", opts.ClientID, "client_test_123456")
			}
			time.Sleep(25 * time.Millisecond)
			return usermanagement.RefreshAuthenticationResponse{
				AccessToken:  accessToken,
				RefreshToken: "refresh_next_001",
			}, nil
		},
	}

	client, ts := newJWTTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jwkDoc{Keys: []jwkKey{rsaJWK(t, &key.PublicKey, "kid-1")}})
	})
	defer ts.Close()
	client.um = um

	const workers = 8
	var wg sync.WaitGroup
	results := make(chan *TokenSet, workers)
	errs := make(chan error, workers)

	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			got, err := client.RefreshTokens(context.Background(), "refresh_abc_123")
			errs <- err
			results <- got
		}()
	}
	wg.Wait()
	close(errs)
	close(results)

	for err := range errs {
		if err != nil {
			t.Fatalf("RefreshTokens() error = %v", err)
		}
	}

	for got := range results {
		if got == nil {
			t.Fatal("RefreshTokens() returned nil TokenSet")
		}
		if got.AccessToken != accessToken {
			t.Fatalf("AccessToken mismatch")
		}
		if got.RefreshToken != "refresh_next_001" {
			t.Fatalf("RefreshToken = %q, want %q", got.RefreshToken, "refresh_next_001")
		}
		if !got.ExpiresAt.Equal(claims.ExpiresAt.Time) {
			t.Fatalf("ExpiresAt = %v, want %v", got.ExpiresAt, claims.ExpiresAt.Time)
		}
	}

	if got := atomic.LoadInt32(&upstreamCalls); got != 1 {
		t.Fatalf("upstream refresh calls = %d, want 1", got)
	}
}

func TestRefreshTokens_FailurePathsAreSanitized(t *testing.T) {
	t.Run("empty refresh token", func(t *testing.T) {
		client := &Client{}
		_, err := client.RefreshTokens(context.Background(), "")
		if err == nil {
			t.Fatal("expected error")
		}
		if err.Error() != "workos: refresh token required" {
			t.Fatalf("error = %q", err.Error())
		}
	})

	t.Run("upstream refresh error", func(t *testing.T) {
		client := &Client{
			cfg: Config{ClientID: "client_test_123456"},
			um: &fakeUMClient{
				authenticateWithRefreshTokenFunc: func(context.Context, usermanagement.AuthenticateWithRefreshTokenOpts) (usermanagement.RefreshAuthenticationResponse, error) {
					return usermanagement.RefreshAuthenticationResponse{}, errors.New("upstream refresh failed for refresh_token=refresh_secret_001 eyJabc")
				},
			},
		}

		_, err := client.RefreshTokens(context.Background(), "refresh_secret_001")
		if err == nil {
			t.Fatal("expected error")
		}
		if err.Error() != "workos: refresh failed" {
			t.Fatalf("error = %q", err.Error())
		}
		assertNoSecretLeak(t, err.Error(), "refresh_secret_001")
	})

	t.Run("empty tokens in response", func(t *testing.T) {
		client := &Client{
			cfg: Config{ClientID: "client_test_123456"},
			um: &fakeUMClient{
				authenticateWithRefreshTokenFunc: func(context.Context, usermanagement.AuthenticateWithRefreshTokenOpts) (usermanagement.RefreshAuthenticationResponse, error) {
					return usermanagement.RefreshAuthenticationResponse{
						AccessToken:  "",
						RefreshToken: "",
					}, nil
				},
			},
		}

		_, err := client.RefreshTokens(context.Background(), "refresh_abc")
		if err == nil {
			t.Fatal("expected error")
		}
		if err.Error() != "workos: refresh failed" {
			t.Fatalf("error = %q", err.Error())
		}
	})

	t.Run("invalid refreshed access token", func(t *testing.T) {
		client := &Client{
			cfg: Config{
				ClientID:          "client_test_123456",
				JWKSURL:           "",
				JWTIssuer:         "https://api.workos.com",
				JWTAudience:       "client_test_audience",
				JWKSCacheDuration: time.Hour,
			},
			um: &fakeUMClient{
				authenticateWithRefreshTokenFunc: func(context.Context, usermanagement.AuthenticateWithRefreshTokenOpts) (usermanagement.RefreshAuthenticationResponse, error) {
					return usermanagement.RefreshAuthenticationResponse{
						AccessToken:  "not-a-jwt",
						RefreshToken: "refresh_next",
					}, nil
				},
			},
		}

		_, err := client.RefreshTokens(context.Background(), "refresh_abc")
		if err == nil {
			t.Fatal("expected error")
		}
		if err.Error() != "workos: refresh failed" {
			t.Fatalf("error = %q", err.Error())
		}
		assertNoSecretLeak(t, err.Error())
	})
}
