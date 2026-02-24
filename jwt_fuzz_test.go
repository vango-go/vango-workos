package workos

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"
)

func FuzzVerifyAccessToken_NoPanic(f *testing.F) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		f.Fatalf("GenerateKey() error = %v", err)
	}

	client := &Client{
		cfg: Config{
			JWTIssuer:         "https://api.workos.com",
			JWTAudience:       "client_test_audience",
			JWKSCacheDuration: time.Hour,
		},
		jwksCache: &jwksCache{
			fetchedAt: time.Now(),
			keys: map[string]*rsa.PublicKey{
				"kid-fuzz": &key.PublicKey,
			},
		},
	}

	f.Add("")
	f.Add(".")
	f.Add("..")
	f.Add("not-a-jwt")
	f.Add("eyJhbGciOiJSUzI1NiJ9.e30.")

	f.Fuzz(func(t *testing.T, token string) {
		_, _ = client.VerifyAccessToken(context.Background(), token)
	})
}
