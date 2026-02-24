package workos

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"time"
)

type jwksCache struct {
	fetchedAt time.Time
	keys      map[string]*rsa.PublicKey
}

type jwkDoc struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func normalizeIssuer(s string) string {
	return strings.TrimRight(strings.TrimSpace(s), "/")
}

func (c *Client) getJWKS(ctx context.Context, force bool) (*jwksCache, error) {
	now := time.Now()
	ttl := c.cfg.JWKSCacheDuration

	c.jwksMu.RLock()
	cur := c.jwksCache
	c.jwksMu.RUnlock()
	if !force && ttl > 0 && cur != nil && now.Sub(cur.fetchedAt) < ttl {
		return cur, nil
	}

	c.jwksFetchMu.Lock()
	defer c.jwksFetchMu.Unlock()

	c.jwksMu.RLock()
	cur = c.jwksCache
	c.jwksMu.RUnlock()
	if !force && ttl > 0 && cur != nil && now.Sub(cur.fetchedAt) < ttl {
		return cur, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.JWKSURL, nil)
	if err != nil {
		return nil, &SafeError{msg: "workos: jwks request build failed", cause: err}
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, &SafeError{msg: "workos: jwks fetch failed", cause: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		return nil, errors.New("workos: jwks fetch failed")
	}

	var doc jwkDoc
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, &SafeError{msg: "workos: jwks decode failed", cause: err}
	}

	keys := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, key := range doc.Keys {
		if key.Kid == "" || strings.ToUpper(key.Kty) != "RSA" {
			continue
		}

		nb, err := base64.RawURLEncoding.DecodeString(key.N)
		if err != nil {
			continue
		}
		eb, err := base64.RawURLEncoding.DecodeString(key.E)
		if err != nil {
			continue
		}

		exponent := 0
		for _, b := range eb {
			exponent = (exponent << 8) | int(b)
		}
		if exponent == 0 {
			continue
		}

		keys[key.Kid] = &rsa.PublicKey{
			N: new(big.Int).SetBytes(nb),
			E: exponent,
		}
	}

	next := &jwksCache{fetchedAt: now, keys: keys}
	c.jwksMu.Lock()
	c.jwksCache = next
	c.jwksMu.Unlock()

	return next, nil
}
