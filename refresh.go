package workos

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"

	"github.com/workos/workos-go/v6/pkg/usermanagement"
)

type refreshGroup struct {
	mu sync.Mutex
	m  map[string]*refreshCall
}

type refreshCall struct {
	done chan struct{}
	res  *TokenSet
	err  error
}

func (g *refreshGroup) Do(key string, fn func() (*TokenSet, error)) (*TokenSet, error) {
	g.mu.Lock()
	if g.m == nil {
		g.m = make(map[string]*refreshCall)
	}
	if c, ok := g.m[key]; ok {
		g.mu.Unlock()
		<-c.done
		return c.res, c.err
	}
	c := &refreshCall{done: make(chan struct{})}
	g.m[key] = c
	g.mu.Unlock()

	c.res, c.err = fn()

	g.mu.Lock()
	delete(g.m, key)
	close(c.done)
	g.mu.Unlock()

	return c.res, c.err
}

func refreshKey(refreshToken string) string {
	sum := sha256.Sum256([]byte(refreshToken))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (c *Client) RefreshTokens(ctx context.Context, refreshToken string) (*TokenSet, error) {
	if refreshToken == "" {
		return nil, errors.New("workos: refresh token required")
	}

	key := refreshKey(refreshToken)
	return c.refresh.Do(key, func() (*TokenSet, error) {
		resp, err := c.um.AuthenticateWithRefreshToken(ctx, usermanagement.AuthenticateWithRefreshTokenOpts{
			ClientID:     c.cfg.ClientID,
			RefreshToken: refreshToken,
		})
		if err != nil {
			return nil, errors.New("workos: refresh failed")
		}
		if resp.AccessToken == "" || resp.RefreshToken == "" {
			return nil, errors.New("workos: refresh failed")
		}
		claims, err := c.VerifyAccessToken(ctx, resp.AccessToken)
		if err != nil {
			return nil, errors.New("workos: refresh failed")
		}

		return &TokenSet{
			AccessToken:  resp.AccessToken,
			RefreshToken: resp.RefreshToken,
			ExpiresAt:    claims.ExpiresAt,
		}, nil
	})
}
