package workos

import (
	"errors"
	"net/http"
	"time"

	"github.com/vango-go/vango"
)

func (c *Client) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookieSess, err := readSessionCookie(r, c.cfg)
			if err != nil {
				if errors.Is(err, http.ErrNoCookie) {
					next.ServeHTTP(w, r)
					return
				}
				clearSessionCookie(w, c.cfg)
				next.ServeHTTP(w, r)
				return
			}
			if cookieSess == nil {
				clearSessionCookie(w, c.cfg)
				next.ServeHTTP(w, r)
				return
			}

			accessToken := cookieSess.AccessToken
			refreshToken := cookieSess.RefreshToken
			needCookieWrite := false

			claims, err := c.VerifyAccessToken(r.Context(), accessToken)
			if err != nil {
				if c.cfg.DisableRefreshInMiddleware || refreshToken == "" {
					clearSessionCookie(w, c.cfg)
					next.ServeHTTP(w, r)
					return
				}
				if err.Error() != "workos: invalid access token" {
					clearSessionCookie(w, c.cfg)
					next.ServeHTTP(w, r)
					return
				}

				refreshed, err := c.RefreshTokens(r.Context(), refreshToken)
				if err != nil {
					clearSessionCookie(w, c.cfg)
					next.ServeHTTP(w, r)
					return
				}
				accessToken = refreshed.AccessToken
				refreshToken = refreshed.RefreshToken
				needCookieWrite = true

				claims, err = c.VerifyAccessToken(r.Context(), accessToken)
				if err != nil {
					clearSessionCookie(w, c.cfg)
					next.ServeHTTP(w, r)
					return
				}
			}

			if !claims.ExpiresAt.IsZero() && time.Now().After(claims.ExpiresAt) {
				if c.cfg.DisableRefreshInMiddleware || refreshToken == "" {
					clearSessionCookie(w, c.cfg)
					next.ServeHTTP(w, r)
					return
				}

				refreshed, err := c.RefreshTokens(r.Context(), refreshToken)
				if err != nil {
					clearSessionCookie(w, c.cfg)
					next.ServeHTTP(w, r)
					return
				}
				accessToken = refreshed.AccessToken
				refreshToken = refreshed.RefreshToken
				needCookieWrite = true

				claims, err = c.VerifyAccessToken(r.Context(), accessToken)
				if err != nil {
					clearSessionCookie(w, c.cfg)
					next.ServeHTTP(w, r)
					return
				}
			}

			hint := cookieSess.IdentityHint
			identity := &Identity{
				UserID:       claims.UserID,
				Email:        claims.Email,
				Name:         claims.Name,
				OrgID:        claims.OrgID,
				Roles:        claims.Roles,
				Permissions:  claims.Permissions,
				Entitlements: claims.Entitlements,
				SessionID:    claims.SessionID,
				ExpiresAt:    claims.ExpiresAt,
			}
			if identity.Email == "" && hint != nil {
				identity.Email = hint.Email
			}
			if identity.Name == "" && hint != nil {
				identity.Name = hint.Name
			}
			if identity.OrgID == "" && hint != nil {
				identity.OrgID = hint.OrgID
			}

			if needCookieWrite || cookieSess.IdentityHint == nil {
				if err := setSessionCookie(w, &cookieSession{
					AccessToken:  accessToken,
					RefreshToken: refreshToken,
					IdentityHint: identity,
				}, c.cfg); err != nil {
					clearSessionCookie(w, c.cfg)
					next.ServeHTTP(w, r)
					return
				}
			}

			ctx := vango.WithUser(r.Context(), identity)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
