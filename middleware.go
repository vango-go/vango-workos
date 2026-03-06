package workos

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/vango-go/vango"
)

var middlewareReadSessionCookie = readSessionCookie

func (c *Client) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Fail open at cookie read/decrypt boundary: treat as unauthenticated and
			// continue without mutating cookie state.
			cookieSess, err := middlewareReadSessionCookie(r, c.cfg)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}
			if cookieSess == nil {
				// Defensive branch for unexpected nil session snapshots.
				next.ServeHTTP(w, r)
				return
			}

			accessToken := cookieSess.AccessToken
			refreshToken := cookieSess.RefreshToken
			needCookieWrite := false

			claims, err := c.VerifyAccessToken(r.Context(), accessToken)
			if err != nil {
				switch {
				case errors.Is(err, ErrJWKSUnavailable):
					next.ServeHTTP(w, r)
					return
				case errors.Is(err, ErrAccessTokenExpired):
					if c.cfg.DisableRefreshInMiddleware || refreshToken == "" {
						clearSessionCookie(w, c.cfg)
						next.ServeHTTP(w, r)
						return
					}
					refreshed, err := c.RefreshTokens(r.Context(), refreshToken)
					if err != nil {
						if errors.Is(err, ErrJWKSUnavailable) {
							next.ServeHTTP(w, r)
							return
						}
						clearSessionCookie(w, c.cfg)
						next.ServeHTTP(w, r)
						return
					}
					accessToken = refreshed.AccessToken
					refreshToken = refreshed.RefreshToken
					needCookieWrite = true

					claims, err = c.VerifyAccessToken(r.Context(), accessToken)
					if err != nil {
						if errors.Is(err, ErrJWKSUnavailable) {
							next.ServeHTTP(w, r)
							return
						}
						clearSessionCookie(w, c.cfg)
						next.ServeHTTP(w, r)
						return
					}
				default:
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
					if errors.Is(err, ErrJWKSUnavailable) {
						next.ServeHTTP(w, r)
						return
					}
					clearSessionCookie(w, c.cfg)
					next.ServeHTTP(w, r)
					return
				}
				accessToken = refreshed.AccessToken
				refreshToken = refreshed.RefreshToken
				needCookieWrite = true

				claims, err = c.VerifyAccessToken(r.Context(), accessToken)
				if err != nil {
					if errors.Is(err, ErrJWKSUnavailable) {
						next.ServeHTTP(w, r)
						return
					}
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

			// Derive tenant org authoritatively. Never use IdentityHint.OrgID for tenancy.
			//
			// Source chain:
			//  1) access token claim org_id (claims.OrgID)
			//  2) cookieSess.OrgID (written only from WorkOS callback/session validation)
			//  3) ValidateSession (WorkOS API) when (1) and (2) are empty
			if claims.OrgID != "" {
				if cookieSess.OrgID != "" && cookieSess.OrgID != claims.OrgID {
					clearSessionCookie(w, c.cfg)
					next.ServeHTTP(w, r)
					return
				}
				if cookieSess.OrgID != claims.OrgID {
					cookieSess.OrgID = claims.OrgID
					needCookieWrite = true
				}
				identity.OrgID = claims.OrgID
			} else if cookieSess.OrgID != "" {
				identity.OrgID = cookieSess.OrgID
			} else {
				ctx, cancel := context.WithTimeout(r.Context(), c.cfg.RevalidationTimeout)
				info, err := c.ValidateSession(ctx, claims.UserID, claims.SessionID)
				cancel()
				if err != nil {
					// Fail open: proceed without tenant org rather than trusting a hint.
				} else if info == nil || !info.Active {
					clearSessionCookie(w, c.cfg)
					next.ServeHTTP(w, r)
					return
				} else if info.OrgID != "" {
					identity.OrgID = info.OrgID
					cookieSess.OrgID = info.OrgID
					needCookieWrite = true
				}
			}

			if needCookieWrite || cookieSess.IdentityHint == nil {
				if err := setSessionCookie(w, &cookieSession{
					AccessToken:  accessToken,
					RefreshToken: refreshToken,
					OrgID:        cookieSess.OrgID,
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
