package workos

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	errJWTUnexpectedAlg = errors.New("workos: unexpected jwt alg")
	errJWTMissingKID    = errors.New("workos: jwt missing kid")
	errJWTUnknownKID    = errors.New("workos: unknown jwt kid")
)

func invalidTokenError(msg string) error {
	return &SafeError{msg: msg, cause: ErrAccessTokenInvalid}
}

func expiredTokenError() error {
	return &SafeError{msg: "workos: invalid access token", cause: ErrAccessTokenExpired}
}

func jwksUnavailableError(cause error) error {
	if cause == nil {
		cause = ErrJWKSUnavailable
	}
	return &SafeError{msg: "workos: jwks unavailable", cause: cause}
}

type rawAccessTokenClaims struct {
	jwt.RegisteredClaims
	OrgID        string   `json:"org_id,omitempty"`
	Role         string   `json:"role,omitempty"`
	Roles        []string `json:"roles,omitempty"`
	Permissions  []string `json:"permissions,omitempty"`
	Entitlements []string `json:"entitlements,omitempty"`
	SID          string   `json:"sid,omitempty"`
	Email        string   `json:"email,omitempty"`
	Name         string   `json:"name,omitempty"`
}

func audienceContains(aud jwt.ClaimStrings, want string) bool {
	if want == "" {
		return false
	}
	for _, v := range aud {
		if v == want {
			return true
		}
	}
	return false
}

// VerifyAccessToken validates a WorkOS access token locally using JWKS.
func (c *Client) VerifyAccessToken(ctx context.Context, accessToken string) (*AccessTokenClaims, error) {
	if strings.TrimSpace(accessToken) == "" {
		return nil, invalidTokenError("workos: access token required")
	}

	cache, err := c.getJWKS(ctx, false)
	if err != nil {
		return nil, err
	}

	claims := &rawAccessTokenClaims{}
	parser := jwt.NewParser(
		jwt.WithLeeway(30*time.Second),
		jwt.WithExpirationRequired(),
	)

	token, err := parser.ParseWithClaims(accessToken, claims, func(tok *jwt.Token) (any, error) {
		alg, _ := tok.Header["alg"].(string)
		if alg != "" && alg != "RS256" {
			return nil, errJWTUnexpectedAlg
		}
		kid, _ := tok.Header["kid"].(string)
		if kid == "" {
			return nil, errJWTMissingKID
		}

		key := cache.keys[kid]
		if key == nil {
			cache2, refreshErr := c.getJWKS(ctx, true)
			if refreshErr != nil {
				return nil, refreshErr
			}
			key = cache2.keys[kid]
			if key == nil {
				return nil, errJWTUnknownKID
			}
		}
		return key, nil
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrJWKSUnavailable):
			return nil, jwksUnavailableError(err)
		case errors.Is(err, errJWTUnexpectedAlg):
			return nil, invalidTokenError("workos: unexpected jwt alg")
		case errors.Is(err, errJWTMissingKID):
			return nil, invalidTokenError("workos: jwt missing kid")
		case errors.Is(err, errJWTUnknownKID):
			return nil, invalidTokenError("workos: unknown jwt kid")
		case errors.Is(err, jwt.ErrTokenRequiredClaimMissing):
			return nil, invalidTokenError("workos: invalid token claims")
		case errors.Is(err, jwt.ErrTokenExpired):
			return nil, expiredTokenError()
		default:
			return nil, invalidTokenError("workos: invalid access token")
		}
	}
	if token == nil || !token.Valid {
		return nil, invalidTokenError("workos: invalid access token")
	}

	if normalizeIssuer(claims.Issuer) != normalizeIssuer(c.cfg.JWTIssuer) {
		return nil, invalidTokenError("workos: invalid token issuer")
	}
	if !audienceContains(claims.Audience, c.cfg.JWTAudience) {
		return nil, invalidTokenError("workos: invalid token audience")
	}
	if claims.Subject == "" || claims.SID == "" {
		return nil, invalidTokenError("workos: invalid token claims")
	}
	if claims.ExpiresAt == nil || claims.ExpiresAt.Time.IsZero() {
		return nil, invalidTokenError("workos: invalid token claims")
	}

	roles := make([]string, 0, 1+len(claims.Roles))
	if claims.Role != "" {
		roles = append(roles, claims.Role)
	}
	roles = append(roles, claims.Roles...)

	exp := claims.ExpiresAt.Time

	aud := ""
	if len(claims.Audience) > 0 {
		aud = claims.Audience[0]
	}

	return &AccessTokenClaims{
		UserID:       claims.Subject,
		SessionID:    claims.SID,
		Email:        claims.Email,
		Name:         claims.Name,
		OrgID:        claims.OrgID,
		Roles:        roles,
		Permissions:  claims.Permissions,
		Entitlements: claims.Entitlements,
		ExpiresAt:    exp,
		Issuer:       claims.Issuer,
		Audience:     aud,
	}, nil
}
