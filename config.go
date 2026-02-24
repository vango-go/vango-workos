package workos

import "time"

// Config controls behavior of the WorkOS integration.
type Config struct {
	APIKey   string
	ClientID string

	RedirectURI        string
	SignOutRedirectURI string

	WebhookSecret       string
	WebhookMaxBodyBytes int64

	CookieName            string
	CookieSecret          string
	CookieSecretFallbacks []string
	CookieMaxAge          time.Duration
	CookieSecure          bool
	CookieSameSite        string

	BaseURL string

	JWKSCacheDuration time.Duration
	JWKSURL           string
	JWTIssuer         string
	JWTAudience       string

	RevalidationInterval             time.Duration
	RevalidationTimeout              time.Duration
	MaxStaleSession                  time.Duration
	DisablePeriodicSessionValidation bool
	SessionListCacheDuration         time.Duration
	DisableRefreshInMiddleware       bool

	EnableAuditLogs bool
}
