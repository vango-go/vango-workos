package workos

import (
	"time"

	"github.com/vango-go/vango"
)

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
	JWKSFetchTimeout  time.Duration
	JWTIssuer         string
	JWTAudience       string

	RevalidationInterval time.Duration
	RevalidationTimeout  time.Duration
	MaxStaleSession      time.Duration
	// RevalidationFailureMode controls how periodic WorkOS session validation
	// behaves when validation fails (e.g. WorkOS outage).
	//
	// Allowed values:
	//  - vango.FailOpenWithGrace (default): keep session alive until MaxStaleSession
	//    elapses without a successful validation.
	//  - vango.FailClosed: expire session immediately on any validation failure.
	RevalidationFailureMode          vango.AuthFailureMode
	DisablePeriodicSessionValidation bool
	SessionListCacheDuration         time.Duration
	SessionListCacheMaxUsers         int
	DisableRefreshInMiddleware       bool

	EnableAuditLogs bool
}
