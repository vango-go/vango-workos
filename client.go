package workos

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/workos/workos-go/v6/pkg/auditlogs"
	"github.com/workos/workos-go/v6/pkg/directorysync"
	"github.com/workos/workos-go/v6/pkg/organizations"
	"github.com/workos/workos-go/v6/pkg/portal"
	"github.com/workos/workos-go/v6/pkg/sso"
	"github.com/workos/workos-go/v6/pkg/usermanagement"
)

// Client is the concrete integration client.
type Client struct {
	cfg Config

	um        umClient
	ssoClient ssoClient
	ds        directorySyncClient
	al        auditLogsClient
	orgs      orgsClient
	portal    portalClient
	wh        webhookVerifier

	jwksMu      sync.RWMutex
	jwksCache   *jwksCache
	jwksFetchMu sync.Mutex

	refresh refreshGroup

	sessionsMu    sync.Mutex
	sessionsCache map[string]sessionListCacheEntry

	jwksHTTPClient *http.Client
}

var _ interface{ Config() Config } = (*Client)(nil)
var _ Sessions = (*Client)(nil)

// New creates a validated client and applies safe defaults.
func New(cfg Config) (*Client, error) {
	if cfg.APIKey == "" {
		return nil, errors.New("workos: APIKey is required")
	}
	if !strings.HasPrefix(cfg.APIKey, "sk_") {
		return nil, errors.New("workos: APIKey must start with 'sk_'")
	}
	if cfg.ClientID == "" {
		return nil, errors.New("workos: ClientID is required")
	}
	if !strings.HasPrefix(cfg.ClientID, "client_") {
		return nil, errors.New("workos: ClientID must start with 'client_'")
	}
	if cfg.RedirectURI == "" {
		return nil, errors.New("workos: RedirectURI is required")
	}
	if cfg.SignOutRedirectURI != "" {
		if !strings.HasPrefix(cfg.SignOutRedirectURI, "/") || strings.HasPrefix(cfg.SignOutRedirectURI, "//") {
			return nil, errors.New("workos: SignOutRedirectURI must be an absolute-path (e.g. \"/auth/signed-out\")")
		}
	}
	if cfg.CookieSecret == "" {
		return nil, errors.New("workos: CookieSecret is required")
	}
	if len(cfg.CookieSecret) < 32 {
		return nil, errors.New("workos: CookieSecret must be at least 32 characters")
	}
	for _, s := range cfg.CookieSecretFallbacks {
		if len(s) < 32 {
			return nil, errors.New("workos: CookieSecretFallbacks entries must be at least 32 characters")
		}
	}
	if cfg.BaseURL == "" {
		return nil, errors.New("workos: BaseURL is required")
	}
	baseURL, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return nil, errors.New("workos: BaseURL is invalid")
	}
	switch strings.ToLower(baseURL.Scheme) {
	case "http", "https":
	default:
		return nil, errors.New("workos: BaseURL is invalid")
	}
	if baseURL.Host == "" {
		return nil, errors.New("workos: BaseURL is invalid")
	}
	if cfg.JWKSFetchTimeout < 0 {
		return nil, errors.New("workos: JWKSFetchTimeout cannot be negative")
	}
	if cfg.SessionListCacheMaxUsers < 0 {
		return nil, errors.New("workos: SessionListCacheMaxUsers cannot be negative")
	}

	if cfg.CookieName == "" {
		cfg.CookieName = "__vango_workos_session"
	}
	if cfg.CookieMaxAge == 0 {
		cfg.CookieMaxAge = 7 * 24 * time.Hour
	}
	if cfg.CookieSameSite == "" {
		cfg.CookieSameSite = "lax"
	}
	if !cfg.CookieSecure {
		if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(cfg.BaseURL)), "http://") {
			cfg.CookieSecure = true
		}
	}
	if strings.EqualFold(strings.TrimSpace(cfg.CookieSameSite), "none") {
		cfg.CookieSecure = true
	}
	if cfg.JWKSCacheDuration == 0 {
		cfg.JWKSCacheDuration = 1 * time.Hour
	}
	if cfg.JWKSURL == "" {
		jwksURL, err := usermanagement.GetJWKSURL(cfg.ClientID)
		if err != nil {
			return nil, errors.New("workos: failed to derive JWKS URL")
		}
		cfg.JWKSURL = jwksURL.String()
	}
	if cfg.JWTIssuer == "" {
		cfg.JWTIssuer = "https://api.workos.com"
	}
	if cfg.JWTAudience == "" {
		cfg.JWTAudience = cfg.ClientID
	}
	if cfg.JWKSFetchTimeout == 0 {
		cfg.JWKSFetchTimeout = 5 * time.Second
	}
	if cfg.RevalidationInterval == 0 {
		cfg.RevalidationInterval = 5 * time.Minute
	}
	if cfg.RevalidationTimeout == 0 {
		cfg.RevalidationTimeout = 5 * time.Second
	}
	if cfg.MaxStaleSession == 0 {
		cfg.MaxStaleSession = 15 * time.Minute
	}
	if cfg.SessionListCacheDuration == 0 {
		cfg.SessionListCacheDuration = 30 * time.Second
	}
	if cfg.SessionListCacheMaxUsers == 0 {
		cfg.SessionListCacheMaxUsers = 10000
	}
	if cfg.WebhookMaxBodyBytes == 0 {
		cfg.WebhookMaxBodyBytes = 1 << 20
	}
	if cfg.SignOutRedirectURI == "" {
		cfg.SignOutRedirectURI = "/auth/signed-out"
	}

	umClient := usermanagement.NewClient(cfg.APIKey)
	ssoClient := &sso.Client{APIKey: cfg.APIKey, ClientID: cfg.ClientID}
	dsClient := &directorysync.Client{APIKey: cfg.APIKey}
	alClient := &auditlogs.Client{APIKey: cfg.APIKey}
	orgsClient := &organizations.Client{APIKey: cfg.APIKey}
	portalSDKClient := &portal.Client{APIKey: cfg.APIKey}

	return &Client{
		cfg: cfg,
		um:  &realUMClient{client: umClient},

		ssoClient: &realSSOClient{client: ssoClient},
		ds:        &realDirectorySyncClient{client: dsClient},
		al:        &realAuditLogsClient{client: alClient},
		orgs:      &realOrgsClient{client: orgsClient},
		portal:    &realPortalClient{client: portalSDKClient},
		wh:        &realWebhookVerifier{},
		jwksHTTPClient: &http.Client{
			Timeout: cfg.JWKSFetchTimeout,
		},
	}, nil
}

// Config returns a redacted copy safe for logging.
func (c *Client) Config() Config {
	cfg := c.cfg
	cfg.APIKey = "sk_***"
	cfg.CookieSecret = "***"
	cfg.CookieSecretFallbacks = nil
	cfg.WebhookSecret = "***"
	return cfg
}
