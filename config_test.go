package workos

import (
	"testing"
	"time"

	"github.com/vango-go/vango"
)

func validConfig() Config {
	return Config{
		APIKey:       "sk_test_abcdefghijklmnopqrstuvwxyz123456",
		ClientID:     "client_1234567890",
		RedirectURI:  "https://app.example.com/auth/callback",
		CookieSecret: "0123456789abcdef0123456789abcdef",
		BaseURL:      "https://app.example.com",
	}
}

func TestNewValidation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{name: "missing api key", cfg: Config{}, wantErr: "workos: APIKey is required"},
		{name: "bad api key prefix", cfg: func() Config { c := validConfig(); c.APIKey = "bad"; return c }(), wantErr: "workos: APIKey must start with 'sk_'"},
		{name: "missing client id", cfg: func() Config { c := validConfig(); c.ClientID = ""; return c }(), wantErr: "workos: ClientID is required"},
		{name: "bad client id prefix", cfg: func() Config { c := validConfig(); c.ClientID = "bad"; return c }(), wantErr: "workos: ClientID must start with 'client_'"},
		{name: "missing redirect", cfg: func() Config { c := validConfig(); c.RedirectURI = ""; return c }(), wantErr: "workos: RedirectURI is required"},
		{name: "bad signout path", cfg: func() Config { c := validConfig(); c.SignOutRedirectURI = "https://evil.test"; return c }(), wantErr: "workos: SignOutRedirectURI must be an absolute-path (e.g. \"/auth/signed-out\")"},
		{name: "missing cookie secret", cfg: func() Config { c := validConfig(); c.CookieSecret = ""; return c }(), wantErr: "workos: CookieSecret is required"},
		{name: "short cookie secret", cfg: func() Config { c := validConfig(); c.CookieSecret = "short"; return c }(), wantErr: "workos: CookieSecret must be at least 32 characters"},
		{name: "short cookie fallback", cfg: func() Config { c := validConfig(); c.CookieSecretFallbacks = []string{"short"}; return c }(), wantErr: "workos: CookieSecretFallbacks entries must be at least 32 characters"},
		{name: "missing base url", cfg: func() Config { c := validConfig(); c.BaseURL = ""; return c }(), wantErr: "workos: BaseURL is required"},
		{name: "invalid base url", cfg: func() Config { c := validConfig(); c.BaseURL = "://bad"; return c }(), wantErr: "workos: BaseURL is invalid"},
		{name: "base url missing scheme", cfg: func() Config { c := validConfig(); c.BaseURL = "app.example.com"; return c }(), wantErr: "workos: BaseURL is invalid"},
		{name: "base url unsupported scheme", cfg: func() Config { c := validConfig(); c.BaseURL = "ftp://app.example.com"; return c }(), wantErr: "workos: BaseURL is invalid"},
		{name: "negative jwks timeout", cfg: func() Config { c := validConfig(); c.JWKSFetchTimeout = -1; return c }(), wantErr: "workos: JWKSFetchTimeout cannot be negative"},
		{name: "negative session cache max users", cfg: func() Config { c := validConfig(); c.SessionListCacheMaxUsers = -1; return c }(), wantErr: "workos: SessionListCacheMaxUsers cannot be negative"},
		{name: "invalid revalidation failure mode", cfg: func() Config { c := validConfig(); c.RevalidationFailureMode = vango.AuthFailureMode(99); return c }(), wantErr: "workos: RevalidationFailureMode is invalid"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.cfg)
			if err == nil {
				t.Fatalf("expected error %q, got nil", tt.wantErr)
			}
			if err.Error() != tt.wantErr {
				t.Fatalf("error = %q, want %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestNewDefaults(t *testing.T) {
	c, err := New(validConfig())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	cfg := c.cfg

	if cfg.CookieName != "__vango_workos_session" {
		t.Fatalf("CookieName = %q", cfg.CookieName)
	}
	if cfg.CookieMaxAge != 7*24*time.Hour {
		t.Fatalf("CookieMaxAge = %v", cfg.CookieMaxAge)
	}
	if cfg.CookieSameSite != "lax" {
		t.Fatalf("CookieSameSite = %q", cfg.CookieSameSite)
	}
	if !cfg.CookieSecure {
		t.Fatal("CookieSecure should default to true for non-http base URLs")
	}
	if cfg.JWKSCacheDuration != time.Hour {
		t.Fatalf("JWKSCacheDuration = %v", cfg.JWKSCacheDuration)
	}
	if cfg.JWKSFetchTimeout != 5*time.Second {
		t.Fatalf("JWKSFetchTimeout = %v", cfg.JWKSFetchTimeout)
	}
	if cfg.JWKSURL == "" {
		t.Fatal("JWKSURL should be defaulted")
	}
	if cfg.JWTIssuer != "https://api.workos.com" {
		t.Fatalf("JWTIssuer = %q", cfg.JWTIssuer)
	}
	if cfg.JWTAudience != cfg.ClientID {
		t.Fatalf("JWTAudience = %q, want %q", cfg.JWTAudience, cfg.ClientID)
	}
	if cfg.RevalidationInterval != 5*time.Minute {
		t.Fatalf("RevalidationInterval = %v", cfg.RevalidationInterval)
	}
	if cfg.RevalidationTimeout != 5*time.Second {
		t.Fatalf("RevalidationTimeout = %v", cfg.RevalidationTimeout)
	}
	if cfg.MaxStaleSession != 15*time.Minute {
		t.Fatalf("MaxStaleSession = %v", cfg.MaxStaleSession)
	}
	if cfg.RevalidationFailureMode != vango.FailOpenWithGrace {
		t.Fatalf("RevalidationFailureMode = %v", cfg.RevalidationFailureMode)
	}
	if cfg.SessionListCacheDuration != 30*time.Second {
		t.Fatalf("SessionListCacheDuration = %v", cfg.SessionListCacheDuration)
	}
	if cfg.SessionListCacheMaxUsers != 10000 {
		t.Fatalf("SessionListCacheMaxUsers = %d", cfg.SessionListCacheMaxUsers)
	}
	if cfg.WebhookMaxBodyBytes != 1<<20 {
		t.Fatalf("WebhookMaxBodyBytes = %d", cfg.WebhookMaxBodyBytes)
	}
	if cfg.SignOutRedirectURI != "/auth/signed-out" {
		t.Fatalf("SignOutRedirectURI = %q", cfg.SignOutRedirectURI)
	}
	if cfg.EnableAuditLogs {
		t.Fatal("EnableAuditLogs should default to false")
	}
}

func TestNew_SameSiteNoneForcesSecure(t *testing.T) {
	cfg := validConfig()
	cfg.BaseURL = "http://localhost:8080"
	cfg.CookieSecure = false
	cfg.CookieSameSite = "none"

	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if !c.cfg.CookieSecure {
		t.Fatal("CookieSecure should be forced true when CookieSameSite is none")
	}
}

func TestConfigRedaction(t *testing.T) {
	cfg := validConfig()
	cfg.WebhookSecret = "whsec_secret"
	cfg.CookieSecretFallbacks = []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}

	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	redacted := c.Config()
	if redacted.APIKey != "sk_***" {
		t.Fatalf("APIKey = %q", redacted.APIKey)
	}
	if redacted.CookieSecret != "***" {
		t.Fatalf("CookieSecret = %q", redacted.CookieSecret)
	}
	if redacted.WebhookSecret != "***" {
		t.Fatalf("WebhookSecret = %q", redacted.WebhookSecret)
	}
	if redacted.CookieSecretFallbacks != nil {
		t.Fatal("CookieSecretFallbacks should be nil in redacted config")
	}
}
