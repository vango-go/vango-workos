# Vango + WorkOS: Native Integration Specification (WIP)

---

## Document Structure

1. **The `vango-workos` Package Specification** — API, configuration, integration primitives, test kit.
2. **Developer Guide Sections (proposed additions)** — WorkOS integration, authentication layer, enterprise features, testing auth.
3. **Appendix H** — Enterprise Readiness Workflow, CLI Reference, Admin Portal, Troubleshooting.

All code targets the official WorkOS Go SDK (`github.com/workos/workos-go/v6`).

This document is a *native Vango integration* spec. That means:
- The WorkOS integration MUST align with Vango’s auth primitives in `github.com/vango-go/vango/pkg/auth` (runtime-only projection keys, resume semantics, AuthCheck semantics).
- HTTP-boundary auth MUST be implemented as net/http middleware (`func(http.Handler) http.Handler`) and installed via `app.Server().Use(...)` (not `app.Use`, which is Vango route middleware). Use `app.Server().SetHandler(...)` only when you need to mount a custom `http.ServeMux` (auth routes, webhooks, etc.).

---

# Part 1: The `vango-workos` Package Specification

**Import Path:** `github.com/vango-go/vango-workos`

**Dependencies:**
- `github.com/workos/workos-go/v6`
- `github.com/workos/workos-go/v6/pkg/usermanagement`
- `github.com/workos/workos-go/v6/pkg/sso`
- `github.com/workos/workos-go/v6/pkg/directorysync`
- `github.com/workos/workos-go/v6/pkg/auditlogs`
- `github.com/workos/workos-go/v6/pkg/organizations`
- `github.com/workos/workos-go/v6/pkg/webhooks`
- `github.com/golang-jwt/jwt/v5`

---

## 1.1 Design Principles

The `vango-workos` package bridges two systems with fundamentally different lifecycle models:

**WorkOS** is request/response: HTTP callbacks, REST API calls, webhook deliveries.

**Vango** is session-driven: long-lived WebSocket sessions with a single-writer event loop, where HTTP middleware only runs at session start/resume.

This gap creates the central design challenge. The package must:

1. **Bridge HTTP identity into Vango sessions** — validate at HTTP entry, project into session runtime state, revalidate periodically.
2. **Expose a mockable interface for application code** — services and components target the interface, not the SDK.
3. **Provide pre-wired Vango integration primitives** — middleware, session hooks, revalidation config, webhook handlers that respect Vango's execution model.
4. **Keep enterprise features (SSO, SCIM, Audit Logs, and optional FGA) accessible** without requiring deep WorkOS SDK knowledge.
5. **Never perform blocking I/O on the session loop** — all WorkOS API calls occur in Resource loaders, Action work functions, or HTTP handlers.

---

## 1.2 Interfaces (Mockable Facade)

Vango apps should depend on small, mockable interfaces rather than on WorkOS SDK clients directly.

This integration intentionally separates:
- **Auth/session primitives** used by Vango’s runtime (cookie validation, token refresh, session revalidation).
- **Enterprise/read APIs** (users, orgs, roles, directories, audit logs).

This reduces “mock tax” while still letting larger apps depend on a single `Auth` interface if they prefer.

```go
package workos

	import (
		"context"
		"errors"
		"time"

		"github.com/vango-go/vango/pkg/auth"
	)

// Sessions is the minimum interface needed for Vango session lifecycle integration.
//
// IMPORTANT:
// - VerifyAccessToken is a local JWT verification step (JWKS + claims).
// - ValidateSession is an *active* (network) check used for revocation detection.
// - RefreshTokens MUST be refresh-rotation safe (see §1.5.4 / §H.5.4).
type Sessions interface {
	// VerifyAccessToken validates a WorkOS access token locally using JWKS.
	// It returns normalized claims used to project auth into Vango.
	VerifyAccessToken(ctx context.Context, accessToken string) (*AccessTokenClaims, error)

	// RefreshTokens exchanges a refresh token for a new token set.
	// Implementations MUST tolerate refresh token rotation and concurrent requests.
	RefreshTokens(ctx context.Context, refreshToken string) (*TokenSet, error)

	// ValidateSession checks whether a session is still active.
	// This is used for Vango resume checks and periodic AuthCheck.
	//
	// WorkOS's User Management Sessions API lists sessions by user. Therefore,
	// userID is required to validate a session without maintaining server-side
	// session state.
	ValidateSession(ctx context.Context, userID, sessionID string) (*SessionInfo, error)

	// RevokeSession terminates a session (logout/sign-out everywhere).
	RevokeSession(ctx context.Context, sessionID string) error
}

type Users interface {
	GetUser(ctx context.Context, userID string) (*User, error)
	ListUsers(ctx context.Context, opts ListUsersOpts) (*UserList, error)
	UpdateUser(ctx context.Context, userID string, opts UpdateUserOpts) (*User, error)
	DeleteUser(ctx context.Context, userID string) error
}

type Orgs interface {
	GetOrganization(ctx context.Context, orgID string) (*Organization, error)
	ListOrganizations(ctx context.Context, opts ListOrganizationsOpts) (*OrganizationList, error)
	ListOrganizationMemberships(ctx context.Context, opts ListMembershipsOpts) (*MembershipList, error)
	GetOrganizationMembership(ctx context.Context, membershipID string) (*Membership, error)
}

type RBAC interface {
	HasRole(ctx context.Context, userID, orgID, roleSlug string) (bool, error)
	ListRoles(ctx context.Context, opts ListRolesOpts) (*RoleList, error)
}

type AuditLogs interface {
	// EmitAuditEvent MUST be called from Action work functions or HTTP handlers only.
	// Never call from render closures, event handlers, or Setup callbacks.
	EmitAuditEvent(ctx context.Context, event AuditEvent) error
}

type SSORead interface {
	ListConnections(ctx context.Context, opts ListConnectionsOpts) (*ConnectionList, error)
}

type DirectorySyncRead interface {
	ListDirectories(ctx context.Context, opts ListDirectoriesOpts) (*DirectoryList, error)
	ListDirectoryUsers(ctx context.Context, opts ListDirectoryUsersOpts) (*DirectoryUserList, error)
	ListDirectoryGroups(ctx context.Context, opts ListDirectoryGroupsOpts) (*DirectoryGroupList, error)
}

// Auth is the “full surface” convenience interface.
//
// Small apps should depend on Sessions (+ whatever else they actually use).
// Large apps can depend on Auth for simplicity.
type Auth interface {
	Sessions
	Users
	Orgs
	RBAC
	AuditLogs
	SSORead
	DirectorySyncRead
}
```

---

## 1.3 Domain Types

All types are Vango-native structs that normalize WorkOS SDK types into a stable, minimal surface. This insulates application code from SDK version churn and simplifies testing.

```go
package workos

import "time"

// --- Identity Types ---

// User represents an authenticated user from WorkOS User Management.
type User struct {
	ID             string            `json:"id"`
	Email          string            `json:"email"`
	EmailVerified  bool              `json:"email_verified"`
	FirstName      string            `json:"first_name"`
	LastName       string            `json:"last_name"`
	ProfilePicURL  string            `json:"profile_picture_url"`
	Metadata       map[string]string `json:"metadata"`
	CreatedAt      time.Time         `json:"created_at"`
	UpdatedAt      time.Time         `json:"updated_at"`
}

// DisplayName returns "First Last", falling back to email if both are empty.
func (u *User) DisplayName() string {
	name := u.FirstName
	if u.LastName != "" {
		if name != "" {
			name += " "
		}
		name += u.LastName
	}
	if name == "" {
		return u.Email
	}
	return name
}

	// Identity is the authenticated identity projection used inside Vango.
	//
	// Storage rules (MUST):
	// - Identity MUST be treated as *runtime-only* auth state (rehydrated on
	//   session start/resume). Do not persist it via state schema.
	// - Access/refresh tokens MUST NOT be stored in Vango session KV. Tokens are
	//   stored only inside the encrypted session cookie payload.
	//
	// Vango integration stores Identity as the “user object” via pkg/auth:
	//   - SSR: attached to request context via vango.WithUser(...)
	//   - WS:  auth.Set(session, identity) during OnSessionStart/OnSessionResume
	type Identity struct {
		UserID      string   `json:"user_id"`
		Email       string   `json:"email"`
		Name        string   `json:"name,omitempty"`
		OrgID       string   `json:"org_id,omitempty"` // Active organization (WorkOS Organization ID)
		Roles       []string `json:"roles,omitempty"`
		Permissions []string `json:"permissions,omitempty"`
		Entitlements []string `json:"entitlements,omitempty"`

		// WorkOS session metadata (needed for revocation checks).
		SessionID  string    `json:"session_id,omitempty"`
		// ExpiresAt is the access token expiry ("exp"), not the WorkOS session lifetime.
		// Treat as a hint for HTTP-boundary refresh decisions and UI only.
		ExpiresAt  time.Time `json:"expires_at"`
		AuthMethod string    `json:"auth_method,omitempty"`
	}

	func (i *Identity) IsExpired() bool {
		if i == nil {
			return true
		}
		return !i.ExpiresAt.IsZero() && time.Now().After(i.ExpiresAt)
	}

	func (i *Identity) HasPermission(perm string) bool {
		if i == nil || perm == "" {
			return false
		}
		for _, p := range i.Permissions {
			if p == perm {
				return true
			}
		}
		return false
	}

	// AccessTokenClaims are normalized JWT claims extracted from a WorkOS User Management
	// access token (JWT). These claims are used to build Identity + auth.Principal for Vango.
	//
	// WorkOS conventions (as of WorkOS User Management Sessions):
	// - "sub" = user ID
	// - "sid" = session ID
	// - "org_id" = active organization ID (when applicable)
	// - "role" may be present as a single role string
	// - "permissions" may be present as a string array
	type AccessTokenClaims struct {
		// UserID is the WorkOS user ID (from "sub").
		UserID string `json:"user_id"`

		// SessionID is the WorkOS session ID (from "sid").
		SessionID string `json:"session_id"`

		Email        string    `json:"email,omitempty"`
		Name         string    `json:"name,omitempty"`
		OrgID        string    `json:"org_id,omitempty"`
		// Roles is normalized from WorkOS's "role" (single) and/or any future multi-role claims.
		Roles        []string  `json:"roles,omitempty"`
		Permissions  []string  `json:"permissions,omitempty"`
		Entitlements []string  `json:"entitlements,omitempty"`
		ExpiresAt    time.Time `json:"expires_at"`
		Issuer       string    `json:"issuer,omitempty"`
		Audience     string    `json:"audience,omitempty"`
	}

	// TokenSet is the sensitive token material issued by WorkOS.
	// This MUST only appear inside the encrypted cookie payload.
	type TokenSet struct {
		AccessToken  string    `json:"-"` // sensitive
		RefreshToken string    `json:"-"` // sensitive
		ExpiresAt    time.Time `json:"expires_at"`
	}

// SessionInfo is the response from ValidateSession.
type SessionInfo struct {
	SessionID string    `json:"session_id"`
	UserID    string    `json:"user_id"`
	OrgID     string    `json:"org_id,omitempty"`
	Active    bool      `json:"active"`
	ExpiresAt time.Time `json:"expires_at"`
}

// --- Organization Types ---

type Organization struct {
	ID                  string    `json:"id"`
	Name                string    `json:"name"`
	AllowProfilesOutside bool    `json:"allow_profiles_outside_organization"`
	Domains             []OrgDomain `json:"domains"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

type OrgDomain struct {
	ID       string `json:"id"`
	Domain   string `json:"domain"`
	State    string `json:"state"`
}

type Membership struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	OrgID     string    `json:"organization_id"`
	RoleSlug  string    `json:"role_slug"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// --- SSO Types ---

type Connection struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	ConnectionType string `json:"connection_type"`
	State          string `json:"state"`
	OrgID          string `json:"organization_id"`
}

// --- Directory Sync Types ---

type Directory struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Domain    string `json:"domain"`
	Type      string `json:"type"`
	State     string `json:"state"`
	OrgID     string `json:"organization_id"`
}

type DirectoryUser struct {
	ID        string            `json:"id"`
	Email     string            `json:"email"`
	FirstName string            `json:"first_name"`
	LastName  string            `json:"last_name"`
	State     string            `json:"state"`
	Groups    []DirectoryGroup  `json:"groups"`
	RawAttrs  map[string]any    `json:"raw_attributes"`
}

type DirectoryGroup struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// --- Authorization Types ---

type PermissionCheck struct {
	// Subject is the entity requesting access (e.g., "user_01ABC").
	Subject  string `json:"subject"`
	// Relation is the relationship being checked (e.g., "editor", "viewer").
	Relation string `json:"relation"`
	// Resource is the target resource (e.g., "document:doc_01XYZ").
	Resource string `json:"resource"`
}

// --- Audit Log Types ---

type AuditEvent struct {
	// OrganizationID scopes the event. REQUIRED.
	OrganizationID string `json:"organization_id"`
	// Action is the event type (e.g., "document.updated"). REQUIRED.
	Action string `json:"action"`
	// OccurredAt is when the action happened. Defaults to time.Now() if zero.
	OccurredAt time.Time `json:"occurred_at"`
	// Actor is who performed the action.
	Actor AuditActor `json:"actor"`
	// Targets are the resources affected.
	Targets []AuditTarget `json:"targets"`
	// Context provides additional metadata.
	Context AuditContext `json:"context,omitempty"`
	// IdempotencyKey prevents duplicate events. Auto-generated if empty.
	IdempotencyKey string `json:"idempotency_key,omitempty"`
}

type AuditActor struct {
	ID       string            `json:"id"`
	Name     string            `json:"name,omitempty"`
	Type     string            `json:"type"` // e.g., "user", "service"
	Metadata map[string]any    `json:"metadata,omitempty"`
}

type AuditTarget struct {
	ID       string            `json:"id"`
	Name     string            `json:"name,omitempty"`
	Type     string            `json:"type"` // e.g., "document", "project"
	Metadata map[string]any    `json:"metadata,omitempty"`
}

type AuditContext struct {
	Location  string `json:"location,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
}

// --- Pagination ---

type ListMeta struct {
	Before string `json:"before"`
	After  string `json:"after"`
}

// List response types follow the pattern: { Data []T, ListMeta }
type UserList struct {
	Data     []User   `json:"data"`
	ListMeta ListMeta `json:"list_metadata"`
}

type OrganizationList struct {
	Data     []Organization `json:"data"`
	ListMeta ListMeta       `json:"list_metadata"`
}

type MembershipList struct {
	Data     []Membership `json:"data"`
	ListMeta ListMeta     `json:"list_metadata"`
}

type ConnectionList struct {
	Data     []Connection `json:"data"`
	ListMeta ListMeta     `json:"list_metadata"`
}

type DirectoryList struct {
	Data     []Directory `json:"data"`
	ListMeta ListMeta    `json:"list_metadata"`
}

type DirectoryUserList struct {
	Data     []DirectoryUser `json:"data"`
	ListMeta ListMeta        `json:"list_metadata"`
}

type DirectoryGroupList struct {
	Data     []DirectoryGroup `json:"data"`
	ListMeta ListMeta         `json:"list_metadata"`
}

type RoleList struct {
	Data     []Role   `json:"data"`
	ListMeta ListMeta `json:"list_metadata"`
}

type Role struct {
	ID          string   `json:"id"`
	Slug        string   `json:"slug"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Type        string   `json:"type"` // "EnvironmentRole" or "OrganizationRole"
	Permissions []string `json:"permissions"`
}

// --- Filter/Option types ---

type ListUsersOpts struct {
	Email          string
	OrganizationID string
	Limit          int
	Before         string
	After          string
	Order          string // "asc" or "desc"
}

type UpdateUserOpts struct {
	FirstName      *string
	LastName       *string
	EmailVerified  *bool
	Metadata       map[string]*string // nil value removes key
}

type ListOrganizationsOpts struct {
	Domains []string
	Limit   int
	Before  string
	After   string
	Order   string
}

type ListMembershipsOpts struct {
	UserID         string
	OrganizationID string
	Statuses       []string
	Limit          int
	Before         string
	After          string
	Order          string
}

type ListConnectionsOpts struct {
	OrganizationID string
	ConnectionType string
	Limit          int
	Before         string
	After          string
	Order          string
}

type ListDirectoriesOpts struct {
	OrganizationID string
	Limit          int
	Before         string
	After          string
}

type ListDirectoryUsersOpts struct {
	DirectoryID string
	Group       string
	Limit       int
	Before      string
	After       string
}

type ListDirectoryGroupsOpts struct {
	DirectoryID string
	Limit       int
	Before      string
	After       string
}

type ListRolesOpts struct {
	OrganizationID string // empty = environment-level roles
	Limit          int
	Before         string
	After          string
	Order          string
}
```

---

## 1.4 Configuration

```go
package workos

import "time"

// Config controls the behavior of the WorkOS integration.
type Config struct {
	// APIKey is the WorkOS API key (prefixed with sk_).
	// REQUIRED. Obtain from: WorkOS Dashboard → API Keys.
	//
	// MUST be treated as a secret. Never commit to version control.
	// Never log. Store in environment variables or a secrets manager.
	APIKey string

	// ClientID is the WorkOS Client ID (prefixed with client_).
	// REQUIRED. Obtain from: WorkOS Dashboard → API Keys.
	ClientID string

	// RedirectURI is the callback URL that WorkOS redirects to after
	// authentication. Must match a configured redirect URI in the
	// WorkOS Dashboard under Redirects.
	//
	// Example: "http://localhost:8080/auth/callback" (development)
	// Example: "https://myapp.com/auth/callback" (production)
	// REQUIRED.
	RedirectURI string

	// SignOutRedirectURI is where users land after logout.
	// Must match the sign-out redirect configured in WorkOS Dashboard.
	// MUST be a relative absolute-path (starts with "/"), not a full URL.
	// If empty, defaults to "/auth/signed-out".
	SignOutRedirectURI string

	// WebhookSecret is the signing secret for verifying webhook payloads.
	// Obtain from: WorkOS Dashboard → Webhooks → endpoint detail.
	// REQUIRED if using webhook handler. Otherwise optional.
	WebhookSecret string

	// WebhookMaxBodyBytes limits webhook request bodies.
	// Default: 1MB.
	WebhookMaxBodyBytes int64

	// CookieName is the name of the session cookie.
	// Default: "__vango_workos_session"
	CookieName string

	// CookieSecret is used to encrypt the session cookie. Must be at
	// least 32 characters. Generate with: openssl rand -base64 32
	// REQUIRED.
	CookieSecret string

	// CookieSecretFallbacks is an ordered list of additional secrets accepted
	// for cookie decryption only (key rotation).
	//
	// The client MUST encrypt using CookieSecret and MUST attempt decryption
	// using CookieSecret first, then each fallback.
	CookieSecretFallbacks []string

	// CookieMaxAge is the maximum cookie lifetime.
	// Default: 7 days (matching WorkOS default session length).
	CookieMaxAge time.Duration

	// CookieSecure sets the Secure flag on cookies.
	// Default: true. Set to false ONLY for local HTTP development.
	CookieSecure bool

	// CookieSameSite sets SameSite policy.
	// Default: "lax"
	CookieSameSite string

	// BaseURL is the application's public base URL. Used for generating
	// callback URLs and logout redirects.
	// Example: "https://myapp.com" or "http://localhost:8080"
	// REQUIRED.
	BaseURL string

	// JWKSCacheDuration controls how long the JWKS (used for JWT
	// verification) is cached locally.
	// Default: 1 hour. WorkOS rotates keys infrequently.
	JWKSCacheDuration time.Duration

	// JWKSURL is the WorkOS JWKS endpoint for JWT verification.
	// Default: usermanagement.GetJWKSURL(ClientID)
	// Override only for testing.
	JWKSURL string

	// JWTIssuer is the expected JWT issuer ("iss" claim).
	// Default: "https://api.workos.com"
	// If you configure a custom WorkOS auth domain, set this to that issuer.
	JWTIssuer string

	// JWTAudience is the expected JWT audience ("aud" claim).
	// Default: ClientID.
	JWTAudience string

	// --- Revalidation ---

	// RevalidationInterval controls periodic session checks against
	// WorkOS during long-lived WebSocket sessions. See §42.3.
	// Default: 5 minutes.
	RevalidationInterval time.Duration

	// RevalidationTimeout is the maximum time for a revalidation call.
	// Default: 5 seconds.
	RevalidationTimeout time.Duration

	// MaxStaleSession is how long a session can remain active without
	// a successful revalidation before forced logout.
	// Default: 15 minutes.
	MaxStaleSession time.Duration

	// DisablePeriodicSessionValidation disables network revocation checks during
	// long-lived WebSocket sessions.
	//
	// When false (default), RevalidationConfig() returns a vango.AuthCheckConfig
	// that calls ValidateSession periodically to detect WorkOS session revocation.
	//
	// When true, RevalidationConfig() returns nil (no periodic AuthCheck). Resume
	// revalidation still occurs (OnSessionResume), but long-lived tabs may remain
	// authenticated until the session ends.
	//
	// Operational note:
	// - Enable periodic validation for "enterprise hardening" posture.
	// - Disable periodic validation in extremely high-scale deployments if the
	//   Sessions API cost is prohibitive, and instead require on-demand
	//   ctx.RevalidateAuth() for high-value actions.
	DisablePeriodicSessionValidation bool

	// SessionListCacheDuration controls process-local caching for the WorkOS
	// Sessions API list call used by ValidateSession.
	//
	// This exists because some WorkOS APIs validate sessions by listing sessions
	// for a user and scanning for the session ID. Without caching, a user with
	// many concurrent sessions could amplify API calls.
	//
	// Default: 30 seconds.
	SessionListCacheDuration time.Duration

	// DisableRefreshInMiddleware disables refresh-token exchange in the HTTP middleware.
	//
	// When false (default), the middleware refreshes an expired access token using the
	// refresh token stored in the encrypted cookie.
	//
	// When true, an expired access token causes the middleware to clear the session
	// cookie and treat the request as unauthenticated (forcing a re-auth).
	//
	// Operational note:
	// - Refresh tokens are single-use and rotate. The built-in refresh coordination is
	//   process-local (§1.5.4). In multi-instance deployments without sticky sessions,
	//   set DisableRefreshInMiddleware=true to avoid intermittent logout loops.
	DisableRefreshInMiddleware bool

	// --- Enterprise Features ---

	// EnableAuditLogs enables audit log emission.
	// When false, EmitAuditEvent is a no-op (returns nil).
	// Default: false.
	EnableAuditLogs bool
}
```

### 1.4.1 Session Cookie (Normative)

The WorkOS integration uses an **encrypted, HttpOnly session cookie** to store:
- the current **access token** (JWT),
- the current **refresh token** (rotating; sensitive),
- an optional cached **identity hint** used for UX (non-authoritative; may be stale).

**Authoritative identity** comes from verifying the access token locally (JWKS + claims). Any cached identity data in the cookie exists only to avoid extra API calls and MUST be treated as a hint.

**Cookie payload (v1):**

```go
// cookieSession is encrypted and stored in the cookie value.
// It MUST never be logged or returned in error messages.
type cookieSession struct {
	V            int       `json:"v"`
	IssuedAtUnix int64     `json:"iat_unix_ms"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	IdentityHint *Identity `json:"identity_hint,omitempty"`
}
```

**Encryption (MUST):**
- Algorithm: **AES-256-GCM**
- Nonce: 12 random bytes per encryption
- Key derivation: `key = SHA256([]byte(CookieSecret))` (32 bytes)
- Additional authenticated data (AAD): bind to `CookieName` (prevents cross-cookie substitution)
- Encoding: base64url without padding of `v || nonce || ciphertext`
- Decryption: try `CookieSecret` first, then each `CookieSecretFallbacks` entry in order

**Cookie attributes (MUST defaults):**
- `HttpOnly=true`, `Path=/`, `SameSite=Lax`
- `Secure=true` in production; allow insecure only for local HTTP development
- `MaxAge` derived from `CookieMaxAge` (default 7 days)

### 1.4.2 OAuth State Cookie (Normative)

The AuthKit redirect flow uses an OAuth-style `state` parameter for CSRF protection.
The integration MUST implement state verification using a short-lived, HttpOnly cookie.

**State cookie name (v1):** `__vango_workos_state`

**State cookie payload (v1):** opaque random string (hex or base64url), stored as-is.

**State cookie attributes (MUST defaults):**
- `HttpOnly=true`, `Path=/`, `SameSite=Lax`
- `Secure=true` in production; allow insecure only for local HTTP development
- `MaxAge=10 minutes`

**Verification rule (MUST):**
- Callback must reject if query `state` is empty or does not exactly match the cookie value.
- The cookie MUST be cleared after successful verification (one-time use).

---

## 1.5 The `Client` Implementation

```go
package workos

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	wos "github.com/workos/workos-go/v6"
	"github.com/workos/workos-go/v6/pkg/auditlogs"
	"github.com/workos/workos-go/v6/pkg/directorysync"
	"github.com/workos/workos-go/v6/pkg/organizations"
	"github.com/workos/workos-go/v6/pkg/sso"
	"github.com/workos/workos-go/v6/pkg/usermanagement"
	"github.com/workos/workos-go/v6/pkg/webhooks"
)

// Client is the concrete implementation of Auth backed by WorkOS.
//
// It wraps the WorkOS Go SDK and provides:
//   - All Auth interface methods
//   - HTTP handlers for AuthKit callback and logout
//   - Webhook verification and handling
//   - Admin Portal link generation
//   - Vango session lifecycle integration
//
// Client is safe for concurrent use.
type Client struct {
	cfg        Config
	um         usermanagement.Client
	ssoClient  sso.Client
	ds         directorysync.Client
	al         auditlogs.Client
	orgs       organizations.Client
	wh         webhooks.Client

	// JWKS cache
	jwksMu     sync.RWMutex
	jwksCache  *jwksCache
	jwksFetchMu sync.Mutex

	// Refresh coordination (process-local; see §1.5.4).
	refresh    refreshGroup

	// Sessions list caching (process-local; see §1.5.4).
	sessionsMu    sync.Mutex
	sessionsCache map[string]sessionListCacheEntry // userID -> entry
}

var _ Auth = (*Client)(nil)

	// New creates a validated, production-ready WorkOS client.
	//
	// Validations performed:
	//  1. Rejects empty APIKey, ClientID, RedirectURI, CookieSecret, BaseURL.
	//  2. Rejects CookieSecret shorter than 32 characters.
	//  3. Rejects APIKey that doesn't start with "sk_".
	//  4. Rejects ClientID that doesn't start with "client_".
	//  5. Applies safe defaults for all optional fields.
	//  6. Initializes all WorkOS SDK sub-clients.
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
			// Must be a path on this application (no open redirects).
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

	// Apply defaults
	if cfg.CookieName == "" {
		cfg.CookieName = "__vango_workos_session"
	}
	if cfg.CookieMaxAge == 0 {
		cfg.CookieMaxAge = 7 * 24 * time.Hour
	}
	if cfg.CookieSameSite == "" {
		cfg.CookieSameSite = "lax"
	}
		if cfg.JWKSCacheDuration == 0 {
			cfg.JWKSCacheDuration = 1 * time.Hour
		}
		if cfg.JWKSURL == "" {
			cfg.JWKSURL = usermanagement.GetJWKSURL(cfg.ClientID)
		}
		if cfg.JWTIssuer == "" {
			cfg.JWTIssuer = "https://api.workos.com"
		}
		if cfg.JWTAudience == "" {
			cfg.JWTAudience = cfg.ClientID
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
			if cfg.WebhookMaxBodyBytes == 0 {
				cfg.WebhookMaxBodyBytes = 1 << 20
			}
		if cfg.SignOutRedirectURI == "" {
			cfg.SignOutRedirectURI = "/auth/signed-out"
		}

	// Initialize SDK clients
	umClient := usermanagement.NewClient(cfg.APIKey)
	ssoClient := sso.Client{APIKey: cfg.APIKey, ClientID: cfg.ClientID}
	dsClient := directorysync.Client{APIKey: cfg.APIKey}
	alClient := auditlogs.Client{APIKey: cfg.APIKey}
	orgsClient := organizations.Client{APIKey: cfg.APIKey}
	whClient := webhooks.Client{}

	return &Client{
		cfg:       cfg,
		um:        *umClient,
		ssoClient: ssoClient,
		ds:        dsClient,
		al:        alClient,
		orgs:      orgsClient,
		wh:        whClient,
	}, nil
}

// --- Auth Interface Implementation ---
// (Each method delegates to the appropriate SDK client and converts
// WorkOS SDK types into vango-workos domain types.)

func (c *Client) GetUser(ctx context.Context, userID string) (*User, error) {
	u, err := c.um.GetUser(ctx, usermanagement.GetUserOpts{User: userID})
	if err != nil {
		return nil, fmt.Errorf("workos: get user %s: %w", userID, err)
	}
	return convertUser(u), nil
}

func (c *Client) EmitAuditEvent(ctx context.Context, event AuditEvent) error {
	if !c.cfg.EnableAuditLogs {
		return nil // no-op when disabled
	}
	if event.OccurredAt.IsZero() {
		event.OccurredAt = time.Now()
	}
	if event.IdempotencyKey == "" {
		event.IdempotencyKey = generateUUID()
	}
	return c.al.CreateEvent(ctx, convertAuditEvent(event))
}

	// Sessions primitives (VerifyAccessToken, RefreshTokens, ValidateSession, RevokeSession)
	// are implemented with the semantics specified by:
	//   - Sessions interface (§1.2)
	//   - Vango integration primitives (§1.7)
	//
	// Other Auth interface methods delegate to SDK clients, normalize types, and wrap
	// errors with a "workos:" prefix.

// --- Concrete-Only Methods (not on Auth interface) ---

// Config returns a copy of the client configuration.
// Connection strings and secrets are redacted.
func (c *Client) Config() Config {
	cfg := c.cfg
	cfg.APIKey = "sk_***"
	cfg.CookieSecret = "***"
	cfg.CookieSecretFallbacks = nil
	cfg.WebhookSecret = "***"
	return cfg
}
```

---

## 1.5.1 Secrets-Safe Errors (Normative)

`vango-workos` MUST treat cookies, refresh tokens, access tokens, and any request bodies containing them as secret material.
Error strings returned by cookie/JWT helpers MUST be safe to log by default.

The package uses a safe outer error wrapper (similar to the `vango-neon` posture):

```go
package workos

// SafeError is an error wrapper whose Error() string is guaranteed not to
// include secret material (cookies, JWTs, refresh tokens, etc.).
//
// The underlying cause is available via errors.Unwrap / errors.Is / errors.As.
// WARNING: the cause may contain sensitive strings depending on upstream
// libraries and should not be logged verbatim in production.
type SafeError struct {
	msg   string
	cause error
}

func (e *SafeError) Error() string { return e.msg }
func (e *SafeError) Unwrap() error { return e.cause }
```

---

## 1.5.2 Cookie + State Helpers (Complete Reference)

This section defines the complete reference implementation for:
- state cookie set/verify/clear
- session cookie encrypt/decrypt/set/read/clear

These helpers are used by the HTTP handlers (§1.6) and middleware (§1.7).

```go
package workos

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	stateCookieName        = "__vango_workos_state"
	cookieEnvelopeVersion  = byte(1)
	stateCookieMaxAge      = 10 * time.Minute
)

func cookieKeyFromSecret(secret string) [32]byte {
	return sha256.Sum256([]byte(secret))
}

func sameSiteFromConfig(v string) http.SameSite {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	default:
		// "lax" and any unknown value.
		return http.SameSiteLaxMode
	}
}

// --- State cookie ---

func setStateCookie(w http.ResponseWriter, state string, cfg Config) {
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookieName,
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		Secure:   cfg.CookieSecure,
		SameSite: sameSiteFromConfig(cfg.CookieSameSite),
		MaxAge:   int(stateCookieMaxAge.Seconds()),
	})
}

func validateStateCookie(r *http.Request, wantState string, cfg Config) bool {
	if wantState == "" {
		return false
	}
	c, err := r.Cookie(stateCookieName)
	if err != nil || c == nil || c.Value == "" {
		return false
	}
	// Exact string match; state is opaque.
	return c.Value == wantState
}

func clearStateCookie(w http.ResponseWriter, cfg Config) {
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   cfg.CookieSecure,
		SameSite: sameSiteFromConfig(cfg.CookieSameSite),
		MaxAge:   -1,
	})
}

// --- Session cookie ---

func sealCookieSession(sess *cookieSession, secret string, aad string) (string, error) {
	if sess == nil {
		return "", errors.New("workos: nil session")
	}
	key := cookieKeyFromSecret(secret)

	plain, err := json.Marshal(sess)
	if err != nil {
		return "", &SafeError{msg: "workos: failed to serialize cookie session", cause: err}
	}

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", &SafeError{msg: "workos: failed to initialize cookie cipher", cause: err}
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", &SafeError{msg: "workos: failed to initialize cookie AEAD", cause: err}
	}

	nonce := make([]byte, gcm.NonceSize()) // 12 bytes for GCM
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", &SafeError{msg: "workos: failed to generate cookie nonce", cause: err}
	}

	// Additional authenticated data binds ciphertext to cookie name/version.
	aadBytes := []byte(aad)
	ciphertext := gcm.Seal(nil, nonce, plain, aadBytes)

	raw := make([]byte, 0, 1+len(nonce)+len(ciphertext))
	raw = append(raw, cookieEnvelopeVersion)
	raw = append(raw, nonce...)
	raw = append(raw, ciphertext...)

	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func openCookieSession(value string, secret string, aad string) (*cookieSession, error) {
	if value == "" {
		return nil, errors.New("workos: empty cookie value")
	}

	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, &SafeError{msg: "workos: invalid cookie encoding", cause: err}
	}
	if len(raw) < 1 {
		return nil, errors.New("workos: invalid cookie payload")
	}
	if raw[0] != cookieEnvelopeVersion {
		return nil, errors.New("workos: unsupported cookie version")
	}

	key := cookieKeyFromSecret(secret)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, &SafeError{msg: "workos: failed to initialize cookie cipher", cause: err}
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, &SafeError{msg: "workos: failed to initialize cookie AEAD", cause: err}
	}

	nonceSize := gcm.NonceSize()
	if len(raw) < 1+nonceSize+gcm.Overhead() {
		return nil, errors.New("workos: invalid cookie payload")
	}

	nonce := raw[1 : 1+nonceSize]
	ciphertext := raw[1+nonceSize:]
	plain, err := gcm.Open(nil, nonce, ciphertext, []byte(aad))
	if err != nil {
		// Do not surface details; cookie contents are sensitive.
		return nil, &SafeError{msg: "workos: cookie decryption failed", cause: err}
	}

	var sess cookieSession
	if err := json.Unmarshal(plain, &sess); err != nil {
		return nil, &SafeError{msg: "workos: cookie decode failed", cause: err}
	}
	return &sess, nil
}

func setSessionCookie(w http.ResponseWriter, sess *cookieSession, cfg Config) error {
	if sess == nil {
		return errors.New("workos: nil cookie session")
	}
	sess.V = 1
	if sess.IssuedAtUnix == 0 {
		sess.IssuedAtUnix = time.Now().UnixMilli()
	}

	// Bind ciphertext to cookie name so cross-cookie substitution is detected.
	val, err := sealCookieSession(sess, cfg.CookieSecret, cfg.CookieName)
	if err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     cfg.CookieName,
		Value:    val,
		Path:     "/",
		HttpOnly: true,
		Secure:   cfg.CookieSecure,
		SameSite: sameSiteFromConfig(cfg.CookieSameSite),
		MaxAge:   int(cfg.CookieMaxAge.Seconds()),
	})
	return nil
}

func readSessionCookie(r *http.Request, cfg Config) (*cookieSession, error) {
	c, err := r.Cookie(cfg.CookieName)
	if err != nil || c == nil || c.Value == "" {
		return nil, err
	}

	// Attempt decryption with primary, then fallbacks (rotation).
	aad := cfg.CookieName
	if sess, err := openCookieSession(c.Value, cfg.CookieSecret, aad); err == nil {
		return sess, nil
	}
	for _, fb := range cfg.CookieSecretFallbacks {
		sess, err := openCookieSession(c.Value, fb, aad)
		if err == nil {
			return sess, nil
		}
	}
	return nil, errors.New("workos: cookie invalid")
}

func clearSessionCookie(w http.ResponseWriter, cfg Config) {
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.CookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   cfg.CookieSecure,
		SameSite: sameSiteFromConfig(cfg.CookieSameSite),
		MaxAge:   -1,
	})
}
```

---

## 1.5.3 JWKS Fetch/Cache + JWT Verification (Complete Reference)

The WorkOS access token returned by AuthKit is a JWT. It MUST be verified locally using JWKS:
- signature verification (WorkOS uses RSA keys; tokens are typically `RS256`)
- issuer (`iss`) check
- audience (`aud`) check
- time checks (`exp`, optionally `nbf`) with small clock skew tolerance

The decoded access token includes `sid` (session ID) and `sub` (user ID).

```go
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

	"github.com/golang-jwt/jwt/v5"
)

type jwksCache struct {
	fetchedAt time.Time
	keys      map[string]*rsa.PublicKey // kid -> pubkey
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

	c.jwksMu.RLock()
	cur := c.jwksCache
	c.jwksMu.RUnlock()
	if !force && cur != nil && now.Sub(cur.fetchedAt) < c.cfg.JWKSCacheDuration {
		return cur, nil
	}

	// Serialize JWKS refresh so we don't stampede on key rotation.
	c.jwksFetchMu.Lock()
	defer c.jwksFetchMu.Unlock()

	// Re-check after acquiring fetch lock.
	c.jwksMu.RLock()
	cur = c.jwksCache
	c.jwksMu.RUnlock()
	if !force && cur != nil && now.Sub(cur.fetchedAt) < c.cfg.JWKSCacheDuration {
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
	for _, k := range doc.Keys {
		if k.Kid == "" || strings.ToUpper(k.Kty) != "RSA" {
			continue
		}
		nb, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			continue
		}
		eb, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			continue
		}
		e := 0
		for _, b := range eb {
			e = (e << 8) | int(b)
		}
		if e == 0 {
			continue
		}
		keys[k.Kid] = &rsa.PublicKey{
			N: new(big.Int).SetBytes(nb),
			E: e,
		}
	}

	next := &jwksCache{fetchedAt: now, keys: keys}
	c.jwksMu.Lock()
	c.jwksCache = next
	c.jwksMu.Unlock()
	return next, nil
}

type rawAccessTokenClaims struct {
	jwt.RegisteredClaims
	OrgID       string   `json:"org_id,omitempty"`
	Role        string   `json:"role,omitempty"`
	Roles       []string `json:"roles,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	Entitlements []string `json:"entitlements,omitempty"`
	SID         string   `json:"sid,omitempty"`
	Email       string   `json:"email,omitempty"`
	Name        string   `json:"name,omitempty"`
}

// VerifyAccessToken validates a WorkOS access token locally using JWKS.
// It returns normalized claims used to project auth into Vango.
func (c *Client) VerifyAccessToken(ctx context.Context, accessToken string) (*AccessTokenClaims, error) {
	if strings.TrimSpace(accessToken) == "" {
		return nil, errors.New("workos: access token required")
	}

	cache, err := c.getJWKS(ctx, false)
	if err != nil {
		return nil, err
	}

	claims := &rawAccessTokenClaims{}

	// Clock skew tolerance.
	parser := jwt.NewParser(jwt.WithLeeway(30*time.Second))

	tok, err := parser.ParseWithClaims(accessToken, claims, func(t *jwt.Token) (any, error) {
		alg, _ := t.Header["alg"].(string)
		if alg != "" && alg != "RS256" {
			return nil, errors.New("workos: unexpected jwt alg")
		}
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("workos: jwt missing kid")
		}
			key := cache.keys[kid]
			if key == nil {
				// Key rotation: force refresh once.
				cache2, err := c.getJWKS(ctx, true)
				if err != nil {
					return nil, err
				}
			key = cache2.keys[kid]
			if key == nil {
				return nil, errors.New("workos: unknown jwt kid")
			}
		}
		return key, nil
	})
	if err != nil || tok == nil || !tok.Valid {
		return nil, errors.New("workos: invalid access token")
	}

	// Issuer/audience are part of the application contract; validate explicitly.
	if normalizeIssuer(claims.Issuer) != normalizeIssuer(c.cfg.JWTIssuer) {
		return nil, errors.New("workos: invalid token issuer")
	}
	if !claims.VerifyAudience(c.cfg.JWTAudience, true) {
		return nil, errors.New("workos: invalid token audience")
	}
	if claims.Subject == "" || claims.SID == "" {
		return nil, errors.New("workos: invalid token claims")
	}

	roles := make([]string, 0, 2)
	if claims.Role != "" {
		roles = append(roles, claims.Role)
	}
	if len(claims.Roles) > 0 {
		roles = append(roles, claims.Roles...)
	}

	var exp time.Time
	if claims.ExpiresAt != nil {
		exp = claims.ExpiresAt.Time
	}

	aud := ""
	if len(claims.Audience) > 0 {
		aud = claims.Audience[0]
	}

	return &AccessTokenClaims{
		UserID:      claims.Subject,
		SessionID:   claims.SID,
		Email:       claims.Email,
		Name:        claims.Name,
		OrgID:       claims.OrgID,
		Roles:       roles,
		Permissions: claims.Permissions,
		Entitlements: claims.Entitlements,
		ExpiresAt:   exp,
		Issuer:      claims.Issuer,
		Audience:    aud,
	}, nil
}
```

---

## 1.5.4 Refresh + Session Validation (Complete Reference)

WorkOS refresh tokens are **single-use**: a refresh token may only be used once.
Therefore, `RefreshTokens` MUST be concurrency-safe.

WorkOS provides endpoints to refresh tokens and to revoke/list sessions.
SDK method names and response types may vary across versions; `vango-workos`
must preserve the semantics specified by the `Sessions` interface regardless
of underlying SDK shapes.

**Cost note (important):** some WorkOS session revocation checks are implemented by
listing sessions for a user and scanning for the session ID. This can be expensive
for users with many active sessions. `vango-workos` mitigates this with a short,
process-local per-user sessions cache (`SessionListCacheDuration`) and by allowing
operators to disable periodic validation (`DisablePeriodicSessionValidation`) when
necessary.

```go
package workos

	import (
		"context"
		"crypto/sha256"
		"encoding/base64"
		"errors"
		"strings"
		"sync"
		"time"

		"github.com/workos/workos-go/v6/pkg/usermanagement"
	)

// refreshGroup ensures that concurrent refresh attempts for the same refresh token
// share the same upstream refresh call (single-flight) within a process.
//
// IMPORTANT: This coordination is process-local. For multi-instance deployments,
// you MUST enable sticky sessions so that a single browser's concurrent requests
// land on the same instance. See §H.5.4 (Operational Guardrails).
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

	// Ensure single-use refresh tokens are not used concurrently (process-local).
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

func parseWorkOSTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, errors.New("empty time")
	}
	// WorkOS APIs use RFC3339 timestamps in string fields (often with fractional seconds).
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339, s)
}

type sessionListCacheEntry struct {
	fetchedAt time.Time
	sessions  map[string]*SessionInfo // sessionID -> info
}

// listSessionsForUser fetches (or returns a cached snapshot of) all sessions for a user.
//
// Why a per-user cache exists:
// Some deployments validate sessions by listing sessions for a user and scanning for
// the session ID. Without caching, a user with many concurrent sessions could amplify
// Sessions API calls (each session performing its own list operation).
//
// Cache scope: process-local only.
func (c *Client) listSessionsForUser(ctx context.Context, userID string) (map[string]*SessionInfo, error) {
	if userID == "" {
		return nil, errors.New("workos: userID required")
	}

	ttl := c.cfg.SessionListCacheDuration
	if ttl > 0 {
		c.sessionsMu.Lock()
		if c.sessionsCache == nil {
			c.sessionsCache = make(map[string]sessionListCacheEntry)
		}
		if ent, ok := c.sessionsCache[userID]; ok && time.Since(ent.fetchedAt) < ttl && ent.sessions != nil {
			s := ent.sessions
			c.sessionsMu.Unlock()
			return s, nil
		}
		c.sessionsMu.Unlock()
	}

	// Fetch all pages.
	sessions := make(map[string]*SessionInfo, 16)

	opts := usermanagement.ListSessionsOpts{Limit: 100}
	for {
		resp, err := c.um.ListSessions(ctx, userID, opts)
		if err != nil {
			return nil, errors.New("workos: session list failed")
		}

		for _, s := range resp.Data {
			exp, _ := parseWorkOSTime(s.ExpiresAt)
			sessions[s.ID] = &SessionInfo{
				SessionID: s.ID,
				UserID:    s.UserID,
				OrgID:     s.OrganizationID,
				Active:    strings.EqualFold(s.Status, "active"),
				ExpiresAt: exp,
			}
		}

		after := resp.ListMetadata.After
		if after == "" {
			break
		}
		opts.Before = ""
		opts.After = after
	}

	if ttl > 0 {
		c.sessionsMu.Lock()
		if c.sessionsCache == nil {
			c.sessionsCache = make(map[string]sessionListCacheEntry)
		}
		c.sessionsCache[userID] = sessionListCacheEntry{
			fetchedAt: time.Now(),
			sessions:  sessions,
		}
		c.sessionsMu.Unlock()
	}

	return sessions, nil
}

func (c *Client) ValidateSession(ctx context.Context, userID, sessionID string) (*SessionInfo, error) {
	if userID == "" || sessionID == "" {
		return nil, errors.New("workos: validate session requires userID and sessionID")
	}

	// If the WorkOS SDK offers a "get session by ID" endpoint, prefer it.
	// Otherwise, list sessions for the user and scan for the session ID.
	sessions, err := c.listSessionsForUser(ctx, userID)
	if err != nil {
		return nil, errors.New("workos: session validation failed")
	}
	if info := sessions[sessionID]; info != nil {
		return info, nil
	}
	return &SessionInfo{SessionID: sessionID, UserID: userID, Active: false}, nil
}

func (c *Client) RevokeSession(ctx context.Context, sessionID string) error {
	if sessionID == "" {
		return errors.New("workos: sessionID required")
	}
	if err := c.um.RevokeSession(ctx, usermanagement.RevokeSessionOpts{SessionID: sessionID}); err != nil {
		return errors.New("workos: revoke session failed")
	}
	return nil
}
```

## 1.6 HTTP Handlers (AuthKit Flow)

These handlers implement the AuthKit hosted UI flow for Vango applications. They are HTTP handlers because they run at the HTTP boundary, not on the Vango session loop.

```go
	package workos

	import (
		"crypto/rand"
		"encoding/hex"
		"fmt"
		"html"
		"net/http"
		"net/url"
		"strings"
		"time"
	)

	// generateState returns an opaque random string for the OAuth/AuthKit "state" parameter.
	// It is stored in a short-lived HttpOnly cookie and verified on callback.
	func generateState() string {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		return hex.EncodeToString(b)
	}

	// --- Sign-In Handler ---

// SignInHandler redirects the user to the AuthKit hosted sign-in page.
// It generates a state parameter for CSRF protection.
//
// Registration:
//   mux.HandleFunc("GET /auth/signin", client.SignInHandler)
func (c *Client) SignInHandler(w http.ResponseWriter, r *http.Request) {
	state := generateState()
	setStateCookie(w, state, c.cfg)

	authURL, err := c.um.GetAuthorizationURL(usermanagement.GetAuthorizationURLOpts{
		ClientID:    c.cfg.ClientID,
		RedirectURI: c.cfg.RedirectURI,
		State:       state,
		Provider:    "", // empty = AuthKit handles provider selection
	})
	if err != nil {
		http.Error(w, "Failed to generate sign-in URL", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, authURL.String(), http.StatusTemporaryRedirect)
}

// SignUpHandler redirects the user to the AuthKit hosted sign-up page.
//
// Registration:
//   mux.HandleFunc("GET /auth/signup", client.SignUpHandler)
func (c *Client) SignUpHandler(w http.ResponseWriter, r *http.Request) {
	state := generateState()
	setStateCookie(w, state, c.cfg)

	authURL, err := c.um.GetAuthorizationURL(usermanagement.GetAuthorizationURLOpts{
		ClientID:    c.cfg.ClientID,
		RedirectURI: c.cfg.RedirectURI,
		State:       state,
		ScreenHint:  "sign-up",
	})
	if err != nil {
		http.Error(w, "Failed to generate sign-up URL", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, authURL.String(), http.StatusTemporaryRedirect)
}

// --- Callback Handler ---

// CallbackHandler handles the OAuth/AuthKit callback from WorkOS.
// It exchanges the authorization code for tokens, creates a session
// cookie, and redirects the user to the application.
//
// This handler MUST be registered at the path matching your configured
// redirect URI in the WorkOS Dashboard.
//
// Registration:
//   mux.HandleFunc("GET /auth/callback", client.CallbackHandler)
func (c *Client) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	errParam := r.URL.Query().Get("error")

	// Check for WorkOS-reported errors
	if errParam != "" {
		desc := r.URL.Query().Get("error_description")
		http.Error(w, fmt.Sprintf("Authentication error: %s: %s", errParam, desc),
			http.StatusBadRequest)
		return
	}

	if code == "" {
		http.Error(w, "Missing authorization code", http.StatusBadRequest)
		return
	}

	// Validate state (CSRF protection)
	if !validateStateCookie(r, state, c.cfg) {
		http.Error(w, "Invalid state parameter", http.StatusForbidden)
		return
	}
	clearStateCookie(w, c.cfg)

	// Exchange code for authenticated user + tokens.
	// The code is valid for 10 minutes (WorkOS enforced).
	authResp, err := c.um.AuthenticateWithCode(r.Context(),
		usermanagement.AuthenticateWithCodeOpts{
			ClientID: c.cfg.ClientID,
			Code:     code,
		},
	)
	if err != nil {
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}

	claims, err := c.VerifyAccessToken(r.Context(), authResp.AccessToken)
	if err != nil {
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}

		identity := &Identity{
			UserID:      authResp.User.ID,
			Email:       authResp.User.Email,
			Name:        strings.TrimSpace(authResp.User.FirstName + " " + authResp.User.LastName),
			OrgID:       claims.OrgID,
			Roles:       claims.Roles,
			Permissions: claims.Permissions,
			Entitlements: claims.Entitlements,
			SessionID:   claims.SessionID,
			ExpiresAt:   claims.ExpiresAt,
			AuthMethod:  authResp.AuthenticationMethod,
		}
	if identity.Name == "" {
		identity.Name = identity.Email
	}
	// If WorkOS returns an org ID out-of-band, prefer it when claims omit it.
	if identity.OrgID == "" {
		identity.OrgID = authResp.OrganizationID
	}

	// Encrypt and set session cookie
	if err := setSessionCookie(w, &cookieSession{
		AccessToken:  authResp.AccessToken,
		RefreshToken: authResp.RefreshToken,
		IdentityHint: identity,
	}, c.cfg); err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	// Redirect to the application.
	// Use the return_to parameter if present, otherwise root.
	returnTo := r.URL.Query().Get("return_to")
	if returnTo == "" || !isSafeRedirect(returnTo, c.cfg.BaseURL) {
		returnTo = "/"
	}
	http.Redirect(w, r, returnTo, http.StatusTemporaryRedirect)
}

// isSafeRedirect validates a return_to value to prevent open redirects.
//
// Rules:
// - Relative redirects MUST be absolute-path ("/...") and MUST NOT start with "//".
// - Absolute redirects are allowed only when they match cfg.BaseURL origin exactly.
func isSafeRedirect(returnTo, baseURL string) bool {
	if returnTo == "" {
		return false
	}
	u, err := url.Parse(returnTo)
	if err != nil {
		return false
	}
	if u.IsAbs() {
		base, err := url.Parse(baseURL)
		if err != nil || base == nil {
			return false
		}
		return u.Scheme == base.Scheme && strings.EqualFold(u.Host, base.Host)
	}
	return strings.HasPrefix(returnTo, "/") && !strings.HasPrefix(returnTo, "//")
}

	// --- Logout + Signed-Out Handlers ---

	// LogoutHandler clears the local session cookie and (best-effort) revokes the
	// WorkOS session. It then redirects the browser to the WorkOS logout URL.
	//
	// IMPORTANT (CSP):
	// Vango's default CSP does not allow inline scripts. Therefore, multi-tab
	// logout coordination is implemented via a dedicated signed-out page that
	// loads a same-origin script (`/auth/signed-out.js`) rather than inline JS.
	//
	// Registration:
	//   mux.HandleFunc("POST /auth/logout", client.LogoutHandler)
	//   mux.HandleFunc("GET /auth/signed-out", client.SignedOutHandler)
	//   mux.HandleFunc("GET /auth/signed-out.js", client.SignedOutScriptHandler)
	func (c *Client) LogoutHandler(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		cookieSess, _ := readSessionCookie(r, c.cfg)

			// Always clear local cookie (forces re-auth on next request).
			clearSessionCookie(w, c.cfg)
			w.Header().Set("Cache-Control", "no-store")

			// Where WorkOS should send the browser after logout.
			// This MUST be allowed in the WorkOS Dashboard sign-out redirects list.
			signedOutURL := strings.TrimRight(c.cfg.BaseURL, "/") + c.cfg.SignOutRedirectURI

			// Best-effort server-side revocation.
			sessionID := ""
			if cookieSess != nil && cookieSess.IdentityHint != nil && cookieSess.IdentityHint.SessionID != "" {
				sessionID = cookieSess.IdentityHint.SessionID
			} else if cookieSess != nil && cookieSess.AccessToken != "" {
				// Fallback: derive session ID from the access token (requires verification).
				if claims, err := c.VerifyAccessToken(r.Context(), cookieSess.AccessToken); err == nil && claims != nil {
					sessionID = claims.SessionID
				}
			}
			if sessionID != "" {
				_ = c.RevokeSession(r.Context(), sessionID)
			}

		// Redirect through WorkOS logout when we have a session ID; otherwise go
		// straight to our signed-out page (still broadcasts to other tabs).
			if sessionID != "" {
				logoutURL, _ := c.um.GetLogoutURL(usermanagement.GetLogoutURLOpts{
					SessionID: sessionID,
					ReturnTo:  signedOutURL,
				})
				if logoutURL != nil {
					http.Redirect(w, r, logoutURL.String(), http.StatusSeeOther)
					return
				}
		}

		http.Redirect(w, r, c.cfg.SignOutRedirectURI, http.StatusSeeOther)
	}

	// SignedOutHandler is the post-logout landing page. It broadcasts a logout
	// signal to other tabs and clears Vango resume keys, then redirects.
	//
	// This MUST be registered at the same path as Config.SignOutRedirectURI,
	// and that redirect MUST be configured in the WorkOS Dashboard.
	func (c *Client) SignedOutHandler(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		returnTo := r.URL.Query().Get("return_to")
		if returnTo == "" || !isSafeRedirect(returnTo, c.cfg.BaseURL) {
			returnTo = "/"
		}

		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(signedOutHTML(returnTo)))
	}

	func signedOutHTML(returnTo string) string {
		// HTML-escape to prevent attribute injection.
		rt := html.EscapeString(returnTo)
		return fmt.Sprintf(`<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="workos-return-to" content="%s">
    <title>Signed out</title>
    <script src="/auth/signed-out.js" defer></script>
  </head>
  <body></body>
</html>`, rt)
	}

	// SignedOutScriptHandler is a same-origin script (no inline JS) that performs:
	//  1) multi-tab logout broadcast (BroadcastChannel with localStorage fallback),
	//  2) clearing Vango resume keys,
	//  3) navigation to the return_to destination.
	func (c *Client) SignedOutScriptHandler(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(signedOutJS))
	}

	const signedOutJS = `(function () {
  function meta(name) {
    var el = document.querySelector('meta[name="' + name + '"]');
    return el && el.content ? el.content : "";
  }

  var channel = "vango:auth";
  var payload = { type: "logout", reason: 0 };
  var redirectTo = meta("workos-return-to") || "/";

  try {
    if (typeof BroadcastChannel !== "undefined") {
      var bc = new BroadcastChannel(channel);
      bc.postMessage(payload);
      bc.close();
    } else if (typeof localStorage !== "undefined") {
      var key = "__vango_auth_" + channel;
      localStorage.setItem(key, JSON.stringify({ payload: payload, ts: Date.now() }));
      localStorage.removeItem(key);
    }
  } catch (err) {}

  try {
    if (typeof sessionStorage !== "undefined") {
      sessionStorage.removeItem("__vango_session_id");
      sessionStorage.removeItem("__vango_last_seq");
    }
  } catch (err) {}

  try {
    window.location.replace(redirectTo);
  } catch (err) {
    window.location.replace("/");
  }
	})();`

	// RegisterAuthHandlers registers the standard AuthKit routes on a mux.
	//
	// This reduces wiring mistakes by keeping handler registration in one place.
	// If you mount auth under a different prefix, register manually instead.
	func (c *Client) RegisterAuthHandlers(mux *http.ServeMux, csrfMw func(http.Handler) http.Handler) {
		mux.HandleFunc("/auth/signin", c.SignInHandler)
		mux.HandleFunc("/auth/signup", c.SignUpHandler)
		mux.HandleFunc("/auth/callback", c.CallbackHandler)
		mux.Handle("/auth/logout", csrfMw(http.HandlerFunc(c.LogoutHandler)))
		mux.HandleFunc("/auth/signed-out", c.SignedOutHandler)
		mux.HandleFunc("/auth/signed-out.js", c.SignedOutScriptHandler)
	}
		```

---

## 1.7 Vango Integration Primitives

These are the primitives that wire WorkOS into Vango’s lifecycle model.

This integration MUST use Vango’s existing auth projection keys in `github.com/vango-go/vango/pkg/auth`:
- `auth.Set(session, identity)` stores the “user object” used by `auth.Get[*Identity](ctx)` and route middleware.
- `auth.SetPrincipal(session, auth.Principal{...})` stores a minimal principal used for `AuthCheck` and stable principal metadata (passive expiry is disabled by default in `vango-workos`).

It MUST NOT store access/refresh tokens in session KV. Tokens only live inside the encrypted cookie payload.

**Auth freshness posture (normative):**
- Authorization inside an established WebSocket session MUST be based on the projected `Identity` / `auth.Principal`, not on access token freshness.
- Access token expiry is enforced at the HTTP boundary (middleware refresh or forced re-auth).
- WorkOS session revocation is enforced via resume checks (OnSessionResume) and optionally via periodic `AuthCheck` (RevalidationConfig).
- High-value operations SHOULD call `ctx.RevalidateAuth()` immediately before performing sensitive mutations.

**Wiring (canonical):**
- Install HTTP-boundary middleware via `app.Server().Use(workosClient.Middleware())` so it runs on SSR *and* WebSocket upgrade/resume requests.
- If you need custom HTTP endpoints (AuthKit routes, webhooks), mount them on a `http.ServeMux` and install it via `app.Server().SetHandler(mux)`.

```go
package workos

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/vango-go/vango"
	"github.com/vango-go/vango/pkg/auth"
	"github.com/vango-go/vango/pkg/authmw"
)

// --- HTTP Boundary Middleware (net/http) ---

// Middleware validates the WorkOS session cookie and (when present) attaches
// Identity to the request context for SSR and for the WebSocket handshake hooks.
//
// This runs at the HTTP boundary (SSR requests, WebSocket upgrade, reconnect entry).
// It does NOT run per-event on the session loop.
//
// IMPORTANT: This middleware does not implement path-based “protected routes”.
// In Vango, protect pages using route middleware (authmw.RequireAuth, RequireRole, etc.).
func (c *Client) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// Read and decrypt cookie payload (tokens + optional identity hint).
					cookieSess, err := readSessionCookie(r, c.cfg)
					if err != nil || cookieSess == nil {
						next.ServeHTTP(w, r)
						return
					}
				accessToken := cookieSess.AccessToken
				refreshToken := cookieSess.RefreshToken
				needCookieWrite := false

				// Validate access token locally (JWKS + claims).
				claims, err := c.VerifyAccessToken(r.Context(), accessToken)
				if err != nil {
					// If access token is invalid for any reason, clear the cookie.
					// Treat as unauthenticated and allow the request to proceed.
					clearSessionCookie(w, c.cfg)
					next.ServeHTTP(w, r)
				return
			}

				// If expired, optionally attempt refresh (refresh tokens are single-use; see §1.5.4 / §H.5.4).
				if !claims.ExpiresAt.IsZero() && time.Now().After(claims.ExpiresAt) {
					if c.cfg.DisableRefreshInMiddleware {
						clearSessionCookie(w, c.cfg)
						next.ServeHTTP(w, r)
						return
					}
					if refreshToken != "" {
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
				}

					// Build a fresh identity projection for Vango.
					// Claims are authoritative; cookieSess.IdentityHint is a UX hint only.
					hint := cookieSess.IdentityHint
					identity := &Identity{
							UserID:      claims.UserID,
							Email:       claims.Email,
							Name:        claims.Name,
							OrgID:       claims.OrgID,
						Roles:       claims.Roles,
						Permissions: claims.Permissions,
						Entitlements: claims.Entitlements,
						SessionID:   claims.SessionID,
							ExpiresAt:   claims.ExpiresAt,
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

				// Persist rotated tokens (and optionally refreshed identity projection) to cookie.
				// Avoid writing on every request; only write when rotation occurred or identity is missing.
				if needCookieWrite || cookieSess.IdentityHint == nil {
					_ = setSessionCookie(w, &cookieSession{
						AccessToken:  accessToken,
						RefreshToken: refreshToken,
						IdentityHint: identity,
					}, c.cfg)
				}

					// Attach Identity for SSR and for handshake hooks.
					ctx := vango.WithUser(r.Context(), identity)
					next.ServeHTTP(w, r.WithContext(ctx))
				})
			}
		}

// --- Refresh Coordination (MUST) ---

	// RefreshTokens MUST be safe under concurrency and refresh-token rotation.
//
// Requirement:
	// - For a given browser session cookie, at most one refresh exchange may be in-flight at a time.
	//
	// Practical constraint:
	// - A losing concurrent request cannot "re-read the cookie" during the same request, because
	//   it only has the cookie value from the inbound request. Therefore, refresh coordination
	//   must be *single-flight* (share the winner's refresh result) at least within a process.
	// - In multi-instance deployments, you MUST enable sticky sessions (LB affinity) so a single
	//   browser's concurrent requests land on the same instance, or you must disable refresh-in-
	//   middleware and require re-auth on expiry.
//
// In single-instance deployments, an in-memory keyed lock is sufficient.
// In multi-instance deployments, prefer sticky sessions OR provide a distributed lock.

// --- Session Bridge ---

// SessionBridge returns Vango session lifecycle hooks pre-wired for WorkOS.
// Wire these into your vango.Config.
//
// Usage:
//   bridge := workosClient.SessionBridge()
//   cfg := vango.Config{
//       OnSessionStart:  bridge.OnSessionStart,
//       OnSessionResume: bridge.OnSessionResume,
//   }
func (c *Client) SessionBridge() *Bridge {
	return &Bridge{client: c}
}

type Bridge struct {
	client *Client
}

// OnSessionStart copies Identity from the HTTP context into the Vango session
// runtime auth projection. This runs during WebSocket upgrade, before the
// handshake completes.
func (b *Bridge) OnSessionStart(httpCtx context.Context, s *vango.Session) {
	user := vango.UserFromContext(httpCtx)
	identity, _ := user.(*Identity)
	if identity == nil {
		return
	}

	// Store the user object for auth.Get[*Identity](ctx) and route middleware.
	auth.Set(s, identity)

	// Store the minimal principal used by Vango for AuthCheck + stable principal metadata.
	auth.SetPrincipal(s, auth.Principal{
			ID:              identity.UserID,
			Email:           identity.Email,
			Name:            identity.Name,
			Roles:           identity.Roles,
			TenantID:        identity.OrgID,
			SessionID:       identity.SessionID,
			// IMPORTANT:
			// WorkOS access tokens are short-lived and refreshed via refresh tokens at the HTTP boundary.
			// Vango WebSocket sessions do not re-enter HTTP middleware per event. Therefore, setting a
			// passive expiry based on the access token's exp would force a reload mid-session.
			//
			// We disable passive expiry by default and rely on periodic active revalidation (AuthCheck).
			ExpiresAtUnixMs: 0,
		})
	}

// OnSessionResume revalidates the WorkOS session during resume.
// If the session was previously authenticated and revalidation fails, Vango
// rejects resume and forces a reload into the HTTP pipeline.
func (b *Bridge) OnSessionResume(httpCtx context.Context, s *vango.Session) error {
	user := vango.UserFromContext(httpCtx)
	identity, _ := user.(*Identity)
	if identity == nil {
		return fmt.Errorf("workos: missing identity on resume (middleware not applied?)")
	}

	ctx, cancel := context.WithTimeout(httpCtx, b.client.cfg.RevalidationTimeout)
	defer cancel()

		info, err := b.client.ValidateSession(ctx, identity.UserID, identity.SessionID)
		if err != nil {
			return fmt.Errorf("workos: session revalidation failed: %w", err)
		}
		if info == nil || !info.Active {
			return fmt.Errorf("workos: session is no longer active")
	}

	// Rehydrate auth projection (REQUIRED for strict resume).
	auth.Set(s, identity)
		auth.SetPrincipal(s, auth.Principal{
			ID:              identity.UserID,
			Email:           identity.Email,
			Name:            identity.Name,
			Roles:           identity.Roles,
			TenantID:        identity.OrgID,
			SessionID:       identity.SessionID,
			ExpiresAtUnixMs: 0,
		})
		return nil
	}

// --- Revalidation Config ---

// RevalidationConfig returns a vango.AuthCheckConfig pre-wired for
// WorkOS periodic session revalidation during long-lived WebSocket
// sessions. See §42.3.
//
// Usage:
//   cfg := vango.Config{
//       Session: vango.SessionConfig{
//           AuthCheck: workosClient.RevalidationConfig(),
//       },
//   }
func (c *Client) RevalidationConfig() *vango.AuthCheckConfig {
	if c.cfg.DisablePeriodicSessionValidation {
		return nil
	}
	return &vango.AuthCheckConfig{
		Interval:    c.cfg.RevalidationInterval,
		Timeout:     c.cfg.RevalidationTimeout,
		FailureMode: vango.FailOpenWithGrace,
		MaxStale:    c.cfg.MaxStaleSession,
		Check: func(ctx context.Context, p auth.Principal) error {
			// Active revocation detection (network call).
			// Do NOT use refresh tokens here; AuthCheck runs off the session loop and must
			// be safe under concurrency and long-lived sessions.
			info, err := c.ValidateSession(ctx, p.ID, p.SessionID)
			if err != nil {
				return err
			}
			if info == nil || !info.Active {
				return fmt.Errorf("workos: session inactive")
			}
			return nil
		},
		OnExpired: vango.AuthExpiredConfig{
			Action: vango.ForceReload,
			Path:   "/auth/signin",
		},
	}
}

// --- Vango Helpers ---

func CurrentIdentity(ctx vango.Ctx) (*Identity, bool) {
	return auth.Get[*Identity](ctx)
}

func RequireIdentity(ctx vango.Ctx) (*Identity, error) {
	return auth.Require[*Identity](ctx)
}

// IdentityFromContext reads Identity from a stdlib context.Context.
//
// This is primarily for Action/Resource work functions, which receive a context.Context
// derived from the session’s std context.
func IdentityFromContext(ctx context.Context) (*Identity, bool) {
	u := vango.UserFromContext(ctx)
	i, _ := u.(*Identity)
	return i, i != nil
}

// WithIdentity attaches Identity to a stdlib context.Context in the same way
// the WorkOS middleware does at runtime (for tests and utilities).
	func WithIdentity(ctx context.Context, identity *Identity) context.Context {
		if ctx == nil {
			ctx = context.Background()
		}
		if identity == nil {
			return ctx
		}
		return vango.WithUser(ctx, identity)
	}

func RequirePermission(ctx vango.Ctx, perm string) error {
	identity, err := RequireIdentity(ctx)
	if err != nil {
		return err
	}
	if !identity.HasPermission(perm) {
		return auth.ErrForbidden
	}
	return nil
}

// Optional: use Vango route middleware to protect routes.
// Example:
//   func Middleware() []router.Middleware { return []router.Middleware{authmw.RequireAuth} }
var RequireAuth = authmw.RequireAuth

	```

---

## 1.8 Webhook Handler

```go
package workos

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// WebhookEvent is a normalized webhook event from WorkOS.
type WebhookEvent struct {
	ID        string          `json:"id"`
	Event     string          `json:"event"`
	Data      json.RawMessage `json:"data"`
	CreatedAt time.Time       `json:"created_at"`
}

// WebhookHandler provides a validated, typed webhook endpoint.
//
// It verifies the webhook signature using the configured secret,
// parses the event, and dispatches to registered handlers.
//
// Registration:
//   mux.Handle("POST /webhooks/workos", workosClient.WebhookHandler(
//       workos.OnDirectoryUserCreated(handleUserProvisioned),
//       workos.OnDirectoryUserDeleted(handleUserDeprovisioned),
//       workos.OnConnectionActivated(handleSSOActivated),
//   ))
	func (c *Client) WebhookHandler(handlers ...WebhookSubscription) http.Handler {
		registry := buildWebhookRegistry(handlers)

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

			// Read body (bounded)
			limit := c.cfg.WebhookMaxBodyBytes
			if limit <= 0 {
				limit = 1 << 20
			}
			body, err := io.ReadAll(io.LimitReader(r.Body, limit))
			if err != nil {
				http.Error(w, "Failed to read body", http.StatusBadRequest)
				return
			}

		// Verify signature.
		//
		// NOTE: net/http header lookup is case-insensitive. "WorkOS-Signature"
		// is the canonical header name used in this spec.
		sig := r.Header.Get("WorkOS-Signature")
		if err := c.wh.VerifyWebhook(body, sig, c.cfg.WebhookSecret); err != nil {
			http.Error(w, "Invalid signature", http.StatusUnauthorized)
			return
		}

		// Parse event
		var event WebhookEvent
			if err := json.Unmarshal(body, &event); err != nil {
				http.Error(w, "Invalid event payload", http.StatusBadRequest)
				return
			}

			// Dispatch synchronously by default.
			//
			// Operational contract (MUST for handlers):
			// - Handlers MUST be fast and SHOULD enqueue durable work rather than doing
			//   slow I/O inline.
			// - Webhook processing MUST be idempotent by event.ID.
			//
			// If you need “ack fast, process async”, your handler should enqueue and return.
			if handler, ok := registry[event.Event]; ok && handler != nil {
				handler(r.Context(), event)
			}
			if any := registry["*"]; any != nil {
				any(r.Context(), event)
			}

			w.WriteHeader(http.StatusOK)
		})
	}

// --- Webhook Subscription Builders ---

	type WebhookSubscription struct {
		Event   string
		Handler func(context.Context, WebhookEvent)
	}

	func OnDirectoryUserCreated(fn func(ctx context.Context, e WebhookEvent)) WebhookSubscription {
		return WebhookSubscription{Event: "dsync.user.created", Handler: fn}
	}

	func OnDirectoryUserUpdated(fn func(ctx context.Context, e WebhookEvent)) WebhookSubscription {
		return WebhookSubscription{Event: "dsync.user.updated", Handler: fn}
	}

	func OnDirectoryUserDeleted(fn func(ctx context.Context, e WebhookEvent)) WebhookSubscription {
		return WebhookSubscription{Event: "dsync.user.deleted", Handler: fn}
	}

	func OnDirectoryGroupCreated(fn func(ctx context.Context, e WebhookEvent)) WebhookSubscription {
		return WebhookSubscription{Event: "dsync.group.created", Handler: fn}
	}

	func OnDirectoryGroupUpdated(fn func(ctx context.Context, e WebhookEvent)) WebhookSubscription {
		return WebhookSubscription{Event: "dsync.group.updated", Handler: fn}
	}

	func OnDirectoryGroupDeleted(fn func(ctx context.Context, e WebhookEvent)) WebhookSubscription {
		return WebhookSubscription{Event: "dsync.group.deleted", Handler: fn}
	}

	func OnConnectionActivated(fn func(ctx context.Context, e WebhookEvent)) WebhookSubscription {
		return WebhookSubscription{Event: "connection.activated", Handler: fn}
	}

	func OnConnectionDeactivated(fn func(ctx context.Context, e WebhookEvent)) WebhookSubscription {
		return WebhookSubscription{Event: "connection.deactivated", Handler: fn}
	}

	func OnUserCreated(fn func(ctx context.Context, e WebhookEvent)) WebhookSubscription {
		return WebhookSubscription{Event: "user.created", Handler: fn}
	}

	func OnUserUpdated(fn func(ctx context.Context, e WebhookEvent)) WebhookSubscription {
		return WebhookSubscription{Event: "user.updated", Handler: fn}
	}

	func OnUserDeleted(fn func(ctx context.Context, e WebhookEvent)) WebhookSubscription {
		return WebhookSubscription{Event: "user.deleted", Handler: fn}
	}

	func OnOrganizationMembershipCreated(fn func(ctx context.Context, e WebhookEvent)) WebhookSubscription {
		return WebhookSubscription{Event: "organization_membership.created", Handler: fn}
	}

	func OnOrganizationMembershipDeleted(fn func(ctx context.Context, e WebhookEvent)) WebhookSubscription {
		return WebhookSubscription{Event: "organization_membership.deleted", Handler: fn}
	}

	func OnSessionCreated(fn func(ctx context.Context, e WebhookEvent)) WebhookSubscription {
		return WebhookSubscription{Event: "session.created", Handler: fn}
	}

	func OnAnyEvent(fn func(ctx context.Context, e WebhookEvent)) WebhookSubscription {
		return WebhookSubscription{Event: "*", Handler: fn}
	}
```

---

## 1.9 Admin Portal Link Generation

```go
package workos

import (
	"context"
	"fmt"
)

// AdminPortalIntent specifies what the Admin Portal shows.
type AdminPortalIntent string

const (
	AdminPortalSSO          AdminPortalIntent = "sso"
	AdminPortalDSync        AdminPortalIntent = "dsync"
	AdminPortalAuditLogs    AdminPortalIntent = "audit_logs"
	AdminPortalLogStreams   AdminPortalIntent = "log_streams"
	AdminPortalCertRenewal AdminPortalIntent = "certificate_renewal"
)

// GenerateAdminPortalLink creates a short-lived URL that gives an
// organization's IT admin self-service access to configure SSO,
// Directory Sync, Audit Logs, etc.
//
// The returned URL is valid for 5 minutes.
//
// MUST be called from an Action work function or HTTP handler.
// The caller MUST verify the requesting user is authorized to
// access the Admin Portal for this organization.
//
// Usage in an Action:
//   link, err := workosClient.GenerateAdminPortalLink(ctx,
//       orgID,
//       workos.AdminPortalSSO,
//       "https://myapp.com/settings",
//   )
func (c *Client) GenerateAdminPortalLink(
	ctx context.Context,
	organizationID string,
	intent AdminPortalIntent,
	returnURL string,
) (string, error) {
	resp, err := c.orgs.GeneratePortalLink(ctx, organizations.GeneratePortalLinkOpts{
		Organization: organizationID,
		Intent:       string(intent),
		ReturnURL:    returnURL,
	})
	if err != nil {
		return "", fmt.Errorf("workos: admin portal link: %w", err)
	}
	return resp.Link, nil
}
```

---

## 1.10 The Test Kit

All test utilities live in `github.com/vango-go/vango-workos`. No subpackage, no build tags.

```go
package workos

	import (
		"context"
		"errors"
		"time"
	)

// TestAuth is a mock implementation of Auth for use in standard Go tests.
// Assign function fields to control per-test behavior.
//
// Design contract:
//   - Unset methods return ErrNotMocked (never nil values that would panic).
//   - EmitAuditEvent is a no-op by default (returns nil).
//   - Ping-equivalent methods succeed by default.
//
// Usage:
//   mock := &workos.TestAuth{
//       GetUserFunc: func(ctx context.Context, id string) (*workos.User, error) {
//           return &workos.User{ID: id, Email: "alice@example.com"}, nil
//       },
//   }
//   routes.SetDeps(routes.Deps{Auth: mock})
type TestAuth struct {
	VerifyAccessTokenFunc           func(ctx context.Context, accessToken string) (*AccessTokenClaims, error)
	RefreshTokensFunc               func(ctx context.Context, refreshToken string) (*TokenSet, error)
	GetUserFunc                    func(ctx context.Context, userID string) (*User, error)
	ListUsersFunc                  func(ctx context.Context, opts ListUsersOpts) (*UserList, error)
	UpdateUserFunc                 func(ctx context.Context, userID string, opts UpdateUserOpts) (*User, error)
	DeleteUserFunc                 func(ctx context.Context, userID string) error
		ValidateSessionFunc            func(ctx context.Context, userID, sessionID string) (*SessionInfo, error)
	RevokeSessionFunc              func(ctx context.Context, sessionID string) error
	GetOrganizationFunc            func(ctx context.Context, orgID string) (*Organization, error)
	ListOrganizationsFunc          func(ctx context.Context, opts ListOrganizationsOpts) (*OrganizationList, error)
	ListOrganizationMembershipsFunc func(ctx context.Context, opts ListMembershipsOpts) (*MembershipList, error)
	GetOrganizationMembershipFunc  func(ctx context.Context, membershipID string) (*Membership, error)
	HasRoleFunc                    func(ctx context.Context, userID, orgID, roleSlug string) (bool, error)
	ListRolesFunc                  func(ctx context.Context, opts ListRolesOpts) (*RoleList, error)
	EmitAuditEventFunc             func(ctx context.Context, event AuditEvent) error
	ListConnectionsFunc            func(ctx context.Context, opts ListConnectionsOpts) (*ConnectionList, error)
	ListDirectoriesFunc            func(ctx context.Context, opts ListDirectoriesOpts) (*DirectoryList, error)
	ListDirectoryUsersFunc         func(ctx context.Context, opts ListDirectoryUsersOpts) (*DirectoryUserList, error)
	ListDirectoryGroupsFunc        func(ctx context.Context, opts ListDirectoryGroupsOpts) (*DirectoryGroupList, error)
}

var _ Auth = (*TestAuth)(nil)

// ErrNotMocked is returned when a TestAuth method is called without
// a corresponding Func field set.
var ErrNotMocked = errors.New("workos.TestAuth: method not mocked")

func (t *TestAuth) VerifyAccessToken(ctx context.Context, accessToken string) (*AccessTokenClaims, error) {
	if t.VerifyAccessTokenFunc != nil {
		return t.VerifyAccessTokenFunc(ctx, accessToken)
	}
	return nil, ErrNotMocked
}

func (t *TestAuth) RefreshTokens(ctx context.Context, refreshToken string) (*TokenSet, error) {
	if t.RefreshTokensFunc != nil {
		return t.RefreshTokensFunc(ctx, refreshToken)
	}
	return nil, ErrNotMocked
}

func (t *TestAuth) GetUser(ctx context.Context, userID string) (*User, error) {
	if t.GetUserFunc != nil {
		return t.GetUserFunc(ctx, userID)
	}
	return nil, ErrNotMocked
}

	func (t *TestAuth) ValidateSession(ctx context.Context, userID, sessionID string) (*SessionInfo, error) {
		if t.ValidateSessionFunc != nil {
			return t.ValidateSessionFunc(ctx, userID, sessionID)
		}
		// Default: session is valid
		return &SessionInfo{SessionID: sessionID, UserID: userID, Active: true, ExpiresAt: time.Now().Add(time.Hour)}, nil
	}

func (t *TestAuth) EmitAuditEvent(ctx context.Context, event AuditEvent) error {
	if t.EmitAuditEventFunc != nil {
		return t.EmitAuditEventFunc(ctx, event)
	}
	return nil // no-op by default
}

// ... remaining methods follow the same pattern.

// --- Test Helpers ---

// TestIdentity creates an Identity with sensible test defaults.
// Override fields as needed.
func TestIdentity(overrides ...func(*Identity)) *Identity {
	i := &Identity{
		UserID:      "user_test_001",
		Email:       "test@example.com",
		Name:        "Test User",
		OrgID:       "org_test_001",
		Roles:       []string{"member"},
		Permissions: nil,
		Entitlements: nil,
		SessionID:   "session_test_001",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	}
	for _, fn := range overrides {
		fn(i)
	}
	return i
}

func WithUserID(id string) func(*Identity) {
	return func(i *Identity) { i.UserID = id }
}

func WithEmail(email string) func(*Identity) {
	return func(i *Identity) { i.Email = email }
}

func WithOrgID(orgID string) func(*Identity) {
	return func(i *Identity) { i.OrgID = orgID }
}

func WithRoles(roles ...string) func(*Identity) {
	return func(i *Identity) { i.Roles = roles }
}

func WithPermissions(perms ...string) func(*Identity) {
	return func(i *Identity) { i.Permissions = perms }
}

func WithEntitlements(ents ...string) func(*Identity) {
	return func(i *Identity) { i.Entitlements = ents }
}

// HydrateSessionForTest populates a Vango session with the same auth projection
// that the WorkOS bridge would set at runtime.
//
// This is useful in unit tests that operate on a session directly (without full
// HTTP middleware + handshake wiring).
func HydrateSessionForTest(session auth.Session, identity *Identity) {
	if session == nil {
		return
	}
	if identity == nil {
		identity = TestIdentity()
	}
	auth.Set(session, identity)
	auth.SetPrincipal(session, auth.Principal{
		ID:              identity.UserID,
		Email:           identity.Email,
		Name:            identity.Name,
		Roles:           identity.Roles,
		TenantID:        identity.OrgID,
		SessionID:       identity.SessionID,
		// Passive expiry is disabled by default in vango-workos (§1.7).
		ExpiresAtUnixMs: 0,
	})
}
```

---

# Part 2: Developer Guide Sections

---

## §42.5 WorkOS Integration

Vango recommends **WorkOS** as the default authentication and enterprise-readiness provider. WorkOS's architecture complements Vango in three specific ways:

**AuthKit provides hosted authentication UI.** Vango's SSR-first model benefits from a redirect-based auth flow that doesn't require custom client-side rendering for sign-in/sign-up.

**Server-authoritative sessions.** WorkOS issues JWTs verified server-side, matching Vango's server-driven model where the session loop is the single writer and the server is the source of truth.

**Enterprise features as API calls.** SSO, SCIM, and Audit Logs are consumed via server-side API calls from Resource loaders and Action work functions, exactly where Vango expects blocking I/O. Fine-grained authorization (if used) follows the same I/O boundary rules.

The `vango-workos` package (`github.com/vango-go/vango-workos`) provides a production-hardened integration layer that bridges WorkOS's HTTP request/response model into Vango's long-lived session lifecycle.

### 42.5.1 The Lifecycle Bridge

The central challenge is that Vango sessions are long-lived (WebSocket-driven), but WorkOS authentication happens at the HTTP boundary (redirects, callbacks, cookies). The bridge works in three phases:

**Phase 1: HTTP Entry (SSR / Reconnect)**
HTTP middleware validates the encrypted session cookie, verifies the access token locally (JWKS), refreshes tokens when expired (rotation-safe), and attaches `*workos.Identity` to the request context via `vango.WithUser(...)`. This runs once per HTTP request, not per WebSocket event.

**Phase 2: Session Start / Resume**
The `SessionBridge` hydrates Vango’s runtime auth projection using `pkg/auth`:
- `auth.Set(session, identity)` to make `auth.Get[*workos.Identity](ctx)` work in components and route middleware
- `auth.SetPrincipal(session, auth.Principal{...})` to enable active `AuthCheck` and stable principal metadata (passive expiry is disabled by default in `vango-workos`)

On resume, it performs an active WorkOS `ValidateSession` call to detect revocation.

**Phase 3: Ongoing Revalidation**
For long-running sessions, periodic revalidation checks with WorkOS ensure terminated users are logged out within a bounded window, even if their tab stays open for hours.

### 42.5.2 The Access Rule (MUST)

> **All WorkOS API calls MUST occur inside Resource loaders, Action work functions, or HTTP handlers.**
>
> Never call the WorkOS API from Setup callbacks, render closures, event handlers, or lifecycle callbacks (OnMount, Effect, OnChange).

This is the same rule as for database access (§37.6.1). The session loop is single-threaded and must remain non-blocking.

**Exception:** Reading the current identity via `auth.Get[*workos.Identity](ctx)` (or `workos.CurrentIdentity(ctx)`) is in-memory only and safe anywhere, including render closures and event handlers.

---

## §37.9 Authentication Layer (WorkOS)

### 37.9.1 Environment Configuration (MUST)

WorkOS requires the following environment variables. Obtain all values from the **WorkOS Dashboard**.

```bash
# API key (Dashboard → API Keys → Secret Key)
WORKOS_API_KEY="sk_live_..."

# Client ID (Dashboard → API Keys → Client ID)
WORKOS_CLIENT_ID="client_..."

# Callback URL (Dashboard → Redirects → add this URL)
WORKOS_REDIRECT_URI="http://localhost:8080/auth/callback"

# Cookie encryption secret (generate with: openssl rand -base64 32)
# MUST be at least 32 characters.
WORKOS_COOKIE_SECRET="your-secure-secret-at-least-32-chars"

# Optional: cookie secret fallbacks for rotation (comma-separated)
# WORKOS_COOKIE_SECRET_FALLBACKS="oldsecret1,oldsecret2"

# Application base URL
WORKOS_BASE_URL="http://localhost:8080"

# Optional: JWT issuer/audience overrides (custom WorkOS auth domain)
# Defaults:
#   WORKOS_JWT_ISSUER="https://api.workos.com"
#   WORKOS_JWT_AUDIENCE="$WORKOS_CLIENT_ID"
# WORKOS_JWT_ISSUER="https://auth.myapp.com/"
# WORKOS_JWT_AUDIENCE="client_..."

# Webhook signing secret (Dashboard → Webhooks → endpoint detail)
# Required only if using webhooks.
WORKOS_WEBHOOK_SECRET="whsec_..."
```

**Secrets handling:** Never commit these values to version control. Never log them. Store in `.env` (development, in `.gitignore`), environment variables (production), or a secrets manager.

### 37.9.2 Project Structure

```
myapp/
├── cmd/server/main.go
├── app/
│   ├── routes/
│   │   ├── deps.go
│   │   ├── layout.go
│   │   ├── index.go
│   │   ├── auth/
│   │   │   ├── signin.go      # /auth/signin
│   │   │   ├── signup.go      # /auth/signup
│   │   │   ├── callback.go    # /auth/callback
│   │   │   └── logout.go      # /auth/logout (POST)
│   │   └── dashboard/
│   │       └── index.go       # Protected page
│   ├── middleware/
│   │   └── auth.go            # WorkOS middleware wiring
│   └── stores/
│       └── ...
├── internal/
│   ├── services/
│   │   └── ...
│   └── config/
│       └── config.go
└── ...
```

### 37.9.3 Dependency Injection Pattern (Canonical)

**`app/routes/deps.go`**:

```go
package routes

import workos "github.com/vango-go/vango-workos"

type Deps struct {
	Auth workos.Auth
}

var deps Deps

func SetDeps(d Deps) { deps = d }
func GetDeps() Deps  { return deps }
```

**`cmd/server/main.go`**:

```go
package main

	import (
		"context"
		"net/http"
		"log/slog"
		"os"
		"os/signal"
		"syscall"

	"github.com/vango-go/vango"
	workos "github.com/vango-go/vango-workos"
	"myapp/app/routes"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// 1. Create WorkOS client
		wosClient, err := workos.New(workos.Config{
			APIKey:         os.Getenv("WORKOS_API_KEY"),
			ClientID:       os.Getenv("WORKOS_CLIENT_ID"),
			RedirectURI:    os.Getenv("WORKOS_REDIRECT_URI"),
			// Must match a configured WorkOS sign-out redirect.
			// Example: https://myapp.com/auth/signed-out
			SignOutRedirectURI: "/auth/signed-out",
			CookieSecret:   os.Getenv("WORKOS_COOKIE_SECRET"),
			BaseURL:        os.Getenv("WORKOS_BASE_URL"),
			WebhookSecret:  os.Getenv("WORKOS_WEBHOOK_SECRET"),
			EnableAuditLogs: true,
		})
	if err != nil {
		logger.Error("failed to create WorkOS client", "error", err)
		os.Exit(1)
	}

	// 2. Inject Auth interface into route dependencies
	routes.SetDeps(routes.Deps{Auth: wosClient})

	// 3. Create Vango app with WorkOS session lifecycle
	bridge := wosClient.SessionBridge()
	app, err := vango.New(vango.Config{
		Logger:          logger,
		OnSessionStart:  bridge.OnSessionStart,
		OnSessionResume: bridge.OnSessionResume,
		Session: vango.SessionConfig{
			AuthCheck: wosClient.RevalidationConfig(),
		},
	})
	if err != nil {
		logger.Error("invalid vango config", "error", err)
		os.Exit(1)
	}

	// 4. Register routes (Vango router)
	routes.Register(app)

	// 5. Wire HTTP boundary (net/http mux + WorkOS middleware)
	//
	// IMPORTANT:
	// - workosClient.Middleware() MUST be installed as SERVER middleware so it runs for:
	//   SSR requests *and* WebSocket upgrade/resume requests.
	// - Logout MUST be CSRF-protected (Vango enables CSRF by default).
	app.Server().Use(wosClient.Middleware())
	csrfMw := app.Server().CSRFMiddleware()

	mux := http.NewServeMux()
	wosClient.RegisterAuthHandlers(mux, csrfMw)
	mux.Handle("/webhooks/workos", wosClient.WebhookHandler(
		workos.OnDirectoryUserCreated(handleUserProvisioned),
		workos.OnDirectoryUserDeleted(handleUserDeprovisioned),
	))
	mux.Handle("/", app)

	// Route all non-/_vango traffic through this mux.
	app.Server().SetHandler(mux)

	// 6. Start server
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger.Info("starting server", "addr", ":8080")
	if err := app.Run(ctx, ":8080"); err != nil {
		logger.Error("server error", "error", err)
		os.Exit(1)
	}
}
```

### 37.9.4 Using Auth in Components

Identity is accessed via `auth.Get[*workos.Identity](ctx)` (or `workos.CurrentIdentity(ctx)`), which reads from Vango’s runtime auth projection (no I/O, safe anywhere).

```go
type DashboardProps struct{}

func Dashboard(p DashboardProps) vango.Component {
	return vango.Setup(p, func(s vango.SetupCtx[DashboardProps]) vango.RenderFn {
		return func() *vango.VNode {
			ctx := vango.UseCtx()
			user, ok := workos.CurrentIdentity(ctx)
			if !ok || user == nil {
				return Div(Text("Please sign in"))
			}
			csrf := server.CSRFCtxToken(ctx)
			return Div(
				H1(Textf("Welcome, %s", user.Email)),
				P(Textf("Organization: %s", user.OrgID)),
				Form(
					Method("POST"), Action("/auth/logout"),
					If(csrf != "", Input(Type("hidden"), Name("csrf"), Value(csrf))),
					Button(Type("submit"), Text("Sign Out")),
				),
			)
		}
	})
}
```

### 37.9.5 Authorization Guards in Actions

For operations that require specific permissions inside Action work functions, read identity from the work context and enforce permissions there:

```go
deleteProject := setup.Action(&s,
	func(ctx context.Context, projectID string) (struct{}, error) {
		identity, _ := workos.IdentityFromContext(ctx)
		if identity == nil {
			return struct{}{}, auth.ErrUnauthorized
		}
		if !identity.HasPermission("projects:delete") {
			return struct{}{}, auth.ErrForbidden
		}
		return struct{}{}, projectService.Delete(ctx, projectID)
	},
	vango.DropWhileRunning(),
)
```

---

## §37.10 Enterprise Features (SSO, Directory Sync, Audit Logs)

### 37.10.1 Enabling SSO for Organizations

SSO configuration is self-service via the WorkOS Admin Portal. Generate a portal link from an Action:

```go
adminLink := setup.Action(&s,
	func(ctx context.Context, _ struct{}) (string, error) {
		identity, _ := workos.IdentityFromContext(ctx)
		if identity == nil {
			return "", auth.ErrUnauthorized
		}
		return wosClient.GenerateAdminPortalLink(ctx,
			identity.OrgID,
			workos.AdminPortalSSO,
			cfg.BaseURL+"/settings",
		)
	},
	vango.DropWhileRunning(),
)
```

The returned URL is valid for 5 minutes and opens the Admin Portal where IT admins can configure their identity provider (Okta, Azure AD, Google, etc.) without developer involvement.

### 37.10.2 Directory Sync (SCIM) via Webhooks

Directory Sync keeps your app's user list synchronized with an organization's employee directory. Configure webhook handlers to react to provisioning events:

```go
func handleUserProvisioned(ctx context.Context, e workos.WebhookEvent) {
	var user workos.DirectoryUser
	if err := json.Unmarshal(e.Data, &user); err != nil {
		slog.Error("failed to parse directory user", "error", err)
		return
	}
	// Create or update user in your database
	err := userService.UpsertFromDirectory(ctx, user)
	if err != nil {
		slog.Error("failed to provision user", "error", err, "user_id", user.ID)
	}
}

func handleUserDeprovisioned(ctx context.Context, e workos.WebhookEvent) {
	var user workos.DirectoryUser
	if err := json.Unmarshal(e.Data, &user); err != nil {
		return
	}
	// Deactivate user in your database
	_ = userService.Deactivate(ctx, user.ID)
}
```

**Idempotency:** WorkOS may deliver the same event more than once. Log processed event IDs and skip duplicates.

**Ordering:** WorkOS does not guarantee event ordering. Handle out-of-order delivery gracefully (e.g., a "deleted" event may arrive before "created" if processing is delayed).

### 37.10.3 Emitting Audit Log Events

Emit audit events from Action work functions. Events are scoped to an organization and follow schemas configured in the WorkOS Dashboard.

```go
deleteProject := setup.Action(&s,
	func(ctx context.Context, projectID string) (struct{}, error) {
		identity, _ := workos.IdentityFromContext(ctx)
		if identity == nil {
			return struct{}{}, auth.ErrUnauthorized
		}

		// Perform the deletion
		if err := projectService.Delete(ctx, projectID); err != nil {
			return struct{}{}, err
		}

		// Emit audit event (idempotent, non-blocking on failure)
		_ = deps.Auth.EmitAuditEvent(ctx, workos.AuditEvent{
			OrganizationID: identity.OrgID,
			Action:         "project.deleted",
			Actor: workos.AuditActor{
				ID:   identity.UserID,
				Name: identity.Email,
				Type: "user",
			},
			Targets: []workos.AuditTarget{{
				ID:   projectID,
				Type: "project",
			}},
		})

		return struct{}{}, nil
	},
	vango.DropWhileRunning(),
)
```

**Design guidance:** audit log emission is intentionally fire-and-forget (errors are logged but don't fail the user action). If you need guaranteed delivery, implement a queue/retry pattern in your service layer.

---

## §37.11 Testing Auth

### 37.11.1 Unit Testing with `workos.TestAuth`

```go
func TestService_UsesWorkOSUserLookup(t *testing.T) {
	mock := &workos.TestAuth{
		GetUserFunc: func(ctx context.Context, id string) (*workos.User, error) {
			return &workos.User{ID: id, Email: "alice@example.com", FirstName: "Alice"}, nil
		},
	}

	svc := NewMyService(mock) // depends on workos.Users

	u, err := svc.LoadUser(context.Background(), "user_123")
	if err != nil {
		t.Fatalf("LoadUser error: %v", err)
	}
	if u.Email != "alice@example.com" {
		t.Fatalf("Email=%q, want %q", u.Email, "alice@example.com")
	}
}
```

### 37.11.2 Testing Authorization Guards

Action/Resource *work functions* run off-loop and receive a `context.Context`.
At runtime, the WorkOS middleware attaches Identity to that context, so guards
should use `workos.IdentityFromContext(ctx)` (not `auth.Get`, which requires `vango.Ctx`).

```go
func TestDeleteProjectWork_RequiresPermission(t *testing.T) {
	ctx := workos.WithIdentity(context.Background(), workos.TestIdentity(
		workos.WithPermissions("projects:read"),
	))

	err := DeleteProjectWork(ctx, "proj_1") // your action work logic
	if !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("err=%v, want forbidden", err)
	}
}
```

### 37.11.3 Testing Webhook Handlers

```go
func TestWebhook_DirectoryUserCreated(t *testing.T) {
	var provisioned bool
	sub := workos.OnDirectoryUserCreated(func(ctx context.Context, e workos.WebhookEvent) {
		provisioned = true
	})

	event := workos.WebhookEvent{
		ID:    "evt_test_001",
		Event: "dsync.user.created",
		Data:  json.RawMessage(`{"id":"du_001","email":"bob@corp.com"}`),
	}
	sub.Handler(context.Background(), event)

	if !provisioned {
		t.Error("expected user to be provisioned")
	}
}
```

---

# Part 3: Appendix H — WorkOS Enterprise Readiness

---

## H.1 Why WorkOS Is the Recommended Default

WorkOS provides the complete enterprise feature set that B2B SaaS applications need, through a single API platform:

- **AuthKit** handles authentication (password, social, magic link, MFA, passkeys) with a hosted UI that matches Vango's SSR-first model.
- **SSO** (SAML/OIDC) across 26+ identity providers through a single integration, with a self-serve Admin Portal that reduces support burden.
- **Directory Sync** (SCIM) for automated user provisioning/deprovisioning from corporate directories.
- **Audit Logs** for compliance (SOC 2, HIPAA), with SIEM streaming and CSV exports.
- **Fine-Grained Authorization** for resource-level permissions beyond basic RBAC.

Each of these is consumed server-side, aligning with Vango's session loop model where I/O occurs in Resource/Action work functions and the server is the source of truth.

---

## H.2 The Enterprise Readiness Workflow

### H.2.1 Progressive Adoption

WorkOS features are independently adoptable. A typical progression:

**Week 1: Authentication**
- AuthKit for sign-in/sign-up
- `vango-workos` middleware and session bridge
- Basic role-based access control via organization memberships

**Month 1: Enterprise SSO**
- Enable SSO for enterprise customers
- Admin Portal for self-service SSO configuration
- No code changes required (SSO is transparent to your auth flow)

**Month 2: Directory Sync**
- Configure webhook handlers for provisioning events
- Automated user lifecycle management
- Group-to-role mapping

**Quarter 2: Audit Logs and optional FGA**
- Emit audit events from Action work functions
- Fine-grained authorization for resource-level permissions
- SIEM integration for enterprise compliance

### H.2.2 Authentication Flow Diagram

```
┌─────────────┐     ┌──────────────┐     ┌────────────────┐
│   Browser    │────▶│ /auth/signin │────▶│ WorkOS AuthKit │
│   (Tab)      │     │ (redirect)   │     │ (Hosted UI)    │
└─────────────┘     └──────────────┘     └───────┬────────┘
                                                  │ user authenticates
                                                  ▼
┌─────────────┐     ┌──────────────┐     ┌────────────────┐
│   Browser    │◀────│/auth/callback│◀────│ WorkOS (code)  │
│ (session     │     │(code→tokens) │     └────────────────┘
│  cookie set) │     │(cookie set)  │
└──────┬──────┘     └──────────────┘
       │
       │ SSR request with session cookie
       ▼
┌──────────────────────────────────────────────────────────┐
│  Vango HTTP Middleware                                    │
│  → reads cookie → verifies JWT (JWKS) → attaches Identity │
│  → refreshes token if expired (rotation-safe)            │
└──────────────────────┬───────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────┐
│  Vango Session Bridge                                     │
│  OnSessionStart: auth.Set + auth.SetPrincipal             │
│  OnSessionResume: ValidateSession + rehydrate projections  │
└──────────────────────┬───────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────┐
│  Interactive Session (WebSocket)                          │
│  auth.Get[*workos.Identity](ctx) → in-memory identity     │
│  workos.RequirePermission(ctx, "…") → checks local perms  │
│  Periodic: AuthCheck → ValidateSession against WorkOS     │
└──────────────────────────────────────────────────────────┘
```

---

## H.3 Multi-Tab Logout Coordination

When one tab logs out, other tabs must follow. The `vango-workos` package integrates with Vango's multi-tab coordination (§42.4):

1. Logout handler (`POST /auth/logout`) clears the session cookie and (best-effort) revokes the WorkOS session.
2. Logout handler redirects through the WorkOS logout URL, which redirects back to the configured sign-out redirect (`/auth/signed-out` by default).
3. Signed-out page (`GET /auth/signed-out`) loads a same-origin script (`/auth/signed-out.js`) that broadcasts a logout signal to other tabs (BroadcastChannel with localStorage fallback) and clears Vango resume storage keys, then navigates.
4. Other tabs reload into the HTTP pipeline (where the missing/invalid cookie redirects to sign-in).

For explicit cross-tab logout via the WorkOS session revocation API:

```go
// In your logout Action (or use the built-in LogoutHandler):
func handleLogout(ctx context.Context, _ struct{}) (struct{}, error) {
	identity, _ := workos.IdentityFromContext(ctx)
	if identity != nil {
		_ = auth.RevokeSession(ctx, identity.SessionID)
	}
	return struct{}{}, nil
}
```

---

## H.4 CLI Integration

### H.4.1 `vango create --with workos` (Phase 2)

Scaffolds a complete authentication setup:

1. Generates `app/routes/auth/` with signin, signup, callback, logout, signed-out (`/auth/signed-out`), and signed-out script (`/auth/signed-out.js`) handlers.
2. Generates `app/middleware/auth.go` (net/http) with WorkOS middleware wiring.
3. Updates `app/routes/deps.go` with `Auth workos.Auth`.
4. Updates `cmd/server/main.go` with WorkOS client initialization, session bridge, installs `workosClient.Middleware()` via `app.Server().Use(...)`, and (when needed) mounts auth routes + webhook route on a `http.ServeMux` installed via `app.Server().SetHandler(mux)`.
5. Creates `.env` with placeholder values.
6. Prints setup instructions for WorkOS Dashboard configuration.

**Non-interactive mode** (AI agents): accepts `--workos-api-key`, `--workos-client-id`, `--workos-redirect-uri` flags.

### H.4.2 `vango dev` AuthKit Helpers (Phase 3)

When `vango.json` has `"workos": { "enabled": true }`:
- Auto-checks that `WORKOS_REDIRECT_URI` matches a configured redirect in WorkOS.
- Warns if `CookieSecure` is true but `BaseURL` is HTTP (common local dev mistake).
- Provides test user creation via `vango workos create-test-user`.

---

## H.5 Operational Guardrails

### H.5.1 Rate Limiting

WorkOS API rate limits vary by endpoint. The `vango-workos` package does not implement client-side rate limiting, but:

- Resource loaders with keyed caching naturally reduce API calls (same key = cached result).
- `EmitAuditEvent` supports idempotency keys to avoid duplicate events on retries.
- For high-volume operations, use the Events API (polling) instead of webhooks when appropriate.

### H.5.2 JWT Validation Strategy

The package defaults to **local JWT validation** for performance (no network call per request):

1. Fetch JWKS from WorkOS on first use.
2. Cache for `JWKSCacheDuration` (default: 1 hour).
3. Validate the `exp`, `iss`, and `aud` claims locally (issuer/audience configurable via `JWTIssuer`/`JWTAudience` for custom auth domains).
4. Periodically revalidate the session with WorkOS (via `AuthCheck`) for revocation detection.

This balances speed (sub-millisecond validation per request) with security (revoked sessions detected within `RevalidationInterval`).

### H.5.3 Cookie Security

Production defaults enforced by the package:

| Attribute | Default | Rationale |
|---|---|---|
| `Secure` | `true` | HTTPS required in production |
| `HttpOnly` | `true` | Prevents XSS cookie theft |
| `SameSite` | `Lax` | CSRF protection with usability |
| `Path` | `/` | Available to all routes |
| `MaxAge` | 7 days | Matches WorkOS default session length |
| `Encryption` | AES-256-GCM | Cookie payload encrypted with `CookieSecret` |

**Session tokens stored in cookies:** The encrypted cookie contains the access token and refresh token. These are sensitive and must never be logged, included in error messages, or transmitted in URLs.

### H.5.4 Refresh Rotation + Multi-Instance Deployments (MUST)

WorkOS refresh tokens are single-use and rotate on refresh. If two concurrent requests attempt to refresh the same token, one will succeed and the other will fail.

`vango-workos` prevents this race **within a single process** via single-flight refresh coordination (§1.5.4). In multi-instance deployments, you MUST ensure requests from the same browser session are routed to the same instance during refresh windows.

**MUST (recommended default): enable sticky sessions / LB affinity**
- Configure your load balancer to route requests consistently by the WorkOS session cookie (`__vango_workos_session` by default) or by a stable affinity cookie you control.
- This applies to SSR requests, the WebSocket upgrade/resume endpoints, and `/auth/*` routes.

**If you cannot enable stickiness:**
- Disable refresh-in-middleware and treat expired access tokens as unauthenticated (force re-auth), OR
- Implement a distributed single-flight mechanism that shares the *refresh result* across instances (not just a lock).

Without one of these postures, intermittent logout loops can occur under real-world concurrency (multi-tab + multi-instance).

---

## H.6 Troubleshooting

### H.6.1 Symptom Table

| Scenario | Symptom | Root Cause | Resolution |
|---|---|---|---|
| **Callback 400** | "Missing authorization code" | Redirect URI mismatch | Verify `WORKOS_REDIRECT_URI` matches WorkOS Dashboard → Redirects exactly |
| **Cookie not set** | User redirected to sign-in repeatedly | `CookieSecure=true` on HTTP | Set `CookieSecure=false` for local dev, or use HTTPS |
| **Session expired** | Forced reload after idle period | Access token expired, refresh failed | Check `CookieMaxAge` and WorkOS Dashboard → Sessions → Maximum session length |
| **403 on resume** | "session revalidation failed" | WorkOS session revoked (logout from another device) | Expected. User re-authenticates normally. |
| **JWKS fetch failure** | JWT validation errors at startup | Network issue, incorrect `ClientID`, or custom issuer mismatch | Verify `WORKOS_CLIENT_ID`. If using a custom auth domain, set `WORKOS_JWT_ISSUER` / `WORKOS_JWT_AUDIENCE`. Check network connectivity to `api.workos.com`. |
| **Webhook 401** | "Invalid signature" | Wrong webhook secret | Use the secret from the specific webhook endpoint detail page, not the API key |
| **Webhook duplicate** | Event processed twice | At-least-once delivery | Implement idempotent event processing (check event ID before processing) |
| **SSO not working** | Users see "no connection" error | SSO not configured for the organization | Direct IT admin to Admin Portal to configure their identity provider |
| **Directory Sync lag** | Users not provisioned/deprovisioned | Webhook endpoint unreachable | Check webhook delivery status in WorkOS Dashboard. Verify endpoint is accessible. |
| **Audit event rejected** | 422 error from EmitAuditEvent | Event schema not configured | Configure allowed event schemas in WorkOS Dashboard → Audit Logs → Events |
| **API key error** | 401 on all API calls | Wrong key or environment mismatch | Use staging key (`sk_test_`) for staging, production key (`sk_live_`) for production |

### H.6.2 Diagnostic Checklist

**Authentication:**
- [ ] `WORKOS_API_KEY` set and starts with `sk_`?
- [ ] `WORKOS_CLIENT_ID` set and starts with `client_`?
- [ ] `WORKOS_REDIRECT_URI` matches WorkOS Dashboard → Redirects?
- [ ] `WORKOS_COOKIE_SECRET` at least 32 characters?
- [ ] Sign-out redirect configured in WorkOS Dashboard?
- [ ] AuthKit enabled and set up in WorkOS Dashboard?

**Session Bridge:**
- [ ] `OnSessionStart` and `OnSessionResume` wired in `vango.Config`?
- [ ] `AuthCheck` configured with `RevalidationConfig()`?
- [ ] WorkOS middleware installed as **server** middleware (`app.Server().Use(...)`) so it runs on SSR and WebSocket upgrade/resume requests?

**Enterprise Features:**
- [ ] Webhook endpoint accessible from the internet (use ngrok for local dev)?
- [ ] Webhook secret matches the specific endpoint (not the API key)?
- [ ] Audit log event schemas created in WorkOS Dashboard?
- [ ] Organizations created for enterprise customers?

**Security:**
- [ ] Cookie `Secure=true` in production?
- [ ] HTTPS configured for all production traffic?
- [ ] WebSocket origin checks include production domain?
- [ ] Webhook handler validates signatures before processing?

---

## H.7 `vango.json` WorkOS Configuration

```json
{
  "workos": {
    "enabled": true,
    "auth_routes": "/auth",
    "webhook_path": "/webhooks/workos",
    "public_paths": ["/", "/about", "/auth/*", "/webhooks/*"]
  }
}
```

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Enables WorkOS-aware CLI features |
| `auth_routes` | string | `"/auth"` | Base path for auth handlers |
| `webhook_path` | string | `"/webhooks/workos"` | Path for the webhook endpoint |
| `public_paths` | []string | `[]` | **Scaffolding hint only.** Paths excluded from *generated route-level auth middleware*; `vango-workos` server middleware never enforces access by path. |

---

## H.8 Phased Rollout

| Phase | Deliverable | Enables |
|---|---|---|
| **1** (Now) | `vango-workos` package + Guide §42.5, §37.9–§37.11 + Appendix H | Correct, idiomatic WorkOS auth with AuthKit. Enterprise SSO, SCIM, Audit Logs as incremental additions. Deterministic testing via `TestAuth`. |
| **2** | `vango create --with workos` scaffolding | New projects get complete auth wiring out of the box. |
| **3** | `vango dev` AuthKit helpers + `vango workos` subcommands | Test user management, redirect URI validation, organization setup from CLI. |
| **4** | WorkOS Admin Portal component | Pre-built Vango Setup component for embedding Admin Portal links in settings pages. |

Phase 1 is implementation-ready. All type signatures are consistent with the WorkOS Go SDK v6 and the Vango Developer Guide (v1).

---

## H.9 Security Summary

### Connection Credentials
- Never commit `WORKOS_API_KEY`, `WORKOS_COOKIE_SECRET`, or `WORKOS_WEBHOOK_SECRET` to version control.
- `vango-workos` never exposes secrets after initialization. Error messages include only non-sensitive metadata.
- The `Client.Config()` method returns a copy with all secrets redacted.

### Session Cookies
- Encrypted with AES-256-GCM using `CookieSecret`.
- Contains access token and refresh token (sensitive material).
- `HttpOnly` prevents JavaScript access. `Secure` requires HTTPS. `SameSite=Lax` prevents CSRF.

### Webhook Verification
- All webhook payloads are verified using the endpoint-specific signing secret before processing.
- Invalid signatures return HTTP 401 immediately.
- Webhook handlers should be idempotent (WorkOS may deliver events more than once).

### Token Lifecycle
- Access tokens are short-lived; derive expiry from the JWT `exp` claim (do not hard-code durations).
- Refresh tokens are long-lived and may rotate; refresh logic must be rotation-safe under concurrency.
- The middleware refreshes expired access tokens using the refresh token (when present).
- Periodic revalidation (`AuthCheck`) detects revoked sessions within the configured interval.

### Admin Portal Links
- Portal links are time-limited (5 minutes).
- Authorization must be verified before generating links (the package does not enforce this automatically — your Action must check permissions).
- Links are organization-scoped and intent-scoped (SSO, SCIM, Audit Logs, etc.).
