package workos

import (
	"context"
	"encoding/json"
	"time"
)

// User represents an authenticated user from WorkOS User Management.
type User struct {
	ID            string            `json:"id"`
	Email         string            `json:"email"`
	EmailVerified bool              `json:"email_verified"`
	FirstName     string            `json:"first_name"`
	LastName      string            `json:"last_name"`
	ProfilePicURL string            `json:"profile_picture_url"`
	Metadata      map[string]string `json:"metadata"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
}

// Identity is the authenticated identity projection used inside Vango.
type Identity struct {
	UserID       string    `json:"user_id"`
	Email        string    `json:"email"`
	Name         string    `json:"name,omitempty"`
	OrgID        string    `json:"org_id,omitempty"`
	Roles        []string  `json:"roles,omitempty"`
	Permissions  []string  `json:"permissions,omitempty"`
	Entitlements []string  `json:"entitlements,omitempty"`
	SessionID    string    `json:"session_id,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
	AuthMethod   string    `json:"auth_method,omitempty"`
}

// AccessTokenClaims are normalized JWT claims extracted from a WorkOS access token.
type AccessTokenClaims struct {
	UserID       string    `json:"user_id"`
	SessionID    string    `json:"session_id"`
	Email        string    `json:"email,omitempty"`
	Name         string    `json:"name,omitempty"`
	OrgID        string    `json:"org_id,omitempty"`
	Roles        []string  `json:"roles,omitempty"`
	Permissions  []string  `json:"permissions,omitempty"`
	Entitlements []string  `json:"entitlements,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
	Issuer       string    `json:"issuer,omitempty"`
	Audience     string    `json:"audience,omitempty"`
}

// TokenSet is sensitive token material and must only live in encrypted cookie payloads.
type TokenSet struct {
	AccessToken  string    `json:"-"`
	RefreshToken string    `json:"-"`
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

type Organization struct {
	ID                   string      `json:"id"`
	Name                 string      `json:"name"`
	AllowProfilesOutside bool        `json:"allow_profiles_outside_organization"`
	Domains              []OrgDomain `json:"domains"`
	CreatedAt            time.Time   `json:"created_at"`
	UpdatedAt            time.Time   `json:"updated_at"`
}

type OrgDomain struct {
	ID     string `json:"id"`
	Domain string `json:"domain"`
	State  string `json:"state"`
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

type Connection struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	ConnectionType string `json:"connection_type"`
	State          string `json:"state"`
	OrgID          string `json:"organization_id"`
}

type Directory struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Domain string `json:"domain"`
	Type   string `json:"type"`
	State  string `json:"state"`
	OrgID  string `json:"organization_id"`
}

type DirectoryUser struct {
	ID        string           `json:"id"`
	Email     string           `json:"email"`
	FirstName string           `json:"first_name"`
	LastName  string           `json:"last_name"`
	State     string           `json:"state"`
	Groups    []DirectoryGroup `json:"groups"`
	RawAttrs  map[string]any   `json:"raw_attributes"`
}

type DirectoryGroup struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type PermissionCheck struct {
	Subject  string `json:"subject"`
	Relation string `json:"relation"`
	Resource string `json:"resource"`
}

type AuditEvent struct {
	OrganizationID string        `json:"organization_id"`
	Action         string        `json:"action"`
	OccurredAt     time.Time     `json:"occurred_at"`
	Actor          AuditActor    `json:"actor"`
	Targets        []AuditTarget `json:"targets"`
	Context        AuditContext  `json:"context,omitempty"`
	IdempotencyKey string        `json:"idempotency_key,omitempty"`
}

type AuditActor struct {
	ID       string         `json:"id"`
	Name     string         `json:"name,omitempty"`
	Type     string         `json:"type"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

type AuditTarget struct {
	ID       string         `json:"id"`
	Name     string         `json:"name,omitempty"`
	Type     string         `json:"type"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

type AuditContext struct {
	Location  string `json:"location,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
}

type ListMeta struct {
	Before string `json:"before"`
	After  string `json:"after"`
}

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
	Type        string   `json:"type"`
	Permissions []string `json:"permissions"`
}

type ListUsersOpts struct {
	Email          string
	OrganizationID string
	Limit          int
	Before         string
	After          string
	Order          string
}

type UpdateUserOpts struct {
	FirstName     *string
	LastName      *string
	EmailVerified *bool
	Metadata      map[string]*string
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
	// OrganizationID scopes role listing to an organization.
	// Empty means best-effort environment role aggregation across orgs.
	OrganizationID string
	// Limit is applied client-side after roles are fetched.
	Limit int
	// Before/After/Order are currently ignored for role listing due WorkOS SDK
	// constraints on ListOrganizationRolesOpts.
	Before string
	After  string
	Order  string
}

// WebhookEvent is a normalized webhook event from WorkOS.
type WebhookEvent struct {
	ID        string          `json:"id"`
	Event     string          `json:"event"`
	Data      json.RawMessage `json:"data"`
	CreatedAt time.Time       `json:"created_at"`
}

type WebhookSubscription struct {
	Event   string
	Handler func(context.Context, WebhookEvent)
}

// AdminPortalIntent specifies what the Admin Portal shows.
type AdminPortalIntent string

const (
	AdminPortalSSO                AdminPortalIntent = "sso"
	AdminPortalDSync              AdminPortalIntent = "dsync"
	AdminPortalAuditLogs          AdminPortalIntent = "audit_logs"
	AdminPortalLogStreams         AdminPortalIntent = "log_streams"
	AdminPortalCertRenewal        AdminPortalIntent = "certificate_renewal"
	AdminPortalDomainVerification AdminPortalIntent = "domain_verification"
)
