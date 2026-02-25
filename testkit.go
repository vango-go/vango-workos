package workos

import (
	"context"
	"errors"
	"time"

	"github.com/vango-go/vango/pkg/auth"
)

// ErrNotMocked is returned when a TestAuth method is called without a function override.
var ErrNotMocked = errors.New("workos.TestAuth: method not mocked")

// TestAuth is a mock implementation of Auth for unit tests.
type TestAuth struct {
	VerifyAccessTokenFunc            func(ctx context.Context, accessToken string) (*AccessTokenClaims, error)
	RefreshTokensFunc                func(ctx context.Context, refreshToken string) (*TokenSet, error)
	ValidateSessionFunc              func(ctx context.Context, userID, sessionID string) (*SessionInfo, error)
	RevokeSessionFunc                func(ctx context.Context, sessionID string) error
	GetUserFunc                      func(ctx context.Context, userID string) (*User, error)
	ListUsersFunc                    func(ctx context.Context, opts ListUsersOpts) (*UserList, error)
	UpdateUserFunc                   func(ctx context.Context, userID string, opts UpdateUserOpts) (*User, error)
	DeleteUserFunc                   func(ctx context.Context, userID string) error
	GetOrganizationFunc              func(ctx context.Context, orgID string) (*Organization, error)
	ListOrganizationsFunc            func(ctx context.Context, opts ListOrganizationsOpts) (*OrganizationList, error)
	ListOrganizationMembershipsFunc  func(ctx context.Context, opts ListMembershipsOpts) (*MembershipList, error)
	GetOrganizationMembershipFunc    func(ctx context.Context, membershipID string) (*Membership, error)
	HasRoleFunc                      func(ctx context.Context, userID, orgID, roleSlug string) (bool, error)
	ListRolesFunc                    func(ctx context.Context, opts ListRolesOpts) (*RoleList, error)
	EmitAuditEventFunc               func(ctx context.Context, event AuditEvent) error
	ListConnectionsFunc              func(ctx context.Context, opts ListConnectionsOpts) (*ConnectionList, error)
	ListDirectoriesFunc              func(ctx context.Context, opts ListDirectoriesOpts) (*DirectoryList, error)
	ListDirectoryUsersFunc           func(ctx context.Context, opts ListDirectoryUsersOpts) (*DirectoryUserList, error)
	ListDirectoryGroupsFunc          func(ctx context.Context, opts ListDirectoryGroupsOpts) (*DirectoryGroupList, error)
}

var _ Auth = (*TestAuth)(nil)

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

func (t *TestAuth) ValidateSession(ctx context.Context, userID, sessionID string) (*SessionInfo, error) {
	if t.ValidateSessionFunc != nil {
		return t.ValidateSessionFunc(ctx, userID, sessionID)
	}
	return &SessionInfo{
		SessionID: sessionID,
		UserID:    userID,
		Active:    true,
		ExpiresAt: time.Now().Add(time.Hour),
	}, nil
}

func (t *TestAuth) RevokeSession(ctx context.Context, sessionID string) error {
	if t.RevokeSessionFunc != nil {
		return t.RevokeSessionFunc(ctx, sessionID)
	}
	return ErrNotMocked
}

func (t *TestAuth) GetUser(ctx context.Context, userID string) (*User, error) {
	if t.GetUserFunc != nil {
		return t.GetUserFunc(ctx, userID)
	}
	return nil, ErrNotMocked
}

func (t *TestAuth) ListUsers(ctx context.Context, opts ListUsersOpts) (*UserList, error) {
	if t.ListUsersFunc != nil {
		return t.ListUsersFunc(ctx, opts)
	}
	return nil, ErrNotMocked
}

func (t *TestAuth) UpdateUser(ctx context.Context, userID string, opts UpdateUserOpts) (*User, error) {
	if t.UpdateUserFunc != nil {
		return t.UpdateUserFunc(ctx, userID, opts)
	}
	return nil, ErrNotMocked
}

func (t *TestAuth) DeleteUser(ctx context.Context, userID string) error {
	if t.DeleteUserFunc != nil {
		return t.DeleteUserFunc(ctx, userID)
	}
	return ErrNotMocked
}

func (t *TestAuth) GetOrganization(ctx context.Context, orgID string) (*Organization, error) {
	if t.GetOrganizationFunc != nil {
		return t.GetOrganizationFunc(ctx, orgID)
	}
	return nil, ErrNotMocked
}

func (t *TestAuth) ListOrganizations(ctx context.Context, opts ListOrganizationsOpts) (*OrganizationList, error) {
	if t.ListOrganizationsFunc != nil {
		return t.ListOrganizationsFunc(ctx, opts)
	}
	return nil, ErrNotMocked
}

func (t *TestAuth) ListOrganizationMemberships(ctx context.Context, opts ListMembershipsOpts) (*MembershipList, error) {
	if t.ListOrganizationMembershipsFunc != nil {
		return t.ListOrganizationMembershipsFunc(ctx, opts)
	}
	return nil, ErrNotMocked
}

func (t *TestAuth) GetOrganizationMembership(ctx context.Context, membershipID string) (*Membership, error) {
	if t.GetOrganizationMembershipFunc != nil {
		return t.GetOrganizationMembershipFunc(ctx, membershipID)
	}
	return nil, ErrNotMocked
}

func (t *TestAuth) HasRole(ctx context.Context, userID, orgID, roleSlug string) (bool, error) {
	if t.HasRoleFunc != nil {
		return t.HasRoleFunc(ctx, userID, orgID, roleSlug)
	}
	return false, ErrNotMocked
}

func (t *TestAuth) ListRoles(ctx context.Context, opts ListRolesOpts) (*RoleList, error) {
	if t.ListRolesFunc != nil {
		return t.ListRolesFunc(ctx, opts)
	}
	return nil, ErrNotMocked
}

func (t *TestAuth) EmitAuditEvent(ctx context.Context, event AuditEvent) error {
	if t.EmitAuditEventFunc != nil {
		return t.EmitAuditEventFunc(ctx, event)
	}
	return nil
}

func (t *TestAuth) ListConnections(ctx context.Context, opts ListConnectionsOpts) (*ConnectionList, error) {
	if t.ListConnectionsFunc != nil {
		return t.ListConnectionsFunc(ctx, opts)
	}
	return nil, ErrNotMocked
}

func (t *TestAuth) ListDirectories(ctx context.Context, opts ListDirectoriesOpts) (*DirectoryList, error) {
	if t.ListDirectoriesFunc != nil {
		return t.ListDirectoriesFunc(ctx, opts)
	}
	return nil, ErrNotMocked
}

func (t *TestAuth) ListDirectoryUsers(ctx context.Context, opts ListDirectoryUsersOpts) (*DirectoryUserList, error) {
	if t.ListDirectoryUsersFunc != nil {
		return t.ListDirectoryUsersFunc(ctx, opts)
	}
	return nil, ErrNotMocked
}

func (t *TestAuth) ListDirectoryGroups(ctx context.Context, opts ListDirectoryGroupsOpts) (*DirectoryGroupList, error) {
	if t.ListDirectoryGroupsFunc != nil {
		return t.ListDirectoryGroupsFunc(ctx, opts)
	}
	return nil, ErrNotMocked
}

// TestIdentity creates an Identity with sensible test defaults.
func TestIdentity(overrides ...func(*Identity)) *Identity {
	identity := &Identity{
		UserID:    "user_test_001",
		Email:     "test@example.com",
		Name:      "Test User",
		OrgID:     "org_test_001",
		Roles:     []string{"member"},
		SessionID: "session_test_001",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	for _, override := range overrides {
		override(identity)
	}
	return identity
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

// HydrateSessionForTest sets the same runtime auth projection used by SessionBridge hooks.
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
		ExpiresAtUnixMs: 0,
	})
}
