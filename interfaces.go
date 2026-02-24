package workos

import "context"

// Sessions is the minimum interface needed for Vango session lifecycle integration.
type Sessions interface {
	VerifyAccessToken(ctx context.Context, accessToken string) (*AccessTokenClaims, error)
	RefreshTokens(ctx context.Context, refreshToken string) (*TokenSet, error)
	ValidateSession(ctx context.Context, userID, sessionID string) (*SessionInfo, error)
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

// Auth is the full convenience interface.
type Auth interface {
	Sessions
	Users
	Orgs
	RBAC
	AuditLogs
	SSORead
	DirectorySyncRead
}
