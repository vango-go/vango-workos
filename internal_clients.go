package workos

import (
	"context"
	"net/url"

	"github.com/workos/workos-go/v6/pkg/auditlogs"
	"github.com/workos/workos-go/v6/pkg/directorysync"
	"github.com/workos/workos-go/v6/pkg/organizations"
	"github.com/workos/workos-go/v6/pkg/portal"
	"github.com/workos/workos-go/v6/pkg/sso"
	"github.com/workos/workos-go/v6/pkg/usermanagement"
	"github.com/workos/workos-go/v6/pkg/webhooks"
)

// Private seams for deterministic tests.
type umClient interface {
	privateUMClient()
	GetAuthorizationURL(opts usermanagement.GetAuthorizationURLOpts) (*url.URL, error)
	AuthenticateWithCode(ctx context.Context, opts usermanagement.AuthenticateWithCodeOpts) (usermanagement.AuthenticateResponse, error)
	GetLogoutURL(opts usermanagement.GetLogoutURLOpts) (*url.URL, error)
	AuthenticateWithRefreshToken(ctx context.Context, opts usermanagement.AuthenticateWithRefreshTokenOpts) (usermanagement.RefreshAuthenticationResponse, error)
	ListSessions(ctx context.Context, userID string, opts usermanagement.ListSessionsOpts) (usermanagement.ListSessionsResponse, error)
	RevokeSession(ctx context.Context, opts usermanagement.RevokeSessionOpts) error
	GetUser(ctx context.Context, opts usermanagement.GetUserOpts) (usermanagement.User, error)
	ListUsers(ctx context.Context, opts usermanagement.ListUsersOpts) (usermanagement.ListUsersResponse, error)
	UpdateUser(ctx context.Context, opts usermanagement.UpdateUserOpts) (usermanagement.User, error)
	DeleteUser(ctx context.Context, opts usermanagement.DeleteUserOpts) error
	ListOrganizationMemberships(ctx context.Context, opts usermanagement.ListOrganizationMembershipsOpts) (usermanagement.ListOrganizationMembershipsResponse, error)
	GetOrganizationMembership(ctx context.Context, opts usermanagement.GetOrganizationMembershipOpts) (usermanagement.OrganizationMembership, error)
}
type ssoClient interface {
	privateSSOClient()
	ListConnections(ctx context.Context, opts sso.ListConnectionsOpts) (sso.ListConnectionsResponse, error)
}
type directorySyncClient interface {
	privateDirectorySyncClient()
	ListDirectories(ctx context.Context, opts directorysync.ListDirectoriesOpts) (directorysync.ListDirectoriesResponse, error)
	ListUsers(ctx context.Context, opts directorysync.ListUsersOpts) (directorysync.ListUsersResponse, error)
	ListGroups(ctx context.Context, opts directorysync.ListGroupsOpts) (directorysync.ListGroupsResponse, error)
}
type auditLogsClient interface {
	privateAuditLogsClient()
	CreateEvent(ctx context.Context, e auditlogs.CreateEventOpts) error
}
type orgsClient interface {
	privateOrgsClient()
	GetOrganization(ctx context.Context, opts organizations.GetOrganizationOpts) (organizations.Organization, error)
	ListOrganizations(ctx context.Context, opts organizations.ListOrganizationsOpts) (organizations.ListOrganizationsResponse, error)
	ListOrganizationRoles(ctx context.Context, opts organizations.ListOrganizationRolesOpts) (organizations.ListOrganizationRolesResponse, error)
}
type portalClient interface {
	privatePortalClient()
	GenerateLink(ctx context.Context, opts portal.GenerateLinkOpts) (string, error)
}
type webhookVerifier interface {
	privateWebhookVerifier()
	VerifyWebhook(body []byte, signature, secret string) error
}

type realUMClient struct{ client *usermanagement.Client }

func (*realUMClient) privateUMClient() {}

func (c *realUMClient) GetAuthorizationURL(opts usermanagement.GetAuthorizationURLOpts) (*url.URL, error) {
	return c.client.GetAuthorizationURL(opts)
}

func (c *realUMClient) AuthenticateWithCode(ctx context.Context, opts usermanagement.AuthenticateWithCodeOpts) (usermanagement.AuthenticateResponse, error) {
	return c.client.AuthenticateWithCode(ctx, opts)
}

func (c *realUMClient) GetLogoutURL(opts usermanagement.GetLogoutURLOpts) (*url.URL, error) {
	return c.client.GetLogoutURL(opts)
}

func (c *realUMClient) AuthenticateWithRefreshToken(ctx context.Context, opts usermanagement.AuthenticateWithRefreshTokenOpts) (usermanagement.RefreshAuthenticationResponse, error) {
	return c.client.AuthenticateWithRefreshToken(ctx, opts)
}

func (c *realUMClient) ListSessions(ctx context.Context, userID string, opts usermanagement.ListSessionsOpts) (usermanagement.ListSessionsResponse, error) {
	return c.client.ListSessions(ctx, userID, opts)
}

func (c *realUMClient) RevokeSession(ctx context.Context, opts usermanagement.RevokeSessionOpts) error {
	return c.client.RevokeSession(ctx, opts)
}

func (c *realUMClient) GetUser(ctx context.Context, opts usermanagement.GetUserOpts) (usermanagement.User, error) {
	return c.client.GetUser(ctx, opts)
}

func (c *realUMClient) ListUsers(ctx context.Context, opts usermanagement.ListUsersOpts) (usermanagement.ListUsersResponse, error) {
	return c.client.ListUsers(ctx, opts)
}

func (c *realUMClient) UpdateUser(ctx context.Context, opts usermanagement.UpdateUserOpts) (usermanagement.User, error) {
	return c.client.UpdateUser(ctx, opts)
}

func (c *realUMClient) DeleteUser(ctx context.Context, opts usermanagement.DeleteUserOpts) error {
	return c.client.DeleteUser(ctx, opts)
}

func (c *realUMClient) ListOrganizationMemberships(ctx context.Context, opts usermanagement.ListOrganizationMembershipsOpts) (usermanagement.ListOrganizationMembershipsResponse, error) {
	return c.client.ListOrganizationMemberships(ctx, opts)
}

func (c *realUMClient) GetOrganizationMembership(ctx context.Context, opts usermanagement.GetOrganizationMembershipOpts) (usermanagement.OrganizationMembership, error) {
	return c.client.GetOrganizationMembership(ctx, opts)
}

type realSSOClient struct{ client *sso.Client }

func (*realSSOClient) privateSSOClient() {}

func (c *realSSOClient) ListConnections(ctx context.Context, opts sso.ListConnectionsOpts) (sso.ListConnectionsResponse, error) {
	return c.client.ListConnections(ctx, opts)
}

type realDirectorySyncClient struct{ client *directorysync.Client }

func (*realDirectorySyncClient) privateDirectorySyncClient() {}

func (c *realDirectorySyncClient) ListDirectories(ctx context.Context, opts directorysync.ListDirectoriesOpts) (directorysync.ListDirectoriesResponse, error) {
	return c.client.ListDirectories(ctx, opts)
}

func (c *realDirectorySyncClient) ListUsers(ctx context.Context, opts directorysync.ListUsersOpts) (directorysync.ListUsersResponse, error) {
	return c.client.ListUsers(ctx, opts)
}

func (c *realDirectorySyncClient) ListGroups(ctx context.Context, opts directorysync.ListGroupsOpts) (directorysync.ListGroupsResponse, error) {
	return c.client.ListGroups(ctx, opts)
}

type realAuditLogsClient struct{ client *auditlogs.Client }

func (*realAuditLogsClient) privateAuditLogsClient() {}

func (c *realAuditLogsClient) CreateEvent(ctx context.Context, e auditlogs.CreateEventOpts) error {
	return c.client.CreateEvent(ctx, e)
}

type realOrgsClient struct{ client *organizations.Client }

func (*realOrgsClient) privateOrgsClient() {}

func (c *realOrgsClient) GetOrganization(ctx context.Context, opts organizations.GetOrganizationOpts) (organizations.Organization, error) {
	return c.client.GetOrganization(ctx, opts)
}

func (c *realOrgsClient) ListOrganizations(ctx context.Context, opts organizations.ListOrganizationsOpts) (organizations.ListOrganizationsResponse, error) {
	return c.client.ListOrganizations(ctx, opts)
}

func (c *realOrgsClient) ListOrganizationRoles(ctx context.Context, opts organizations.ListOrganizationRolesOpts) (organizations.ListOrganizationRolesResponse, error) {
	return c.client.ListOrganizationRoles(ctx, opts)
}

type realPortalClient struct{ client *portal.Client }

func (*realPortalClient) privatePortalClient() {}

func (c *realPortalClient) GenerateLink(ctx context.Context, opts portal.GenerateLinkOpts) (string, error) {
	return c.client.GenerateLink(ctx, opts)
}

type realWebhookVerifier struct{ client *webhooks.Client }

func (*realWebhookVerifier) privateWebhookVerifier() {}

func (c *realWebhookVerifier) VerifyWebhook(body []byte, signature, secret string) error {
	verifier := webhooks.NewClient(secret)
	_, err := verifier.ValidatePayload(signature, string(body))
	return err
}
