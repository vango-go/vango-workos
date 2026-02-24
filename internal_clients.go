package workos

import (
	"context"
	"net/url"

	"github.com/workos/workos-go/v6/pkg/auditlogs"
	"github.com/workos/workos-go/v6/pkg/directorysync"
	"github.com/workos/workos-go/v6/pkg/organizations"
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
}
type ssoClient interface{ privateSSOClient() }
type directorySyncClient interface{ privateDirectorySyncClient() }
type auditLogsClient interface{ privateAuditLogsClient() }
type orgsClient interface{ privateOrgsClient() }
type webhookVerifier interface{ privateWebhookVerifier() }

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

type realSSOClient struct{ client *sso.Client }

func (*realSSOClient) privateSSOClient() {}

type realDirectorySyncClient struct{ client *directorysync.Client }

func (*realDirectorySyncClient) privateDirectorySyncClient() {}

type realAuditLogsClient struct{ client *auditlogs.Client }

func (*realAuditLogsClient) privateAuditLogsClient() {}

type realOrgsClient struct{ client *organizations.Client }

func (*realOrgsClient) privateOrgsClient() {}

type realWebhookVerifier struct{ client *webhooks.Client }

func (*realWebhookVerifier) privateWebhookVerifier() {}
