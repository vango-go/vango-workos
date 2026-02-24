package workos

import (
	"github.com/workos/workos-go/v6/pkg/auditlogs"
	"github.com/workos/workos-go/v6/pkg/directorysync"
	"github.com/workos/workos-go/v6/pkg/organizations"
	"github.com/workos/workos-go/v6/pkg/sso"
	"github.com/workos/workos-go/v6/pkg/usermanagement"
	"github.com/workos/workos-go/v6/pkg/webhooks"
)

// Private seams for deterministic tests.
type umClient interface{ privateUMClient() }
type ssoClient interface{ privateSSOClient() }
type directorySyncClient interface{ privateDirectorySyncClient() }
type auditLogsClient interface{ privateAuditLogsClient() }
type orgsClient interface{ privateOrgsClient() }
type webhookVerifier interface{ privateWebhookVerifier() }

type realUMClient struct{ client *usermanagement.Client }

func (*realUMClient) privateUMClient() {}

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
