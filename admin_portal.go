package workos

import (
	"context"

	"github.com/workos/workos-go/v6/pkg/portal"
)

func (c *Client) GenerateAdminPortalLink(
	ctx context.Context,
	organizationID string,
	intent AdminPortalIntent,
	returnURL string,
) (string, error) {
	link, err := c.portal.GenerateLink(ctx, portal.GenerateLinkOpts{
		Intent:       portal.GenerateLinkIntent(intent),
		Organization: organizationID,
		ReturnURL:    returnURL,
	})
	if err != nil {
		return "", &SafeError{
			msg:   "workos: admin portal link failed",
			cause: err,
		}
	}

	return link, nil
}
