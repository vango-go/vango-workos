package workos

import (
	"context"
	"fmt"

	"github.com/vango-go/vango"
	"github.com/vango-go/vango/pkg/auth"
	"github.com/vango-go/vango/pkg/authmw"
)

func (c *Client) SessionBridge() *Bridge {
	return &Bridge{client: c}
}

type Bridge struct {
	client *Client
}

func (b *Bridge) OnSessionStart(httpCtx context.Context, s *vango.Session) {
	user := vango.UserFromContext(httpCtx)
	identity, _ := user.(*Identity)
	if identity == nil {
		return
	}

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
}

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

func CurrentIdentity(ctx vango.Ctx) (*Identity, bool) {
	return auth.Get[*Identity](ctx)
}

func RequireIdentity(ctx vango.Ctx) (*Identity, error) {
	return auth.Require[*Identity](ctx)
}

func IdentityFromContext(ctx context.Context) (*Identity, bool) {
	u := vango.UserFromContext(ctx)
	i, ok := u.(*Identity)
	return i, ok
}

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

var RequireAuth = authmw.RequireAuth
