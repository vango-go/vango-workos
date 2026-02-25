package workos

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/workos/workos-go/v6/pkg/portal"
)

type fakePortalClient struct {
	generateLinkFunc func(ctx context.Context, opts portal.GenerateLinkOpts) (string, error)
}

func (*fakePortalClient) privatePortalClient() {}

func (f *fakePortalClient) GenerateLink(ctx context.Context, opts portal.GenerateLinkOpts) (string, error) {
	if f.generateLinkFunc == nil {
		return "", errors.New("not mocked")
	}
	return f.generateLinkFunc(ctx, opts)
}

func TestGenerateAdminPortalLink(t *testing.T) {
	t.Run("success maps options and returns link", func(t *testing.T) {
		client := newEnterpriseTestClient(t)

		var captured portal.GenerateLinkOpts
		client.portal = &fakePortalClient{
			generateLinkFunc: func(_ context.Context, opts portal.GenerateLinkOpts) (string, error) {
				captured = opts
				return "https://portal.workos.com/link_123", nil
			},
		}

		link, err := client.GenerateAdminPortalLink(
			context.Background(),
			"org_123",
			AdminPortalSSO,
			"https://app.example.com/settings",
		)
		if err != nil {
			t.Fatalf("GenerateAdminPortalLink() error = %v", err)
		}
		if link != "https://portal.workos.com/link_123" {
			t.Fatalf("link = %q", link)
		}
		if captured.Organization != "org_123" {
			t.Fatalf("Organization = %q", captured.Organization)
		}
		if captured.Intent != portal.SSO {
			t.Fatalf("Intent = %q", captured.Intent)
		}
		if captured.ReturnURL != "https://app.example.com/settings" {
			t.Fatalf("ReturnURL = %q", captured.ReturnURL)
		}
	})

	t.Run("domain verification intent maps correctly", func(t *testing.T) {
		client := newEnterpriseTestClient(t)

		var captured portal.GenerateLinkOpts
		client.portal = &fakePortalClient{
			generateLinkFunc: func(_ context.Context, opts portal.GenerateLinkOpts) (string, error) {
				captured = opts
				return "https://portal.workos.com/link_456", nil
			},
		}

		link, err := client.GenerateAdminPortalLink(
			context.Background(),
			"org_123",
			AdminPortalDomainVerification,
			"https://app.example.com/settings",
		)
		if err != nil {
			t.Fatalf("GenerateAdminPortalLink() error = %v", err)
		}
		if link != "https://portal.workos.com/link_456" {
			t.Fatalf("link = %q", link)
		}
		if captured.Intent != portal.DomainVerification {
			t.Fatalf("Intent = %q", captured.Intent)
		}
	})

	t.Run("error wraps with SafeError and preserves cause", func(t *testing.T) {
		client := newEnterpriseTestClient(t)
		upstreamErr := errors.New("upstream failure token=secret")
		client.portal = &fakePortalClient{
			generateLinkFunc: func(context.Context, portal.GenerateLinkOpts) (string, error) {
				return "", upstreamErr
			},
		}

		link, err := client.GenerateAdminPortalLink(
			context.Background(),
			"org_123",
			AdminPortalDSync,
			"https://app.example.com/settings",
		)
		if err == nil {
			t.Fatal("expected error")
		}
		if link != "" {
			t.Fatalf("link = %q, want empty", link)
		}
		if !strings.HasPrefix(err.Error(), "workos:") {
			t.Fatalf("error prefix = %q", err.Error())
		}
		if err.Error() != "workos: admin portal link failed" {
			t.Fatalf("error = %q", err.Error())
		}
		if !errors.Is(err, upstreamErr) {
			t.Fatal("expected errors.Is(err, upstreamErr) to be true")
		}
		assertNoSecretLeak(t, err.Error(), "secret")
	})
}
