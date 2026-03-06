package workos

import (
	"context"
	"net/http"

	"github.com/vango-go/vango/pkg/auth"
)

func Example_standardVangoWiring() {
	cfg := Config{
		APIKey:        "sk_test_abcdefghijklmnopqrstuvwxyz123456",
		ClientID:      "client_1234567890",
		RedirectURI:   "https://app.example.com/auth/callback",
		CookieSecret:  "0123456789abcdef0123456789abcdef",
		BaseURL:       "https://app.example.com",
		WebhookSecret: "whsec_test_example",
	}

	client, err := New(cfg)
	if err != nil {
		return
	}

	bridge := client.SessionBridge()
	_ = bridge
	_ = client.Middleware()
	_ = client.RevalidationConfig()

	mux := http.NewServeMux()
	csrfMw := func(next http.Handler) http.Handler { return next }
	client.RegisterAuthHandlers(mux, csrfMw)
	mux.Handle("/webhooks/workos", client.WebhookHandler(
		OnDirectoryUserCreated(func(context.Context, WebhookEvent) {}),
		OnDirectoryUserDeleted(func(context.Context, WebhookEvent) {}),
	))
}

func Example_strictWebhookWiring() {
	cfg := Config{
		APIKey:        "sk_test_abcdefghijklmnopqrstuvwxyz123456",
		ClientID:      "client_1234567890",
		RedirectURI:   "https://app.example.com/auth/callback",
		CookieSecret:  "0123456789abcdef0123456789abcdef",
		BaseURL:       "https://app.example.com",
		WebhookSecret: "whsec_test_example",
	}

	client, err := New(cfg)
	if err != nil {
		return
	}

	mux := http.NewServeMux()
	mux.Handle("/webhooks/workos", client.WebhookHandlerWithOptions(
		WebhookHandlerOptions{
			IdempotencyStore: NewMemoryWebhookIdempotencyStore(),
		},
		OnUserCreatedErr(func(ctx context.Context, e WebhookEvent) error {
			return nil
		}),
	))
}

func ExampleCurrentIdentity_componentUsage() {
	ctx := &ctxStub{
		user: TestIdentity(
			WithUserID("user_component_001"),
			WithEmail("component@example.com"),
		),
	}

	identity, ok := CurrentIdentity(ctx)
	if !ok || identity == nil {
		return
	}

	_ = identity.UserID
	_ = identity.Email
}

func ExampleIdentityFromContext_actionPermissionCheck() {
	deleteProjectWork := func(ctx context.Context) error {
		identity, ok := IdentityFromContext(ctx)
		if !ok || identity == nil {
			return auth.ErrUnauthorized
		}
		if !identity.HasPermission("projects:delete") {
			return auth.ErrForbidden
		}
		return nil
	}

	ctx := WithIdentity(context.Background(), TestIdentity(
		WithPermissions("projects:delete"),
	))
	_ = deleteProjectWork(ctx)
}
