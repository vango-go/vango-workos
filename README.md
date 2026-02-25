# vango-workos

`vango-workos` is the native WorkOS integration for Vango applications.

It provides production-ready AuthKit handlers, encrypted cookie sessions, HTTP-boundary middleware, Vango session-bridge hooks, periodic revalidation, enterprise APIs, verified webhooks, admin portal links, and a deterministic test kit.

## Environment variables

```bash
# Required
WORKOS_API_KEY="sk_live_..."
WORKOS_CLIENT_ID="client_..."
WORKOS_REDIRECT_URI="http://localhost:8080/auth/callback"
WORKOS_COOKIE_SECRET="your-secure-secret-at-least-32-chars"
WORKOS_BASE_URL="http://localhost:8080"

# Optional
WORKOS_WEBHOOK_SECRET="whsec_..."
WORKOS_COOKIE_SECRET_FALLBACKS="oldsecret1,oldsecret2"
WORKOS_JWT_ISSUER="https://api.workos.com"
WORKOS_JWT_AUDIENCE="$WORKOS_CLIENT_ID"
```

`WORKOS_COOKIE_SECRET` and all fallback secrets must be at least 32 characters.

## Canonical wiring

```go
wosClient, err := workos.New(workos.Config{
	APIKey:             os.Getenv("WORKOS_API_KEY"),
	ClientID:           os.Getenv("WORKOS_CLIENT_ID"),
	RedirectURI:        os.Getenv("WORKOS_REDIRECT_URI"),
	SignOutRedirectURI: "/auth/signed-out",
	CookieSecret:       os.Getenv("WORKOS_COOKIE_SECRET"),
	BaseURL:            os.Getenv("WORKOS_BASE_URL"),
	WebhookSecret:      os.Getenv("WORKOS_WEBHOOK_SECRET"),
	EnableAuditLogs:    true,
})
if err != nil {
	return err
}

bridge := wosClient.SessionBridge()
app, err := vango.New(vango.Config{
	OnSessionStart:  bridge.OnSessionStart,
	OnSessionResume: bridge.OnSessionResume,
	Session: vango.SessionConfig{
		AuthCheck: wosClient.RevalidationConfig(),
	},
})
if err != nil {
	return err
}

app.Server().Use(wosClient.Middleware())
csrfMw := app.Server().CSRFMiddleware()

mux := http.NewServeMux()
wosClient.RegisterAuthHandlers(mux, csrfMw)
mux.Handle("/webhooks/workos", wosClient.WebhookHandler(
	workos.OnDirectoryUserCreated(func(ctx context.Context, e workos.WebhookEvent) {}),
))
mux.Handle("/", app)
app.Server().SetHandler(mux)
```

## Route protection model

- `wosClient.Middleware()` validates cookies/tokens and attaches identity at the HTTP boundary.
- Route access control belongs to Vango route middleware (`authmw.RequireAuth`, role checks, etc.).
- Never use HTTP middleware as path-based authorization logic.

## Operational guardrails

- Access token refresh in middleware is enabled by default.
- Refresh token rotation coordination is process-local.
- JWKS fetches are bounded by `JWKSFetchTimeout` (default `5s`).
- Session list cache is bounded by `SessionListCacheMaxUsers` (default `10000`).
- In multi-instance deployments without sticky sessions, consider `DisableRefreshInMiddleware=true` to avoid refresh races across instances.
- Resume revalidation still runs via `OnSessionResume`, and periodic checks are controlled by `RevalidationConfig()`.

## Test kit

The package includes deterministic test helpers in the root package:

- `TestAuth` (`ErrNotMocked` defaults, `ValidateSession` active default, `EmitAuditEvent` no-op default)
- `TestIdentity(...)` with override helpers (`WithUserID`, `WithEmail`, `WithOrgID`, `WithRoles`, `WithPermissions`, `WithEntitlements`)
- `HydrateSessionForTest(session, identity)` to populate runtime auth projection in unit tests

Webhook handlers can be tested directly with subscription builders such as `OnDirectoryUserCreated`.

## Security summary

- Access/refresh tokens are stored only in encrypted HttpOnly cookie payloads.
- Session cookie encryption uses AES-256-GCM and binds ciphertext to the configured cookie name.
- Redirect handling blocks open redirects.
- Webhook payloads are signature-verified before dispatch.
- Sensitive helper errors are safe to log by default.

## Status

AuthKit, middleware, bridge hooks, enterprise APIs, webhook handling, Admin Portal links, and test kit are implemented with full test coverage in this package.
