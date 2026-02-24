# vango-workos: Phased Build Plan

**Package goal:** ship `github.com/vango-go/vango-workos`, a production-hardened native WorkOS integration for Vango apps built on `github.com/workos/workos-go/v6`, including AuthKit handlers, encrypted cookie sessions, JWT verification via JWKS, session resume/active revalidation wiring, webhook verification, admin portal links, and a deterministic test kit.

**Primary spec (source of truth):** `/Users/collinshill/Documents/vango/vango-workos/WORKOS_INTEGRATION_SPEC.md` (copy of `/Users/collinshill/Documents/vango/vango/WORKOS_INTEGRATION.md`).

This plan is intentionally “maximally thorough”: it includes repository/module scaffolding, implementation sequencing, test strategy, acceptance criteria mapped to explicit invariants, and CI/release readiness.

---

## 0) Scope, Non-Goals, and Constraints

### Glossary (terms used throughout this plan)
- **AuthKit**: WorkOS hosted authentication UI / redirect flow.
- **Session cookie**: encrypted, HttpOnly cookie storing access+refresh tokens (and optional identity hint).
- **State cookie**: short-lived HttpOnly cookie storing `state` for CSRF protection in the AuthKit callback.
- **Identity**: Vango runtime-only auth projection used inside a Vango session and SSR request contexts.
- **Principal**: minimal Vango auth principal (`github.com/vango-go/vango/pkg/auth.Principal`) used for AuthCheck and stable metadata.
- **HTTP boundary**: net/http request lifecycle (SSR, initial navigation, WS upgrade/resume), where middleware runs.
- **Session loop**: Vango single-writer event loop for long-lived WS sessions. Must never block on I/O.
- **Safe error**: an `error` whose `Error()` string is safe to log by default (no tokens/cookies/secret bodies).

### In scope (this repo/package)
- Implement the **full public API** specified in `WORKOS_INTEGRATION_SPEC.md` Part 1:
  - Interfaces: `Sessions`, `Users`, `Orgs`, `RBAC`, `AuditLogs`, `SSORead`, `DirectorySyncRead`, `Auth`
  - Domain types: `Identity`, `AccessTokenClaims`, `TokenSet`, `SessionInfo`, org/user/role/dsync/sso/audit/webhook types, list option types
  - `Config` with validation + defaults
  - `Client` implementation backed by WorkOS SDK v6
  - `SafeError`
  - Cookie + state helpers (AES-256-GCM, AAD binding, key rotation)
  - JWKS fetch/cache + JWT verification
  - Refresh single-flight + session validation caching
  - HTTP handlers: sign-in, sign-up, callback, logout, signed-out page + script, and registration helper
  - net/http middleware for SSR + WS handshake identity attachment
  - Vango integration primitives: `SessionBridge`, `RevalidationConfig`, helper accessors
  - Webhook handler with signature verification + event routing
  - Admin Portal link generation
  - Test kit: `TestAuth`, `TestIdentity`, `HydrateSessionForTest`, etc. (in package root; no subpackage, no build tags)
- Provide production-grade tests that prove the security/behavioral contract and avoid network dependence by default.

### Out of scope (belongs to Vango core repo)
- `vango create --with workos` scaffolding, `vango dev` helpers, and `vango workos ...` CLI subcommands (Appendix H Phase 2/3).
- Any Vango core changes needed to support this package; this package must integrate with Vango’s existing primitives.

### Hard constraints (must not regress)
- **No secrets leakage** in error strings by default:
  - cookie values, access tokens, refresh tokens
  - webhook payloads, signing secrets, cookie secrets
  - query parameters that may contain codes/tokens (e.g., auth callback `code`)
- **Do not perform blocking I/O on the Vango session loop**:
  - WorkOS API calls may only occur in HTTP handlers, Resource loaders, or Action work functions.
- **Auth state projection semantics must match Vango’s auth primitives**:
  - store Identity via `auth.Set(session, identity)` on start/resume
  - store `auth.Principal` via `auth.SetPrincipal(session, ...)`
  - never store access/refresh tokens in Vango session KV
- **Cookie session is encrypted** exactly per spec (§1.4.1 / §1.5.2).
- **Refresh rotation is concurrency-safe** within a process (§1.5.4) and has an explicit operational story for multi-instance deployments (§H.5.4).

---

## 1) Design Invariants (Acceptance Criteria)

Define explicit invariants so the implementation and tests can be audited quickly.

### W1: Tokens are cookie-only
- Access token and refresh token MUST exist only in the encrypted cookie payload.
- Tokens MUST NOT be persisted to Vango session KV, signals, or logs.

### W2: Session cookie encryption is deterministic and versioned
- AES-256-GCM, 12-byte nonce, key = `SHA256(CookieSecret)`, AAD binds to `CookieName`.
- Encoding is base64url without padding of `v || nonce || ciphertext`.
- Decryption attempts `CookieSecret`, then `CookieSecretFallbacks` in order.

### W3: State cookie is one-time-use CSRF protection for callback
- Callback rejects missing/invalid state; state cookie cleared after success.
- State cookie is HttpOnly, bounded TTL (10 minutes), SameSite and Secure follow config.

### W4: JWT verification is local and strict (with leeway)
- Verify signature via JWKS; enforce `iss` and `aud`; validate time claims with small leeway.
- Handle JWKS key rotation (force refresh on unknown `kid` once).

### W5: Refresh rotation is safe under concurrency
- A refresh token must never be used concurrently within a process.
- “Losers” of a refresh race must receive the winner’s result (single-flight).

### W6: Resume + periodic revalidation semantics match Vango
- `OnSessionStart` hydrates runtime auth projection from HTTP context.
- `OnSessionResume` actively validates session with WorkOS; rejects resume on failure when previously authenticated.
- `RevalidationConfig` enforces bounded revocation detection over long-lived sessions (or can be disabled explicitly).

### W7: HTTP middleware is non-authoritative for route protection
- Middleware attaches Identity when present; it must not implement “protected paths”.
- Route protection remains Vango route middleware (`authmw.RequireAuth`, etc.).

### W8: Webhooks are verified before dispatch
- Signature verified with configured secret; invalid signature returns 401.
- Request body size is bounded.

### W9: Open redirect prevention
- `return_to` handling only allows:
  - absolute-path relative redirects (must start with `/` and not `//`)
  - absolute redirects only when origin matches `Config.BaseURL`

### W10: Test kit is deterministic and low “mock tax”
- Unset `TestAuth` methods return `ErrNotMocked` (never nil values that cause panics).
- `ValidateSession` defaults to “active” (to reduce boilerplate).
- `EmitAuditEvent` is no-op by default.

---

## 1.1) Cross-Cutting Implementation Details (Add Before Coding)

These are not new requirements; they are engineering decisions that make the spec implementable with deterministic tests and fewer regressions.

### Internal test seams (recommended)
- **SDK adapters:** wrap the concrete WorkOS SDK clients behind private interfaces (small, method-minimal) so unit tests can inject fakes without network.
- **Webhook verifier seam:** wrap `webhooks.Client` verification behind a private interface so signature verification can be tested deterministically (or at least simulated without coupling to SDK internals).
- **HTTP client seam for JWKS:** use an injectable `*http.Client` (default `http.DefaultClient`) so tests can enforce timeouts and count requests without global monkeypatching.
- **Time and randomness seams:** keep production defaults (`time.Now`, `crypto/rand`) but allow tests to override via unexported variables/functions where determinism matters (e.g., `generateUUID()` and `generateState()`).

### Cache/memory boundaries
- `sessionsCache` (per-user session snapshots) can grow without bound if a process sees many distinct users. Add an opportunistic pruning strategy:
  - store `fetchedAt` per user and delete expired entries on insert (cheap) or when map exceeds a threshold.
- `jwksCache.keys` growth is bounded by JWKS size (small), but JWKS refresh should be serialized and failures should not poison the cache.
- `refreshGroup.m` must delete keys after completion (already required by design).

### Context/timeouts
- JWKS fetch, refresh exchanges, session list calls, and session revoke calls should respect the inbound request context and/or apply bounded timeouts consistently:
  - `Config.RevalidationTimeout` applies to resume and AuthCheck validation.
  - For middleware refresh, use the request context (and consider a bounded timeout to avoid holding HTTP connections indefinitely).

### Secret leakage audit stance (enforced by tests)
Add a shared test helper that asserts strings do not contain likely secret material. It should be used on:
- `error.Error()` strings returned by helpers/handlers/middleware
- HTTP response bodies for auth handlers (especially callback and webhook failure paths)
- cookie values (must never be printed into an error string)

Example denylist patterns (heuristics):
- `"eyJ"` (JWT header prefix)
- `"access_token"`, `"refresh_token"`
- `"sk_"`, `"whsec_"`, `"client_"` (context-dependent, but useful in error scanning)
- `cfg.CookieName` cookie value should never appear in output

---

## 2) Repository & Module Setup (Phase 0)

### Deliverables
- Go module initialized at `github.com/vango-go/vango-workos`.
- `README.md` with “how to wire into Vango” and operational guidance.
- Package docs (godoc) stating the I/O boundary rules and auth projection semantics.

### Tasks
1. Create `go.mod`:
   - `module github.com/vango-go/vango-workos`
   - require:
     - `github.com/vango-go/vango` (for integration primitives)
     - `github.com/workos/workos-go/v6` and required subpackages
     - `github.com/golang-jwt/jwt/v5`
2. Establish file layout (single `package workos`):
   - `doc.go` (package-level contract and wiring example)
   - `interfaces.go` (facade interfaces)
   - `types_*.go` (domain types and list option types)
   - `config.go` (Config, defaults, validation, redaction)
   - `safe_error.go` (`SafeError`)
   - `cookie.go` (cookie + state helpers)
   - `jwks.go` (JWKS fetch/cache)
   - `jwt.go` (VerifyAccessToken)
   - `refresh.go` (refreshGroup, RefreshTokens)
   - `sessions.go` (ValidateSession, sessions cache, RevokeSession)
   - `client.go` (Client, constructor, SDK wiring, service methods)
   - `handlers.go` (AuthKit handlers)
   - `middleware.go` (net/http boundary middleware)
   - `bridge.go` (SessionBridge, revalidation config, helpers)
   - `webhook.go` (WebhookHandler, subscriptions/registry)
   - `admin_portal.go` (Admin portal link generation)
   - `testkit.go` (TestAuth + helpers; in root package)
3. Add baseline CI entrypoints (at minimum local):
   - `go test ./...`
   - `go vet ./...`

### Exit criteria
- `go test ./...` passes locally (initially trivial).
- `go vet ./...` passes.
- README explains the wiring pattern: `app.Server().Use(client.Middleware())`, mux mounting, `SessionBridge`, and `RevalidationConfig()`.

---

## 3) Core Public API & Domain Model (Phase 1)

### Deliverables
- Interfaces and all public domain types compile and match the spec signatures.
- Domain types are independent of WorkOS SDK types (normalized “Vango-native” surface).

### Tasks
1. Implement interfaces exactly per spec §1.2:
   - `Sessions`, `Users`, `Orgs`, `RBAC`, `AuditLogs`, `SSORead`, `DirectorySyncRead`, `Auth`
2. Implement domain types per spec §1.3:
   - Identity and claims (`Identity`, `AccessTokenClaims`, `TokenSet`, `SessionInfo`)
   - Users/orgs/memberships/roles, SSO connections
   - Directory Sync types (Directory, DirectoryUser, DirectoryGroup)
   - Audit log types (AuditEvent, actor/target/context)
   - Pagination types (`ListMeta` + list wrappers)
   - Option/filter types for list/update calls
3. Implement Identity helpers:
   - `(*User).DisplayName()`
   - `(*Identity).IsExpired()` and `HasPermission()`
4. Ensure JSON tags and field names match spec and avoid accidental token serialization.

### Tests
- Small unit tests for:
  - `User.DisplayName()` fallback semantics
  - `Identity.IsExpired()` and `HasPermission()`

### Exit criteria
- API surface compiles cleanly and matches the spec.
- No WorkOS SDK types leak into exported fields or signatures.

---

## 4) Config + SafeError (Phase 2)

### Deliverables
- `Config` with validation + defaults exactly per spec §1.4.
- `Client.New(cfg)` validates required fields and sets defaults.
- `SafeError` wrapper implemented and used in secret-bearing helpers.

### Tasks
1. Implement `Config` struct and `New(cfg)` validation:
   - required: `APIKey`, `ClientID`, `RedirectURI`, `CookieSecret`, `BaseURL`
   - enforce prefixes: `sk_`, `client_`
   - enforce cookie secrets length (>= 32), including fallbacks
   - validate `SignOutRedirectURI` is absolute-path only (no `//`)
2. Apply defaults:
   - cookie defaults:
     - `CookieName`: `"__vango_workos_session"`
     - `CookieMaxAge`: `7 * 24 * time.Hour`
     - `CookieSecure`: `true` (operators must set `false` only for local HTTP development)
     - `CookieSameSite`: `"lax"` (mapped to `http.SameSiteLaxMode`)
   - redirect defaults:
     - `SignOutRedirectURI`: `"/auth/signed-out"`
   - JWKS/JWT defaults:
     - `JWKSCacheDuration`: `1 * time.Hour`
     - `JWKSURL`: `usermanagement.GetJWKSURL(ClientID)` unless overridden
     - `JWTIssuer`: `"https://api.workos.com"` (normalized by trimming trailing `/` during comparisons)
     - `JWTAudience`: `ClientID`
   - revalidation defaults:
     - `RevalidationInterval`: `5 * time.Minute`
     - `RevalidationTimeout`: `5 * time.Second`
     - `MaxStaleSession`: `15 * time.Minute`
     - `DisablePeriodicSessionValidation`: `false` (so `RevalidationConfig()` is enabled by default)
   - refresh defaults:
     - `DisableRefreshInMiddleware`: `false` (refresh enabled by default; see multi-instance posture in Appendix H)
   - session list caching defaults:
     - `SessionListCacheDuration`: `30 * time.Second`
   - webhook defaults:
     - `WebhookMaxBodyBytes`: `1 << 20` (1MB)
     - `WebhookSecret`: required only if using the webhook handler; otherwise may be empty
   - audit logs defaults:
     - `EnableAuditLogs`: `false` (so audit emission is a no-op unless enabled)
3. Implement `(*Client).Config() Config` redacting secrets (API key, cookie secrets, webhook secret).
4. Implement `SafeError` and adopt it in:
   - cookie encrypt/decrypt helpers
   - JWKS fetch/decode
   - any JWT parsing errors that might contain the raw token

### Tests
- Table tests for `New(Config)`:
  - missing required fields
  - invalid prefixes
  - short cookie secret/fallback
  - invalid sign-out redirect URI
  - default application behavior (fields set as specified)
- Tests for redaction in `Client.Config()`:
  - secrets are replaced/cleared deterministically

### Exit criteria
- `New(cfg)` enforces all spec validations and sets defaults.
- `Client.Config()` is safe to log.

---

## 5) Cookie + State Helpers (Phase 3)

### Deliverables
- Session cookie helper implementation matches spec §1.5.2 precisely (W2).
- OAuth state cookie helpers match spec §1.4.2 precisely (W3).

### Tasks
1. Implement state cookie:
   - `setStateCookie`, `validateStateCookie`, `clearStateCookie`
   - ensure TTL and attributes match the spec
2. Implement session cookie:
   - `cookieSession` payload type (v1)
   - `sealCookieSession` / `openCookieSession` using AES-256-GCM
   - `setSessionCookie`, `readSessionCookie`, `clearSessionCookie`
   - enforce AAD binding to cookie name (`cfg.CookieName`)
   - implement secret fallback decryption in order
3. Implement `sameSiteFromConfig` mapping.

### Tests (must be explicit about invariants)
- Cookie roundtrip (seal->open) yields identical struct.
- Envelope format:
  - version byte is required and validated
  - payload cannot be opened with wrong AAD (different cookie name)
  - payload cannot be opened with wrong secret
- Fallback decryption order works:
  - encrypt with fallback secret and ensure read succeeds when primary fails, and vice versa
- Cookie attribute tests:
  - HttpOnly true, Path "/", SameSite mapping, Secure equals cfg.CookieSecure
- State cookie one-time-use semantics in handler-level tests (see Phase 7).

### Exit criteria
- Cookie helpers are correct, safe-error wrapped, and exhaustively unit-tested.

---

## 6) JWKS Fetch/Cache + JWT Verification (Phase 4)

### Deliverables
- JWKS cache with stampede protection and rotation handling (W4).
- JWT verification implementation returning `AccessTokenClaims` exactly per spec §1.5.3.

### Tasks
1. Implement JWKS cache:
   - `jwksCache` with `fetchedAt` and `kid -> rsa.PublicKey` map
   - TTL-based cache invalidation (`JWKSCacheDuration`)
   - refresh serialization with `jwksFetchMu` to prevent thundering herd
2. JWKS parsing:
   - accept RSA keys only
   - decode N/E correctly; ignore invalid keys
   - treat non-2xx fetch as failure (safe error)
3. JWT verification:
   - use `github.com/golang-jwt/jwt/v5`
   - strict algorithm expectations (`RS256` only; reject unexpected `alg` if provided)
   - enforce presence of `kid`, `sub`, `sid`
   - validate issuer and audience against `Config.JWTIssuer`/`JWTAudience`
   - allow small clock skew leeway (30s)
   - normalize roles from `role` (single) and `roles` (slice)
4. Rotation behavior:
   - if `kid` unknown, force-refresh JWKS once and retry lookup; fail if still missing.

### Tests (no external network)
- JWKS server using `httptest.Server` that returns:
  - a valid RSA JWKS with known `kid`
  - a rotated JWKS (kid changed) to test force-refresh behavior
  - invalid JSON / non-2xx to ensure safe errors
- JWT verification tests:
  - mint RS256 JWTs in tests using generated RSA private key
  - ensure issuer/audience mismatches fail
  - ensure missing/invalid `kid`, `sub`, or `sid` fails
  - ensure leeway covers small clock skew without accepting long-expired tokens
- JWKS caching:
  - repeated verify calls within TTL do not refetch (count requests)
  - forcing refresh occurs only on unknown `kid` path

### Extra hardening tests (low cost, high value)
- `go test -race` targeted at refresh single-flight tests (catches data races in `refreshGroup` and caches).
- Fuzz tests (Go built-in fuzzing) for:
  - `openCookieSession` (never panics, always returns safe errors)
  - JWT parsing on random inputs (never panics, never returns success without required claims)

### Exit criteria
- `VerifyAccessToken` is correct, strict, rotation-safe, and deterministic under tests.

---

## 7) Refresh + Session Validation (Phase 5)

### Deliverables
- Process-local refresh single-flight (W5).
- Session validation that detects revocation via WorkOS Sessions API with short per-user cache (§1.5.4).

### Tasks
1. Implement refresh group:
   - `refreshGroup.Do(key, fn)` single-flight
   - refresh key derived from SHA256(refresh token) base64url
2. Implement `Client.RefreshTokens(ctx, refreshToken)`:
   - call WorkOS refresh endpoint
   - verify returned access token (derive `ExpiresAt`)
   - ensure returned tokens are non-empty
   - on any failure, return safe, non-sensitive error strings
3. Implement time parsing:
   - WorkOS timestamp parsing helper (`RFC3339Nano` and `RFC3339`)
4. Implement session validation cache:
   - `SessionListCacheDuration` TTL
   - cache is per-user: maps `sessionID -> *SessionInfo`
   - list pagination until `after` is empty
5. Implement `ValidateSession(ctx, userID, sessionID)` semantics:
   - missing args -> error
   - if session found, return info
   - if session missing, return inactive session info (Active=false)
6. Implement `RevokeSession(ctx, sessionID)`.

### Testability strategy (important)
The WorkOS SDK uses concrete client structs; to unit test refresh/session flows without network:
- introduce private interfaces for the SDK sub-clients used by `Client`:
  - `type umClient interface { AuthenticateWithRefreshToken(...); ListSessions(...); RevokeSession(...); GetAuthorizationURL(...); AuthenticateWithCode(...) ... }`
  - similar minimal interfaces for other subclients as needed
- in `New`, wire these interfaces to real SDK clients.
- in unit tests, inject fakes implementing these interfaces.

This is an internal design choice; the public API remains exactly as the spec.

### Tests
- Refresh single-flight:
  - concurrently call `RefreshTokens` with same refresh token and assert only one upstream exchange occurs and both calls return identical `TokenSet`.
- Refresh failure paths:
  - upstream error -> safe error string (no token echoed)
  - empty tokens -> safe error
  - returned access token fails verification -> safe error
- Session list caching:
  - repeated `ValidateSession` within TTL hits upstream once
  - after TTL, refetch occurs
  - pagination merges all pages correctly
- Session status normalization:
  - `active` status maps to Active=true; other statuses false

### Exit criteria
- Refresh/session validation is concurrency-safe, cached, and covered by deterministic unit tests.

---

## 8) AuthKit HTTP Handlers (Phase 6)

### Deliverables
- AuthKit routes implemented per spec §1.6:
  - `SignInHandler`, `SignUpHandler`, `CallbackHandler`
  - `LogoutHandler`, `SignedOutHandler`, `SignedOutScriptHandler`
  - `RegisterAuthHandlers`
- Open redirect protection and CSP-safe signed-out script approach (W9).

### Tasks
1. Implement state generation:
   - cryptographically secure random state (32 bytes) and hex/base64url encoding
2. Implement sign-in/sign-up:
   - set state cookie
   - generate authorization URL via WorkOS SDK
   - redirect 307/302 as specified
3. Implement callback:
   - handle WorkOS error params safely (do not reflect secrets)
   - never echo `code` or `state` in error strings or responses
   - validate state cookie and clear it after success
   - exchange code for tokens; verify JWT; build Identity
   - set session cookie with `cookieSession`
   - redirect to safe `return_to` (or `/`)
4. Implement logout:
   - POST-only
   - clear local cookie unconditionally
   - best-effort server-side session revocation
   - redirect through WorkOS logout URL when sessionID known
5. Implement signed-out page + script:
   - HTML with meta return-to
   - JS broadcasts logout to other tabs (BroadcastChannel + localStorage fallback)
   - clears Vango resume keys in sessionStorage
   - navigates to return_to via `location.replace`
6. Implement `RegisterAuthHandlers(mux, csrfMw)`:
   - wrap logout with CSRF middleware (provided by app server)

### Tests
- Handler tests using `httptest`:
  - state cookie set on sign-in and sign-up
  - callback rejects missing code
  - callback rejects missing/invalid state
  - callback clears state cookie on success
  - return_to open redirect prevention (absolute-path rules and BaseURL origin matching)
  - logout is method-gated, clears session cookie, sets no-store
  - signed-out handlers return correct content types and no-store
  - callback error paths do not echo query params (especially `code`, `state`, `error_description`)

### Exit criteria
- Complete AuthKit flow works end-to-end in unit tests with faked WorkOS SDK calls.

---

## 9) net/http Boundary Middleware (Phase 7)

### Deliverables
- `Client.Middleware() func(http.Handler) http.Handler` implemented per spec §1.7 (W1, W4, W5, W7).

### Tasks
1. Implement middleware flow:
   - read and decrypt session cookie (if missing/invalid: pass through unauthenticated)
   - verify access token locally via JWKS
   - if invalid: clear cookie and pass through unauthenticated
   - if expired:
     - if `DisableRefreshInMiddleware`: clear cookie and pass through unauthenticated
     - else attempt refresh (single-flight), rewrite cookie with rotated tokens
   - build fresh Identity (claims authoritative; cookie hint as fallback only for UX fields)
   - write cookie only when:
     - refresh occurred, OR
     - IdentityHint is missing (seed it once), OR
     - other explicit need-to-write conditions (keep minimal to reduce churn)
   - attach Identity to request context via `vango.WithUser`
2. Ensure behavior is safe under:
   - concurrent requests
   - missing refresh token
   - verification errors (no token leakage)

### Tests
- Middleware tests with `httptest`:
  - no cookie -> does not set user in context
  - valid cookie -> attaches *Identity via vango.UserFromContext
  - invalid cookie -> clears cookie, no identity
  - expired access token + refresh enabled -> calls refresh once, writes new cookie, attaches identity
  - expired access token + refresh disabled -> clears cookie, no identity
  - identity hint fallback populates name/email/org when claims omit them
- “No secret in error” assertions:
  - test helper that scans `err.Error()` and handler responses for access token / refresh token substrings.

### Exit criteria
- Middleware is correct, safe-by-default, and provides the only HTTP-boundary token lifecycle logic.

---

## 10) Vango Integration Primitives (Phase 8)

### Deliverables
- Session lifecycle bridge (`SessionBridge`) and periodic revalidation config (`RevalidationConfig`), plus helper functions, per spec §1.7.

### Tasks
1. Implement `SessionBridge()` returning `*Bridge`:
   - `OnSessionStart`:
     - read identity from `vango.UserFromContext(httpCtx)`
     - set `auth.Set(session, identity)`
     - set `auth.SetPrincipal(session, auth.Principal{...})` with passive expiry disabled (ExpiresAtUnixMs=0)
   - `OnSessionResume`:
     - require identity present (indicates middleware installed)
     - active validation via `ValidateSession` with timeout
     - reject resume if inactive; otherwise rehydrate auth + principal
2. Implement `RevalidationConfig()`:
   - return nil if `DisablePeriodicSessionValidation`
   - else return `*vango.AuthCheckConfig`:
     - Interval, Timeout, FailureMode, MaxStale from config
     - Check uses `ValidateSession` with `auth.Principal` inputs
     - OnExpired uses `ForceReload` to `/auth/signin`
3. Implement helpers:
   - `CurrentIdentity`, `RequireIdentity`
   - `IdentityFromContext`, `WithIdentity`
   - `RequirePermission`
   - `var RequireAuth = authmw.RequireAuth`

### Tests
- Bridge tests:
  - OnSessionStart hydrates auth.Set and auth.SetPrincipal keys on a fake session
  - OnSessionResume rejects when identity missing
  - OnSessionResume rejects when ValidateSession returns inactive
  - OnSessionResume rehydrates when active
- AuthCheck config tests:
  - returns nil when disabled
  - Check returns error on inactive session
  - OnExpired values match spec (ForceReload + /auth/signin)

### Exit criteria
- Vango integration works with Vango’s strict resume semantics and long-lived AuthCheck model.

---

## 11) WorkOS Read/Enterprise APIs (Phase 9)

### Deliverables
- `Client` implements the full `Auth` interface (users, orgs, memberships, roles, connections, directories, audit logs).
- All conversions from SDK types to domain types are covered by tests where reasonable.

### Tasks
1. Implement client wiring:
   - set WorkOS global config (if needed by SDK) or use per-client APIKey fields
   - initialize required SDK subclients in `New`
2. Users:
   - Get/List/Update/Delete user via User Management API
   - normalize metadata types carefully
3. Organizations + memberships:
   - Get/List organizations
   - list org memberships and get membership
4. RBAC:
   - HasRole (may require list memberships / roles depending on WorkOS model)
   - ListRoles (environment-level vs org-level)
5. SSO read:
   - ListConnections via SSO API
6. Directory Sync read:
   - list directories/users/groups via DS API
7. Audit logs:
   - EmitAuditEvent is no-op unless enabled
   - ensure OccurredAt default and IdempotencyKey generation
   - normalize to SDK request type

### Tests
- Conversion-level tests for:
  - role normalization, membership mapping, list metadata mapping
- Audit event behavior tests:
  - no-op when disabled
  - occurred_at defaulted
  - idempotency key auto-generated when empty

### Exit criteria
- Client fulfills all interfaces and apps can target only the interfaces, not SDK clients.

---

## 12) Webhook Handler + Subscriptions (Phase 10)

### Deliverables
- Webhook endpoint per spec §1.8 (W8).

### Tasks
1. Implement `WebhookHandler(handlers ...WebhookSubscription) http.Handler`:
   - method gate: POST only
   - body read with `WebhookMaxBodyBytes` limit
   - signature verify via WorkOS SDK webhook verifier using `WebhookSecret`
   - parse event into normalized `WebhookEvent`
   - dispatch:
     - exact match handler for event name
     - optional wildcard handler `"*"`
2. Implement subscription builders:
   - `OnDirectoryUserCreated/Updated/Deleted`
   - `OnDirectoryGroupCreated/Updated/Deleted`
   - `OnConnectionActivated/Deactivated`
   - `OnUserCreated/Updated/Deleted`
   - `OnOrganizationMembershipCreated/Deleted`
   - `OnSessionCreated`
   - `OnAnyEvent`
3. Implement registry builder helper:
   - validate no duplicates or define deterministic “last wins” semantics
   - treat empty handler as no-op

### Tests
- Signature verify path:
  - use SDK verifier if it exposes a way to generate signatures in tests; otherwise inject verifier interface (recommended)
- Routing tests:
  - exact match calls correct handler
  - wildcard handler executes for any event
  - unknown event only triggers wildcard (if present)
- Body limit tests:
  - oversized body returns 400
  - invalid signature returns 401 without echoing request body

### Exit criteria
- Webhook handler is safe-by-default and deterministic.

---

## 13) Admin Portal Link Generation (Phase 11)

### Deliverables
- `GenerateAdminPortalLink(...) (string, error)` implemented per spec §1.9.

### Tasks
- Implement method calling WorkOS Organizations API to generate portal link.
- Expose `AdminPortalIntent` constants exactly as spec.

### Tests
- With fake orgs client, ensure:
  - correct intent string passed through
  - returned URL is the response link
  - errors are wrapped with `workos:` prefix without secrets

### Exit criteria
- Admin Portal generation is complete and covered by deterministic tests.

---

## 14) Test Kit (Phase 12)

### Deliverables
- `TestAuth` and helper functions per spec §1.10 (W10).

### Tasks
1. Implement `TestAuth` struct with per-method function fields.
2. Ensure unset methods return `ErrNotMocked` (except documented defaults):
   - `ValidateSession` defaults to active
   - `EmitAuditEvent` defaults to nil
3. Implement helpers:
   - `TestIdentity` and override helpers (`WithUserID`, `WithEmail`, etc.)
   - `HydrateSessionForTest(session auth.Session, identity *Identity)`
4. Keep all test kit code in `package workos` (no subpackage/build tags).

### Tests
- Ensure each method:
  - calls the function field when set
  - returns `ErrNotMocked` when unset
- ValidateSession default behavior returns active
- HydrateSessionForTest sets `auth.Set` and `auth.SetPrincipal` correctly and disables passive expiry

### Exit criteria
- Test kit enables unit tests in downstream apps with minimal boilerplate.

---

## 15) Documentation, Examples, and Integration Testing (Phase 13)

### Deliverables
- `README.md` and godoc updated to reflect the final API and wiring.
- Optional integration tests behind a build tag (not required for default unit test runs).

### Tasks
1. README:
   - environment variables (from spec Part 2)
   - wiring example (server middleware + mux + session bridge + authcheck)
   - operational guardrails (sticky sessions vs DisableRefreshInMiddleware)
   - security posture summary (no token storage in session KV, cookie encryption, open redirect rules)
2. Add `Example...` tests (in `_test.go`) for:
   - standard Vango wiring
   - using `CurrentIdentity` in components
   - verifying permission in an Action work function with `IdentityFromContext`
3. Integration tests (optional):
   - behind `//go:build integration`
   - require env vars: `WORKOS_API_KEY`, `WORKOS_CLIENT_ID`, etc.
   - cover:
     - JWKS fetch works and VerifyAccessToken passes for a real token (may be hard without interactive auth)
     - webhook verify can be validated against known samples (if WorkOS provides test vectors)

### Exit criteria
- Package is self-explanatory for Vango app developers, including pitfalls and deployment guidance.

---

## 16) CI/Release Readiness (Phase 14)

### Deliverables
- CI runs unit tests and vet reliably.
- Release notes/changelog discipline established.

### Tasks
1. CI:
   - `go test ./...`
   - `go vet ./...`
   - ensure tests do not require network or secrets by default
2. Versioning:
   - semver tags
   - define compatibility policy:
     - public API changes follow semver
     - WorkOS SDK v6 compatibility pinned in `go.mod`
3. Security checklist:
   - grep tests for accidental token echo in error strings and responses
   - ensure handler responses do not reflect cookies/tokens
   - ensure `Client.Config()` redacts secrets

### Exit criteria
- A new version can be tagged with high confidence and minimal manual steps.

---

## 17) Recommended Implementation Sequencing (PR-sized increments)

This sequencing keeps risk low and review crisp:

1. **PR A: Module + public types/interfaces**
   - go.mod/go.sum, doc/README skeleton, interfaces/types compiled
2. **PR B: Config validation + SafeError + cookie helpers**
   - proves W2/W3 and redaction
3. **PR C: JWKS + VerifyAccessToken**
   - proves W4 with httptest JWKS
4. **PR D: Refresh + session validation**
   - proves W5 and caching behavior
5. **PR E: AuthKit handlers**
   - callback flow, open redirect prevention, signed-out page/script
6. **PR F: HTTP middleware**
   - integrates cookie+jwt+refresh; attaches Identity to context
7. **PR G: Vango bridge + revalidation config**
   - strict resume semantics, AuthCheck behavior
8. **PR H: Enterprise read APIs + audit logs**
   - conversions, no-op audit logs by default
9. **PR I: Webhooks + admin portal**
10. **PR J: Test kit + examples**

---

## 18) Invariants → Tests Matrix (Implementation Checklist)

Use this as an audit trail:

- **W1 (Tokens are cookie-only)**
  - Tests: middleware/handlers never store tokens in session; cookie helpers don’t log; scan errors/responses for token substrings.
- **W2 (Session cookie encryption)**
  - Tests: roundtrip, wrong secret/AAD/version, fallback decryption.
- **W3 (State cookie CSRF)**
  - Tests: callback rejects invalid state; clears cookie after success; MaxAge enforced.
- **W4 (JWT verification + JWKS rotation)**
  - Tests: mint RS256 tokens; validate iss/aud/sub/sid; unknown kid triggers JWKS force refresh once.
- **W5 (Refresh single-flight)**
  - Tests: concurrency test ensures single upstream refresh call.
- **W6 (Resume + periodic revalidation)**
  - Tests: bridge rehydrates and rejects inactive; AuthCheck config values and check semantics.
- **W7 (Middleware is not route protection)**
  - Tests: middleware attaches or clears cookie only; does not redirect/deny by path.
- **W8 (Webhook verification)**
  - Tests: invalid signature 401; body limit; routing correctness.
- **W9 (Open redirect prevention)**
  - Tests: absolute-path ok; `//evil.com` rejected; absolute URL only if origin matches BaseURL.
- **W10 (Test kit contract)**
  - Tests: ErrNotMocked defaults; ValidateSession and EmitAuditEvent defaults.
