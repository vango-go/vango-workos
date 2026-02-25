# vango-workos “100% Finished” Report (Pending Action Items)

Date: 2026-02-24  
Workspace: `/Users/collinshill/Documents/vango/vango-workos`  
Module: `github.com/vango-go/vango-workos` (WorkOS SDK `github.com/workos/workos-go/v6@v6.4.0`)

This document is a maximally thorough, **actionable** checklist to take `vango-workos` from “PR J complete / tests passing” to **“100% finished according to the spec”**.

It focuses on:
- **Spec compliance gaps** (true mismatches).
- **Spec ambiguities / spec bugs** (where the spec is currently not implementable or contradicts the WorkOS SDK surface).
- **Production hardening gaps** explicitly called out in the phased plan (even when not strictly required to compile/run).
- **Concrete acceptance criteria + tests** required to confidently claim “done”.

---

## Completion Update (2026-02-25)

The blocking and hardening items in this report are now implemented in `vango-workos`:
- Middleware now branches by typed error taxonomy (`errors.Is`) instead of brittle string comparisons.
- JWT/JWKS verification exposes stable sentinel errors (`ErrAccessTokenExpired`, `ErrAccessTokenInvalid`, `ErrJWKSUnavailable`).
- Cookie policy enforces browser invariant `SameSite=None => Secure=true` for session and state cookies.
- `Config` and `New` now include strict `BaseURL` validation (absolute URL + `http/https` + host).
- JWKS fetches are bounded by `JWKSFetchTimeout` (default `5s`) and tested.
- Session list cache is bounded by `SessionListCacheMaxUsers` (default `10000`) with deterministic eviction tests.
- Admin Portal intent coverage includes `domain_verification`.
- `WORKOS_INTEGRATION_SPEC.md` is updated to match SDK v6 constraints (AuthKit provider selector, portal package usage, role-listing limits).

Validation:
- `go test ./...` passes.
- `go vet ./...` passes.

---

## 0) Definition of “100% Finished”

For this package, “100% finished” should mean:

1) **Spec-aligned public contract**  
   - The public Go API surface (`Config`, `Client`, interfaces, domain types, handlers, middleware, Vango bridge, webhook handler, admin portal, test kit) matches `WORKOS_INTEGRATION_SPEC.md`.
   - Where the WorkOS SDK does not support something, the spec is updated to match the real SDK constraints or the public API is adjusted accordingly (breaking changes allowed if they improve correctness).

2) **Operationally production-safe by default**  
   - No requests can hang indefinitely due to missing timeouts.
   - In-memory caches do not grow without bound.
   - Cookie semantics are browser-valid (e.g., SameSite=None requires Secure).

3) **Deterministic tests validate the invariants**  
   - `go test ./...` and `go vet ./...` pass.
   - Tests explicitly cover the “must not leak secrets” posture and the auth/session lifecycle semantics.

---

## 1) Current State Snapshot (What’s Already Done)

All major Phase 1 deliverables exist and are tested:
- Config validation/defaults + redaction: `client.go`
- Cookie + state cookies (AES-256-GCM + AAD binding + fallback keys): `cookie.go`
- JWKS fetch/cache + JWT verification: `jwks.go`, `jwt.go`
- Refresh single-flight + sessions list caching + revoke: `refresh.go`, `sessions.go`
- AuthKit handlers: `handlers.go`
- HTTP boundary middleware (cookie → verify/refresh → context identity): `middleware.go`
- Vango lifecycle bridge + periodic revalidation config: `bridge.go`
- Enterprise read APIs + audit logs: `enterprise.go`
- Webhook verification + routing: `webhook.go`
- Admin portal links: `admin_portal.go`
- Test kit: `testkit.go`

Local validation currently passes:
- `go test ./...`
- `go vet ./...`

---

## 2) Key Reality Check: WorkOS SDK Constraints That Impact the Spec

These items matter because the spec must not promise impossible semantics.

### 2.1 AuthKit authorization URL requires a selector (provider/org/connection)

WorkOS Go SDK v6 docs for `GetAuthorizationURL` state:

> “To indicate the connection to use for authentication, use one of the following connection selectors: `connection_id`, `organization_id`, or `provider`. These connection selectors are mutually exclusive, and **exactly one must be provided**.”

Therefore, the spec’s earlier example “`Provider: ""` (empty)” is **not a valid SDK call** unless another selector is set.

The SDK also documents:
- `ScreenHint` is used “when the provider is Authkit.”

So if this integration intends to use AuthKit hosted UI, the spec should be **normative** about using `Provider: "authkit"` (or whatever exact value the SDK expects).

### 2.2 Organization role listing supports only `OrganizationID` (no pagination/order)

WorkOS SDK v6 `organizations.ListOrganizationRolesOpts` contains only:
- `OrganizationID string`

So the spec’s `ListRolesOpts` fields `Before/After/Order` cannot be passed through to WorkOS for org-scoped roles. At most, `Limit` can be applied client-side after retrieving the full list.

This impacts what it means to be “spec complete” for `ListRoles`.

### 2.3 Admin Portal link generation is in the `portal` package (SDK v6)

WorkOS SDK v6 has a dedicated `portal` package with `GenerateLink`. If the spec references `organizations.GeneratePortalLink`, that is spec drift (or was based on a prior SDK shape).

---

## 3) Pending Action Items (Master List)

The list below is ordered by “blocks claiming 100% finished” first.

Legend:
- **P0** = must-do to claim “100% finished”
- **P1** = should-do to be confidently production-ready per phased plan posture
- **P2** = high-value enhancements / tightening, but not strictly blocking

Each item includes:
- **Type**: Code / Spec / Both
- **Acceptance**: exact conditions for marking done
- **Tests**: what to add/adjust

---

## P0 — Blocking Items

### P0-1) Remove brittle string-compare in middleware; introduce typed/sentinel error taxonomy

**Type:** Code (and likely Spec clarification)  
**Where:** `middleware.go` compares `err.Error() == "workos: invalid access token"` (see `/Users/collinshill/Documents/vango/vango-workos/middleware.go:41`).  
**Problem:** This is a real correctness hazard:
- Any change to error strings breaks refresh behavior.
- The middleware cannot make stable decisions without knowing *why* verification failed (expired vs invalid signature vs JWKS fetch failure vs malformed JWT).

**Action:**
1) Introduce sentinel errors (exported or unexported—decide contract):
   - `ErrAccessTokenExpired`
   - `ErrAccessTokenInvalid`
   - `ErrJWKSUnavailable` (or `ErrJWKSFetchFailed`)
   - Optionally: `ErrJWTUnexpectedAlg`, `ErrJWTMissingKID`, `ErrJWTUnknownKID` (already present as vars, but not cleanly used as a policy taxonomy)
2) Update `VerifyAccessToken` to return (or wrap) these errors so callers can use `errors.Is`.
3) Update middleware to branch using `errors.Is`, not string equality.
4) Decide/define semantics for “JWKS fetch transient failure”:
   - Don’t clear cookie just because JWKS fetch failed.
   - Choose: treat request as unauthenticated for this request, or return 503 (spec currently implies pass-through unauthenticated, not hard fail).

**Acceptance:**
- `middleware.go` contains no `err.Error() == ...` branching.
- Middleware behavior is stable under error-message wording changes.
- A new test proves each branch:
  - expired → refresh attempted (if enabled + refresh present)
  - hard invalid (bad sig/issuer/audience) → cookie cleared
  - JWKS fetch failure → cookie not cleared (or explicitly spec’d behavior)

**Tests to add/adjust:**
- Add table tests in `middleware_test.go` to force each error class deterministically.
- Add unit tests for `VerifyAccessToken` returning the sentinel errors in the right circumstances.

---

### P0-2) Resolve CookieSecure default policy and make the spec *normative* (code+spec alignment)

**Type:** Both (policy decision)  
**Where:** `New` infers Secure based on `BaseURL` scheme (`client.go:92`); spec says “default Secure=true; set false only for local HTTP dev.”  

**Options:**

**Option A (spec-first strict security posture):**
- Keep spec: default `CookieSecure=true` always.
- Require explicit `CookieSecure=false` for local HTTP development.

**Option B (DX-first, deterministic, “native integration” friendly):**
- Define default as:
  - If user explicitly sets `CookieSecure`, honor it.
  - Else infer `CookieSecure = (BaseURL is https://)` (and maybe warn/log when BaseURL is http://).

**Must-add invariant regardless of option:**
- If `SameSite=None`, force `Secure=true` (browser requirement), otherwise auth breaks in modern browsers.

**Acceptance:**
- Spec and code agree on the exact defaulting behavior.
- “SameSite=None ⇒ Secure=true” is implemented and tested for both session cookie and state cookie.

**Tests to add/adjust:**
- Config tests verifying defaulting choice.
- Cookie attribute tests verifying SameSite=None forces Secure.

---

### P0-3) Fix spec mismatch for AuthKit Provider selector (spec bug); ensure code/spec align

**Type:** Spec (and optionally Code flexibility)  
**Where:**
- Implementation: `Provider: "authkit"` in `/Users/collinshill/Documents/vango/vango-workos/handlers.go:36` and `:63`.
- Spec example uses `Provider: ""` (empty) with the comment “AuthKit handles provider selection.”

**Reality:** WorkOS SDK requires exactly one selector (provider/connection_id/organization_id). Empty provider is not a valid selector.

**Action:**
- Update `WORKOS_INTEGRATION_SPEC.md` to be normative:
  - For AuthKit hosted auth, `Provider` must be `"authkit"` (or the correct constant/value per SDK).
  - Document how SSO is initiated via `ConnectionID` / `OrganizationID` selectors (if you intend to support that in this integration).

**Acceptance:**
- Spec no longer instructs invalid SDK usage.
- Existing implementation remains correct and tests remain valid.

**Tests:**
- Keep existing handler tests validating provider is `"authkit"`.

---

### P0-4) Decide what `ListRoles` contract *actually* is; align spec + code to SDK constraints

**Type:** Both  
**Where:** `enterprise.go` role methods and the spec’s `ListRolesOpts` definition.

**Issues:**
1) **Unsupported options:** WorkOS SDK org roles listing has no pagination/order params, so `Before/After/Order` cannot be honored.
2) **Environment roles:** SDK provides no environment roles list endpoint. Current code aggregates across orgs as a best-effort fallback, which may be:
   - expensive,
   - semantically wrong if env roles aren’t the union of org roles.

**Action (pick one path):**

**Path A: Narrow the public API to what WorkOS supports (preferred for correctness).**
- Replace `ListRoles(opts ListRolesOpts)` with:
  - `ListOrganizationRoles(ctx, orgID string) (*RoleList, error)` and apply `Limit` client-side if needed.
- Drop `Before/After/Order` from role listing opts entirely.
- If you still want “environment roles,” expose a separate method:
  - `ListEnvironmentRoles(ctx)` with explicit warnings/cost semantics, or omit entirely.

**Path B: Keep the method but make the spec explicit about limitations.**
- Keep `ListRolesOpts` but specify:
  - Only `OrganizationID` + `Limit` are supported.
  - `Before/After/Order` are ignored.
- For “environment roles,” document the best-effort scan and warn about cost; consider a config flag to disable that behavior to avoid surprising operators.

**Acceptance:**
- Spec and code agree on:
  - which fields are supported,
  - whether environment roles are supported,
  - cost/behavioral implications.
- There is no implied pagination ordering contract that cannot be met.

**Tests:**
- Keep and/or adjust `enterprise_test.go` to match the finalized contract.
- If environment role aggregation remains, add a test asserting the behavior is behind an explicit posture/flag (recommended).

---

### P0-5) Update Admin Portal spec to match SDK v6 `portal` package (and optionally expand intent constants)

**Type:** Spec (and optional code enhancement)  
**Where:** Code uses `portal.Client.GenerateLink`; spec text references orgs generation.

**Action:**
- Update `WORKOS_INTEGRATION_SPEC.md` to reference WorkOS SDK v6 `portal` package as the canonical implementation detail.
- Consider adding the missing intent supported by SDK v6 (`domain_verification`) if you want the integration to be “complete” relative to WorkOS Admin Portal intents (this is not required by current spec, but is a completeness consideration).

**Acceptance:**
- Spec describes the same SDK path used by the implementation.
- Tests remain green (`admin_portal_test.go` already asserts mapping and safe error wrapping).

---

## P1 — Production Hardening (Strongly Recommended / Plan-Aligned)

### P1-1) JWKS fetch must have bounded time (no indefinite hangs)

**Type:** Both (add config + implement)  
**Where:** `jwks.go` uses `http.DefaultClient.Do(req)` (see `/Users/collinshill/Documents/vango/vango-workos/jwks.go:63`). If the caller context has no deadline, this can hang.

**Action:**
- Introduce one of:
  - `Config.HTTPClient *http.Client` (used for JWKS and maybe other HTTP calls), or
  - `Config.JWKSHTTPClient *http.Client`, or
  - `Config.JWKSFetchTimeout time.Duration` and internally `http.Client{Timeout: ...}`.
- Default to a safe timeout (e.g., 5s) unless explicitly overridden.
- Ensure the timeout is actually enforced even when the inbound context lacks a deadline.

**Acceptance:**
- JWKS fetch is guaranteed to complete/fail within a bounded duration.
- A deterministic test proves timeout behavior using a server that never responds (or sleeps beyond timeout).

**Tests to add:**
- `jwks_test.go`: start `httptest.Server` that blocks; set timeout small; assert `getJWKS` returns within expected time and error is safe (no secrets).

---

### P1-2) Bound `sessionsCache` growth (no unbounded memory over time)

**Type:** Code (and optionally Spec hardening note)  
**Where:** `sessionsCache map[string]sessionListCacheEntry` grows by userID and is never pruned (`sessions.go:33+`).

**Action:**
- Add a bounded cache strategy. Minimal, effective options:
  1) **Max entries + opportunistic sweep**:
     - `Config.SessionListCacheMaxUsers int` (default maybe 10k or lower).
     - On insert, delete expired entries, and if still above max, evict oldest N (track timestamps).
  2) **Tiny LRU**:
     - Implement a simple LRU list keyed by userID.
- Ensure concurrency safety (existing mutex).

**Acceptance:**
- Cache cannot grow without bound by unique userIDs.
- Deterministic tests demonstrate eviction (insert > max; ensure size capped).

---

### P1-3) Add timeouts for refresh/session API calls made inside middleware (optional but recommended)

**Type:** Code (and optionally Spec)  
**Where:** Middleware calls `RefreshTokens` / `VerifyAccessToken` without applying a bounded timeout, relying on request context.

**Action:**
- Apply a short timeout for refresh exchange (distinct from session revalidation timeout):
  - `Config.MiddlewareTimeout time.Duration` or reuse `RevalidationTimeout` carefully.
- Ensure refresh cannot hang and stall HTTP requests indefinitely.

**Acceptance:**
- Middleware refresh and token verification are bounded in time even if upstream is slow.

---

## P2 — Tightening / Completeness Enhancements

### P2-1) Strengthen `BaseURL` validation to require absolute URL with scheme+host

**Type:** Code (and possibly Spec)  
**Where:** `New` only checks `url.Parse(cfg.BaseURL)` error; scheme-less strings parse without error.

**Action:**
- Require:
  - `u.Scheme` in `{http, https}`
  - `u.Host` non-empty
- This prevents surprising behavior in `isSafeRedirect` and other URL logic.

**Acceptance:**
- Invalid base URLs are rejected early with clear error messages.

---

### P2-2) Clarify and codify middleware behavior for different verification failures

**Type:** Spec + Code docs (after P0-1)  

Once you have sentinel errors, make the middleware’s policy explicit:
- hard invalid token → clear cookie → unauthenticated pass-through
- expired token → refresh (if enabled)
- JWKS unavailable → do not clear cookie; treat as unauthenticated (or 503, whichever is desired)

This turns a fragile implementation detail into a stable contract.

---

### P2-3) Consider validating cookie payload’s internal `V` field on decrypt

**Type:** Code (optional)  
**Where:** Cookie envelope has a version byte; payload also has `cookieSession.V` set to 1. The code does not currently validate payload `V`.

**Action:**
- Either remove the redundant `V` field (if not needed), or validate it on decrypt and treat mismatch as invalid cookie.

**Acceptance:**
- The versioning story is unambiguous (one version field, validated).

---

### P2-4) Expand Admin Portal intent constants to match SDK (optional completeness)

**Type:** Code + Spec (optional)  
**Where:** SDK supports `domain_verification` intent; current constants omit it.

**Action:**
- Add `AdminPortalDomainVerification` constant (if desired).
- Update spec accordingly.

---

## 4) Suggested “Done” Sequencing (Minimal Churn)

If the goal is to reach “100% finished” quickly while respecting “spec-first”:

1) **P0-1** sentinel errors + middleware branching by `errors.Is` (must-do).
2) **P0-3** fix spec on AuthKit provider selector (spec bug).
3) **P0-5** fix spec on Admin Portal SDK path (spec drift).
4) **P0-4** resolve `ListRoles` contract (this is the biggest “public contract” decision).
5) **P0-2** decide CookieSecure default policy + enforce SameSite=None ⇒ Secure.
6) **P1-1** JWKS fetch bounded timeout (must for production posture).
7) **P1-2** bound sessionsCache (must for long-running processes).
8) Optional P2 tightening items.

---

## 5) “Claiming 100% Finished” Checklist

Marking this integration as “100% finished” should require:

- [ ] Spec updated to reflect WorkOS SDK constraints (AuthKit provider selector; Admin Portal SDK path; roles options reality).
- [ ] Middleware decisions are stable via sentinel errors (`errors.Is`), no string compares.
- [ ] Cookie defaults and invariants are explicitly spec’d and implemented (including SameSite=None ⇒ Secure).
- [ ] JWKS fetch has a bounded timeout by default.
- [ ] Session list cache is bounded (max users + eviction strategy).
- [ ] `go test ./...` and `go vet ./...` pass.

---

## 6) Notes / Non-Goals (Still True)

Per the phased plan/spec, these remain out-of-scope for Phase 1 completion:
- Vango CLI scaffolding (`vango create --with workos`)
- `vango dev` WorkOS helpers and `vango workos ...` subcommands
