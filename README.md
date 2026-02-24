# vango-workos

`vango-workos` is the native WorkOS integration for Vango applications.

This repository currently includes the PR A-H foundation:
- public interfaces and normalized domain types
- strict config validation and safe defaults
- secret-safe error wrapper
- encrypted session-cookie and state-cookie helpers
- JWKS caching and local access-token verification
- refresh-token single-flight and session validation/revocation primitives
- AuthKit HTTP handlers (signin/signup/callback/logout/signed-out)
- net/http boundary middleware for cookie validation, refresh, and identity projection
- Vango session bridge hooks (`OnSessionStart`/`OnSessionResume`) with strict resume revalidation
- periodic AuthCheck revalidation config and identity helper accessors
- enterprise/read APIs for users, organizations, memberships, roles, SSO, and Directory Sync
- audit log emission with no-op default, timestamp defaulting, and auto idempotency keys

## Security posture

- Access and refresh tokens are stored only in the encrypted session cookie.
- Cookie payloads are encrypted with AES-256-GCM and bound to the cookie name.
- Error messages returned by sensitive helpers are safe to log by default.

## Status

This package is under active phased implementation. The current scope does not yet include webhook routing, admin portal helpers, and test kit utilities (PR I+).
