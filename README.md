# vango-workos

`vango-workos` is the native WorkOS integration for Vango applications.

This repository currently includes the PR A-D foundation:
- public interfaces and normalized domain types
- strict config validation and safe defaults
- secret-safe error wrapper
- encrypted session-cookie and state-cookie helpers
- JWKS caching and local access-token verification
- refresh-token single-flight and session validation/revocation primitives

## Security posture

- Access and refresh tokens are stored only in the encrypted session cookie.
- Cookie payloads are encrypted with AES-256-GCM and bound to the cookie name.
- Error messages returned by sensitive helpers are safe to log by default.

## Status

This package is under active phased implementation. The current scope does not yet include middleware, handlers, bridge wiring, webhook routing, or most WorkOS read/API method implementations.
