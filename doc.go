// Package workos provides a native WorkOS integration for Vango.
//
// The package bridges HTTP-boundary WorkOS authentication into Vango's
// long-lived session model:
//   - Identity is validated at the HTTP boundary and projected into runtime-only
//     Vango auth state during session start/resume.
//   - Access and refresh tokens are stored only in the encrypted session cookie.
//     Tokens must not be stored in Vango session KV.
//   - Blocking WorkOS API calls belong in HTTP handlers, Resource loaders, or
//     Action work functions, never on the Vango session loop.
package workos
