package workos

import "errors"

var (
	// ErrAccessTokenExpired indicates a token verification failure caused by expiry.
	ErrAccessTokenExpired = errors.New("workos: access token expired")
	// ErrAccessTokenInvalid indicates a non-expiry token verification failure.
	ErrAccessTokenInvalid = errors.New("workos: access token invalid")
	// ErrJWKSUnavailable indicates the verifier could not fetch/parse JWKS.
	ErrJWKSUnavailable = errors.New("workos: jwks unavailable")
)
