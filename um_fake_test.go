package workos

import (
	"context"
	"errors"
	"net/url"

	"github.com/workos/workos-go/v6/pkg/usermanagement"
)

type fakeUMClient struct {
	getAuthorizationURLFunc          func(opts usermanagement.GetAuthorizationURLOpts) (*url.URL, error)
	authenticateWithCodeFunc         func(ctx context.Context, opts usermanagement.AuthenticateWithCodeOpts) (usermanagement.AuthenticateResponse, error)
	getLogoutURLFunc                 func(opts usermanagement.GetLogoutURLOpts) (*url.URL, error)
	authenticateWithRefreshTokenFunc func(ctx context.Context, opts usermanagement.AuthenticateWithRefreshTokenOpts) (usermanagement.RefreshAuthenticationResponse, error)
	listSessionsFunc                 func(ctx context.Context, userID string, opts usermanagement.ListSessionsOpts) (usermanagement.ListSessionsResponse, error)
	revokeSessionFunc                func(ctx context.Context, opts usermanagement.RevokeSessionOpts) error
}

func (*fakeUMClient) privateUMClient() {}

func (f *fakeUMClient) GetAuthorizationURL(opts usermanagement.GetAuthorizationURLOpts) (*url.URL, error) {
	if f.getAuthorizationURLFunc == nil {
		return nil, errors.New("not mocked")
	}
	return f.getAuthorizationURLFunc(opts)
}

func (f *fakeUMClient) AuthenticateWithCode(ctx context.Context, opts usermanagement.AuthenticateWithCodeOpts) (usermanagement.AuthenticateResponse, error) {
	if f.authenticateWithCodeFunc == nil {
		return usermanagement.AuthenticateResponse{}, errors.New("not mocked")
	}
	return f.authenticateWithCodeFunc(ctx, opts)
}

func (f *fakeUMClient) GetLogoutURL(opts usermanagement.GetLogoutURLOpts) (*url.URL, error) {
	if f.getLogoutURLFunc == nil {
		return nil, errors.New("not mocked")
	}
	return f.getLogoutURLFunc(opts)
}

func (f *fakeUMClient) AuthenticateWithRefreshToken(ctx context.Context, opts usermanagement.AuthenticateWithRefreshTokenOpts) (usermanagement.RefreshAuthenticationResponse, error) {
	if f.authenticateWithRefreshTokenFunc == nil {
		return usermanagement.RefreshAuthenticationResponse{}, errors.New("not mocked")
	}
	return f.authenticateWithRefreshTokenFunc(ctx, opts)
}

func (f *fakeUMClient) ListSessions(ctx context.Context, userID string, opts usermanagement.ListSessionsOpts) (usermanagement.ListSessionsResponse, error) {
	if f.listSessionsFunc == nil {
		return usermanagement.ListSessionsResponse{}, errors.New("not mocked")
	}
	return f.listSessionsFunc(ctx, userID, opts)
}

func (f *fakeUMClient) RevokeSession(ctx context.Context, opts usermanagement.RevokeSessionOpts) error {
	if f.revokeSessionFunc == nil {
		return errors.New("not mocked")
	}
	return f.revokeSessionFunc(ctx, opts)
}
