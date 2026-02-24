package workos

import (
	"context"
	"errors"

	"github.com/workos/workos-go/v6/pkg/usermanagement"
)

type fakeUMClient struct {
	authenticateWithRefreshTokenFunc func(ctx context.Context, opts usermanagement.AuthenticateWithRefreshTokenOpts) (usermanagement.RefreshAuthenticationResponse, error)
	listSessionsFunc                 func(ctx context.Context, userID string, opts usermanagement.ListSessionsOpts) (usermanagement.ListSessionsResponse, error)
	revokeSessionFunc                func(ctx context.Context, opts usermanagement.RevokeSessionOpts) error
}

func (*fakeUMClient) privateUMClient() {}

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
