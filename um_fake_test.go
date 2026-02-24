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
	getUserFunc                      func(ctx context.Context, opts usermanagement.GetUserOpts) (usermanagement.User, error)
	listUsersFunc                    func(ctx context.Context, opts usermanagement.ListUsersOpts) (usermanagement.ListUsersResponse, error)
	updateUserFunc                   func(ctx context.Context, opts usermanagement.UpdateUserOpts) (usermanagement.User, error)
	deleteUserFunc                   func(ctx context.Context, opts usermanagement.DeleteUserOpts) error
	listOrganizationMembershipsFunc  func(ctx context.Context, opts usermanagement.ListOrganizationMembershipsOpts) (usermanagement.ListOrganizationMembershipsResponse, error)
	getOrganizationMembershipFunc    func(ctx context.Context, opts usermanagement.GetOrganizationMembershipOpts) (usermanagement.OrganizationMembership, error)
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

func (f *fakeUMClient) GetUser(ctx context.Context, opts usermanagement.GetUserOpts) (usermanagement.User, error) {
	if f.getUserFunc == nil {
		return usermanagement.User{}, errors.New("not mocked")
	}
	return f.getUserFunc(ctx, opts)
}

func (f *fakeUMClient) ListUsers(ctx context.Context, opts usermanagement.ListUsersOpts) (usermanagement.ListUsersResponse, error) {
	if f.listUsersFunc == nil {
		return usermanagement.ListUsersResponse{}, errors.New("not mocked")
	}
	return f.listUsersFunc(ctx, opts)
}

func (f *fakeUMClient) UpdateUser(ctx context.Context, opts usermanagement.UpdateUserOpts) (usermanagement.User, error) {
	if f.updateUserFunc == nil {
		return usermanagement.User{}, errors.New("not mocked")
	}
	return f.updateUserFunc(ctx, opts)
}

func (f *fakeUMClient) DeleteUser(ctx context.Context, opts usermanagement.DeleteUserOpts) error {
	if f.deleteUserFunc == nil {
		return errors.New("not mocked")
	}
	return f.deleteUserFunc(ctx, opts)
}

func (f *fakeUMClient) ListOrganizationMemberships(ctx context.Context, opts usermanagement.ListOrganizationMembershipsOpts) (usermanagement.ListOrganizationMembershipsResponse, error) {
	if f.listOrganizationMembershipsFunc == nil {
		return usermanagement.ListOrganizationMembershipsResponse{}, errors.New("not mocked")
	}
	return f.listOrganizationMembershipsFunc(ctx, opts)
}

func (f *fakeUMClient) GetOrganizationMembership(ctx context.Context, opts usermanagement.GetOrganizationMembershipOpts) (usermanagement.OrganizationMembership, error) {
	if f.getOrganizationMembershipFunc == nil {
		return usermanagement.OrganizationMembership{}, errors.New("not mocked")
	}
	return f.getOrganizationMembershipFunc(ctx, opts)
}
