package workos

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/vango-go/vango"
	"github.com/vango-go/vango/pkg/auth"
)

func TestTestAuth_ImplementsAuth(t *testing.T) {
	var _ Auth = (*TestAuth)(nil)
}

func TestTestAuth_UnsetMethodsReturnErrNotMocked(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name string
		call func(*TestAuth) error
	}{
		{
			name: "VerifyAccessToken",
			call: func(m *TestAuth) error {
				_, err := m.VerifyAccessToken(context.Background(), "access")
				return err
			},
		},
		{
			name: "RefreshTokens",
			call: func(m *TestAuth) error {
				_, err := m.RefreshTokens(context.Background(), "refresh")
				return err
			},
		},
		{
			name: "RevokeSession",
			call: func(m *TestAuth) error {
				return m.RevokeSession(context.Background(), "session")
			},
		},
		{
			name: "GetUser",
			call: func(m *TestAuth) error {
				_, err := m.GetUser(context.Background(), "user")
				return err
			},
		},
		{
			name: "ListUsers",
			call: func(m *TestAuth) error {
				_, err := m.ListUsers(context.Background(), ListUsersOpts{})
				return err
			},
		},
		{
			name: "UpdateUser",
			call: func(m *TestAuth) error {
				_, err := m.UpdateUser(context.Background(), "user", UpdateUserOpts{})
				return err
			},
		},
		{
			name: "DeleteUser",
			call: func(m *TestAuth) error {
				return m.DeleteUser(context.Background(), "user")
			},
		},
		{
			name: "GetOrganization",
			call: func(m *TestAuth) error {
				_, err := m.GetOrganization(context.Background(), "org")
				return err
			},
		},
		{
			name: "ListOrganizations",
			call: func(m *TestAuth) error {
				_, err := m.ListOrganizations(context.Background(), ListOrganizationsOpts{})
				return err
			},
		},
		{
			name: "ListOrganizationMemberships",
			call: func(m *TestAuth) error {
				_, err := m.ListOrganizationMemberships(context.Background(), ListMembershipsOpts{})
				return err
			},
		},
		{
			name: "GetOrganizationMembership",
			call: func(m *TestAuth) error {
				_, err := m.GetOrganizationMembership(context.Background(), "membership")
				return err
			},
		},
		{
			name: "HasRole",
			call: func(m *TestAuth) error {
				_, err := m.HasRole(context.Background(), "user", "org", "role")
				return err
			},
		},
		{
			name: "ListRoles",
			call: func(m *TestAuth) error {
				_, err := m.ListRoles(context.Background(), ListRolesOpts{})
				return err
			},
		},
		{
			name: "ListConnections",
			call: func(m *TestAuth) error {
				_, err := m.ListConnections(context.Background(), ListConnectionsOpts{})
				return err
			},
		},
		{
			name: "ListDirectories",
			call: func(m *TestAuth) error {
				_, err := m.ListDirectories(context.Background(), ListDirectoriesOpts{})
				return err
			},
		},
		{
			name: "ListDirectoryUsers",
			call: func(m *TestAuth) error {
				_, err := m.ListDirectoryUsers(context.Background(), ListDirectoryUsersOpts{})
				return err
			},
		},
		{
			name: "ListDirectoryGroups",
			call: func(m *TestAuth) error {
				_, err := m.ListDirectoryGroups(context.Background(), ListDirectoryGroupsOpts{})
				return err
			},
		},
		{
			name: "ValidateSession default is active",
			call: func(m *TestAuth) error {
				info, err := m.ValidateSession(context.Background(), "user", "session")
				if err != nil {
					return err
				}
				if info == nil || !info.Active || info.UserID != "user" || info.SessionID != "session" {
					return errors.New("unexpected ValidateSession default response")
				}
				if !info.ExpiresAt.After(now) {
					return errors.New("ValidateSession default expiry should be in the future")
				}
				return nil
			},
		},
		{
			name: "EmitAuditEvent default is no-op",
			call: func(m *TestAuth) error {
				return m.EmitAuditEvent(context.Background(), AuditEvent{})
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mock := &TestAuth{}
			err := tc.call(mock)
			if tc.name == "ValidateSession default is active" || tc.name == "EmitAuditEvent default is no-op" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrNotMocked) {
				t.Fatalf("err=%v, want ErrNotMocked", err)
			}
		})
	}
}

func TestTestAuth_MethodOverrides(t *testing.T) {
	t.Run("VerifyAccessToken", func(t *testing.T) {
		mock := &TestAuth{
			VerifyAccessTokenFunc: func(_ context.Context, accessToken string) (*AccessTokenClaims, error) {
				if accessToken != "access_1" {
					t.Fatalf("accessToken = %q", accessToken)
				}
				return &AccessTokenClaims{UserID: "user_1"}, nil
			},
		}
		got, err := mock.VerifyAccessToken(context.Background(), "access_1")
		if err != nil || got == nil || got.UserID != "user_1" {
			t.Fatalf("got=%#v err=%v", got, err)
		}
	})

	t.Run("RefreshTokens", func(t *testing.T) {
		mock := &TestAuth{
			RefreshTokensFunc: func(_ context.Context, refreshToken string) (*TokenSet, error) {
				if refreshToken != "refresh_1" {
					t.Fatalf("refreshToken = %q", refreshToken)
				}
				return &TokenSet{AccessToken: "a2", RefreshToken: "r2"}, nil
			},
		}
		got, err := mock.RefreshTokens(context.Background(), "refresh_1")
		if err != nil || got == nil || got.AccessToken != "a2" || got.RefreshToken != "r2" {
			t.Fatalf("got=%#v err=%v", got, err)
		}
	})

	t.Run("ValidateSession", func(t *testing.T) {
		mock := &TestAuth{
			ValidateSessionFunc: func(_ context.Context, userID, sessionID string) (*SessionInfo, error) {
				if userID != "user_1" || sessionID != "session_1" {
					t.Fatalf("userID=%q sessionID=%q", userID, sessionID)
				}
				return &SessionInfo{UserID: userID, SessionID: sessionID, Active: false}, nil
			},
		}
		got, err := mock.ValidateSession(context.Background(), "user_1", "session_1")
		if err != nil || got == nil || got.Active {
			t.Fatalf("got=%#v err=%v", got, err)
		}
	})

	t.Run("RevokeSession", func(t *testing.T) {
		called := false
		mock := &TestAuth{
			RevokeSessionFunc: func(_ context.Context, sessionID string) error {
				called = true
				if sessionID != "session_1" {
					t.Fatalf("sessionID = %q", sessionID)
				}
				return nil
			},
		}
		if err := mock.RevokeSession(context.Background(), "session_1"); err != nil {
			t.Fatalf("RevokeSession error: %v", err)
		}
		if !called {
			t.Fatal("expected RevokeSessionFunc to be called")
		}
	})

	t.Run("Users", func(t *testing.T) {
		mock := &TestAuth{
			GetUserFunc: func(_ context.Context, userID string) (*User, error) {
				return &User{ID: userID}, nil
			},
			ListUsersFunc: func(_ context.Context, opts ListUsersOpts) (*UserList, error) {
				if opts.Email != "a@example.com" {
					t.Fatalf("email = %q", opts.Email)
				}
				return &UserList{Data: []User{{ID: "u1"}}}, nil
			},
			UpdateUserFunc: func(_ context.Context, userID string, opts UpdateUserOpts) (*User, error) {
				if userID != "u1" {
					t.Fatalf("userID = %q", userID)
				}
				return &User{ID: "u1"}, nil
			},
			DeleteUserFunc: func(_ context.Context, userID string) error {
				if userID != "u1" {
					t.Fatalf("userID = %q", userID)
				}
				return nil
			},
		}

		if got, err := mock.GetUser(context.Background(), "u1"); err != nil || got.ID != "u1" {
			t.Fatalf("GetUser got=%#v err=%v", got, err)
		}
		if got, err := mock.ListUsers(context.Background(), ListUsersOpts{Email: "a@example.com"}); err != nil || len(got.Data) != 1 {
			t.Fatalf("ListUsers got=%#v err=%v", got, err)
		}
		if got, err := mock.UpdateUser(context.Background(), "u1", UpdateUserOpts{}); err != nil || got.ID != "u1" {
			t.Fatalf("UpdateUser got=%#v err=%v", got, err)
		}
		if err := mock.DeleteUser(context.Background(), "u1"); err != nil {
			t.Fatalf("DeleteUser err=%v", err)
		}
	})

	t.Run("Organizations and memberships", func(t *testing.T) {
		mock := &TestAuth{
			GetOrganizationFunc: func(_ context.Context, orgID string) (*Organization, error) {
				return &Organization{ID: orgID}, nil
			},
			ListOrganizationsFunc: func(context.Context, ListOrganizationsOpts) (*OrganizationList, error) {
				return &OrganizationList{Data: []Organization{{ID: "org_1"}}}, nil
			},
			ListOrganizationMembershipsFunc: func(context.Context, ListMembershipsOpts) (*MembershipList, error) {
				return &MembershipList{Data: []Membership{{ID: "om_1"}}}, nil
			},
			GetOrganizationMembershipFunc: func(_ context.Context, membershipID string) (*Membership, error) {
				return &Membership{ID: membershipID}, nil
			},
		}

		if got, err := mock.GetOrganization(context.Background(), "org_1"); err != nil || got.ID != "org_1" {
			t.Fatalf("GetOrganization got=%#v err=%v", got, err)
		}
		if got, err := mock.ListOrganizations(context.Background(), ListOrganizationsOpts{}); err != nil || len(got.Data) != 1 {
			t.Fatalf("ListOrganizations got=%#v err=%v", got, err)
		}
		if got, err := mock.ListOrganizationMemberships(context.Background(), ListMembershipsOpts{}); err != nil || len(got.Data) != 1 {
			t.Fatalf("ListOrganizationMemberships got=%#v err=%v", got, err)
		}
		if got, err := mock.GetOrganizationMembership(context.Background(), "om_1"); err != nil || got.ID != "om_1" {
			t.Fatalf("GetOrganizationMembership got=%#v err=%v", got, err)
		}
	})

	t.Run("RBAC", func(t *testing.T) {
		mock := &TestAuth{
			HasRoleFunc: func(_ context.Context, userID, orgID, roleSlug string) (bool, error) {
				if userID != "u1" || orgID != "o1" || roleSlug != "admin" {
					t.Fatalf("unexpected args user=%q org=%q role=%q", userID, orgID, roleSlug)
				}
				return true, nil
			},
			ListRolesFunc: func(_ context.Context, _ ListRolesOpts) (*RoleList, error) {
				return &RoleList{Data: []Role{{Slug: "admin"}}}, nil
			},
		}
		ok, err := mock.HasRole(context.Background(), "u1", "o1", "admin")
		if err != nil || !ok {
			t.Fatalf("HasRole ok=%v err=%v", ok, err)
		}
		list, err := mock.ListRoles(context.Background(), ListRolesOpts{})
		if err != nil || len(list.Data) != 1 || list.Data[0].Slug != "admin" {
			t.Fatalf("ListRoles list=%#v err=%v", list, err)
		}
	})

	t.Run("EmitAuditEvent", func(t *testing.T) {
		called := false
		mock := &TestAuth{
			EmitAuditEventFunc: func(_ context.Context, event AuditEvent) error {
				called = true
				if event.Action != "project.deleted" {
					t.Fatalf("action=%q", event.Action)
				}
				return nil
			},
		}
		if err := mock.EmitAuditEvent(context.Background(), AuditEvent{Action: "project.deleted"}); err != nil {
			t.Fatalf("EmitAuditEvent err=%v", err)
		}
		if !called {
			t.Fatal("expected EmitAuditEventFunc to be called")
		}
	})

	t.Run("SSO and directory sync", func(t *testing.T) {
		mock := &TestAuth{
			ListConnectionsFunc: func(context.Context, ListConnectionsOpts) (*ConnectionList, error) {
				return &ConnectionList{Data: []Connection{{ID: "conn_1"}}}, nil
			},
			ListDirectoriesFunc: func(context.Context, ListDirectoriesOpts) (*DirectoryList, error) {
				return &DirectoryList{Data: []Directory{{ID: "dir_1"}}}, nil
			},
			ListDirectoryUsersFunc: func(context.Context, ListDirectoryUsersOpts) (*DirectoryUserList, error) {
				return &DirectoryUserList{Data: []DirectoryUser{{ID: "du_1"}}}, nil
			},
			ListDirectoryGroupsFunc: func(context.Context, ListDirectoryGroupsOpts) (*DirectoryGroupList, error) {
				return &DirectoryGroupList{Data: []DirectoryGroup{{ID: "dg_1"}}}, nil
			},
		}

		if got, err := mock.ListConnections(context.Background(), ListConnectionsOpts{}); err != nil || len(got.Data) != 1 {
			t.Fatalf("ListConnections got=%#v err=%v", got, err)
		}
		if got, err := mock.ListDirectories(context.Background(), ListDirectoriesOpts{}); err != nil || len(got.Data) != 1 {
			t.Fatalf("ListDirectories got=%#v err=%v", got, err)
		}
		if got, err := mock.ListDirectoryUsers(context.Background(), ListDirectoryUsersOpts{}); err != nil || len(got.Data) != 1 {
			t.Fatalf("ListDirectoryUsers got=%#v err=%v", got, err)
		}
		if got, err := mock.ListDirectoryGroups(context.Background(), ListDirectoryGroupsOpts{}); err != nil || len(got.Data) != 1 {
			t.Fatalf("ListDirectoryGroups got=%#v err=%v", got, err)
		}
	})
}

func TestTestIdentity_DefaultsAndOverrides(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		i := TestIdentity()
		if i.UserID != "user_test_001" || i.Email != "test@example.com" || i.Name != "Test User" {
			t.Fatalf("unexpected defaults: %#v", i)
		}
		if i.OrgID != "org_test_001" || i.SessionID != "session_test_001" {
			t.Fatalf("unexpected defaults: %#v", i)
		}
		if len(i.Roles) != 1 || i.Roles[0] != "member" {
			t.Fatalf("Roles=%#v", i.Roles)
		}
		if i.Permissions != nil || i.Entitlements != nil {
			t.Fatalf("expected nil permissions/entitlements: %#v", i)
		}
		if !i.ExpiresAt.After(time.Now()) {
			t.Fatalf("ExpiresAt=%v should be in the future", i.ExpiresAt)
		}
	})

	t.Run("overrides", func(t *testing.T) {
		i := TestIdentity(
			WithUserID("user_override"),
			WithEmail("override@example.com"),
			WithOrgID("org_override"),
			WithRoles("admin", "owner"),
			WithPermissions("projects:delete"),
			WithEntitlements("feature:enterprise"),
		)
		if i.UserID != "user_override" || i.Email != "override@example.com" || i.OrgID != "org_override" {
			t.Fatalf("unexpected identity: %#v", i)
		}
		if len(i.Roles) != 2 || i.Roles[0] != "admin" || i.Roles[1] != "owner" {
			t.Fatalf("roles=%#v", i.Roles)
		}
		if len(i.Permissions) != 1 || i.Permissions[0] != "projects:delete" {
			t.Fatalf("permissions=%#v", i.Permissions)
		}
		if len(i.Entitlements) != 1 || i.Entitlements[0] != "feature:enterprise" {
			t.Fatalf("entitlements=%#v", i.Entitlements)
		}
	})
}

func TestHydrateSessionForTest(t *testing.T) {
	t.Run("nil session is safe", func(t *testing.T) {
		HydrateSessionForTest(nil, TestIdentity())
	})

	t.Run("nil identity uses default", func(t *testing.T) {
		sess := &vango.Session{}
		HydrateSessionForTest(sess, nil)

		stored, ok := sess.Get(auth.SessionKey).(*Identity)
		if !ok || stored == nil {
			t.Fatal("expected default identity in session")
		}
		if stored.UserID != "user_test_001" {
			t.Fatalf("UserID=%q", stored.UserID)
		}

		p, ok := sess.Get(auth.SessionKeyPrincipal).(auth.Principal)
		if !ok {
			t.Fatal("expected principal in session")
		}
		if p.ID != stored.UserID || p.Email != stored.Email || p.TenantID != stored.OrgID || p.SessionID != stored.SessionID {
			t.Fatalf("principal mismatch: %#v stored=%#v", p, stored)
		}
		if p.ExpiresAtUnixMs != 0 {
			t.Fatalf("ExpiresAtUnixMs=%d, want 0", p.ExpiresAtUnixMs)
		}
		if expiry := sess.Get(auth.SessionKeyExpiryUnixMs); expiry != nil {
			t.Fatalf("expected no passive expiry key, got %#v", expiry)
		}
	})

	t.Run("custom identity maps into auth projection", func(t *testing.T) {
		sess := &vango.Session{}
		identity := TestIdentity(
			WithUserID("user_custom"),
			WithEmail("custom@example.com"),
			WithOrgID("org_custom"),
			WithRoles("admin"),
		)
		identity.Name = "Custom User"
		identity.SessionID = "sess_custom"

		HydrateSessionForTest(sess, identity)

		stored, ok := sess.Get(auth.SessionKey).(*Identity)
		if !ok || stored == nil || stored.UserID != "user_custom" {
			t.Fatalf("stored=%#v", stored)
		}

		p, ok := sess.Get(auth.SessionKeyPrincipal).(auth.Principal)
		if !ok {
			t.Fatal("expected principal in session")
		}
		if p.ID != "user_custom" || p.Email != "custom@example.com" || p.Name != "Custom User" || p.TenantID != "org_custom" || p.SessionID != "sess_custom" {
			t.Fatalf("principal=%#v", p)
		}
		if len(p.Roles) != 1 || p.Roles[0] != "admin" {
			t.Fatalf("roles=%#v", p.Roles)
		}
		if p.ExpiresAtUnixMs != 0 {
			t.Fatalf("ExpiresAtUnixMs=%d, want 0", p.ExpiresAtUnixMs)
		}
	})
}
