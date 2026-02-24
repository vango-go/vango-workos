package workos

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/workos/workos-go/v6/pkg/auditlogs"
	"github.com/workos/workos-go/v6/pkg/common"
	"github.com/workos/workos-go/v6/pkg/directorysync"
	"github.com/workos/workos-go/v6/pkg/organization_domains"
	"github.com/workos/workos-go/v6/pkg/organizations"
	"github.com/workos/workos-go/v6/pkg/roles"
	"github.com/workos/workos-go/v6/pkg/sso"
	"github.com/workos/workos-go/v6/pkg/usermanagement"
)

type fakeOrgsClient struct {
	getOrganizationFunc       func(ctx context.Context, opts organizations.GetOrganizationOpts) (organizations.Organization, error)
	listOrganizationsFunc     func(ctx context.Context, opts organizations.ListOrganizationsOpts) (organizations.ListOrganizationsResponse, error)
	listOrganizationRolesFunc func(ctx context.Context, opts organizations.ListOrganizationRolesOpts) (organizations.ListOrganizationRolesResponse, error)
}

func (*fakeOrgsClient) privateOrgsClient() {}

func (f *fakeOrgsClient) GetOrganization(ctx context.Context, opts organizations.GetOrganizationOpts) (organizations.Organization, error) {
	if f.getOrganizationFunc == nil {
		return organizations.Organization{}, errors.New("not mocked")
	}
	return f.getOrganizationFunc(ctx, opts)
}

func (f *fakeOrgsClient) ListOrganizations(ctx context.Context, opts organizations.ListOrganizationsOpts) (organizations.ListOrganizationsResponse, error) {
	if f.listOrganizationsFunc == nil {
		return organizations.ListOrganizationsResponse{}, errors.New("not mocked")
	}
	return f.listOrganizationsFunc(ctx, opts)
}

func (f *fakeOrgsClient) ListOrganizationRoles(ctx context.Context, opts organizations.ListOrganizationRolesOpts) (organizations.ListOrganizationRolesResponse, error) {
	if f.listOrganizationRolesFunc == nil {
		return organizations.ListOrganizationRolesResponse{}, errors.New("not mocked")
	}
	return f.listOrganizationRolesFunc(ctx, opts)
}

type fakeSSOClient struct {
	listConnectionsFunc func(ctx context.Context, opts sso.ListConnectionsOpts) (sso.ListConnectionsResponse, error)
}

func (*fakeSSOClient) privateSSOClient() {}

func (f *fakeSSOClient) ListConnections(ctx context.Context, opts sso.ListConnectionsOpts) (sso.ListConnectionsResponse, error) {
	if f.listConnectionsFunc == nil {
		return sso.ListConnectionsResponse{}, errors.New("not mocked")
	}
	return f.listConnectionsFunc(ctx, opts)
}

type fakeDirectorySyncClient struct {
	listDirectoriesFunc func(ctx context.Context, opts directorysync.ListDirectoriesOpts) (directorysync.ListDirectoriesResponse, error)
	listUsersFunc       func(ctx context.Context, opts directorysync.ListUsersOpts) (directorysync.ListUsersResponse, error)
	listGroupsFunc      func(ctx context.Context, opts directorysync.ListGroupsOpts) (directorysync.ListGroupsResponse, error)
}

func (*fakeDirectorySyncClient) privateDirectorySyncClient() {}

func (f *fakeDirectorySyncClient) ListDirectories(ctx context.Context, opts directorysync.ListDirectoriesOpts) (directorysync.ListDirectoriesResponse, error) {
	if f.listDirectoriesFunc == nil {
		return directorysync.ListDirectoriesResponse{}, errors.New("not mocked")
	}
	return f.listDirectoriesFunc(ctx, opts)
}

func (f *fakeDirectorySyncClient) ListUsers(ctx context.Context, opts directorysync.ListUsersOpts) (directorysync.ListUsersResponse, error) {
	if f.listUsersFunc == nil {
		return directorysync.ListUsersResponse{}, errors.New("not mocked")
	}
	return f.listUsersFunc(ctx, opts)
}

func (f *fakeDirectorySyncClient) ListGroups(ctx context.Context, opts directorysync.ListGroupsOpts) (directorysync.ListGroupsResponse, error) {
	if f.listGroupsFunc == nil {
		return directorysync.ListGroupsResponse{}, errors.New("not mocked")
	}
	return f.listGroupsFunc(ctx, opts)
}

type fakeAuditLogsClient struct {
	createEventFunc func(ctx context.Context, e auditlogs.CreateEventOpts) error
}

func (*fakeAuditLogsClient) privateAuditLogsClient() {}

func (f *fakeAuditLogsClient) CreateEvent(ctx context.Context, e auditlogs.CreateEventOpts) error {
	if f.createEventFunc == nil {
		return errors.New("not mocked")
	}
	return f.createEventFunc(ctx, e)
}

func newEnterpriseTestClient(t *testing.T) *Client {
	t.Helper()
	client, err := New(validConfig())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return client
}

func TestUsersMethods(t *testing.T) {
	client := newEnterpriseTestClient(t)

	createdAt := time.Now().Add(-2 * time.Hour).UTC()
	updatedAt := time.Now().Add(-1 * time.Hour).UTC()
	client.um = &fakeUMClient{
		getUserFunc: func(_ context.Context, opts usermanagement.GetUserOpts) (usermanagement.User, error) {
			if opts.User != "user_1" {
				t.Fatalf("GetUser opts.User = %q", opts.User)
			}
			return usermanagement.User{
				ID:                "user_1",
				Email:             "alice@example.com",
				FirstName:         "Alice",
				LastName:          "Anderson",
				EmailVerified:     true,
				ProfilePictureURL: "https://example.com/a.png",
				Metadata:          map[string]string{"team": "eng"},
				CreatedAt:         createdAt.Format(time.RFC3339Nano),
				UpdatedAt:         updatedAt.Format(time.RFC3339Nano),
			}, nil
		},
		listUsersFunc: func(_ context.Context, opts usermanagement.ListUsersOpts) (usermanagement.ListUsersResponse, error) {
			if opts.Email != "alice@example.com" || opts.OrganizationID != "org_1" || opts.Order != usermanagement.Asc {
				t.Fatalf("unexpected ListUsers opts: %#v", opts)
			}
			return usermanagement.ListUsersResponse{
				Data: []usermanagement.User{{ID: "user_1", Email: "alice@example.com"}},
				ListMetadata: common.ListMetadata{
					Before: "before_1",
					After:  "after_1",
				},
			}, nil
		},
		updateUserFunc: func(_ context.Context, opts usermanagement.UpdateUserOpts) (usermanagement.User, error) {
			if opts.User != "user_1" || opts.FirstName != "Alicia" || opts.LastName != "A" || !opts.EmailVerified {
				t.Fatalf("unexpected UpdateUser opts: %#v", opts)
			}
			if opts.Metadata["foo"] == nil || *opts.Metadata["foo"] != "bar" {
				t.Fatalf("expected metadata foo=bar, got %#v", opts.Metadata)
			}
			return usermanagement.User{ID: "user_1", FirstName: opts.FirstName, LastName: opts.LastName, EmailVerified: opts.EmailVerified}, nil
		},
		deleteUserFunc: func(_ context.Context, opts usermanagement.DeleteUserOpts) error {
			if opts.User != "user_1" {
				t.Fatalf("DeleteUser opts.User = %q", opts.User)
			}
			return nil
		},
	}

	user, err := client.GetUser(context.Background(), "user_1")
	if err != nil {
		t.Fatalf("GetUser() error = %v", err)
	}
	if user.Email != "alice@example.com" || user.ProfilePicURL != "https://example.com/a.png" {
		t.Fatalf("unexpected user mapping: %#v", user)
	}
	if user.CreatedAt.IsZero() || user.UpdatedAt.IsZero() {
		t.Fatalf("expected parsed timestamps, got %#v", user)
	}

	userList, err := client.ListUsers(context.Background(), ListUsersOpts{
		Email:          "alice@example.com",
		OrganizationID: "org_1",
		Order:          "asc",
	})
	if err != nil {
		t.Fatalf("ListUsers() error = %v", err)
	}
	if len(userList.Data) != 1 || userList.ListMeta.After != "after_1" {
		t.Fatalf("unexpected ListUsers result: %#v", userList)
	}

	firstName := "Alicia"
	lastName := "A"
	emailVerified := true
	metaVal := "bar"
	updated, err := client.UpdateUser(context.Background(), "user_1", UpdateUserOpts{
		FirstName:     &firstName,
		LastName:      &lastName,
		EmailVerified: &emailVerified,
		Metadata:      map[string]*string{"foo": &metaVal},
	})
	if err != nil {
		t.Fatalf("UpdateUser() error = %v", err)
	}
	if updated.FirstName != "Alicia" {
		t.Fatalf("unexpected updated user: %#v", updated)
	}

	if err := client.DeleteUser(context.Background(), "user_1"); err != nil {
		t.Fatalf("DeleteUser() error = %v", err)
	}
}

func TestOrganizationAndMembershipMethods(t *testing.T) {
	client := newEnterpriseTestClient(t)

	client.orgs = &fakeOrgsClient{
		getOrganizationFunc: func(_ context.Context, opts organizations.GetOrganizationOpts) (organizations.Organization, error) {
			if opts.Organization != "org_1" {
				t.Fatalf("GetOrganization opts.Organization = %q", opts.Organization)
			}
			return organizations.Organization{
				ID:   "org_1",
				Name: "Acme",
				Domains: []organization_domains.OrganizationDomain{
					{ID: "od_1", Domain: "acme.com", State: organization_domains.OrganizationDomainVerified},
				},
				CreatedAt: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano),
				UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano),
			}, nil
		},
		listOrganizationsFunc: func(_ context.Context, opts organizations.ListOrganizationsOpts) (organizations.ListOrganizationsResponse, error) {
			if opts.Order != organizations.Desc {
				t.Fatalf("expected desc order, got %q", opts.Order)
			}
			return organizations.ListOrganizationsResponse{
				Data: []organizations.Organization{{ID: "org_1", Name: "Acme"}},
				ListMetadata: common.ListMetadata{
					Before: "before_org",
					After:  "after_org",
				},
			}, nil
		},
	}
	client.um = &fakeUMClient{
		listOrganizationMembershipsFunc: func(_ context.Context, opts usermanagement.ListOrganizationMembershipsOpts) (usermanagement.ListOrganizationMembershipsResponse, error) {
			if opts.OrganizationID != "org_1" || opts.UserID != "user_1" || len(opts.Statuses) != 1 || opts.Statuses[0] != usermanagement.Active {
				t.Fatalf("unexpected ListOrganizationMemberships opts: %#v", opts)
			}
			return usermanagement.ListOrganizationMembershipsResponse{
				Data: []usermanagement.OrganizationMembership{{
					ID:             "om_1",
					UserID:         "user_1",
					OrganizationID: "org_1",
					Roles:          []common.RoleResponse{{Slug: "admin"}},
					Status:         usermanagement.Active,
					CreatedAt:      time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339Nano),
					UpdatedAt:      time.Now().UTC().Format(time.RFC3339Nano),
				}},
				ListMetadata: common.ListMetadata{After: "after_m"},
			}, nil
		},
		getOrganizationMembershipFunc: func(_ context.Context, opts usermanagement.GetOrganizationMembershipOpts) (usermanagement.OrganizationMembership, error) {
			if opts.OrganizationMembership != "om_1" {
				t.Fatalf("GetOrganizationMembership opts.OrganizationMembership = %q", opts.OrganizationMembership)
			}
			return usermanagement.OrganizationMembership{
				ID:             "om_1",
				UserID:         "user_1",
				OrganizationID: "org_1",
				Role:           common.RoleResponse{Slug: "member"},
				Status:         usermanagement.PendingOrganizationMembership,
			}, nil
		},
	}

	org, err := client.GetOrganization(context.Background(), "org_1")
	if err != nil {
		t.Fatalf("GetOrganization() error = %v", err)
	}
	if org.Name != "Acme" || len(org.Domains) != 1 || org.Domains[0].State != "verified" {
		t.Fatalf("unexpected org mapping: %#v", org)
	}

	orgs, err := client.ListOrganizations(context.Background(), ListOrganizationsOpts{Order: "desc"})
	if err != nil {
		t.Fatalf("ListOrganizations() error = %v", err)
	}
	if len(orgs.Data) != 1 || orgs.ListMeta.After != "after_org" {
		t.Fatalf("unexpected org list: %#v", orgs)
	}

	memberships, err := client.ListOrganizationMemberships(context.Background(), ListMembershipsOpts{
		UserID:         "user_1",
		OrganizationID: "org_1",
		Statuses:       []string{"active"},
	})
	if err != nil {
		t.Fatalf("ListOrganizationMemberships() error = %v", err)
	}
	if len(memberships.Data) != 1 || memberships.Data[0].RoleSlug != "admin" || memberships.ListMeta.After != "after_m" {
		t.Fatalf("unexpected memberships mapping: %#v", memberships)
	}

	membership, err := client.GetOrganizationMembership(context.Background(), "om_1")
	if err != nil {
		t.Fatalf("GetOrganizationMembership() error = %v", err)
	}
	if membership.RoleSlug != "member" || membership.Status != "pending" {
		t.Fatalf("unexpected membership mapping: %#v", membership)
	}
}

func TestHasRole(t *testing.T) {
	t.Run("validates args", func(t *testing.T) {
		client := newEnterpriseTestClient(t)
		ok, err := client.HasRole(context.Background(), "", "org_1", "admin")
		if err == nil || ok {
			t.Fatalf("expected validation error, got ok=%v err=%v", ok, err)
		}
	})

	t.Run("matches across pages", func(t *testing.T) {
		client := newEnterpriseTestClient(t)
		call := 0
		client.um = &fakeUMClient{
			listOrganizationMembershipsFunc: func(_ context.Context, opts usermanagement.ListOrganizationMembershipsOpts) (usermanagement.ListOrganizationMembershipsResponse, error) {
				call++
				if call == 1 {
					return usermanagement.ListOrganizationMembershipsResponse{
						Data: []usermanagement.OrganizationMembership{{
							ID:             "om_1",
							UserID:         "user_1",
							OrganizationID: "org_1",
							Roles:          []common.RoleResponse{{Slug: "viewer"}},
							Status:         usermanagement.Active,
						}},
						ListMetadata: common.ListMetadata{After: "page2"},
					}, nil
				}
				if opts.After != "page2" {
					t.Fatalf("expected opts.After=page2, got %q", opts.After)
				}
				return usermanagement.ListOrganizationMembershipsResponse{
					Data: []usermanagement.OrganizationMembership{{
						ID:             "om_2",
						UserID:         "user_1",
						OrganizationID: "org_1",
						Role:           common.RoleResponse{Slug: "admin"},
						Status:         usermanagement.Active,
					}},
				}, nil
			},
		}

		ok, err := client.HasRole(context.Background(), "user_1", "org_1", "admin")
		if err != nil || !ok {
			t.Fatalf("HasRole() = (%v, %v), want (true, nil)", ok, err)
		}
	})
}

func TestListRoles(t *testing.T) {
	t.Run("organization scoped", func(t *testing.T) {
		client := newEnterpriseTestClient(t)
		client.orgs = &fakeOrgsClient{
			listOrganizationRolesFunc: func(_ context.Context, opts organizations.ListOrganizationRolesOpts) (organizations.ListOrganizationRolesResponse, error) {
				if opts.OrganizationID != "org_1" {
					t.Fatalf("unexpected org id: %q", opts.OrganizationID)
				}
				return organizations.ListOrganizationRolesResponse{
					Data: []roles.Role{{
						ID:          "role_1",
						Slug:        "admin",
						Name:        "Admin",
						Description: "Administrator",
						Type:        roles.Organization,
						Permissions: []string{"projects:read"},
					}},
				}, nil
			},
		}

		roleList, err := client.ListRoles(context.Background(), ListRolesOpts{OrganizationID: "org_1"})
		if err != nil {
			t.Fatalf("ListRoles() error = %v", err)
		}
		if len(roleList.Data) != 1 || roleList.Data[0].Slug != "admin" || roleList.Data[0].Type != "OrganizationRole" {
			t.Fatalf("unexpected role list: %#v", roleList)
		}
	})

	t.Run("environment roles aggregated", func(t *testing.T) {
		client := newEnterpriseTestClient(t)
		client.orgs = &fakeOrgsClient{
			listOrganizationsFunc: func(_ context.Context, opts organizations.ListOrganizationsOpts) (organizations.ListOrganizationsResponse, error) {
				if opts.After == "" {
					return organizations.ListOrganizationsResponse{
						Data: []organizations.Organization{{ID: "org_1"}},
						ListMetadata: common.ListMetadata{
							After: "next_page",
						},
					}, nil
				}
				return organizations.ListOrganizationsResponse{
					Data: []organizations.Organization{{ID: "org_2"}},
				}, nil
			},
			listOrganizationRolesFunc: func(_ context.Context, opts organizations.ListOrganizationRolesOpts) (organizations.ListOrganizationRolesResponse, error) {
				if opts.OrganizationID == "org_1" {
					return organizations.ListOrganizationRolesResponse{
						Data: []roles.Role{
							{ID: "env_1", Slug: "env-admin", Type: roles.Environment},
							{ID: "org_1_role", Slug: "org-admin", Type: roles.Organization},
						},
					}, nil
				}
				return organizations.ListOrganizationRolesResponse{
					Data: []roles.Role{
						{ID: "env_1", Slug: "env-admin", Type: roles.Environment},
						{ID: "env_2", Slug: "env-viewer", Type: roles.Environment},
					},
				}, nil
			},
		}

		roleList, err := client.ListRoles(context.Background(), ListRolesOpts{})
		if err != nil {
			t.Fatalf("ListRoles() error = %v", err)
		}
		if len(roleList.Data) != 2 {
			t.Fatalf("expected 2 env roles, got %#v", roleList.Data)
		}
		slugs := []string{roleList.Data[0].Slug, roleList.Data[1].Slug}
		if !slices.Contains(slugs, "env-admin") || !slices.Contains(slugs, "env-viewer") {
			t.Fatalf("unexpected slugs: %#v", slugs)
		}
	})
}

func TestSSOAndDirectoryReadMethods(t *testing.T) {
	client := newEnterpriseTestClient(t)
	client.ssoClient = &fakeSSOClient{
		listConnectionsFunc: func(_ context.Context, opts sso.ListConnectionsOpts) (sso.ListConnectionsResponse, error) {
			if opts.OrganizationID != "org_1" || opts.ConnectionType != sso.OktaSAML || opts.Order != sso.Asc {
				t.Fatalf("unexpected ListConnections opts: %#v", opts)
			}
			return sso.ListConnectionsResponse{
				Data: []sso.Connection{{
					ID:             "conn_1",
					Name:           "Okta SAML",
					ConnectionType: sso.OktaSAML,
					State:          sso.Active,
					OrganizationID: "org_1",
				}},
				ListMetadata: common.ListMetadata{After: "after_conn"},
			}, nil
		},
	}
	client.ds = &fakeDirectorySyncClient{
		listDirectoriesFunc: func(_ context.Context, opts directorysync.ListDirectoriesOpts) (directorysync.ListDirectoriesResponse, error) {
			if opts.OrganizationID != "org_1" {
				t.Fatalf("unexpected ListDirectories opts: %#v", opts)
			}
			return directorysync.ListDirectoriesResponse{
				Data: []directorysync.Directory{{
					ID:             "dir_1",
					Name:           "Acme Directory",
					Domain:         "acme.com",
					Type:           directorysync.OktaSCIMV2_0,
					State:          directorysync.Linked,
					OrganizationID: "org_1",
				}},
				ListMetadata: common.ListMetadata{After: "after_dir"},
			}, nil
		},
		listUsersFunc: func(_ context.Context, opts directorysync.ListUsersOpts) (directorysync.ListUsersResponse, error) {
			if opts.Directory != "dir_1" || opts.Group != "grp_1" {
				t.Fatalf("unexpected ListUsers opts: %#v", opts)
			}
			return directorysync.ListUsersResponse{
				Data: []directorysync.User{{
					ID:            "du_1",
					Email:         "alice@acme.com",
					FirstName:     "Alice",
					LastName:      "A",
					State:         directorysync.Active,
					Groups:        []directorysync.UserGroup{{ID: "grp_1", Name: "Admins"}},
					RawAttributes: []byte(`{"dept":"eng"}`),
				}},
				ListMetadata: common.ListMetadata{After: "after_du"},
			}, nil
		},
		listGroupsFunc: func(_ context.Context, opts directorysync.ListGroupsOpts) (directorysync.ListGroupsResponse, error) {
			if opts.Directory != "dir_1" {
				t.Fatalf("unexpected ListGroups opts: %#v", opts)
			}
			return directorysync.ListGroupsResponse{
				Data:         []directorysync.Group{{ID: "grp_1", Name: "Admins"}},
				ListMetadata: common.ListMetadata{After: "after_dg"},
			}, nil
		},
	}

	connections, err := client.ListConnections(context.Background(), ListConnectionsOpts{
		OrganizationID: "org_1",
		ConnectionType: string(sso.OktaSAML),
		Order:          "asc",
	})
	if err != nil {
		t.Fatalf("ListConnections() error = %v", err)
	}
	if len(connections.Data) != 1 || connections.Data[0].State != "active" || connections.ListMeta.After != "after_conn" {
		t.Fatalf("unexpected connections: %#v", connections)
	}

	directories, err := client.ListDirectories(context.Background(), ListDirectoriesOpts{OrganizationID: "org_1"})
	if err != nil {
		t.Fatalf("ListDirectories() error = %v", err)
	}
	if len(directories.Data) != 1 || directories.Data[0].Type == "" || directories.ListMeta.After != "after_dir" {
		t.Fatalf("unexpected directories: %#v", directories)
	}

	dirUsers, err := client.ListDirectoryUsers(context.Background(), ListDirectoryUsersOpts{DirectoryID: "dir_1", Group: "grp_1"})
	if err != nil {
		t.Fatalf("ListDirectoryUsers() error = %v", err)
	}
	if len(dirUsers.Data) != 1 || dirUsers.Data[0].Groups[0].Name != "Admins" || dirUsers.Data[0].RawAttrs["dept"] != "eng" {
		t.Fatalf("unexpected directory users: %#v", dirUsers)
	}

	dirGroups, err := client.ListDirectoryGroups(context.Background(), ListDirectoryGroupsOpts{DirectoryID: "dir_1"})
	if err != nil {
		t.Fatalf("ListDirectoryGroups() error = %v", err)
	}
	if len(dirGroups.Data) != 1 || dirGroups.Data[0].Name != "Admins" || dirGroups.ListMeta.After != "after_dg" {
		t.Fatalf("unexpected directory groups: %#v", dirGroups)
	}
}

func TestEmitAuditEvent(t *testing.T) {
	t.Run("disabled is no-op", func(t *testing.T) {
		client := newEnterpriseTestClient(t)
		calls := 0
		client.al = &fakeAuditLogsClient{
			createEventFunc: func(context.Context, auditlogs.CreateEventOpts) error {
				calls++
				return nil
			},
		}
		if err := client.EmitAuditEvent(context.Background(), AuditEvent{}); err != nil {
			t.Fatalf("EmitAuditEvent() error = %v", err)
		}
		if calls != 0 {
			t.Fatalf("CreateEvent calls = %d, want 0", calls)
		}
	})

	t.Run("enabled defaults occurred_at and idempotency", func(t *testing.T) {
		client := newEnterpriseTestClient(t)
		client.cfg.EnableAuditLogs = true

		var captured auditlogs.CreateEventOpts
		client.al = &fakeAuditLogsClient{
			createEventFunc: func(_ context.Context, e auditlogs.CreateEventOpts) error {
				captured = e
				return nil
			},
		}

		err := client.EmitAuditEvent(context.Background(), AuditEvent{
			OrganizationID: "org_1",
			Action:         "project.deleted",
			Actor: AuditActor{
				ID:   "user_1",
				Type: "user",
			},
			Targets: []AuditTarget{{ID: "proj_1", Type: "project"}},
		})
		if err != nil {
			t.Fatalf("EmitAuditEvent() error = %v", err)
		}
		if captured.OrganizationID != "org_1" || captured.Event.Action != "project.deleted" {
			t.Fatalf("unexpected audit payload: %#v", captured)
		}
		if captured.Event.OccurredAt.IsZero() {
			t.Fatal("OccurredAt should be defaulted")
		}
		if captured.IdempotencyKey == "" {
			t.Fatal("IdempotencyKey should be auto-generated")
		}
	})

	t.Run("invalid required fields", func(t *testing.T) {
		client := newEnterpriseTestClient(t)
		client.cfg.EnableAuditLogs = true
		client.al = &fakeAuditLogsClient{
			createEventFunc: func(_ context.Context, _ auditlogs.CreateEventOpts) error { return nil },
		}

		err := client.EmitAuditEvent(context.Background(), AuditEvent{OrganizationID: "", Action: ""})
		if err == nil || err.Error() != "workos: invalid audit event" {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("upstream error is sanitized", func(t *testing.T) {
		client := newEnterpriseTestClient(t)
		client.cfg.EnableAuditLogs = true
		client.al = &fakeAuditLogsClient{
			createEventFunc: func(_ context.Context, _ auditlogs.CreateEventOpts) error {
				return errors.New("boom with token=secret")
			},
		}

		err := client.EmitAuditEvent(context.Background(), AuditEvent{
			OrganizationID: "org_1",
			Action:         "project.deleted",
			Actor:          AuditActor{ID: "user_1", Type: "user"},
		})
		if err == nil || err.Error() != "workos: emit audit event failed" {
			t.Fatalf("unexpected error: %v", err)
		}
		assertNoSecretLeak(t, err.Error(), "secret")
	})
}
