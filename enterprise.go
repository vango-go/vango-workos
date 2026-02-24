package workos

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/workos/workos-go/v6/pkg/auditlogs"
	"github.com/workos/workos-go/v6/pkg/common"
	"github.com/workos/workos-go/v6/pkg/directorysync"
	"github.com/workos/workos-go/v6/pkg/organizations"
	"github.com/workos/workos-go/v6/pkg/roles"
	"github.com/workos/workos-go/v6/pkg/sso"
	"github.com/workos/workos-go/v6/pkg/usermanagement"
)

var _ Auth = (*Client)(nil)

func (c *Client) GetUser(ctx context.Context, userID string) (*User, error) {
	user, err := c.um.GetUser(ctx, usermanagement.GetUserOpts{User: userID})
	if err != nil {
		return nil, fmt.Errorf("workos: get user %s: %w", userID, err)
	}
	return convertUser(user), nil
}

func (c *Client) ListUsers(ctx context.Context, opts ListUsersOpts) (*UserList, error) {
	resp, err := c.um.ListUsers(ctx, usermanagement.ListUsersOpts{
		Email:          opts.Email,
		OrganizationID: opts.OrganizationID,
		Limit:          opts.Limit,
		Order:          usermanagement.Order(strings.ToLower(strings.TrimSpace(opts.Order))),
		Before:         opts.Before,
		After:          opts.After,
	})
	if err != nil {
		return nil, errors.New("workos: list users failed")
	}

	out := &UserList{
		Data:     make([]User, 0, len(resp.Data)),
		ListMeta: convertListMeta(resp.ListMetadata),
	}
	for _, user := range resp.Data {
		out.Data = append(out.Data, *convertUser(user))
	}
	return out, nil
}

func (c *Client) UpdateUser(ctx context.Context, userID string, opts UpdateUserOpts) (*User, error) {
	umOpts := usermanagement.UpdateUserOpts{
		User:     userID,
		Metadata: opts.Metadata,
	}
	if opts.FirstName != nil {
		umOpts.FirstName = *opts.FirstName
	}
	if opts.LastName != nil {
		umOpts.LastName = *opts.LastName
	}
	if opts.EmailVerified != nil {
		umOpts.EmailVerified = *opts.EmailVerified
	}

	user, err := c.um.UpdateUser(ctx, umOpts)
	if err != nil {
		return nil, fmt.Errorf("workos: update user %s: %w", userID, err)
	}
	return convertUser(user), nil
}

func (c *Client) DeleteUser(ctx context.Context, userID string) error {
	if err := c.um.DeleteUser(ctx, usermanagement.DeleteUserOpts{User: userID}); err != nil {
		return fmt.Errorf("workos: delete user %s: %w", userID, err)
	}
	return nil
}

func (c *Client) GetOrganization(ctx context.Context, orgID string) (*Organization, error) {
	org, err := c.orgs.GetOrganization(ctx, organizations.GetOrganizationOpts{Organization: orgID})
	if err != nil {
		return nil, fmt.Errorf("workos: get organization %s: %w", orgID, err)
	}
	return convertOrganization(org), nil
}

func (c *Client) ListOrganizations(ctx context.Context, opts ListOrganizationsOpts) (*OrganizationList, error) {
	resp, err := c.orgs.ListOrganizations(ctx, organizations.ListOrganizationsOpts{
		Domains: opts.Domains,
		Limit:   opts.Limit,
		Before:  opts.Before,
		After:   opts.After,
		Order:   organizations.Order(strings.ToLower(strings.TrimSpace(opts.Order))),
	})
	if err != nil {
		return nil, errors.New("workos: list organizations failed")
	}

	out := &OrganizationList{
		Data:     make([]Organization, 0, len(resp.Data)),
		ListMeta: convertListMeta(resp.ListMetadata),
	}
	for _, org := range resp.Data {
		out.Data = append(out.Data, *convertOrganization(org))
	}
	return out, nil
}

func (c *Client) ListOrganizationMemberships(ctx context.Context, opts ListMembershipsOpts) (*MembershipList, error) {
	statuses := make([]usermanagement.OrganizationMembershipStatus, 0, len(opts.Statuses))
	for _, status := range opts.Statuses {
		if s := strings.TrimSpace(status); s != "" {
			statuses = append(statuses, usermanagement.OrganizationMembershipStatus(s))
		}
	}

	resp, err := c.um.ListOrganizationMemberships(ctx, usermanagement.ListOrganizationMembershipsOpts{
		UserID:         opts.UserID,
		OrganizationID: opts.OrganizationID,
		Statuses:       statuses,
		Limit:          opts.Limit,
		Before:         opts.Before,
		After:          opts.After,
		Order:          usermanagement.Order(strings.ToLower(strings.TrimSpace(opts.Order))),
	})
	if err != nil {
		return nil, errors.New("workos: list organization memberships failed")
	}

	out := &MembershipList{
		Data:     make([]Membership, 0, len(resp.Data)),
		ListMeta: convertListMeta(resp.ListMetadata),
	}
	for _, membership := range resp.Data {
		out.Data = append(out.Data, convertMembership(membership))
	}
	return out, nil
}

func (c *Client) GetOrganizationMembership(ctx context.Context, membershipID string) (*Membership, error) {
	membership, err := c.um.GetOrganizationMembership(ctx, usermanagement.GetOrganizationMembershipOpts{
		OrganizationMembership: membershipID,
	})
	if err != nil {
		return nil, fmt.Errorf("workos: get organization membership %s: %w", membershipID, err)
	}
	out := convertMembership(membership)
	return &out, nil
}

func (c *Client) HasRole(ctx context.Context, userID, orgID, roleSlug string) (bool, error) {
	if strings.TrimSpace(userID) == "" || strings.TrimSpace(orgID) == "" || strings.TrimSpace(roleSlug) == "" {
		return false, errors.New("workos: has role requires userID, orgID, and roleSlug")
	}

	opts := usermanagement.ListOrganizationMembershipsOpts{
		UserID:         userID,
		OrganizationID: orgID,
		Statuses:       []usermanagement.OrganizationMembershipStatus{usermanagement.Active},
		Limit:          100,
	}
	for {
		resp, err := c.um.ListOrganizationMemberships(ctx, opts)
		if err != nil {
			return false, errors.New("workos: has role failed")
		}
		for _, membership := range resp.Data {
			if membershipRoleMatch(membership, roleSlug) {
				return true, nil
			}
		}
		after := resp.ListMetadata.After
		if after == "" {
			break
		}
		opts.Before = ""
		opts.After = after
	}
	return false, nil
}

func (c *Client) ListRoles(ctx context.Context, opts ListRolesOpts) (*RoleList, error) {
	if strings.TrimSpace(opts.OrganizationID) != "" {
		resp, err := c.orgs.ListOrganizationRoles(ctx, organizations.ListOrganizationRolesOpts{
			OrganizationID: opts.OrganizationID,
		})
		if err != nil {
			return nil, errors.New("workos: list roles failed")
		}
		return roleListFromSDK(resp.Data, opts), nil
	}

	// WorkOS SDK v6 does not expose a dedicated environment-roles endpoint.
	// Aggregate environment roles across organizations as a best-effort fallback.
	orgOpts := organizations.ListOrganizationsOpts{Limit: 100}
	roleByID := make(map[string]Role, 16)
	roleBySlug := make(map[string]Role, 16)
	for {
		orgResp, err := c.orgs.ListOrganizations(ctx, orgOpts)
		if err != nil {
			return nil, errors.New("workos: list roles failed")
		}
		for _, org := range orgResp.Data {
			roleResp, err := c.orgs.ListOrganizationRoles(ctx, organizations.ListOrganizationRolesOpts{
				OrganizationID: org.ID,
			})
			if err != nil {
				return nil, errors.New("workos: list roles failed")
			}
			for _, role := range roleResp.Data {
				if role.Type != roles.Environment {
					continue
				}
				converted := convertRole(role)
				if converted.ID != "" {
					roleByID[converted.ID] = converted
					continue
				}
				if converted.Slug != "" {
					roleBySlug[converted.Slug] = converted
				}
			}
		}

		after := orgResp.ListMetadata.After
		if after == "" {
			break
		}
		orgOpts.Before = ""
		orgOpts.After = after
	}

	out := &RoleList{
		Data: make([]Role, 0, len(roleByID)+len(roleBySlug)),
	}
	for _, role := range roleByID {
		out.Data = append(out.Data, role)
	}
	for _, role := range roleBySlug {
		if role.ID != "" {
			if _, ok := roleByID[role.ID]; ok {
				continue
			}
		}
		out.Data = append(out.Data, role)
	}
	if opts.Limit > 0 && len(out.Data) > opts.Limit {
		out.Data = out.Data[:opts.Limit]
	}
	return out, nil
}

func (c *Client) ListConnections(ctx context.Context, opts ListConnectionsOpts) (*ConnectionList, error) {
	resp, err := c.ssoClient.ListConnections(ctx, sso.ListConnectionsOpts{
		OrganizationID: opts.OrganizationID,
		ConnectionType: sso.ConnectionType(opts.ConnectionType),
		Limit:          opts.Limit,
		Before:         opts.Before,
		After:          opts.After,
		Order:          sso.Order(strings.ToLower(strings.TrimSpace(opts.Order))),
	})
	if err != nil {
		return nil, errors.New("workos: list connections failed")
	}

	out := &ConnectionList{
		Data:     make([]Connection, 0, len(resp.Data)),
		ListMeta: convertListMeta(resp.ListMetadata),
	}
	for _, connection := range resp.Data {
		out.Data = append(out.Data, Connection{
			ID:             connection.ID,
			Name:           connection.Name,
			ConnectionType: string(connection.ConnectionType),
			State:          string(connection.State),
			OrgID:          connection.OrganizationID,
		})
	}
	return out, nil
}

func (c *Client) ListDirectories(ctx context.Context, opts ListDirectoriesOpts) (*DirectoryList, error) {
	resp, err := c.ds.ListDirectories(ctx, directorysync.ListDirectoriesOpts{
		OrganizationID: opts.OrganizationID,
		Limit:          opts.Limit,
		Before:         opts.Before,
		After:          opts.After,
	})
	if err != nil {
		return nil, errors.New("workos: list directories failed")
	}

	out := &DirectoryList{
		Data:     make([]Directory, 0, len(resp.Data)),
		ListMeta: convertListMeta(resp.ListMetadata),
	}
	for _, directory := range resp.Data {
		out.Data = append(out.Data, Directory{
			ID:     directory.ID,
			Name:   directory.Name,
			Domain: directory.Domain,
			Type:   string(directory.Type),
			State:  string(directory.State),
			OrgID:  directory.OrganizationID,
		})
	}
	return out, nil
}

func (c *Client) ListDirectoryUsers(ctx context.Context, opts ListDirectoryUsersOpts) (*DirectoryUserList, error) {
	resp, err := c.ds.ListUsers(ctx, directorysync.ListUsersOpts{
		Directory: opts.DirectoryID,
		Group:     opts.Group,
		Limit:     opts.Limit,
		Before:    opts.Before,
		After:     opts.After,
	})
	if err != nil {
		return nil, errors.New("workos: list directory users failed")
	}

	out := &DirectoryUserList{
		Data:     make([]DirectoryUser, 0, len(resp.Data)),
		ListMeta: convertListMeta(resp.ListMetadata),
	}
	for _, user := range resp.Data {
		groups := make([]DirectoryGroup, 0, len(user.Groups))
		for _, group := range user.Groups {
			groups = append(groups, DirectoryGroup{
				ID:   group.ID,
				Name: group.Name,
			})
		}
		out.Data = append(out.Data, DirectoryUser{
			ID:        user.ID,
			Email:     user.Email,
			FirstName: user.FirstName,
			LastName:  user.LastName,
			State:     string(user.State),
			Groups:    groups,
			RawAttrs:  decodeRawAttrs(user.RawAttributes),
		})
	}
	return out, nil
}

func (c *Client) ListDirectoryGroups(ctx context.Context, opts ListDirectoryGroupsOpts) (*DirectoryGroupList, error) {
	resp, err := c.ds.ListGroups(ctx, directorysync.ListGroupsOpts{
		Directory: opts.DirectoryID,
		Limit:     opts.Limit,
		Before:    opts.Before,
		After:     opts.After,
	})
	if err != nil {
		return nil, errors.New("workos: list directory groups failed")
	}

	out := &DirectoryGroupList{
		Data:     make([]DirectoryGroup, 0, len(resp.Data)),
		ListMeta: convertListMeta(resp.ListMetadata),
	}
	for _, group := range resp.Data {
		out.Data = append(out.Data, DirectoryGroup{
			ID:   group.ID,
			Name: group.Name,
		})
	}
	return out, nil
}

func (c *Client) EmitAuditEvent(ctx context.Context, event AuditEvent) error {
	if !c.cfg.EnableAuditLogs {
		return nil
	}
	if strings.TrimSpace(event.OrganizationID) == "" || strings.TrimSpace(event.Action) == "" {
		return errors.New("workos: invalid audit event")
	}
	if event.OccurredAt.IsZero() {
		event.OccurredAt = time.Now()
	}
	if strings.TrimSpace(event.IdempotencyKey) == "" {
		event.IdempotencyKey = generateEventKey()
	}

	targets := make([]auditlogs.Target, 0, len(event.Targets))
	for _, target := range event.Targets {
		targets = append(targets, auditlogs.Target{
			ID:       target.ID,
			Name:     target.Name,
			Type:     target.Type,
			Metadata: target.Metadata,
		})
	}

	err := c.al.CreateEvent(ctx, auditlogs.CreateEventOpts{
		OrganizationID: event.OrganizationID,
		IdempotencyKey: event.IdempotencyKey,
		Event: auditlogs.Event{
			Action:     event.Action,
			OccurredAt: event.OccurredAt,
			Actor: auditlogs.Actor{
				ID:       event.Actor.ID,
				Name:     event.Actor.Name,
				Type:     event.Actor.Type,
				Metadata: event.Actor.Metadata,
			},
			Targets: targets,
			Context: auditlogs.Context{
				Location:  event.Context.Location,
				UserAgent: event.Context.UserAgent,
			},
		},
	})
	if err != nil {
		return errors.New("workos: emit audit event failed")
	}
	return nil
}

func convertUser(in usermanagement.User) *User {
	createdAt, _ := parseWorkOSTime(in.CreatedAt)
	updatedAt, _ := parseWorkOSTime(in.UpdatedAt)
	return &User{
		ID:            in.ID,
		Email:         in.Email,
		EmailVerified: in.EmailVerified,
		FirstName:     in.FirstName,
		LastName:      in.LastName,
		ProfilePicURL: in.ProfilePictureURL,
		Metadata:      in.Metadata,
		CreatedAt:     createdAt,
		UpdatedAt:     updatedAt,
	}
}

func convertOrganization(in organizations.Organization) *Organization {
	createdAt, _ := parseWorkOSTime(in.CreatedAt)
	updatedAt, _ := parseWorkOSTime(in.UpdatedAt)
	domains := make([]OrgDomain, 0, len(in.Domains))
	for _, domain := range in.Domains {
		domains = append(domains, OrgDomain{
			ID:     domain.ID,
			Domain: domain.Domain,
			State:  string(domain.State),
		})
	}
	return &Organization{
		ID:                   in.ID,
		Name:                 in.Name,
		AllowProfilesOutside: in.AllowProfilesOutsideOrganization,
		Domains:              domains,
		CreatedAt:            createdAt,
		UpdatedAt:            updatedAt,
	}
}

func convertMembership(in usermanagement.OrganizationMembership) Membership {
	createdAt, _ := parseWorkOSTime(in.CreatedAt)
	updatedAt, _ := parseWorkOSTime(in.UpdatedAt)
	return Membership{
		ID:        in.ID,
		UserID:    in.UserID,
		OrgID:     in.OrganizationID,
		RoleSlug:  membershipRoleSlug(in),
		Status:    strings.ToLower(string(in.Status)),
		CreatedAt: createdAt,
		UpdatedAt: updatedAt,
	}
}

func membershipRoleSlug(in usermanagement.OrganizationMembership) string {
	if in.Role.Slug != "" {
		return in.Role.Slug
	}
	for _, role := range in.Roles {
		if role.Slug != "" {
			return role.Slug
		}
	}
	return ""
}

func membershipRoleMatch(in usermanagement.OrganizationMembership, wantSlug string) bool {
	if in.Role.Slug == wantSlug {
		return true
	}
	for _, role := range in.Roles {
		if role.Slug == wantSlug {
			return true
		}
	}
	return false
}

func convertListMeta(in common.ListMetadata) ListMeta {
	return ListMeta{
		Before: in.Before,
		After:  in.After,
	}
}

func roleListFromSDK(in []roles.Role, opts ListRolesOpts) *RoleList {
	out := &RoleList{
		Data: make([]Role, 0, len(in)),
	}
	for _, role := range in {
		out.Data = append(out.Data, convertRole(role))
	}
	if opts.Limit > 0 && len(out.Data) > opts.Limit {
		out.Data = out.Data[:opts.Limit]
	}
	return out
}

func convertRole(in roles.Role) Role {
	return Role{
		ID:          in.ID,
		Slug:        in.Slug,
		Name:        in.Name,
		Description: in.Description,
		Type:        string(in.Type),
		Permissions: in.Permissions,
	}
}

func decodeRawAttrs(raw json.RawMessage) map[string]any {
	if len(raw) == 0 {
		return nil
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}
	return out
}

func generateEventKey() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("workos-%d", time.Now().UnixNano())
	}
	return "workos-" + hex.EncodeToString(b[:])
}
