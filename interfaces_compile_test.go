package workos

import "testing"

func TestInterfaceSurfaceCompiles(t *testing.T) {
	var _ Sessions
	var _ Users
	var _ Orgs
	var _ RBAC
	var _ AuditLogs
	var _ SSORead
	var _ DirectorySyncRead
	var _ Auth
}
