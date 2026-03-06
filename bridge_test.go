package workos

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vango-go/vango"
	"github.com/vango-go/vango/pkg/auth"
	"github.com/workos/workos-go/v6/pkg/usermanagement"
)

func TestOnSessionStart_HydratesAuthProjection(t *testing.T) {
	client, err := New(validConfig())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	bridge := client.SessionBridge()

	identity := &Identity{
		UserID:    "user_start",
		Email:     "start@example.com",
		Name:      "Start User",
		OrgID:     "org_start",
		Roles:     []string{"admin"},
		SessionID: "sess_start",
	}

	httpCtx := vango.WithUser(context.Background(), identity)
	sess := &vango.Session{}

	bridge.OnSessionStart(httpCtx, sess)

	stored, ok := sess.Get(auth.SessionKey).(*Identity)
	if !ok || stored == nil {
		t.Fatal("expected identity in auth session key")
	}
	if stored.UserID != "user_start" {
		t.Fatalf("UserID = %q, want %q", stored.UserID, "user_start")
	}

	p, ok := sess.Get(auth.SessionKeyPrincipal).(auth.Principal)
	if !ok {
		t.Fatal("expected principal in auth session key")
	}
	if p.ID != "user_start" {
		t.Fatalf("Principal.ID = %q, want %q", p.ID, "user_start")
	}
	if p.Email != "start@example.com" {
		t.Fatalf("Principal.Email = %q", p.Email)
	}
	if p.TenantID != "org_start" {
		t.Fatalf("Principal.TenantID = %q", p.TenantID)
	}
	if p.SessionID != "sess_start" {
		t.Fatalf("Principal.SessionID = %q", p.SessionID)
	}
	if p.ExpiresAtUnixMs != 0 {
		t.Fatalf("Principal.ExpiresAtUnixMs = %d, want 0", p.ExpiresAtUnixMs)
	}
}

func TestOnSessionResume_MissingIdentityRejects(t *testing.T) {
	client, err := New(validConfig())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	bridge := client.SessionBridge()
	sess := &vango.Session{}

	err = bridge.OnSessionResume(context.Background(), sess)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "missing identity on resume") {
		t.Fatalf("error = %q", err.Error())
	}
}

func TestOnSessionResume_InactiveRejects(t *testing.T) {
	client, err := New(validConfig())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	client.um = &fakeUMClient{
		listSessionsFunc: func(context.Context, string, usermanagement.ListSessionsOpts) (usermanagement.ListSessionsResponse, error) {
			return usermanagement.ListSessionsResponse{}, nil
		},
	}
	bridge := client.SessionBridge()
	sess := &vango.Session{}

	identity := &Identity{
		UserID:    "user_resume",
		Email:     "resume@example.com",
		SessionID: "sess_missing",
	}
	httpCtx := vango.WithUser(context.Background(), identity)

	err = bridge.OnSessionResume(httpCtx, sess)
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "workos: session is no longer active" {
		t.Fatalf("error = %q", err.Error())
	}
}

func TestOnSessionResume_ActiveRehydrates(t *testing.T) {
	client, err := New(validConfig())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	client.um = &fakeUMClient{
		listSessionsFunc: func(_ context.Context, _ string, _ usermanagement.ListSessionsOpts) (usermanagement.ListSessionsResponse, error) {
			return usermanagement.ListSessionsResponse{
				Data: []usermanagement.Session{{
					ID:             "sess_active",
					UserID:         "user_resume",
					OrganizationID: "org_resume",
					Status:         "active",
					ExpiresAt:      time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano),
				}},
			}, nil
		},
	}
	bridge := client.SessionBridge()
	sess := &vango.Session{}

	identity := &Identity{
		UserID:    "user_resume",
		Email:     "resume@example.com",
		Name:      "Resume User",
		OrgID:     "org_resume",
		Roles:     []string{"member"},
		SessionID: "sess_active",
	}
	httpCtx := vango.WithUser(context.Background(), identity)

	if err := bridge.OnSessionResume(httpCtx, sess); err != nil {
		t.Fatalf("OnSessionResume() error = %v", err)
	}

	stored, ok := sess.Get(auth.SessionKey).(*Identity)
	if !ok || stored == nil {
		t.Fatal("expected identity in session after resume")
	}
	if stored.UserID != "user_resume" {
		t.Fatalf("UserID = %q", stored.UserID)
	}

	p, ok := sess.Get(auth.SessionKeyPrincipal).(auth.Principal)
	if !ok {
		t.Fatal("expected principal after resume")
	}
	if p.ID != "user_resume" || p.SessionID != "sess_active" {
		t.Fatalf("principal = %#v", p)
	}
}

func TestOnSessionResume_ActiveRehydrates_SetsOrgWhenMissing(t *testing.T) {
	client, err := New(validConfig())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	client.um = &fakeUMClient{
		listSessionsFunc: func(_ context.Context, _ string, _ usermanagement.ListSessionsOpts) (usermanagement.ListSessionsResponse, error) {
			return usermanagement.ListSessionsResponse{
				Data: []usermanagement.Session{{
					ID:             "sess_active",
					UserID:         "user_resume",
					OrganizationID: "org_resume",
					Status:         "active",
					ExpiresAt:      time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano),
				}},
			}, nil
		},
	}
	bridge := client.SessionBridge()
	sess := &vango.Session{}

	identity := &Identity{
		UserID:    "user_resume",
		Email:     "resume@example.com",
		Name:      "Resume User",
		OrgID:     "",
		Roles:     []string{"member"},
		SessionID: "sess_active",
	}
	httpCtx := vango.WithUser(context.Background(), identity)

	if err := bridge.OnSessionResume(httpCtx, sess); err != nil {
		t.Fatalf("OnSessionResume() error = %v", err)
	}

	stored, ok := sess.Get(auth.SessionKey).(*Identity)
	if !ok || stored == nil {
		t.Fatal("expected identity in session after resume")
	}
	if stored.OrgID != "org_resume" {
		t.Fatalf("OrgID = %q, want %q", stored.OrgID, "org_resume")
	}

	p, ok := sess.Get(auth.SessionKeyPrincipal).(auth.Principal)
	if !ok {
		t.Fatal("expected principal after resume")
	}
	if p.TenantID != "org_resume" {
		t.Fatalf("Principal.TenantID = %q, want %q", p.TenantID, "org_resume")
	}
}

func TestOnSessionResume_OrgMismatchRejects(t *testing.T) {
	client, err := New(validConfig())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	client.um = &fakeUMClient{
		listSessionsFunc: func(_ context.Context, _ string, _ usermanagement.ListSessionsOpts) (usermanagement.ListSessionsResponse, error) {
			return usermanagement.ListSessionsResponse{
				Data: []usermanagement.Session{{
					ID:             "sess_active",
					UserID:         "user_resume",
					OrganizationID: "org_b",
					Status:         "active",
					ExpiresAt:      time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano),
				}},
			}, nil
		},
	}
	bridge := client.SessionBridge()
	sess := &vango.Session{}

	identity := &Identity{
		UserID:    "user_resume",
		Email:     "resume@example.com",
		OrgID:     "org_a",
		SessionID: "sess_active",
	}
	httpCtx := vango.WithUser(context.Background(), identity)

	err = bridge.OnSessionResume(httpCtx, sess)
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "workos: session org mismatch" {
		t.Fatalf("error = %q", err.Error())
	}
}

func TestOnSessionResume_ValidateErrorWrapped(t *testing.T) {
	client, err := New(validConfig())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	client.um = &fakeUMClient{
		listSessionsFunc: func(context.Context, string, usermanagement.ListSessionsOpts) (usermanagement.ListSessionsResponse, error) {
			return usermanagement.ListSessionsResponse{}, errors.New("upstream down")
		},
	}
	bridge := client.SessionBridge()
	sess := &vango.Session{}
	identity := &Identity{
		UserID:    "user_resume",
		Email:     "resume@example.com",
		SessionID: "sess_active",
	}
	httpCtx := vango.WithUser(context.Background(), identity)

	err = bridge.OnSessionResume(httpCtx, sess)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "session revalidation failed") {
		t.Fatalf("error = %q", err.Error())
	}
}

func TestRevalidationConfig_DisabledReturnsNil(t *testing.T) {
	client, err := New(validConfig())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	client.cfg.DisablePeriodicSessionValidation = true

	if got := client.RevalidationConfig(); got != nil {
		t.Fatalf("RevalidationConfig() = %#v, want nil", got)
	}
}

func TestRevalidationConfig_CheckAndOnExpired(t *testing.T) {
	client, err := New(validConfig())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	client.cfg.RevalidationInterval = 2 * time.Minute
	client.cfg.RevalidationTimeout = 3 * time.Second
	client.cfg.MaxStaleSession = 7 * time.Minute
	client.cfg.SessionListCacheDuration = 0

	t.Run("inactive check returns error", func(t *testing.T) {
		client.um = &fakeUMClient{
			listSessionsFunc: func(context.Context, string, usermanagement.ListSessionsOpts) (usermanagement.ListSessionsResponse, error) {
				return usermanagement.ListSessionsResponse{}, nil
			},
		}

		cfg := client.RevalidationConfig()
		if cfg == nil {
			t.Fatal("expected revalidation config")
		}
		if cfg.Interval != 2*time.Minute {
			t.Fatalf("Interval = %v", cfg.Interval)
		}
		if cfg.Timeout != 3*time.Second {
			t.Fatalf("Timeout = %v", cfg.Timeout)
		}
		if cfg.MaxStale != 7*time.Minute {
			t.Fatalf("MaxStale = %v", cfg.MaxStale)
		}
		if cfg.FailureMode != vango.FailOpenWithGrace {
			t.Fatalf("FailureMode = %v", cfg.FailureMode)
		}
		if cfg.OnExpired.Action != vango.ForceReload {
			t.Fatalf("OnExpired.Action = %v", cfg.OnExpired.Action)
		}
		if cfg.OnExpired.Path != "/auth/signin" {
			t.Fatalf("OnExpired.Path = %q", cfg.OnExpired.Path)
		}

		err := cfg.Check(context.Background(), auth.Principal{ID: "user_1", SessionID: "sess_1"})
		if err == nil || err.Error() != "workos: session inactive" {
			t.Fatalf("Check error = %v", err)
		}
	})

	t.Run("failure mode is configurable", func(t *testing.T) {
		client.cfg.RevalidationFailureMode = vango.FailClosed
		cfg := client.RevalidationConfig()
		if cfg == nil {
			t.Fatal("expected revalidation config")
		}
		if cfg.FailureMode != vango.FailClosed {
			t.Fatalf("FailureMode = %v, want %v", cfg.FailureMode, vango.FailClosed)
		}
	})

	t.Run("active check succeeds", func(t *testing.T) {
		client.um = &fakeUMClient{
			listSessionsFunc: func(context.Context, string, usermanagement.ListSessionsOpts) (usermanagement.ListSessionsResponse, error) {
				return usermanagement.ListSessionsResponse{
					Data: []usermanagement.Session{{
						ID:        "sess_1",
						UserID:    "user_1",
						Status:    "active",
						ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano),
					}},
				}, nil
			},
		}
		cfg := client.RevalidationConfig()
		err := cfg.Check(context.Background(), auth.Principal{ID: "user_1", SessionID: "sess_1"})
		if err != nil {
			t.Fatalf("Check() error = %v", err)
		}
	})
}
