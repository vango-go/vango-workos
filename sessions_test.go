package workos

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/workos/workos-go/v6/pkg/common"
	"github.com/workos/workos-go/v6/pkg/usermanagement"
)

func newSessionTestClient(um *fakeUMClient, ttl time.Duration) *Client {
	return &Client{
		cfg: Config{
			SessionListCacheDuration: ttl,
			SessionListCacheMaxUsers: 10000,
		},
		um: um,
	}
}

func TestParseWorkOSTime(t *testing.T) {
	now := time.Now().UTC().Round(0)

	got, err := parseWorkOSTime(now.Format(time.RFC3339Nano))
	if err != nil {
		t.Fatalf("parseWorkOSTime(RFC3339Nano) error = %v", err)
	}
	if !got.Equal(now) {
		t.Fatalf("parseWorkOSTime(RFC3339Nano) = %v, want %v", got, now)
	}

	got, err = parseWorkOSTime(now.Format(time.RFC3339))
	if err != nil {
		t.Fatalf("parseWorkOSTime(RFC3339) error = %v", err)
	}
	if !got.Equal(now.Truncate(time.Second)) {
		t.Fatalf("parseWorkOSTime(RFC3339) = %v, want %v", got, now.Truncate(time.Second))
	}

	_, err = parseWorkOSTime("")
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestValidateSession_ArgValidation(t *testing.T) {
	c := newSessionTestClient(&fakeUMClient{}, time.Minute)

	_, err := c.ValidateSession(context.Background(), "", "sess_1")
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "workos: validate session requires userID and sessionID" {
		t.Fatalf("error = %q", err.Error())
	}

	_, err = c.ValidateSession(context.Background(), "user_1", "")
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "workos: validate session requires userID and sessionID" {
		t.Fatalf("error = %q", err.Error())
	}
}

func TestValidateSession_UsesCacheWithinTTL(t *testing.T) {
	var calls int32
	um := &fakeUMClient{
		listSessionsFunc: func(_ context.Context, userID string, opts usermanagement.ListSessionsOpts) (usermanagement.ListSessionsResponse, error) {
			atomic.AddInt32(&calls, 1)
			if userID != "user_1" {
				t.Fatalf("userID = %q, want %q", userID, "user_1")
			}
			if opts.Limit != 100 {
				t.Fatalf("opts.Limit = %d, want 100", opts.Limit)
			}
			return usermanagement.ListSessionsResponse{
				Data: []usermanagement.Session{{
					ID:             "sess_1",
					UserID:         "user_1",
					OrganizationID: "org_1",
					Status:         "active",
					ExpiresAt:      time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339Nano),
				}},
			}, nil
		},
	}
	c := newSessionTestClient(um, time.Minute)

	for i := 0; i < 2; i++ {
		got, err := c.ValidateSession(context.Background(), "user_1", "sess_1")
		if err != nil {
			t.Fatalf("ValidateSession() error = %v", err)
		}
		if got == nil || !got.Active {
			t.Fatalf("ValidateSession() = %#v, want active session", got)
		}
	}

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("ListSessions calls = %d, want 1", got)
	}
}

func TestValidateSession_CacheExpiresAndRefetches(t *testing.T) {
	var calls int32
	um := &fakeUMClient{
		listSessionsFunc: func(context.Context, string, usermanagement.ListSessionsOpts) (usermanagement.ListSessionsResponse, error) {
			atomic.AddInt32(&calls, 1)
			return usermanagement.ListSessionsResponse{
				Data: []usermanagement.Session{{
					ID:        "sess_1",
					UserID:    "user_1",
					Status:    "active",
					ExpiresAt: time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339Nano),
				}},
			}, nil
		},
	}
	c := newSessionTestClient(um, 10*time.Millisecond)

	if _, err := c.ValidateSession(context.Background(), "user_1", "sess_1"); err != nil {
		t.Fatalf("ValidateSession() error = %v", err)
	}
	time.Sleep(25 * time.Millisecond)
	if _, err := c.ValidateSession(context.Background(), "user_1", "sess_1"); err != nil {
		t.Fatalf("ValidateSession() error = %v", err)
	}

	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("ListSessions calls = %d, want 2", got)
	}
}

func TestValidateSession_PaginatesAndNormalizesStatus(t *testing.T) {
	var calls int32
	um := &fakeUMClient{
		listSessionsFunc: func(_ context.Context, _ string, opts usermanagement.ListSessionsOpts) (usermanagement.ListSessionsResponse, error) {
			atomic.AddInt32(&calls, 1)
			switch opts.After {
			case "":
				return usermanagement.ListSessionsResponse{
					Data: []usermanagement.Session{{
						ID:        "sess_1",
						UserID:    "user_1",
						Status:    "inactive",
						ExpiresAt: "2026-01-01T00:00:00Z",
					}},
					ListMetadata: common.ListMetadata{After: "cursor_2"},
				}, nil
			case "cursor_2":
				return usermanagement.ListSessionsResponse{
					Data: []usermanagement.Session{{
						ID:             "sess_2",
						UserID:         "user_1",
						OrganizationID: "org_2",
						Status:         "AcTiVe",
						ExpiresAt:      "2026-01-02T00:00:00.123456Z",
					}},
					ListMetadata: common.ListMetadata{},
				}, nil
			default:
				t.Fatalf("unexpected pagination cursor %q", opts.After)
				return usermanagement.ListSessionsResponse{}, nil
			}
		},
	}
	c := newSessionTestClient(um, 0)

	got, err := c.ValidateSession(context.Background(), "user_1", "sess_2")
	if err != nil {
		t.Fatalf("ValidateSession() error = %v", err)
	}
	if got == nil || !got.Active {
		t.Fatalf("ValidateSession() = %#v, want active session", got)
	}
	if got.OrgID != "org_2" {
		t.Fatalf("OrgID = %q, want %q", got.OrgID, "org_2")
	}
	if got.ExpiresAt.IsZero() {
		t.Fatal("ExpiresAt should be parsed")
	}

	if gotCalls := atomic.LoadInt32(&calls); gotCalls != 2 {
		t.Fatalf("ListSessions calls = %d, want 2", gotCalls)
	}
}

func TestValidateSession_MissingSessionReturnsInactive(t *testing.T) {
	um := &fakeUMClient{
		listSessionsFunc: func(context.Context, string, usermanagement.ListSessionsOpts) (usermanagement.ListSessionsResponse, error) {
			return usermanagement.ListSessionsResponse{
				Data: []usermanagement.Session{{
					ID:        "sess_other",
					UserID:    "user_1",
					Status:    "active",
					ExpiresAt: "2026-01-02T00:00:00Z",
				}},
			}, nil
		},
	}
	c := newSessionTestClient(um, time.Minute)

	got, err := c.ValidateSession(context.Background(), "user_1", "sess_missing")
	if err != nil {
		t.Fatalf("ValidateSession() error = %v", err)
	}
	if got == nil {
		t.Fatal("expected session info")
	}
	if got.Active {
		t.Fatalf("Active = %v, want false", got.Active)
	}
	if got.SessionID != "sess_missing" || got.UserID != "user_1" {
		t.Fatalf("session info = %#v", got)
	}
}

func TestValidateSession_UpstreamError(t *testing.T) {
	c := newSessionTestClient(&fakeUMClient{
		listSessionsFunc: func(context.Context, string, usermanagement.ListSessionsOpts) (usermanagement.ListSessionsResponse, error) {
			return usermanagement.ListSessionsResponse{}, errors.New("upstream failure")
		},
	}, time.Minute)

	_, err := c.ValidateSession(context.Background(), "user_1", "sess_1")
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "workos: session validation failed" {
		t.Fatalf("error = %q", err.Error())
	}
}

func TestValidateSession_CacheBoundedByMaxUsers(t *testing.T) {
	var calls int32
	um := &fakeUMClient{
		listSessionsFunc: func(_ context.Context, userID string, _ usermanagement.ListSessionsOpts) (usermanagement.ListSessionsResponse, error) {
			atomic.AddInt32(&calls, 1)
			return usermanagement.ListSessionsResponse{
				Data: []usermanagement.Session{{
					ID:        "sess_" + userID,
					UserID:    userID,
					Status:    "active",
					ExpiresAt: time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339Nano),
				}},
			}, nil
		},
	}
	c := &Client{
		cfg: Config{
			SessionListCacheDuration: time.Minute,
			SessionListCacheMaxUsers: 2,
		},
		um: um,
	}

	if _, err := c.ValidateSession(context.Background(), "user_1", "sess_user_1"); err != nil {
		t.Fatalf("ValidateSession(user_1) error = %v", err)
	}
	if _, err := c.ValidateSession(context.Background(), "user_2", "sess_user_2"); err != nil {
		t.Fatalf("ValidateSession(user_2) error = %v", err)
	}
	if _, err := c.ValidateSession(context.Background(), "user_3", "sess_user_3"); err != nil {
		t.Fatalf("ValidateSession(user_3) error = %v", err)
	}

	if len(c.sessionsCache) != 2 {
		t.Fatalf("sessionsCache len = %d, want 2", len(c.sessionsCache))
	}
	if _, ok := c.sessionsCache["user_1"]; ok {
		t.Fatal("expected oldest cache entry user_1 to be evicted")
	}
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Fatalf("ListSessions calls = %d, want 3", got)
	}
}

func TestRevokeSession(t *testing.T) {
	t.Run("missing session id", func(t *testing.T) {
		c := newSessionTestClient(&fakeUMClient{}, time.Minute)
		err := c.RevokeSession(context.Background(), "")
		if err == nil {
			t.Fatal("expected error")
		}
		if err.Error() != "workos: sessionID required" {
			t.Fatalf("error = %q", err.Error())
		}
	})

	t.Run("success", func(t *testing.T) {
		var gotID string
		c := newSessionTestClient(&fakeUMClient{
			revokeSessionFunc: func(_ context.Context, opts usermanagement.RevokeSessionOpts) error {
				gotID = opts.SessionID
				return nil
			},
		}, time.Minute)

		if err := c.RevokeSession(context.Background(), "sess_123"); err != nil {
			t.Fatalf("RevokeSession() error = %v", err)
		}
		if gotID != "sess_123" {
			t.Fatalf("SessionID = %q, want %q", gotID, "sess_123")
		}
	})

	t.Run("upstream error", func(t *testing.T) {
		c := newSessionTestClient(&fakeUMClient{
			revokeSessionFunc: func(context.Context, usermanagement.RevokeSessionOpts) error {
				return errors.New("network failure")
			},
		}, time.Minute)

		err := c.RevokeSession(context.Background(), "sess_123")
		if err == nil {
			t.Fatal("expected error")
		}
		if err.Error() != "workos: revoke session failed" {
			t.Fatalf("error = %q", err.Error())
		}
	})
}
