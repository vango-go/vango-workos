package workos

import (
	"testing"
	"time"
)

func TestUserDisplayName(t *testing.T) {
	t.Run("first and last", func(t *testing.T) {
		u := &User{FirstName: "Ada", LastName: "Lovelace", Email: "ada@example.com"}
		if got := u.DisplayName(); got != "Ada Lovelace" {
			t.Fatalf("DisplayName() = %q, want %q", got, "Ada Lovelace")
		}
	})

	t.Run("first only", func(t *testing.T) {
		u := &User{FirstName: "Ada", Email: "ada@example.com"}
		if got := u.DisplayName(); got != "Ada" {
			t.Fatalf("DisplayName() = %q, want %q", got, "Ada")
		}
	})

	t.Run("fallback email", func(t *testing.T) {
		u := &User{Email: "ada@example.com"}
		if got := u.DisplayName(); got != "ada@example.com" {
			t.Fatalf("DisplayName() = %q, want %q", got, "ada@example.com")
		}
	})
}

func TestIdentityHasPermission(t *testing.T) {
	if (&Identity{}).HasPermission("") {
		t.Fatal("expected empty perm check to be false")
	}

	var i *Identity
	if i.HasPermission("projects:read") {
		t.Fatal("expected nil identity permission check to be false")
	}

	i = &Identity{Permissions: []string{"projects:read"}}
	if !i.HasPermission("projects:read") {
		t.Fatal("expected permission match to be true")
	}
	if i.HasPermission("projects:write") {
		t.Fatal("expected missing permission to be false")
	}
}

func TestIdentityIsExpired(t *testing.T) {
	var i *Identity
	if !i.IsExpired() {
		t.Fatal("expected nil identity to be expired")
	}

	i = &Identity{}
	if i.IsExpired() {
		t.Fatal("expected zero expiry identity not to be expired")
	}

	i = &Identity{ExpiresAt: time.Now().Add(-time.Minute)}
	if !i.IsExpired() {
		t.Fatal("expected past expiry to be expired")
	}

	i = &Identity{ExpiresAt: time.Now().Add(time.Minute)}
	if i.IsExpired() {
		t.Fatal("expected future expiry not to be expired")
	}
}
