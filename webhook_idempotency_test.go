package workos

import (
	"context"
	"testing"
	"time"
)

func TestMemoryWebhookIdempotencyStore_LeaseLifecycle(t *testing.T) {
	now := time.Date(2026, 3, 5, 12, 0, 0, 0, time.UTC)
	store := NewMemoryWebhookIdempotencyStore().(*memoryWebhookIdempotencyStore)
	store.now = func() time.Time { return now }

	status, token, err := store.Claim(context.Background(), "evt_1", 5*time.Minute)
	if err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	if status != WebhookClaimAcquired {
		t.Fatalf("Claim() status = %v, want %v", status, WebhookClaimAcquired)
	}
	if token == "" {
		t.Fatal("expected non-empty lease token")
	}

	status, dupToken, err := store.Claim(context.Background(), "evt_1", 5*time.Minute)
	if err != nil {
		t.Fatalf("second Claim() error = %v", err)
	}
	if status != WebhookClaimInFlight {
		t.Fatalf("second Claim() status = %v, want %v", status, WebhookClaimInFlight)
	}
	if dupToken != "" {
		t.Fatalf("second Claim() token = %q, want empty", dupToken)
	}

	if err := store.MarkProcessed(context.Background(), "evt_1", token, 24*time.Hour); err != nil {
		t.Fatalf("MarkProcessed() error = %v", err)
	}

	status, _, err = store.Claim(context.Background(), "evt_1", 5*time.Minute)
	if err != nil {
		t.Fatalf("third Claim() error = %v", err)
	}
	if status != WebhookClaimDuplicate {
		t.Fatalf("third Claim() status = %v, want %v", status, WebhookClaimDuplicate)
	}
}

func TestMemoryWebhookIdempotencyStore_TokenMismatchDoesNotStealLease(t *testing.T) {
	store := NewMemoryWebhookIdempotencyStore().(*memoryWebhookIdempotencyStore)

	status, token, err := store.Claim(context.Background(), "evt_lease", 5*time.Minute)
	if err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	if status != WebhookClaimAcquired {
		t.Fatalf("Claim() status = %v, want %v", status, WebhookClaimAcquired)
	}

	if err := store.Release(context.Background(), "evt_lease", "wrong_token"); err != nil {
		t.Fatalf("Release() error = %v", err)
	}

	status, _, err = store.Claim(context.Background(), "evt_lease", 5*time.Minute)
	if err != nil {
		t.Fatalf("second Claim() error = %v", err)
	}
	if status != WebhookClaimInFlight {
		t.Fatalf("second Claim() status = %v, want %v", status, WebhookClaimInFlight)
	}

	if err := store.MarkProcessed(context.Background(), "evt_lease", "wrong_token", 24*time.Hour); err == nil {
		t.Fatal("MarkProcessed() with wrong token succeeded, want error")
	}

	if err := store.MarkProcessed(context.Background(), "evt_lease", token, 24*time.Hour); err != nil {
		t.Fatalf("MarkProcessed() with correct token error = %v", err)
	}
}

func TestMemoryWebhookIdempotencyStore_LeaseExpiryAllowsRetry(t *testing.T) {
	now := time.Date(2026, 3, 5, 12, 0, 0, 0, time.UTC)
	store := NewMemoryWebhookIdempotencyStore().(*memoryWebhookIdempotencyStore)
	store.now = func() time.Time { return now }

	status, firstToken, err := store.Claim(context.Background(), "evt_expire", 5*time.Minute)
	if err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	if status != WebhookClaimAcquired {
		t.Fatalf("Claim() status = %v, want %v", status, WebhookClaimAcquired)
	}

	now = now.Add(6 * time.Minute)

	status, secondToken, err := store.Claim(context.Background(), "evt_expire", 5*time.Minute)
	if err != nil {
		t.Fatalf("second Claim() error = %v", err)
	}
	if status != WebhookClaimAcquired {
		t.Fatalf("second Claim() status = %v, want %v", status, WebhookClaimAcquired)
	}
	if secondToken == "" || secondToken == firstToken {
		t.Fatalf("second token = %q, want new non-empty token different from %q", secondToken, firstToken)
	}
}

func TestMemoryWebhookIdempotencyStore_ProcessedExpiryAllowsRedelivery(t *testing.T) {
	now := time.Date(2026, 3, 5, 12, 0, 0, 0, time.UTC)
	store := NewMemoryWebhookIdempotencyStore().(*memoryWebhookIdempotencyStore)
	store.now = func() time.Time { return now }

	status, token, err := store.Claim(context.Background(), "evt_processed_expire", 5*time.Minute)
	if err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	if status != WebhookClaimAcquired {
		t.Fatalf("Claim() status = %v, want %v", status, WebhookClaimAcquired)
	}
	if err := store.MarkProcessed(context.Background(), "evt_processed_expire", token, time.Hour); err != nil {
		t.Fatalf("MarkProcessed() error = %v", err)
	}

	now = now.Add(2 * time.Hour)

	status, newToken, err := store.Claim(context.Background(), "evt_processed_expire", 5*time.Minute)
	if err != nil {
		t.Fatalf("second Claim() error = %v", err)
	}
	if status != WebhookClaimAcquired {
		t.Fatalf("second Claim() status = %v, want %v", status, WebhookClaimAcquired)
	}
	if newToken == "" {
		t.Fatal("expected non-empty token after processed expiry")
	}
}
