package workos

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

const (
	defaultWebhookInFlightTTL  = 5 * time.Minute
	defaultWebhookProcessedTTL = 24 * time.Hour
)

var errWebhookLeaseNotHeld = errors.New("workos: webhook lease not held")

// NewMemoryWebhookIdempotencyStore returns a single-process in-memory
// WebhookIdempotencyStore. It is suitable for tests, local development, and
// single-instance deployments. Multi-instance deployments should provide a
// shared store implementation.
func NewMemoryWebhookIdempotencyStore() WebhookIdempotencyStore {
	return &memoryWebhookIdempotencyStore{
		now:     time.Now,
		entries: make(map[string]memoryWebhookIdempotencyEntry),
	}
}

type memoryWebhookIdempotencyStore struct {
	mu      sync.Mutex
	now     func() time.Time
	entries map[string]memoryWebhookIdempotencyEntry
}

type memoryWebhookIdempotencyEntry struct {
	state     WebhookClaimStatus
	token     string
	expiresAt time.Time
}

func (s *memoryWebhookIdempotencyStore) Claim(_ context.Context, key string, leaseTTL time.Duration) (WebhookClaimStatus, string, error) {
	if key == "" {
		return 0, "", errors.New("workos: webhook idempotency key is required")
	}
	if leaseTTL <= 0 {
		return 0, "", errors.New("workos: webhook lease TTL must be positive")
	}

	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()

	s.pruneExpiredLocked(key, now)
	if entry, ok := s.entries[key]; ok {
		return entry.state, "", nil
	}

	token, err := generateWebhookLeaseToken()
	if err != nil {
		return 0, "", err
	}
	s.entries[key] = memoryWebhookIdempotencyEntry{
		state:     WebhookClaimInFlight,
		token:     token,
		expiresAt: now.Add(leaseTTL),
	}
	return WebhookClaimAcquired, token, nil
}

func (s *memoryWebhookIdempotencyStore) MarkProcessed(_ context.Context, key, token string, ttl time.Duration) error {
	if key == "" {
		return errors.New("workos: webhook idempotency key is required")
	}
	if token == "" {
		return errors.New("workos: webhook lease token is required")
	}
	if ttl <= 0 {
		return errors.New("workos: webhook processed TTL must be positive")
	}

	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()

	s.pruneExpiredLocked(key, now)
	entry, ok := s.entries[key]
	if !ok || entry.state != WebhookClaimInFlight || entry.token != token {
		return errWebhookLeaseNotHeld
	}

	s.entries[key] = memoryWebhookIdempotencyEntry{
		state:     WebhookClaimDuplicate,
		expiresAt: now.Add(ttl),
	}
	return nil
}

func (s *memoryWebhookIdempotencyStore) Release(_ context.Context, key, token string) error {
	if key == "" {
		return errors.New("workos: webhook idempotency key is required")
	}
	if token == "" {
		return errors.New("workos: webhook lease token is required")
	}

	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()

	s.pruneExpiredLocked(key, now)
	entry, ok := s.entries[key]
	if !ok {
		return nil
	}
	if entry.state != WebhookClaimInFlight || entry.token != token {
		return nil
	}
	delete(s.entries, key)
	return nil
}

func (s *memoryWebhookIdempotencyStore) pruneExpiredLocked(key string, now time.Time) {
	if entry, ok := s.entries[key]; ok && !entry.expiresAt.After(now) {
		delete(s.entries, key)
	}
}

func generateWebhookLeaseToken() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
