package workos

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/workos/workos-go/v6/pkg/usermanagement"
)

type sessionListCacheEntry struct {
	fetchedAt time.Time
	sessions  map[string]*SessionInfo
}

func parseWorkOSTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, errors.New("empty time")
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339, s)
}

func (c *Client) listSessionsForUser(ctx context.Context, userID string) (map[string]*SessionInfo, error) {
	if userID == "" {
		return nil, errors.New("workos: userID required")
	}

	ttl := c.cfg.SessionListCacheDuration
	if ttl > 0 {
		c.sessionsMu.Lock()
		if c.sessionsCache == nil {
			c.sessionsCache = make(map[string]sessionListCacheEntry)
		}
		if ent, ok := c.sessionsCache[userID]; ok && time.Since(ent.fetchedAt) < ttl && ent.sessions != nil {
			sessions := ent.sessions
			c.sessionsMu.Unlock()
			return sessions, nil
		}
		c.sessionsMu.Unlock()
	}

	sessions := make(map[string]*SessionInfo, 16)
	opts := usermanagement.ListSessionsOpts{Limit: 100}
	for {
		resp, err := c.um.ListSessions(ctx, userID, opts)
		if err != nil {
			return nil, errors.New("workos: session list failed")
		}

		for _, session := range resp.Data {
			expiresAt, _ := parseWorkOSTime(session.ExpiresAt)
			sessions[session.ID] = &SessionInfo{
				SessionID: session.ID,
				UserID:    session.UserID,
				OrgID:     session.OrganizationID,
				Active:    strings.EqualFold(session.Status, "active"),
				ExpiresAt: expiresAt,
			}
		}

		after := resp.ListMetadata.After
		if after == "" {
			break
		}
		opts.Before = ""
		opts.After = after
	}

	if ttl > 0 {
		c.sessionsMu.Lock()
		if c.sessionsCache == nil {
			c.sessionsCache = make(map[string]sessionListCacheEntry)
		}
		c.sessionsCache[userID] = sessionListCacheEntry{
			fetchedAt: time.Now(),
			sessions:  sessions,
		}
		c.sessionsMu.Unlock()
	}

	return sessions, nil
}

func (c *Client) ValidateSession(ctx context.Context, userID, sessionID string) (*SessionInfo, error) {
	if userID == "" || sessionID == "" {
		return nil, errors.New("workos: validate session requires userID and sessionID")
	}

	sessions, err := c.listSessionsForUser(ctx, userID)
	if err != nil {
		return nil, errors.New("workos: session validation failed")
	}
	if info := sessions[sessionID]; info != nil {
		return info, nil
	}
	return &SessionInfo{SessionID: sessionID, UserID: userID, Active: false}, nil
}

func (c *Client) RevokeSession(ctx context.Context, sessionID string) error {
	if sessionID == "" {
		return errors.New("workos: sessionID required")
	}
	if err := c.um.RevokeSession(ctx, usermanagement.RevokeSessionOpts{SessionID: sessionID}); err != nil {
		return errors.New("workos: revoke session failed")
	}
	return nil
}
