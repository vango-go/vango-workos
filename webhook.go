package workos

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

func (c *Client) WebhookHandler(handlers ...WebhookSubscription) http.Handler {
	registry := buildWebhookRegistry(handlers)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if strings.TrimSpace(c.cfg.WebhookSecret) == "" {
			http.Error(w, "Webhook handler is not configured", http.StatusInternalServerError)
			return
		}

		limit := c.cfg.WebhookMaxBodyBytes
		if limit <= 0 {
			limit = 1 << 20
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
		if err != nil {
			http.Error(w, "Failed to read body", http.StatusBadRequest)
			return
		}
		if int64(len(body)) > limit {
			http.Error(w, "Request body too large", http.StatusBadRequest)
			return
		}

		sig := r.Header.Get("WorkOS-Signature")
		if err := c.wh.VerifyWebhook(body, sig, c.cfg.WebhookSecret); err != nil {
			http.Error(w, "Invalid signature", http.StatusUnauthorized)
			return
		}

		var event WebhookEvent
		if err := json.Unmarshal(body, &event); err != nil {
			http.Error(w, "Invalid event payload", http.StatusBadRequest)
			return
		}

		if handler := registry[event.Event]; handler != nil {
			handler(r.Context(), event)
		}
		if anyHandler := registry["*"]; anyHandler != nil {
			anyHandler(r.Context(), event)
		}

		w.WriteHeader(http.StatusOK)
	})
}

func buildWebhookRegistry(handlers []WebhookSubscription) map[string]func(context.Context, WebhookEvent) {
	registry := make(map[string]func(context.Context, WebhookEvent), len(handlers))
	for _, h := range handlers {
		event := strings.TrimSpace(h.Event)
		if event == "" || h.Handler == nil {
			continue
		}
		registry[event] = h.Handler
	}
	return registry
}

func OnDirectoryUserCreated(fn func(context.Context, WebhookEvent)) WebhookSubscription {
	return WebhookSubscription{Event: "dsync.user.created", Handler: fn}
}

func OnDirectoryUserUpdated(fn func(context.Context, WebhookEvent)) WebhookSubscription {
	return WebhookSubscription{Event: "dsync.user.updated", Handler: fn}
}

func OnDirectoryUserDeleted(fn func(context.Context, WebhookEvent)) WebhookSubscription {
	return WebhookSubscription{Event: "dsync.user.deleted", Handler: fn}
}

func OnDirectoryGroupCreated(fn func(context.Context, WebhookEvent)) WebhookSubscription {
	return WebhookSubscription{Event: "dsync.group.created", Handler: fn}
}

func OnDirectoryGroupUpdated(fn func(context.Context, WebhookEvent)) WebhookSubscription {
	return WebhookSubscription{Event: "dsync.group.updated", Handler: fn}
}

func OnDirectoryGroupDeleted(fn func(context.Context, WebhookEvent)) WebhookSubscription {
	return WebhookSubscription{Event: "dsync.group.deleted", Handler: fn}
}

func OnConnectionActivated(fn func(context.Context, WebhookEvent)) WebhookSubscription {
	return WebhookSubscription{Event: "connection.activated", Handler: fn}
}

func OnConnectionDeactivated(fn func(context.Context, WebhookEvent)) WebhookSubscription {
	return WebhookSubscription{Event: "connection.deactivated", Handler: fn}
}

func OnUserCreated(fn func(context.Context, WebhookEvent)) WebhookSubscription {
	return WebhookSubscription{Event: "user.created", Handler: fn}
}

func OnUserUpdated(fn func(context.Context, WebhookEvent)) WebhookSubscription {
	return WebhookSubscription{Event: "user.updated", Handler: fn}
}

func OnUserDeleted(fn func(context.Context, WebhookEvent)) WebhookSubscription {
	return WebhookSubscription{Event: "user.deleted", Handler: fn}
}

func OnOrganizationMembershipCreated(fn func(context.Context, WebhookEvent)) WebhookSubscription {
	return WebhookSubscription{Event: "organization_membership.created", Handler: fn}
}

func OnOrganizationMembershipDeleted(fn func(context.Context, WebhookEvent)) WebhookSubscription {
	return WebhookSubscription{Event: "organization_membership.deleted", Handler: fn}
}

func OnSessionCreated(fn func(context.Context, WebhookEvent)) WebhookSubscription {
	return WebhookSubscription{Event: "session.created", Handler: fn}
}

func OnAnyEvent(fn func(context.Context, WebhookEvent)) WebhookSubscription {
	return WebhookSubscription{Event: "*", Handler: fn}
}
