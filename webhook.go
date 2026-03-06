package workos

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// WebhookHandler verifies, parses, and dispatches WorkOS webhooks using the
// legacy success-only subscription model.
func (c *Client) WebhookHandler(handlers ...WebhookSubscription) http.Handler {
	return c.WebhookHandlerWithOptions(WebhookHandlerOptions{}, handlers...)
}

// WebhookHandlerWithOptions verifies, parses, and dispatches WorkOS webhooks
// with optional retry-aware handlers and idempotency by WebhookEvent.ID.
func (c *Client) WebhookHandlerWithOptions(opts WebhookHandlerOptions, handlers ...WebhookSubscription) http.Handler {
	registry := buildWebhookRegistry(handlers)
	inFlightTTL := opts.InFlightTTL
	if inFlightTTL <= 0 {
		inFlightTTL = defaultWebhookInFlightTTL
	}
	processedTTL := opts.ProcessedTTL
	if processedTTL <= 0 {
		processedTTL = defaultWebhookProcessedTTL
	}

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

		var claimToken string
		if opts.IdempotencyStore != nil {
			eventID := strings.TrimSpace(event.ID)
			if eventID == "" {
				http.Error(w, "Webhook event missing id", http.StatusBadRequest)
				return
			}

			status, token, err := opts.IdempotencyStore.Claim(r.Context(), eventID, inFlightTTL)
			if err != nil {
				http.Error(w, "Webhook processing failed", http.StatusInternalServerError)
				return
			}
			switch status {
			case WebhookClaimAcquired:
				if token == "" {
					http.Error(w, "Webhook processing failed", http.StatusInternalServerError)
					return
				}
				claimToken = token
			case WebhookClaimDuplicate:
				w.WriteHeader(http.StatusOK)
				return
			case WebhookClaimInFlight:
				http.Error(w, "Webhook event is already being processed", http.StatusServiceUnavailable)
				return
			default:
				http.Error(w, "Webhook processing failed", http.StatusInternalServerError)
				return
			}
		}

		if err := dispatchWebhookEvent(r.Context(), registry, event); err != nil {
			if opts.IdempotencyStore != nil && claimToken != "" {
				_ = opts.IdempotencyStore.Release(r.Context(), event.ID, claimToken)
			}
			http.Error(w, "Webhook processing failed", http.StatusInternalServerError)
			return
		}

		if opts.IdempotencyStore != nil && claimToken != "" {
			if err := opts.IdempotencyStore.MarkProcessed(r.Context(), event.ID, claimToken, processedTTL); err != nil {
				_ = opts.IdempotencyStore.Release(r.Context(), event.ID, claimToken)
				http.Error(w, "Webhook processing failed", http.StatusInternalServerError)
				return
			}
		}

		w.WriteHeader(http.StatusOK)
	})
}

func buildWebhookRegistry(handlers []WebhookSubscription) map[string]WebhookHandlerFunc {
	registry := make(map[string]WebhookHandlerFunc, len(handlers))
	for _, h := range handlers {
		event := strings.TrimSpace(h.Event)
		handler := normalizeWebhookHandler(h)
		if event == "" || handler == nil {
			continue
		}
		registry[event] = handler
	}
	return registry
}

func normalizeWebhookHandler(h WebhookSubscription) WebhookHandlerFunc {
	if h.HandlerErr != nil {
		return h.HandlerErr
	}
	if h.Handler == nil {
		return nil
	}
	return func(ctx context.Context, event WebhookEvent) error {
		h.Handler(ctx, event)
		return nil
	}
}

func dispatchWebhookEvent(ctx context.Context, registry map[string]WebhookHandlerFunc, event WebhookEvent) error {
	if handler := registry[event.Event]; handler != nil {
		if err := callWebhookHandler(ctx, handler, event); err != nil {
			return err
		}
	}
	if anyHandler := registry["*"]; anyHandler != nil {
		if err := callWebhookHandler(ctx, anyHandler, event); err != nil {
			return err
		}
	}
	return nil
}

func callWebhookHandler(ctx context.Context, handler WebhookHandlerFunc, event WebhookEvent) (err error) {
	defer func() {
		if recover() != nil {
			err = errWebhookHandlerPanic
		}
	}()
	return handler(ctx, event)
}

var errWebhookHandlerPanic = &SafeError{msg: "workos: webhook handler panicked"}

func OnDirectoryUserCreated(fn func(context.Context, WebhookEvent)) WebhookSubscription {
	return WebhookSubscription{Event: "dsync.user.created", Handler: fn}
}

func OnDirectoryUserCreatedErr(fn WebhookHandlerFunc) WebhookSubscription {
	return WebhookSubscription{Event: "dsync.user.created", HandlerErr: fn}
}

func OnDirectoryUserUpdated(fn func(context.Context, WebhookEvent)) WebhookSubscription {
	return WebhookSubscription{Event: "dsync.user.updated", Handler: fn}
}

func OnDirectoryUserUpdatedErr(fn WebhookHandlerFunc) WebhookSubscription {
	return WebhookSubscription{Event: "dsync.user.updated", HandlerErr: fn}
}

func OnDirectoryUserDeleted(fn func(context.Context, WebhookEvent)) WebhookSubscription {
	return WebhookSubscription{Event: "dsync.user.deleted", Handler: fn}
}

func OnDirectoryUserDeletedErr(fn WebhookHandlerFunc) WebhookSubscription {
	return WebhookSubscription{Event: "dsync.user.deleted", HandlerErr: fn}
}

func OnDirectoryGroupCreated(fn func(context.Context, WebhookEvent)) WebhookSubscription {
	return WebhookSubscription{Event: "dsync.group.created", Handler: fn}
}

func OnDirectoryGroupCreatedErr(fn WebhookHandlerFunc) WebhookSubscription {
	return WebhookSubscription{Event: "dsync.group.created", HandlerErr: fn}
}

func OnDirectoryGroupUpdated(fn func(context.Context, WebhookEvent)) WebhookSubscription {
	return WebhookSubscription{Event: "dsync.group.updated", Handler: fn}
}

func OnDirectoryGroupUpdatedErr(fn WebhookHandlerFunc) WebhookSubscription {
	return WebhookSubscription{Event: "dsync.group.updated", HandlerErr: fn}
}

func OnDirectoryGroupDeleted(fn func(context.Context, WebhookEvent)) WebhookSubscription {
	return WebhookSubscription{Event: "dsync.group.deleted", Handler: fn}
}

func OnDirectoryGroupDeletedErr(fn WebhookHandlerFunc) WebhookSubscription {
	return WebhookSubscription{Event: "dsync.group.deleted", HandlerErr: fn}
}

func OnConnectionActivated(fn func(context.Context, WebhookEvent)) WebhookSubscription {
	return WebhookSubscription{Event: "connection.activated", Handler: fn}
}

func OnConnectionActivatedErr(fn WebhookHandlerFunc) WebhookSubscription {
	return WebhookSubscription{Event: "connection.activated", HandlerErr: fn}
}

func OnConnectionDeactivated(fn func(context.Context, WebhookEvent)) WebhookSubscription {
	return WebhookSubscription{Event: "connection.deactivated", Handler: fn}
}

func OnConnectionDeactivatedErr(fn WebhookHandlerFunc) WebhookSubscription {
	return WebhookSubscription{Event: "connection.deactivated", HandlerErr: fn}
}

func OnUserCreated(fn func(context.Context, WebhookEvent)) WebhookSubscription {
	return WebhookSubscription{Event: "user.created", Handler: fn}
}

func OnUserCreatedErr(fn WebhookHandlerFunc) WebhookSubscription {
	return WebhookSubscription{Event: "user.created", HandlerErr: fn}
}

func OnUserUpdated(fn func(context.Context, WebhookEvent)) WebhookSubscription {
	return WebhookSubscription{Event: "user.updated", Handler: fn}
}

func OnUserUpdatedErr(fn WebhookHandlerFunc) WebhookSubscription {
	return WebhookSubscription{Event: "user.updated", HandlerErr: fn}
}

func OnUserDeleted(fn func(context.Context, WebhookEvent)) WebhookSubscription {
	return WebhookSubscription{Event: "user.deleted", Handler: fn}
}

func OnUserDeletedErr(fn WebhookHandlerFunc) WebhookSubscription {
	return WebhookSubscription{Event: "user.deleted", HandlerErr: fn}
}

func OnOrganizationMembershipCreated(fn func(context.Context, WebhookEvent)) WebhookSubscription {
	return WebhookSubscription{Event: "organization_membership.created", Handler: fn}
}

func OnOrganizationMembershipCreatedErr(fn WebhookHandlerFunc) WebhookSubscription {
	return WebhookSubscription{Event: "organization_membership.created", HandlerErr: fn}
}

func OnOrganizationMembershipDeleted(fn func(context.Context, WebhookEvent)) WebhookSubscription {
	return WebhookSubscription{Event: "organization_membership.deleted", Handler: fn}
}

func OnOrganizationMembershipDeletedErr(fn WebhookHandlerFunc) WebhookSubscription {
	return WebhookSubscription{Event: "organization_membership.deleted", HandlerErr: fn}
}

func OnSessionCreated(fn func(context.Context, WebhookEvent)) WebhookSubscription {
	return WebhookSubscription{Event: "session.created", Handler: fn}
}

func OnSessionCreatedErr(fn WebhookHandlerFunc) WebhookSubscription {
	return WebhookSubscription{Event: "session.created", HandlerErr: fn}
}

func OnAnyEvent(fn func(context.Context, WebhookEvent)) WebhookSubscription {
	return WebhookSubscription{Event: "*", Handler: fn}
}

func OnAnyEventErr(fn WebhookHandlerFunc) WebhookSubscription {
	return WebhookSubscription{Event: "*", HandlerErr: fn}
}
