package workos

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeWebhookVerifier struct {
	verifyWebhookFunc func(body []byte, signature, secret string) error
}

func (*fakeWebhookVerifier) privateWebhookVerifier() {}

func (f *fakeWebhookVerifier) VerifyWebhook(body []byte, signature, secret string) error {
	if f.verifyWebhookFunc == nil {
		return errors.New("not mocked")
	}
	return f.verifyWebhookFunc(body, signature, secret)
}

func newWebhookTestClient(t *testing.T, verifier webhookVerifier) *Client {
	t.Helper()
	client, err := New(validConfig())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	client.wh = verifier
	client.cfg.WebhookSecret = "whsec_test_secret"
	return client
}

func TestWebhookHandler_MethodNotAllowed(t *testing.T) {
	client := newWebhookTestClient(t, &fakeWebhookVerifier{
		verifyWebhookFunc: func([]byte, string, string) error { return nil },
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.test/webhooks/workos", nil)
	w := httptest.NewRecorder()

	client.WebhookHandler().ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("StatusCode = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestWebhookHandler_MissingWebhookSecret(t *testing.T) {
	calls := 0
	client := newWebhookTestClient(t, &fakeWebhookVerifier{
		verifyWebhookFunc: func([]byte, string, string) error {
			calls++
			return nil
		},
	})
	client.cfg.WebhookSecret = ""

	req := httptest.NewRequest(http.MethodPost, "http://example.test/webhooks/workos", strings.NewReader(`{"id":"evt_1","event":"user.created","data":{},"created_at":"2026-02-24T00:00:00Z"}`))
	w := httptest.NewRecorder()

	client.WebhookHandler().ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("StatusCode = %d, want %d", w.Code, http.StatusInternalServerError)
	}
	if calls != 0 {
		t.Fatalf("VerifyWebhook calls = %d, want 0", calls)
	}
}

func TestWebhookHandler_OversizedBody(t *testing.T) {
	calls := 0
	client := newWebhookTestClient(t, &fakeWebhookVerifier{
		verifyWebhookFunc: func([]byte, string, string) error {
			calls++
			return nil
		},
	})
	client.cfg.WebhookMaxBodyBytes = 10

	req := httptest.NewRequest(http.MethodPost, "http://example.test/webhooks/workos", strings.NewReader(`{"id":"evt_oversize"}`))
	w := httptest.NewRecorder()

	client.WebhookHandler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("StatusCode = %d, want %d", w.Code, http.StatusBadRequest)
	}
	if calls != 0 {
		t.Fatalf("VerifyWebhook calls = %d, want 0", calls)
	}
}

func TestWebhookHandler_InvalidSignature(t *testing.T) {
	var gotBody string
	var gotSig string
	var gotSecret string
	client := newWebhookTestClient(t, &fakeWebhookVerifier{
		verifyWebhookFunc: func(body []byte, signature, secret string) error {
			gotBody = string(body)
			gotSig = signature
			gotSecret = secret
			return errors.New("bad signature token=secret")
		},
	})

	req := httptest.NewRequest(http.MethodPost, "http://example.test/webhooks/workos", strings.NewReader(`{"id":"evt_sig_1","event":"user.created","data":{},"created_at":"2026-02-24T00:00:00Z"}`))
	req.Header.Set("WorkOS-Signature", "t=123,v1=abc")
	w := httptest.NewRecorder()

	client.WebhookHandler().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("StatusCode = %d, want %d", w.Code, http.StatusUnauthorized)
	}
	if gotSig != "t=123,v1=abc" {
		t.Fatalf("signature = %q", gotSig)
	}
	if gotSecret != client.cfg.WebhookSecret {
		t.Fatalf("secret mismatch: got %q want %q", gotSecret, client.cfg.WebhookSecret)
	}
	if !strings.Contains(gotBody, `"id":"evt_sig_1"`) {
		t.Fatalf("unexpected verifier body: %q", gotBody)
	}
	assertNoSecretLeak(t, w.Body.String(), "secret", "evt_sig_1")
}

func TestWebhookHandler_InvalidJSONAfterVerification(t *testing.T) {
	client := newWebhookTestClient(t, &fakeWebhookVerifier{
		verifyWebhookFunc: func([]byte, string, string) error { return nil },
	})

	req := httptest.NewRequest(http.MethodPost, "http://example.test/webhooks/workos", strings.NewReader(`{`))
	req.Header.Set("WorkOS-Signature", "t=123,v1=abc")
	w := httptest.NewRecorder()

	client.WebhookHandler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("StatusCode = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestWebhookHandler_ExactAndWildcardRouting(t *testing.T) {
	client := newWebhookTestClient(t, &fakeWebhookVerifier{
		verifyWebhookFunc: func([]byte, string, string) error { return nil },
	})

	exactCalls := 0
	anyCalls := 0
	handler := client.WebhookHandler(
		OnUserCreated(func(context.Context, WebhookEvent) {
			exactCalls++
		}),
		OnAnyEvent(func(context.Context, WebhookEvent) {
			anyCalls++
		}),
	)

	req := httptest.NewRequest(http.MethodPost, "http://example.test/webhooks/workos", strings.NewReader(`{"id":"evt_1","event":"user.created","data":{},"created_at":"2026-02-24T00:00:00Z"}`))
	req.Header.Set("WorkOS-Signature", "t=123,v1=abc")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("StatusCode = %d, want %d", w.Code, http.StatusOK)
	}
	if exactCalls != 1 {
		t.Fatalf("exactCalls = %d, want 1", exactCalls)
	}
	if anyCalls != 1 {
		t.Fatalf("anyCalls = %d, want 1", anyCalls)
	}
}

func TestWebhookHandler_UnknownEventTriggersWildcardOnly(t *testing.T) {
	client := newWebhookTestClient(t, &fakeWebhookVerifier{
		verifyWebhookFunc: func([]byte, string, string) error { return nil },
	})

	exactCalls := 0
	anyCalls := 0
	handler := client.WebhookHandler(
		OnUserCreated(func(context.Context, WebhookEvent) {
			exactCalls++
		}),
		OnAnyEvent(func(context.Context, WebhookEvent) {
			anyCalls++
		}),
	)

	req := httptest.NewRequest(http.MethodPost, "http://example.test/webhooks/workos", strings.NewReader(`{"id":"evt_2","event":"unknown.event","data":{},"created_at":"2026-02-24T00:00:00Z"}`))
	req.Header.Set("WorkOS-Signature", "t=123,v1=abc")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("StatusCode = %d, want %d", w.Code, http.StatusOK)
	}
	if exactCalls != 0 {
		t.Fatalf("exactCalls = %d, want 0", exactCalls)
	}
	if anyCalls != 1 {
		t.Fatalf("anyCalls = %d, want 1", anyCalls)
	}
}

func TestWebhookHandler_DuplicateSubscriptionLastWins(t *testing.T) {
	client := newWebhookTestClient(t, &fakeWebhookVerifier{
		verifyWebhookFunc: func([]byte, string, string) error { return nil },
	})

	called := ""
	handler := client.WebhookHandler(
		OnUserCreated(func(context.Context, WebhookEvent) { called = "first" }),
		OnUserCreated(func(context.Context, WebhookEvent) { called = "second" }),
	)

	req := httptest.NewRequest(http.MethodPost, "http://example.test/webhooks/workos", strings.NewReader(`{"id":"evt_3","event":"user.created","data":{},"created_at":"2026-02-24T00:00:00Z"}`))
	req.Header.Set("WorkOS-Signature", "t=123,v1=abc")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("StatusCode = %d, want %d", w.Code, http.StatusOK)
	}
	if called != "second" {
		t.Fatalf("called = %q, want %q", called, "second")
	}
}

func TestWebhookHandler_EmptyOrNilSubscriptionsIgnored(t *testing.T) {
	client := newWebhookTestClient(t, &fakeWebhookVerifier{
		verifyWebhookFunc: func([]byte, string, string) error { return nil },
	})

	called := false
	handler := client.WebhookHandler(
		WebhookSubscription{Event: "", Handler: func(context.Context, WebhookEvent) { called = true }},
		WebhookSubscription{Event: "user.created", Handler: nil},
	)

	req := httptest.NewRequest(http.MethodPost, "http://example.test/webhooks/workos", strings.NewReader(`{"id":"evt_4","event":"user.created","data":{},"created_at":"2026-02-24T00:00:00Z"}`))
	req.Header.Set("WorkOS-Signature", "t=123,v1=abc")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("StatusCode = %d, want %d", w.Code, http.StatusOK)
	}
	if called {
		t.Fatal("expected ignored subscriptions to not be called")
	}
}
