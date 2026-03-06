package workos

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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

type fakeWebhookIdempotencyStore struct {
	claimFunc         func(context.Context, string, time.Duration) (WebhookClaimStatus, string, error)
	markProcessedFunc func(context.Context, string, string, time.Duration) error
	releaseFunc       func(context.Context, string, string) error
}

func (f *fakeWebhookIdempotencyStore) Claim(ctx context.Context, key string, leaseTTL time.Duration) (WebhookClaimStatus, string, error) {
	if f.claimFunc == nil {
		return 0, "", errors.New("claim not mocked")
	}
	return f.claimFunc(ctx, key, leaseTTL)
}

func (f *fakeWebhookIdempotencyStore) MarkProcessed(ctx context.Context, key, token string, ttl time.Duration) error {
	if f.markProcessedFunc == nil {
		return nil
	}
	return f.markProcessedFunc(ctx, key, token, ttl)
}

func (f *fakeWebhookIdempotencyStore) Release(ctx context.Context, key, token string) error {
	if f.releaseFunc == nil {
		return nil
	}
	return f.releaseFunc(ctx, key, token)
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

func TestWebhookHandler_ErrorHandlerReturns500(t *testing.T) {
	client := newWebhookTestClient(t, &fakeWebhookVerifier{
		verifyWebhookFunc: func([]byte, string, string) error { return nil },
	})

	handler := client.WebhookHandler(
		OnUserCreatedErr(func(context.Context, WebhookEvent) error {
			return errors.New("boom")
		}),
	)

	req := httptest.NewRequest(http.MethodPost, "http://example.test/webhooks/workos", strings.NewReader(`{"id":"evt_err_1","event":"user.created","data":{},"created_at":"2026-02-24T00:00:00Z"}`))
	req.Header.Set("WorkOS-Signature", "t=123,v1=abc")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("StatusCode = %d, want %d", w.Code, http.StatusInternalServerError)
	}
}

func TestWebhookHandler_WildcardErrorReturns500(t *testing.T) {
	client := newWebhookTestClient(t, &fakeWebhookVerifier{
		verifyWebhookFunc: func([]byte, string, string) error { return nil },
	})

	calledExact := 0
	handler := client.WebhookHandler(
		OnUserCreated(func(context.Context, WebhookEvent) { calledExact++ }),
		OnAnyEventErr(func(context.Context, WebhookEvent) error {
			return errors.New("wildcard failure")
		}),
	)

	req := httptest.NewRequest(http.MethodPost, "http://example.test/webhooks/workos", strings.NewReader(`{"id":"evt_err_2","event":"user.created","data":{},"created_at":"2026-02-24T00:00:00Z"}`))
	req.Header.Set("WorkOS-Signature", "t=123,v1=abc")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("StatusCode = %d, want %d", w.Code, http.StatusInternalServerError)
	}
	if calledExact != 1 {
		t.Fatalf("calledExact = %d, want 1", calledExact)
	}
}

func TestWebhookHandler_ExactFailurePreventsWildcard(t *testing.T) {
	client := newWebhookTestClient(t, &fakeWebhookVerifier{
		verifyWebhookFunc: func([]byte, string, string) error { return nil },
	})

	anyCalls := 0
	handler := client.WebhookHandler(
		OnUserCreatedErr(func(context.Context, WebhookEvent) error {
			return errors.New("exact failure")
		}),
		OnAnyEvent(func(context.Context, WebhookEvent) { anyCalls++ }),
	)

	req := httptest.NewRequest(http.MethodPost, "http://example.test/webhooks/workos", strings.NewReader(`{"id":"evt_err_3","event":"user.created","data":{},"created_at":"2026-02-24T00:00:00Z"}`))
	req.Header.Set("WorkOS-Signature", "t=123,v1=abc")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("StatusCode = %d, want %d", w.Code, http.StatusInternalServerError)
	}
	if anyCalls != 0 {
		t.Fatalf("anyCalls = %d, want 0", anyCalls)
	}
}

func TestWebhookHandler_PanicRecoveredReturns500(t *testing.T) {
	client := newWebhookTestClient(t, &fakeWebhookVerifier{
		verifyWebhookFunc: func([]byte, string, string) error { return nil },
	})

	handler := client.WebhookHandler(
		OnUserCreated(func(context.Context, WebhookEvent) {
			panic("kaboom")
		}),
	)

	req := httptest.NewRequest(http.MethodPost, "http://example.test/webhooks/workos", strings.NewReader(`{"id":"evt_panic","event":"user.created","data":{},"created_at":"2026-02-24T00:00:00Z"}`))
	req.Header.Set("WorkOS-Signature", "t=123,v1=abc")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("StatusCode = %d, want %d", w.Code, http.StatusInternalServerError)
	}
}

func TestWebhookHandler_WildcardPanicReleasesClaimAndRetrySucceeds(t *testing.T) {
	client := newWebhookTestClient(t, &fakeWebhookVerifier{
		verifyWebhookFunc: func([]byte, string, string) error { return nil },
	})

	store := NewMemoryWebhookIdempotencyStore()
	exactCalls := 0
	wildcardCalls := 0
	handler := client.WebhookHandlerWithOptions(
		WebhookHandlerOptions{IdempotencyStore: store},
		OnUserCreated(func(context.Context, WebhookEvent) {
			exactCalls++
		}),
		OnAnyEventErr(func(context.Context, WebhookEvent) error {
			wildcardCalls++
			if wildcardCalls == 1 {
				panic("wildcard kaboom")
			}
			return nil
		}),
	)

	for i, wantStatus := range []int{http.StatusInternalServerError, http.StatusOK} {
		req := httptest.NewRequest(http.MethodPost, "http://example.test/webhooks/workos", strings.NewReader(`{"id":"evt_panic_retry","event":"user.created","data":{},"created_at":"2026-02-24T00:00:00Z"}`))
		req.Header.Set("WorkOS-Signature", "t=123,v1=abc")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != wantStatus {
			t.Fatalf("attempt %d StatusCode = %d, want %d", i+1, w.Code, wantStatus)
		}
	}
	if exactCalls != 2 {
		t.Fatalf("exactCalls = %d, want 2", exactCalls)
	}
	if wildcardCalls != 2 {
		t.Fatalf("wildcardCalls = %d, want 2", wildcardCalls)
	}
}

func TestWebhookHandler_IdempotencyDuplicateProcessedReturns200(t *testing.T) {
	client := newWebhookTestClient(t, &fakeWebhookVerifier{
		verifyWebhookFunc: func([]byte, string, string) error { return nil },
	})

	calls := 0
	store := &fakeWebhookIdempotencyStore{
		claimFunc: func(context.Context, string, time.Duration) (WebhookClaimStatus, string, error) {
			return WebhookClaimDuplicate, "", nil
		},
	}
	handler := client.WebhookHandlerWithOptions(WebhookHandlerOptions{
		IdempotencyStore: store,
	}, OnUserCreated(func(context.Context, WebhookEvent) {
		calls++
	}))

	req := httptest.NewRequest(http.MethodPost, "http://example.test/webhooks/workos", strings.NewReader(`{"id":"evt_dup","event":"user.created","data":{},"created_at":"2026-02-24T00:00:00Z"}`))
	req.Header.Set("WorkOS-Signature", "t=123,v1=abc")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("StatusCode = %d, want %d", w.Code, http.StatusOK)
	}
	if calls != 0 {
		t.Fatalf("calls = %d, want 0", calls)
	}
}

func TestWebhookHandler_IdempotencyInFlightReturns503(t *testing.T) {
	client := newWebhookTestClient(t, &fakeWebhookVerifier{
		verifyWebhookFunc: func([]byte, string, string) error { return nil },
	})

	store := &fakeWebhookIdempotencyStore{
		claimFunc: func(context.Context, string, time.Duration) (WebhookClaimStatus, string, error) {
			return WebhookClaimInFlight, "", nil
		},
	}
	handler := client.WebhookHandlerWithOptions(WebhookHandlerOptions{
		IdempotencyStore: store,
	}, OnUserCreated(func(context.Context, WebhookEvent) {}))

	req := httptest.NewRequest(http.MethodPost, "http://example.test/webhooks/workos", strings.NewReader(`{"id":"evt_inflight","event":"user.created","data":{},"created_at":"2026-02-24T00:00:00Z"}`))
	req.Header.Set("WorkOS-Signature", "t=123,v1=abc")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("StatusCode = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
}

func TestWebhookHandler_IdempotencyMissingEventIDReturns400(t *testing.T) {
	client := newWebhookTestClient(t, &fakeWebhookVerifier{
		verifyWebhookFunc: func([]byte, string, string) error { return nil },
	})

	store := &fakeWebhookIdempotencyStore{
		claimFunc: func(context.Context, string, time.Duration) (WebhookClaimStatus, string, error) {
			t.Fatal("Claim should not be called when event ID is missing")
			return 0, "", nil
		},
	}
	handler := client.WebhookHandlerWithOptions(WebhookHandlerOptions{
		IdempotencyStore: store,
	}, OnUserCreated(func(context.Context, WebhookEvent) {}))

	req := httptest.NewRequest(http.MethodPost, "http://example.test/webhooks/workos", strings.NewReader(`{"id":"   ","event":"user.created","data":{},"created_at":"2026-02-24T00:00:00Z"}`))
	req.Header.Set("WorkOS-Signature", "t=123,v1=abc")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("StatusCode = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestWebhookHandler_IdempotencyClaimFailureReturns500(t *testing.T) {
	client := newWebhookTestClient(t, &fakeWebhookVerifier{
		verifyWebhookFunc: func([]byte, string, string) error { return nil },
	})

	store := &fakeWebhookIdempotencyStore{
		claimFunc: func(context.Context, string, time.Duration) (WebhookClaimStatus, string, error) {
			return 0, "", errors.New("claim failed")
		},
	}
	handler := client.WebhookHandlerWithOptions(WebhookHandlerOptions{
		IdempotencyStore: store,
	}, OnUserCreated(func(context.Context, WebhookEvent) {}))

	req := httptest.NewRequest(http.MethodPost, "http://example.test/webhooks/workos", strings.NewReader(`{"id":"evt_claim_fail","event":"user.created","data":{},"created_at":"2026-02-24T00:00:00Z"}`))
	req.Header.Set("WorkOS-Signature", "t=123,v1=abc")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("StatusCode = %d, want %d", w.Code, http.StatusInternalServerError)
	}
}

func TestWebhookHandler_IdempotencyMarkProcessedFailureReturns500(t *testing.T) {
	client := newWebhookTestClient(t, &fakeWebhookVerifier{
		verifyWebhookFunc: func([]byte, string, string) error { return nil },
	})

	releaseCalls := 0
	store := &fakeWebhookIdempotencyStore{
		claimFunc: func(context.Context, string, time.Duration) (WebhookClaimStatus, string, error) {
			return WebhookClaimAcquired, "tok_1", nil
		},
		markProcessedFunc: func(context.Context, string, string, time.Duration) error {
			return errors.New("mark failed")
		},
		releaseFunc: func(context.Context, string, string) error {
			releaseCalls++
			return nil
		},
	}
	handler := client.WebhookHandlerWithOptions(WebhookHandlerOptions{
		IdempotencyStore: store,
	}, OnUserCreated(func(context.Context, WebhookEvent) {}))

	req := httptest.NewRequest(http.MethodPost, "http://example.test/webhooks/workos", strings.NewReader(`{"id":"evt_mark_fail","event":"user.created","data":{},"created_at":"2026-02-24T00:00:00Z"}`))
	req.Header.Set("WorkOS-Signature", "t=123,v1=abc")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("StatusCode = %d, want %d", w.Code, http.StatusInternalServerError)
	}
	if releaseCalls != 1 {
		t.Fatalf("releaseCalls = %d, want 1", releaseCalls)
	}
}

func TestWebhookHandler_IdempotencyReleaseFailureReturns500(t *testing.T) {
	client := newWebhookTestClient(t, &fakeWebhookVerifier{
		verifyWebhookFunc: func([]byte, string, string) error { return nil },
	})

	releaseCalls := 0
	store := &fakeWebhookIdempotencyStore{
		claimFunc: func(context.Context, string, time.Duration) (WebhookClaimStatus, string, error) {
			return WebhookClaimAcquired, "tok_release", nil
		},
		releaseFunc: func(context.Context, string, string) error {
			releaseCalls++
			return errors.New("release failed")
		},
	}
	handler := client.WebhookHandlerWithOptions(WebhookHandlerOptions{
		IdempotencyStore: store,
	}, OnUserCreatedErr(func(context.Context, WebhookEvent) error {
		return errors.New("handler failed")
	}))

	req := httptest.NewRequest(http.MethodPost, "http://example.test/webhooks/workos", strings.NewReader(`{"id":"evt_release_fail","event":"user.created","data":{},"created_at":"2026-02-24T00:00:00Z"}`))
	req.Header.Set("WorkOS-Signature", "t=123,v1=abc")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("StatusCode = %d, want %d", w.Code, http.StatusInternalServerError)
	}
	if releaseCalls != 1 {
		t.Fatalf("releaseCalls = %d, want 1", releaseCalls)
	}
}

func TestWebhookHandler_FailureReleasesClaimAndLaterRetrySucceeds(t *testing.T) {
	client := newWebhookTestClient(t, &fakeWebhookVerifier{
		verifyWebhookFunc: func([]byte, string, string) error { return nil },
	})

	store := NewMemoryWebhookIdempotencyStore()
	attempts := 0
	handler := client.WebhookHandlerWithOptions(WebhookHandlerOptions{
		IdempotencyStore: store,
	}, OnUserCreatedErr(func(context.Context, WebhookEvent) error {
		attempts++
		if attempts == 1 {
			return errors.New("first attempt fails")
		}
		return nil
	}))

	for i, wantStatus := range []int{http.StatusInternalServerError, http.StatusOK} {
		req := httptest.NewRequest(http.MethodPost, "http://example.test/webhooks/workos", strings.NewReader(`{"id":"evt_retry","event":"user.created","data":{},"created_at":"2026-02-24T00:00:00Z"}`))
		req.Header.Set("WorkOS-Signature", "t=123,v1=abc")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != wantStatus {
			t.Fatalf("attempt %d StatusCode = %d, want %d", i+1, w.Code, wantStatus)
		}
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2", attempts)
	}
}
