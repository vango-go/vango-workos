package workos

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"testing"

	"github.com/vango-go/vango"
	"github.com/vango-go/vango/pkg/auth"
	"github.com/vango-go/vango/pkg/server"
	corevango "github.com/vango-go/vango/pkg/vango"
)

type ctxStub struct {
	user       any
	stdCtx     context.Context
	patchCount int
}

var _ vango.Ctx = (*ctxStub)(nil)

func (c *ctxStub) Request() *http.Request              { return nil }
func (c *ctxStub) Path() string                        { return "" }
func (c *ctxStub) Method() string                      { return "" }
func (c *ctxStub) Query() url.Values                   { return url.Values{} }
func (c *ctxStub) QueryParam(string) string            { return "" }
func (c *ctxStub) Param(string) string                 { return "" }
func (c *ctxStub) Header(string) string                { return "" }
func (c *ctxStub) Cookie(string) (*http.Cookie, error) { return nil, http.ErrNoCookie }
func (c *ctxStub) Status(int)                          {}
func (c *ctxStub) Redirect(string, int)                {}
func (c *ctxStub) RedirectExternal(string, int)        {}
func (c *ctxStub) SetHeader(string, string)            {}
func (c *ctxStub) SetCookie(*http.Cookie)              {}
func (c *ctxStub) SetCookieStrict(*http.Cookie, ...server.CookieOption) error {
	return nil
}
func (c *ctxStub) Session() corevango.Session        { return nil }
func (c *ctxStub) AuthSession() auth.Session         { return nil }
func (c *ctxStub) User() any                         { return c.user }
func (c *ctxStub) SetUser(user any)                  { c.user = user }
func (c *ctxStub) Principal() (auth.Principal, bool) { return auth.Principal{}, false }
func (c *ctxStub) MustPrincipal() auth.Principal     { return auth.Principal{} }
func (c *ctxStub) RevalidateAuth() error             { return nil }
func (c *ctxStub) BroadcastAuthLogout()              {}
func (c *ctxStub) Logger() *slog.Logger              { return slog.Default() }
func (c *ctxStub) Done() <-chan struct{}             { return nil }
func (c *ctxStub) SetValue(any, any)                 {}
func (c *ctxStub) Value(any) any                     { return nil }
func (c *ctxStub) Emit(string, any)                  {}
func (c *ctxStub) Dispatch(fn func()) {
	if fn != nil {
		fn()
	}
}
func (c *ctxStub) Navigate(string, ...server.NavigateOption) {}
func (c *ctxStub) StdContext() context.Context {
	if c.stdCtx != nil {
		return c.stdCtx
	}
	return context.Background()
}
func (c *ctxStub) WithStdContext(stdCtx context.Context) server.Ctx {
	c.stdCtx = stdCtx
	return c
}
func (c *ctxStub) Event() *server.Event { return nil }
func (c *ctxStub) PatchCount() int      { return c.patchCount }
func (c *ctxStub) AddPatchCount(count int) {
	c.patchCount += count
}
func (c *ctxStub) StormBudget() corevango.StormBudgetChecker { return nil }
func (c *ctxStub) Mode() int                                 { return 0 }
func (c *ctxStub) Asset(source string) string                { return source }

func TestWithIdentityAndIdentityFromContext(t *testing.T) {
	identity := &Identity{UserID: "user_ctx", Email: "ctx@example.com"}

	ctx := WithIdentity(nil, identity)
	if ctx == nil {
		t.Fatal("WithIdentity(nil, identity) returned nil context")
	}

	got, ok := IdentityFromContext(ctx)
	if !ok || got == nil {
		t.Fatal("IdentityFromContext should return identity")
	}
	if got.UserID != "user_ctx" {
		t.Fatalf("UserID = %q, want %q", got.UserID, "user_ctx")
	}

	ctx2 := WithIdentity(ctx, nil)
	if ctx2 != ctx {
		t.Fatal("WithIdentity(ctx, nil) should return original context")
	}
}

func TestIdentityFromContext_Missing(t *testing.T) {
	got, ok := IdentityFromContext(context.Background())
	if ok || got != nil {
		t.Fatalf("IdentityFromContext() = (%#v, %v), want (nil, false)", got, ok)
	}
}

func TestCurrentIdentity(t *testing.T) {
	stub := &ctxStub{user: &Identity{UserID: "user_current", Email: "current@example.com"}}

	got, ok := CurrentIdentity(stub)
	if !ok || got == nil {
		t.Fatal("CurrentIdentity should return identity")
	}
	if got.UserID != "user_current" {
		t.Fatalf("UserID = %q, want %q", got.UserID, "user_current")
	}
}

func TestRequireIdentity(t *testing.T) {
	t.Run("missing returns unauthorized", func(t *testing.T) {
		stub := &ctxStub{}
		_, err := RequireIdentity(stub)
		if !errors.Is(err, auth.ErrUnauthorized) {
			t.Fatalf("err = %v, want ErrUnauthorized", err)
		}
	})

	t.Run("present returns identity", func(t *testing.T) {
		stub := &ctxStub{user: &Identity{UserID: "user_require", Email: "require@example.com"}}
		got, err := RequireIdentity(stub)
		if err != nil {
			t.Fatalf("RequireIdentity() error = %v", err)
		}
		if got.UserID != "user_require" {
			t.Fatalf("UserID = %q, want %q", got.UserID, "user_require")
		}
	})
}

func TestRequirePermission(t *testing.T) {
	t.Run("allowed", func(t *testing.T) {
		stub := &ctxStub{user: &Identity{UserID: "user_1", Permissions: []string{"projects:read"}}}
		if err := RequirePermission(stub, "projects:read"); err != nil {
			t.Fatalf("RequirePermission() error = %v", err)
		}
	})

	t.Run("forbidden", func(t *testing.T) {
		stub := &ctxStub{user: &Identity{UserID: "user_1", Permissions: []string{"projects:read"}}}
		err := RequirePermission(stub, "projects:delete")
		if !errors.Is(err, auth.ErrForbidden) {
			t.Fatalf("err = %v, want ErrForbidden", err)
		}
	})

	t.Run("missing identity is unauthorized", func(t *testing.T) {
		stub := &ctxStub{}
		err := RequirePermission(stub, "projects:read")
		if !errors.Is(err, auth.ErrUnauthorized) {
			t.Fatalf("err = %v, want ErrUnauthorized", err)
		}
	})
}
