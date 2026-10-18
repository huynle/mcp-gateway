package identity_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/identity/identitytest"
	"github.com/huynle/mcp-gateway/internal/store"
)

func TestRunDisableHooksRunsEveryHookInOrder(t *testing.T) {
	svc, _ := newService(t, testConfig(dexProvider()), identitytest.NewMemStore())
	var got []string
	svc.OnDisable(func(_ context.Context, _ store.Tx, userID string) error { got = append(got, "a:"+userID); return nil })
	svc.OnDisable(func(_ context.Context, _ store.Tx, userID string) error { got = append(got, "b:"+userID); return nil })
	if err := svc.RunDisableHooks(context.Background(), nil, "u1"); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"a:u1", "b:u1"}) {
		t.Errorf("hooks ran %v", got)
	}
	boom := errors.New("boom")
	svc.OnDisable(func(context.Context, store.Tx, string) error { return boom })
	if err := svc.RunDisableHooks(context.Background(), nil, "u1"); !errors.Is(err, boom) {
		t.Errorf("RunDisableHooks = %v, want boom", err)
	}
}

func TestIsBootstrapAdmin(t *testing.T) {
	cfg := testConfig(dexProvider())
	cfg.BootstrapAdmins = []string{dexIssuer + "|root-sub"}
	svc, _ := newService(t, cfg, identitytest.NewMemStore())
	if !svc.IsBootstrapAdmin(dexIssuer, "root-sub") {
		t.Error("configured bootstrap admin not recognised")
	}
	if svc.IsBootstrapAdmin(dexIssuer, "other") || svc.IsBootstrapAdmin("https://evil.example", "root-sub") {
		t.Error("non-bootstrap identity recognised as bootstrap admin")
	}
}

func TestClearSessionCookieExpiresTheCookie(t *testing.T) {
	svc, _ := newService(t, testConfig(dexProvider()), identitytest.NewMemStore())
	rec := httptest.NewRecorder()
	svc.ClearSessionCookie(rec)
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != identity.SessionCookie || cookies[0].MaxAge >= 0 || cookies[0].Value != "" {
		t.Errorf("cookies = %+v, want the session cookie expired", cookies)
	}
}
