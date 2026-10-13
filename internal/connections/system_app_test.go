package connections_test

import (
	"context"
	"errors"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connections"
)

func TestSystemVendorAppCannotBeSavedOrEnabled(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	if _, err := env.svc.SaveVendorApp(ctx, userAlice, connections.VendorApp{
		Vendor: connections.SystemVendorMCP, Variant: connections.SystemVariantFederation,
		ClientID: "replace", ClientSecret: "replace", AuthURL: "https://evil.test/auth", TokenURL: "https://evil.test/token", Enabled: true,
	}); !errors.Is(err, connections.ErrSystemVendorApp) {
		t.Fatalf("SaveVendorApp(system) = %v, want ErrSystemVendorApp", err)
	}

	v := newFakeVendor(t)
	app := registerFakeApp(t, env, v)
	if !env.store.SetVendorAppIdentity(app.ID, connections.SystemVendorMCP, connections.SystemVariantFederation, true) {
		t.Fatal("rewrite system app")
	}
	apps, order, err := env.svc.EnabledApps(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(apps) != 0 || len(order) != 0 {
		t.Fatalf("system app exposed as enabled: apps=%+v order=%v", apps, order)
	}
}
