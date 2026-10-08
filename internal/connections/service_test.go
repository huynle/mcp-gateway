package connections_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/connections/connectionstest"
	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/store"
)

const (
	userAlice = "11111111-1111-4111-8111-111111111111"
	userBob   = "22222222-2222-4222-8222-222222222222"
)

// memAudit records events in memory.
type memAudit struct{ events []audit.Event }

func (m *memAudit) Record(_ context.Context, ev audit.Event) error {
	m.events = append(m.events, ev)
	return nil
}

// allowAll is a personal-account policy that permits everything.
type allowAll struct{}

func (allowAll) PersonalAccountsAllowed(context.Context, string, string) (bool, error) {
	return true, nil
}

type testEnv struct {
	svc   *connections.Service
	store *connectionstest.MemStore
	audit *memAudit
	logs  *bytes.Buffer
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	kp, err := crypto.NewStaticProvider("k1", map[string][]byte{"k1": bytes.Repeat([]byte{7}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	logs := &bytes.Buffer{}
	log := slog.New(slog.NewTextHandler(logs, nil))
	mem := connectionstest.NewMemStore()
	rec := &memAudit{}
	svc, err := connections.New(connections.Config{BaseURL: "http://gw.test"}, mem, kp, connections.Options{
		Audit: rec, Policy: allowAll{}, Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &testEnv{svc: svc, store: mem, audit: rec, logs: logs}
}

func TestSaveVendorAppEncryptsSecretAndNeverReturnsIt(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	in := connections.VendorApp{
		Vendor: "github", Variant: "", ClientID: "cid-123", ClientSecret: "sekrit-abc",
		AuthURL: "https://example.test/authorize", TokenURL: "https://example.test/token",
		Scopes: []string{"read:user"}, Enabled: true,
	}
	saved, err := env.svc.SaveVendorApp(ctx, userAlice, in)
	if err != nil {
		t.Fatalf("SaveVendorApp: %v", err)
	}
	if saved.ID == "" || saved.Variant != connections.DefaultVariant || !saved.HasSecret || saved.ClientSecret != "" {
		t.Fatalf("saved = %+v", saved)
	}
	// Nothing in the store holds the plaintext secret.
	for _, row := range env.store.VendorAppRows() {
		if bytes.Contains(row.ClientSecret.Ciphertext, []byte("sekrit-abc")) || strings.Contains(string(row.Config), "sekrit-abc") {
			t.Fatalf("plaintext secret stored: %+v", row)
		}
		if len(row.ClientSecret.Ciphertext) == 0 || row.ClientSecret.KeyID != "k1" {
			t.Fatalf("secret not encrypted: %+v", row.ClientSecret)
		}
	}
	got, err := env.svc.VendorApp(ctx, "github", "")
	if err != nil {
		t.Fatal(err)
	}
	if got.ClientSecret != "" || !got.HasSecret || got.ClientID != "cid-123" || got.AuthURL != in.AuthURL || got.Scopes[0] != "read:user" {
		t.Fatalf("VendorApp = %+v", got)
	}
	// Saving again without a secret keeps the old one; the audit trail
	// names the admin and the app, never the secret.
	in.ClientSecret = ""
	in.ClientID = "cid-456"
	again, err := env.svc.SaveVendorApp(ctx, userAlice, in)
	if err != nil {
		t.Fatal(err)
	}
	if again.ID != saved.ID || !again.HasSecret || again.ClientID != "cid-456" {
		t.Fatalf("second save = %+v", again)
	}
	if len(env.audit.events) != 2 || env.audit.events[0].UserID != userAlice || env.audit.events[0].ResourceIdentity["action"] != "vendor_app_saved" || env.audit.events[0].ResourceIdentity["vendor"] != "github" {
		t.Fatalf("audit = %+v", env.audit.events)
	}
	if strings.Contains(env.logs.String(), "sekrit") {
		t.Fatalf("secret leaked into logs: %s", env.logs.String())
	}
	// Reads of all apps list it under the vendor.
	apps, err := env.svc.VendorApps(ctx)
	if err != nil || len(apps) != 1 || apps[0].Vendor != "github" {
		t.Fatalf("VendorApps = %+v, %v", apps, err)
	}
	if _, err := env.svc.SaveVendorApp(ctx, userAlice, connections.VendorApp{Vendor: "nope", ClientID: "x", ClientSecret: "y"}); err == nil {
		t.Fatal("unknown vendor accepted")
	}
	if _, err := env.svc.SaveVendorApp(ctx, userAlice, connections.VendorApp{Vendor: "google", Variant: "internal", ClientID: "x"}); err == nil {
		t.Fatal("first save without a secret accepted")
	}
	if _, err := env.svc.VendorApp(ctx, "slack", ""); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing app err = %v", err)
	}
}
