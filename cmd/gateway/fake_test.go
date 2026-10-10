package main

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/connections/connectionstest"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/fake"
	"github.com/huynle/mcp-gateway/internal/crypto"
)

const (
	userAlice = "11111111-1111-4111-8111-111111111111"
	userBob   = "22222222-2222-4222-8222-222222222222"
)

func newMemConnections(t *testing.T) (*connections.Service, *connectionstest.MemStore) {
	t.Helper()
	kp, err := crypto.NewStaticProvider("k1", map[string][]byte{"k1": bytes.Repeat([]byte{1}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	mem := connectionstest.NewMemStore()
	svc, err := connections.New(connections.Config{BaseURL: "http://gw.test"}, mem, kp, connections.Options{Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	return svc, mem
}

// With the connections service available, the fake connector's development
// accounts are real connections rows (quirk enqgtw5y): the first listing
// seeds one company account per user through connections.SeedAccount, so
// confirmed and ledgered fake writes, which reference the connection, work
// end to end in the Compose stack.
func TestRegisterConnectorsBacksFakeAccountsWithConnectionsRows(t *testing.T) {
	ctx := context.Background()
	connSvc, mem := newMemConnections(t)
	registry := connectors.NewRegistry()
	src, err := registerConnectors(config.Config{EnableFakeConnector: true}, registry, connSvc, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	accts, err := src.ListAccounts(ctx, userAlice, fake.App)
	if err != nil || len(accts) != 1 || accts[0].Label != connectors.LabelCompany || accts[0].App != fake.App {
		t.Fatalf("first listing = %+v, %v", accts, err)
	}
	rows := mem.ConnectionRows()
	if len(rows) != 1 || rows[0].ID != accts[0].ID || rows[0].UserID != userAlice {
		t.Fatalf("connections rows = %+v, want the listed account", rows)
	}
	// Listing again returns the same row; another user gets their own.
	again, _ := src.ListAccounts(ctx, userAlice, fake.App)
	if len(again) != 1 || again[0].ID != accts[0].ID {
		t.Errorf("second listing = %+v", again)
	}
	bob, _ := src.ListAccounts(ctx, userBob, fake.App)
	if len(bob) != 1 || bob[0].ID == accts[0].ID {
		t.Errorf("bob = %+v", bob)
	}
	if n := len(mem.ConnectionRows()); n != 2 {
		t.Errorf("rows = %d, want 2", n)
	}
	// list_accounts (the generated tool) reads the same source.
	tool, ok := registry.Get("fake.list_accounts")
	if !ok {
		t.Fatal("fake.list_accounts missing")
	}
	res, err := tool.Handler(ctx, connectors.Call{Tool: "fake.list_accounts", Principal: connectors.Principal{UserID: userAlice}})
	if err != nil {
		t.Fatalf("list_accounts: %v", err)
	}
	if got, _ := res.Content.(map[string]any); got == nil {
		t.Fatalf("list_accounts content = %#v", res.Content)
	}
	// Other apps still go to the connections table directly, unseeded.
	if accts, _ := src.ListAccounts(ctx, userAlice, "github"); len(accts) != 0 {
		t.Errorf("github accounts = %+v", accts)
	}
	// Without a user there is nothing to seed.
	if accts, err := src.ListAccounts(ctx, "", fake.App); err != nil || len(accts) != 0 {
		t.Errorf("anonymous = %+v, %v", accts, err)
	}
}
