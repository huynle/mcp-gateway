package connections_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/store"
)

// SeedAccount backs the fake connector's development accounts with real
// connections rows (quirk enqgtw5y): approvals, ledger operations and
// audit events reference connections, so an account that is not a row
// cannot be confirmed, ledgered or audited.
func TestSeedAccountCreatesAFakeConnectionRowTheAccountSourceLists(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	info, err := env.svc.SeedAccount(ctx, userAlice, connections.Seed{ExternalAccountID: "alice-dev", Label: store.AccountCompany, DisplayName: "Fake company account"})
	if err != nil {
		t.Fatalf("SeedAccount: %v", err)
	}
	if info.ID == "" || info.UserID != userAlice || info.Vendor != connections.VendorFake || info.Label != store.AccountCompany || info.DisplayName != "Fake company account" || !info.Active() {
		t.Fatalf("seeded = %+v", info)
	}
	// The vendor app row exists for vendor "fake" and is disabled: there is
	// nothing to connect to, so /connections shows no Connect button.
	apps := env.store.VendorAppRows()
	if len(apps) != 1 || apps[0].Vendor != connections.VendorFake || apps[0].Enabled {
		t.Fatalf("vendor apps = %+v", apps)
	}
	// The account stage sees it as the user's fake account, by row id.
	accounts, err := env.svc.ListAccounts(ctx, userAlice, connections.VendorFake)
	if err != nil || len(accounts) != 1 || accounts[0].ID != info.ID || accounts[0].Label != connectors.LabelCompany || accounts[0].DisplayName != "Fake company account" {
		t.Fatalf("ListAccounts = %+v, %v", accounts, err)
	}
	// It is the user's row: bob sees nothing.
	if accounts, _ := env.svc.ListAccounts(ctx, userBob, connections.VendorFake); len(accounts) != 0 {
		t.Errorf("bob sees alice's seeded account: %+v", accounts)
	}
	// No token bundle was invented.
	if secrets := env.store.SecretRows(); len(secrets) != 0 {
		t.Errorf("seeding stored a secret: %+v", secrets)
	}
	// Audited as the user's own event, naming the connection and the label.
	var seeded int
	for _, ev := range env.audit.events {
		if ev.UserID == userAlice && ev.AccountID == info.ID && ev.ResourceIdentity["action"] == "seeded" && ev.ResourceIdentity["vendor"] == connections.VendorFake {
			seeded++
		}
	}
	if seeded != 1 {
		t.Errorf("seeded audit events = %d", seeded)
	}
}

func TestSeedAccountIsIdempotentAndRevivesARevokedRow(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	seed := connections.Seed{ExternalAccountID: "alice-dev", Label: store.AccountCompany, DisplayName: "Fake company account"}
	first, err := env.svc.SeedAccount(ctx, userAlice, seed)
	if err != nil {
		t.Fatal(err)
	}
	again, err := env.svc.SeedAccount(ctx, userAlice, seed)
	if err != nil || again.ID != first.ID {
		t.Fatalf("second seed = %+v, %v (first %s)", again, err, first.ID)
	}
	if rows := env.store.ConnectionRows(); len(rows) != 1 || len(env.store.VendorAppRows()) != 1 {
		t.Fatalf("rows = %+v, apps = %d", rows, len(env.store.VendorAppRows()))
	}
	// Disconnecting a seeded account works like any other (no secret to
	// delete, no vendor to tell) and seeding again revives the same row.
	if err := env.svc.Disconnect(ctx, userAlice, first.ID); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	if accounts, _ := env.svc.ListAccounts(ctx, userAlice, connections.VendorFake); len(accounts) != 0 {
		t.Fatalf("revoked account still listed: %+v", accounts)
	}
	revived, err := env.svc.SeedAccount(ctx, userAlice, seed)
	if err != nil || revived.ID != first.ID || !revived.Active() {
		t.Fatalf("revived = %+v, %v", revived, err)
	}
	// A second account (personal) is a second row of the same app.
	personal, err := env.svc.SeedAccount(ctx, userAlice, connections.Seed{ExternalAccountID: "alice-home", Label: store.AccountPersonal, DisplayName: "Fake personal account"})
	if err != nil || personal.ID == first.ID {
		t.Fatalf("personal = %+v, %v", personal, err)
	}
	accounts, _ := env.svc.ListAccounts(ctx, userAlice, connections.VendorFake)
	if len(accounts) != 2 || len(env.store.VendorAppRows()) != 1 {
		t.Fatalf("accounts = %+v, apps = %d", accounts, len(env.store.VendorAppRows()))
	}
}

func TestSeedAccountRefusesRealVendorsAndBadInput(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	cases := map[string]struct {
		user string
		seed connections.Seed
		want string
	}{
		"real vendor":    {userAlice, connections.Seed{Vendor: connections.VendorGitHub, ExternalAccountID: "x", Label: store.AccountCompany}, "fake"},
		"unknown vendor": {userAlice, connections.Seed{Vendor: "acme", ExternalAccountID: "x", Label: store.AccountCompany}, "fake"},
		"no user":        {"", connections.Seed{ExternalAccountID: "x", Label: store.AccountCompany}, "user"},
		"no external id": {userAlice, connections.Seed{Label: store.AccountCompany}, "external"},
		"bad label":      {userAlice, connections.Seed{ExternalAccountID: "x", Label: "shared"}, "label"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := env.svc.SeedAccount(ctx, tc.user, tc.seed)
			if !errors.Is(err, connections.ErrInvalidSeed) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want ErrInvalidSeed mentioning %q", err, tc.want)
			}
		})
	}
	if rows := env.store.ConnectionRows(); len(rows) != 0 || len(env.store.VendorAppRows()) != 0 {
		t.Errorf("refused seeds left rows: %+v / %+v", rows, env.store.VendorAppRows())
	}
}
