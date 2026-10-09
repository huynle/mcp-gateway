package main

import (
	"context"
	"fmt"

	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/fake"
	"github.com/huynle/mcp-gateway/internal/store"
)

// fakeDevAccountSource is the fake connector's account source when the
// connections service is available: the user's fake connections rows, with
// one company account seeded through connections.SeedAccount the first
// time a user lists none. Approvals, ledger operations and audit events
// reference the connection row, so the fake's accounts must be rows for
// confirmed and ledgered writes to work in the Compose stack (quirk
// enqgtw5y). Development only, like the fake connector itself.
type fakeDevAccountSource struct {
	conn *connections.Service
}

// fakeDevExternalID is the external account id of the seeded company
// account: one per user, stable across restarts.
const fakeDevExternalID = "dev-company"

// ListAccounts implements connectors.AccountSource.
func (s fakeDevAccountSource) ListAccounts(ctx context.Context, userID, app string) ([]connectors.Account, error) {
	if userID == "" || app != fake.App {
		return s.conn.ListAccounts(ctx, userID, app)
	}
	list, err := s.conn.ListAccounts(ctx, userID, app)
	if err != nil || len(list) > 0 {
		return list, err
	}
	if _, err := s.conn.SeedAccount(ctx, userID, connections.Seed{
		Vendor: connections.VendorFake, ExternalAccountID: fakeDevExternalID,
		Label: store.AccountCompany, DisplayName: "Fake company account",
	}); err != nil {
		return nil, fmt.Errorf("seed fake account: %w", err)
	}
	return s.conn.ListAccounts(ctx, userID, app)
}

// newFakeAccountSource picks the fake connector's account source: the
// connections-backed one when connections are mounted, else the fake's own
// in-memory source that seeds one company account per user (no key
// provider: nothing can be confirmed or ledgered anyway, quirk enqgtw5y).
func newFakeAccountSource(f *fake.Connector, connSvc *connections.Service) connectors.AccountSource {
	if connSvc == nil {
		return f.Accounts()
	}
	return fakeDevAccountSource{conn: connSvc}
}
