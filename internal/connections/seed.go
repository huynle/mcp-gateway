package connections

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/store"
)

// ErrInvalidSeed marks a Seed that SeedAccount refuses; the message after
// the sentinel says why.
var ErrInvalidSeed = errors.New("connections: invalid seed")

// Seed describes a connection created without an OAuth flow: the fake
// connector's development accounts (quirk enqgtw5y). Only VendorFake can
// be seeded; real vendors' accounts always come from the connect flow.
// Vendor defaults to VendorFake.
type Seed struct {
	Vendor            string
	ExternalAccountID string
	// Label is store.AccountCompany or store.AccountPersonal.
	Label       string
	DisplayName string
}

func (in *Seed) normalize(userID string) error {
	in.Vendor = strings.ToLower(strings.TrimSpace(in.Vendor))
	if in.Vendor == "" {
		in.Vendor = VendorFake
	}
	if in.Vendor != VendorFake {
		return fmt.Errorf("%w: only the fake vendor can be seeded, not %q", ErrInvalidSeed, in.Vendor)
	}
	if userID == "" {
		return fmt.Errorf("%w: user is required", ErrInvalidSeed)
	}
	in.ExternalAccountID = strings.TrimSpace(in.ExternalAccountID)
	if in.ExternalAccountID == "" {
		return fmt.Errorf("%w: external account id is required", ErrInvalidSeed)
	}
	if in.Label != store.AccountCompany && in.Label != store.AccountPersonal {
		return fmt.Errorf("%w: label must be %s or %s", ErrInvalidSeed, store.AccountCompany, store.AccountPersonal)
	}
	in.DisplayName = strings.TrimSpace(in.DisplayName)
	if in.DisplayName == "" {
		in.DisplayName = "Fake " + in.Label + " account"
	}
	return nil
}

// SeedAccount gives userID an active connection of the fake vendor without
// an OAuth flow, so the fake connector's accounts are real connections
// rows that approvals, ledger operations and audit events can reference
// (quirk enqgtw5y). The fake vendor app row is created on first use,
// disabled (there is nothing to connect to) and with a placeholder client
// secret; no token bundle is stored. Idempotent: an existing (user, app,
// external account) row is returned, revived to active when it had been
// revoked. The row is created in the user's own scope and the seed is
// audited as the user's event (action "seeded"). Development only.
func (s *Service) SeedAccount(ctx context.Context, userID string, in Seed) (Info, error) {
	if err := in.normalize(userID); err != nil {
		return Info{}, err
	}
	appRow, err := s.ensureFakeVendorApp(ctx)
	if err != nil {
		return Info{}, err
	}
	var (
		conn    *store.Connection
		created bool
	)
	err = s.store.AsUser(ctx, userID, func(tx Tx) error {
		existing, err := tx.FindConnection(ctx, userID, appRow.ID, in.ExternalAccountID)
		switch {
		case err == nil:
			conn = existing
			if conn.Status == store.ConnectionActive {
				return nil
			}
			if err := tx.SetConnectionStatus(ctx, conn.ID, store.ConnectionActive); err != nil {
				return err
			}
			conn.Status = store.ConnectionActive
			created = true
			return nil
		case errors.Is(err, store.ErrNotFound):
			conn = &store.Connection{
				UserID: userID, VendorAppID: appRow.ID, ExternalAccountID: in.ExternalAccountID,
				Label: in.Label, DisplayName: in.DisplayName, Status: store.ConnectionActive,
			}
			if err := tx.CreateConnection(ctx, conn); err != nil {
				return err
			}
			created = true
			return nil
		default:
			return err
		}
	})
	if err != nil {
		return Info{}, fmt.Errorf("connections: seed: %w", err)
	}
	if created {
		s.record(ctx, userID, conn.ID, conn.Label, map[string]string{"action": "seeded", "vendor": VendorFake, "variant": appRow.Name}, "succeeded", "")
		s.log.Info("development account seeded", "event", "connections.seeded", "user_id", userID, "connection_id", conn.ID, "vendor", VendorFake, "label", conn.Label)
	}
	return toInfo(conn, VendorFake, appRow.Name), nil
}

// ensureFakeVendorApp returns the fake vendor's app row, creating it on
// first use. The row is disabled so the portal offers no Connect button
// for it, and its sealed bundle holds a placeholder client secret: the
// column is NOT NULL and nothing ever reads it.
func (s *Service) ensureFakeVendorApp(ctx context.Context) (*store.VendorApp, error) {
	var row *store.VendorApp
	err := s.store.Bypass(ctx, func(tx Tx) error {
		existing, err := tx.FindVendorApp(ctx, VendorFake, DefaultVariant)
		switch {
		case err == nil:
			row = existing
			return nil
		case errors.Is(err, store.ErrNotFound):
		default:
			return err
		}
		app := Defaults(VendorFake, DefaultVariant)
		app.ClientID = "fake"
		app.Enabled = false
		row, err = app.toRow()
		if err != nil {
			return err
		}
		row.ID = connectors.NewAccountID()
		if err := s.sealBundle(ctx, row, secretBundle{SecretClientSecret: "fake-placeholder"}); err != nil {
			return err
		}
		return tx.UpsertVendorApp(ctx, row)
	})
	if err != nil {
		return nil, fmt.Errorf("connections: seed: fake vendor app: %w", err)
	}
	return row, nil
}
