//go:build integration

package store_test

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/store"
)

// Integration tests for harness device grants (migration 00034, RFC 8628
// for the MCP sign-in server).

func randHash(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	return sum[:]
}

func newDeviceClient(t *testing.T, st *store.Store) string {
	t.Helper()
	c := &store.OAuthClient{ClientID: "gwc_" + t.Name(), ClientName: "SSH harness", RedirectURIs: []string{}, Metadata: []byte(`{}`)}
	if err := st.WithJobs(t.Context(), func(tx store.Tx) error { return tx.OAuth().CreateClient(t.Context(), c) }); err != nil {
		t.Fatalf("create client: %v", err)
	}
	return c.ID
}

func newDeviceGrant(t *testing.T, st *store.Store, clientID string, expires time.Time) *store.OAuthDeviceGrant {
	t.Helper()
	g := &store.OAuthDeviceGrant{
		DeviceCodeHash: randHash(t), UserCodeHash: randHash(t), ClientID: clientID, Scope: "mcp", Resource: "https://gw.example.com/mcp",
		RequestIP: "198.51.100.7", UserAgent: "curl/8", Interval: 5, ExpiresAt: expires,
	}
	if err := st.WithJobs(t.Context(), func(tx store.Tx) error { return store.CreateOAuthDeviceGrant(t.Context(), tx, g) }); err != nil {
		t.Fatalf("create device grant: %v", err)
	}
	return g
}

func TestIntegrationOAuthDeviceGrantLifecycle(t *testing.T) {
	env := setup(t)
	env.reset(t)
	st := env.open(t)
	ctx := t.Context()
	alice := newUser(t, st, "Alice")
	client := newDeviceClient(t, st)
	now := time.Now().UTC().Truncate(time.Microsecond)
	g := newDeviceGrant(t, st, client, now.Add(10*time.Minute))
	if g.ID == "" || g.Status != store.OAuthDevicePending || g.CreatedAt.IsZero() || g.UserID != "" {
		t.Fatalf("created grant = %+v", g)
	}

	var byCode, locked *store.OAuthDeviceGrant
	var pending int64
	err := st.WithJobs(ctx, func(tx store.Tx) error {
		var err error
		if byCode, err = store.FindOAuthDeviceGrantByUserCode(ctx, tx, g.UserCodeHash); err != nil {
			return err
		}
		if locked, err = store.LockOAuthDeviceGrant(ctx, tx, g.DeviceCodeHash); err != nil {
			return err
		}
		pending, err = store.CountPendingOAuthDeviceGrants(ctx, tx, client, now)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if byCode.ID != g.ID || locked.ID != g.ID || locked.RequestIP != "198.51.100.7" || locked.UserAgent != "curl/8" || locked.Interval != 5 || pending != 1 {
		t.Fatalf("lookups = %+v / %+v, pending %d", byCode, locked, pending)
	}

	// Approve, then redeem with a family.
	family := "00000000-0000-4000-8000-00000000f00d"
	err = st.WithJobs(ctx, func(tx store.Tx) error {
		d, err := store.LockOAuthDeviceGrantByID(ctx, tx, g.ID)
		if err != nil {
			return err
		}
		d.Status, d.UserID, d.DecidedAt, d.LastPolledAt, d.Interval = store.OAuthDeviceApproved, alice, &now, &now, 10
		if err := store.UpdateOAuthDeviceGrant(ctx, tx, d); err != nil {
			return err
		}
		d.Status, d.FamilyID, d.RedeemedAt = store.OAuthDeviceRedeemed, &family, &now
		return store.UpdateOAuthDeviceGrant(ctx, tx, d)
	})
	if err != nil {
		t.Fatal(err)
	}
	err = st.WithJobs(ctx, func(tx store.Tx) error {
		var err error
		locked, err = store.LockOAuthDeviceGrant(ctx, tx, g.DeviceCodeHash)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if locked.Status != store.OAuthDeviceRedeemed || locked.UserID != alice || locked.FamilyID == nil || *locked.FamilyID != family ||
		locked.Interval != 10 || locked.LastPolledAt == nil || locked.DecidedAt == nil || locked.RedeemedAt == nil {
		t.Fatalf("redeemed grant = %+v", locked)
	}

	// Unknown hashes are ErrNotFound.
	err = st.WithJobs(ctx, func(tx store.Tx) error {
		_, err := store.LockOAuthDeviceGrant(ctx, tx, randHash(t))
		return err
	})
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown device code = %v", err)
	}

	// The request path (gateway_app) cannot read device grants at all.
	err = st.WithUser(ctx, alice, func(tx store.Tx) error {
		_, err := store.FindOAuthDeviceGrantByUserCode(ctx, tx, g.UserCodeHash)
		return err
	})
	if pgCode(err) != "42501" {
		t.Fatalf("gateway_app read = %v, want permission denied", err)
	}
}

func TestIntegrationOAuthDeviceGrantUserCodesNeverCollideWithMachines(t *testing.T) {
	env := setup(t)
	env.reset(t)
	st := env.open(t)
	ctx := t.Context()
	client := newDeviceClient(t, st)
	now := time.Now().UTC()
	g := newDeviceGrant(t, st, client, now.Add(10*time.Minute))

	// The same user code hash again: taken.
	dup := &store.OAuthDeviceGrant{DeviceCodeHash: randHash(t), UserCodeHash: g.UserCodeHash, ClientID: client, Scope: "mcp",
		Resource: "https://gw.example.com/mcp", Interval: 5, ExpiresAt: now.Add(time.Minute)}
	if err := st.WithJobs(ctx, func(tx store.Tx) error { return store.CreateOAuthDeviceGrant(ctx, tx, dup) }); !errors.Is(err, store.ErrUserCodeTaken) {
		t.Fatalf("duplicate user code = %v, want ErrUserCodeTaken", err)
	}

	// A machine request cannot take a harness grant's user code ...
	mr := &store.MachineDeviceRequest{DeviceCodeHash: randHash(t), UserCodeHash: g.UserCodeHash, Name: "laptop", PublicKey: make([]byte, 32),
		Fingerprint: "fp", ExpiresAt: now.Add(time.Minute), Interval: 5}
	if err := st.WithJobs(ctx, func(tx store.Tx) error { return store.CreateMachineDeviceRequest(ctx, tx, mr) }); !errors.Is(err, store.ErrUserCodeTaken) {
		t.Fatalf("machine request with a harness user code = %v, want ErrUserCodeTaken", err)
	}
	// ... and a harness grant cannot take a machine request's.
	mr.UserCodeHash = randHash(t)
	if err := st.WithJobs(ctx, func(tx store.Tx) error { return store.CreateMachineDeviceRequest(ctx, tx, mr) }); err != nil {
		t.Fatalf("machine request: %v", err)
	}
	dup.UserCodeHash = mr.UserCodeHash
	if err := st.WithJobs(ctx, func(tx store.Tx) error { return store.CreateOAuthDeviceGrant(ctx, tx, dup) }); !errors.Is(err, store.ErrUserCodeTaken) {
		t.Fatalf("harness grant with a machine user code = %v, want ErrUserCodeTaken", err)
	}
}

func TestIntegrationOAuthDeviceGrantPruneAndCascade(t *testing.T) {
	env := setup(t)
	env.reset(t)
	st := env.open(t)
	ctx := t.Context()
	alice := newUser(t, st, "Alice")
	client := newDeviceClient(t, st)
	now := time.Now().UTC()
	old := newDeviceGrant(t, st, client, now.Add(-time.Minute))
	live := newDeviceGrant(t, st, client, now.Add(time.Hour))
	approved := newDeviceGrant(t, st, client, now.Add(time.Hour))
	err := st.WithJobs(ctx, func(tx store.Tx) error {
		approved.Status, approved.UserID = store.OAuthDeviceApproved, alice
		return store.UpdateOAuthDeviceGrant(ctx, tx, approved)
	})
	if err != nil {
		t.Fatal(err)
	}

	var pruned, pending int64
	err = st.WithJobs(ctx, func(tx store.Tx) error {
		var err error
		if pruned, err = store.DeleteExpiredOAuthDeviceGrants(ctx, tx, now); err != nil {
			return err
		}
		pending, err = store.CountPendingOAuthDeviceGrants(ctx, tx, client, now)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if pruned != 1 || pending != 1 {
		t.Fatalf("pruned %d, pending %d; want 1, 1", pruned, pending)
	}
	err = st.WithJobs(ctx, func(tx store.Tx) error {
		_, err := store.LockOAuthDeviceGrant(ctx, tx, old.DeviceCodeHash)
		return err
	})
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired grant still there: %v", err)
	}

	// Deleting the user's data drops the grants they decided.
	if err := st.WithJobs(ctx, func(tx store.Tx) error {
		_, err := store.DeleteUserData(ctx, tx, alice, now)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := env.super.QueryRow(ctx, `SELECT count(*) FROM oauth_device_grants WHERE id = ANY($1)`, []string{live.ID, approved.ID}).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("grants left after deleting alice = %d, want only the undecided one", count)
	}
}
