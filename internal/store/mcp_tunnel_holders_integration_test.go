//go:build integration

package store_test

import (
	"errors"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/store"
)

// Integration tests for the tunnel holder registry (migration 00026,
// decision efq0ncag item 5): jobs-only, a fresh epoch per claim, release
// only by the current epoch, liveness joined from mcp_tunnels.

func TestIntegrationMCPTunnelHolders(t *testing.T) {
	env := setup(t)
	env.reset(t)
	st := env.open(t)
	ctx := t.Context()
	alice := newUser(t, st, "Alice")
	tun := &store.MCPTunnel{OwnerUserID: alice, Name: "laptop", TokenHash: []byte("holder-test-hash")}
	if err := st.WithUser(ctx, alice, func(tx store.Tx) error { return store.CreateMCPTunnel(ctx, tx, tun) }); err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Truncate(time.Microsecond)

	jobs := func(fn func(tx store.Tx) error) error { return st.WithJobs(ctx, fn) }

	// No holder yet.
	if err := jobs(func(tx store.Tx) error {
		_, err := store.GetMCPTunnelHolder(ctx, tx, tun.ID)
		return err
	}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetMCPTunnelHolder(none) = %v, want ErrNotFound", err)
	}

	// Claim: epoch assigned, last_seen_at touched.
	var e1, e2 int64
	if err := jobs(func(tx store.Tx) error {
		var err error
		e1, err = store.ClaimMCPTunnelHolder(ctx, tx, tun.ID, "http://10.0.0.1:18081", at)
		return err
	}); err != nil || e1 <= 0 {
		t.Fatalf("Claim A = %d, %v", e1, err)
	}
	var h *store.MCPTunnelHolder
	if err := jobs(func(tx store.Tx) error {
		var err error
		h, err = store.GetMCPTunnelHolder(ctx, tx, tun.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if h.Holder != "http://10.0.0.1:18081" || h.Epoch != e1 || h.Revoked || h.LastSeenAt == nil || !h.LastSeenAt.Equal(at) {
		t.Fatalf("holder = %+v", h)
	}

	// A newer claim (another replica) overwrites with a larger epoch.
	if err := jobs(func(tx store.Tx) error {
		var err error
		e2, err = store.ClaimMCPTunnelHolder(ctx, tx, tun.ID, "http://10.0.0.2:18081", at.Add(time.Second))
		return err
	}); err != nil || e2 <= e1 {
		t.Fatalf("Claim B = %d (after %d), %v", e2, e1, err)
	}

	// The old connection's release is a no-op; the current one's deletes.
	var released bool
	if err := jobs(func(tx store.Tx) error {
		var err error
		released, err = store.ReleaseMCPTunnelHolder(ctx, tx, tun.ID, e1)
		return err
	}); err != nil || released {
		t.Fatalf("Release(old) = %v, %v", released, err)
	}
	if err := jobs(func(tx store.Tx) error {
		var err error
		h, err = store.GetMCPTunnelHolder(ctx, tx, tun.ID)
		return err
	}); err != nil || h.Holder != "http://10.0.0.2:18081" || h.Epoch != e2 {
		t.Fatalf("holder after stale release = %+v, %v", h, err)
	}

	// Revocation shows through the join.
	if err := st.WithUser(ctx, alice, func(tx store.Tx) error { return store.RevokeMCPTunnel(ctx, tx, tun.ID, at) }); err != nil {
		t.Fatal(err)
	}
	if err := jobs(func(tx store.Tx) error {
		var err error
		h, err = store.GetMCPTunnelHolder(ctx, tx, tun.ID)
		return err
	}); err != nil || !h.Revoked {
		t.Fatalf("holder after revoke = %+v, %v", h, err)
	}
	if err := jobs(func(tx store.Tx) error {
		var err error
		released, err = store.ReleaseMCPTunnelHolder(ctx, tx, tun.ID, e2)
		return err
	}); err != nil || !released {
		t.Fatalf("Release(current) = %v, %v", released, err)
	}

	// Unknown tunnel.
	if err := jobs(func(tx store.Tx) error {
		_, err := store.ClaimMCPTunnelHolder(ctx, tx, "00000000-0000-4000-8000-000000000999", "http://x:1", at)
		return err
	}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Claim(unknown) = %v, want ErrNotFound", err)
	}

	// The request-path role has no access at all.
	err := st.WithUser(ctx, alice, func(tx store.Tx) error {
		_, err := store.GetMCPTunnelHolder(ctx, tx, tun.ID)
		return err
	})
	if !isPermissionDenied(err) {
		t.Fatalf("gateway_app read of mcp_tunnel_holders = %v, want permission denied", err)
	}
}
