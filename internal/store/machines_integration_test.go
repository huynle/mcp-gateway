//go:build integration

package store_test

import (
	"bytes"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/store"
)

// Integration tests for enrolled machines (migration 00030, Brain decision
// ldjix4y1): machines, device requests, enrollment codes, machine access
// tokens, assertion jti replay records and machine-linked tunnels.

func newMachine(t *testing.T, st *store.Store, owner, name string) *store.Machine {
	t.Helper()
	m := &store.Machine{
		OwnerUserID: owner, Name: name, PublicKey: bytes.Repeat([]byte{byte(len(name))}, 32),
		Fingerprint: "fp_" + name + "_0123456789012345678901234567890123456789"[:43-len("fp_"+name)], ClientVersion: "1.2.3",
		EnrolledVia: store.MachineEnrolledDevice, EnrolledIP: "192.0.2.1",
	}
	if err := st.WithJobs(t.Context(), func(tx store.Tx) error { return store.CreateMachine(t.Context(), tx, m) }); err != nil {
		t.Fatalf("create machine %s: %v", name, err)
	}
	return m
}

func TestIntegrationMachinesOwnerScopedAndUniqueLiveName(t *testing.T) {
	env := setup(t)
	env.reset(t)
	st := env.open(t)
	ctx := t.Context()
	alice, bob := newUser(t, st, "Alice"), newUser(t, st, "Bob")
	m := newMachine(t, st, alice, "laptop")
	if m.ID == "" || m.CreatedAt.IsZero() {
		t.Fatalf("created machine = %+v", m)
	}

	dup := &store.Machine{OwnerUserID: alice, Name: "laptop", PublicKey: bytes.Repeat([]byte{9}, 32), Fingerprint: m.Fingerprint, EnrolledVia: store.MachineEnrolledDevice}
	if err := st.WithJobs(ctx, func(tx store.Tx) error { return store.CreateMachine(ctx, tx, dup) }); !errors.Is(err, store.ErrMachineNameTaken) {
		t.Fatalf("duplicate live name = %v, want ErrMachineNameTaken", err)
	}
	newMachine(t, st, bob, "laptop") // another owner may use the name

	var mine, theirs []store.Machine
	if err := st.WithUser(ctx, alice, func(tx store.Tx) error {
		var err error
		mine, err = store.ListMachines(ctx, tx, alice)
		if err != nil {
			return err
		}
		theirs, err = store.ListMachines(ctx, tx, bob)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if len(mine) != 1 || mine[0].ID != m.ID || len(theirs) != 0 {
		t.Fatalf("alice lists %d own, %d of bob's (row security)", len(mine), len(theirs))
	}
	var all []store.Machine
	if err := st.WithJobs(ctx, func(tx store.Tx) error {
		var err error
		all, err = store.ListAllMachines(ctx, tx)
		return err
	}); err != nil || len(all) != 2 || all[0].OwnerName == "" {
		t.Fatalf("admin list = %+v, %v", all, err)
	}

	// After revocation the name is free again.
	if err := st.WithJobs(ctx, func(tx store.Tx) error {
		return store.RevokeMachine(ctx, tx, m.ID, alice, store.MachineRevokedByOwner, time.Now())
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.WithJobs(ctx, func(tx store.Tx) error {
		return store.RevokeMachine(ctx, tx, m.ID, alice, store.MachineRevokedByOwner, time.Now())
	}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("second revoke = %v, want ErrNotFound", err)
	}
	newMachine(t, st, alice, "laptop")
	var n int
	if err := st.WithUser(ctx, alice, func(tx store.Tx) error {
		var err error
		n, err = store.CountUserLiveMachines(ctx, tx, alice)
		return err
	}); err != nil || n != 1 {
		t.Fatalf("live machines = %d, %v", n, err)
	}
}

func TestIntegrationMachineDeviceRequestLifecycle(t *testing.T) {
	env := setup(t)
	env.reset(t)
	st := env.open(t)
	ctx := t.Context()
	alice := newUser(t, st, "Alice")
	now := time.Now().UTC().Truncate(time.Microsecond)
	dr := &store.MachineDeviceRequest{
		DeviceCodeHash: []byte("device-" + t.Name()), UserCodeHash: []byte("user-" + t.Name()),
		Name: "laptop", PublicKey: bytes.Repeat([]byte{1}, 32), Fingerprint: "fp", ClientVersion: "1",
		RequestIP: "198.51.100.7", ExpiresAt: now.Add(10 * time.Minute), Interval: 5,
	}
	jobs := func(fn func(tx store.Tx) error) error { return st.WithJobs(ctx, fn) }
	if err := jobs(func(tx store.Tx) error { return store.CreateMachineDeviceRequest(ctx, tx, dr) }); err != nil {
		t.Fatal(err)
	}
	var got *store.MachineDeviceRequest
	if err := jobs(func(tx store.Tx) error {
		var err error
		got, err = store.GetMachineDeviceRequestByUserCode(ctx, tx, dr.UserCodeHash)
		return err
	}); err != nil || got.ID != dr.ID || got.Status != store.MachineRequestPending || got.RequestIP != "198.51.100.7" {
		t.Fatalf("by user code = %+v, %v", got, err)
	}
	m := newMachine(t, st, alice, "laptop")
	if err := jobs(func(tx store.Tx) error {
		return store.DecideMachineDeviceRequest(ctx, tx, dr.ID, store.MachineRequestApproved, alice, m.ID, now)
	}); err != nil {
		t.Fatal(err)
	}
	// Deciding twice is refused.
	if err := jobs(func(tx store.Tx) error {
		return store.DecideMachineDeviceRequest(ctx, tx, dr.ID, store.MachineRequestDenied, alice, "", now)
	}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("second decision = %v, want ErrNotFound", err)
	}
	if err := jobs(func(tx store.Tx) error {
		var err error
		got, err = store.LockMachineDeviceRequest(ctx, tx, dr.DeviceCodeHash)
		if err != nil {
			return err
		}
		return store.ConsumeMachineDeviceRequest(ctx, tx, got.ID)
	}); err != nil || got.Status != store.MachineRequestApproved || got.MachineID != m.ID || got.DecidedBy != alice {
		t.Fatalf("lock approved = %+v, %v", got, err)
	}
	if err := jobs(func(tx store.Tx) error { return store.ConsumeMachineDeviceRequest(ctx, tx, dr.ID) }); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("second consume = %v, want ErrNotFound", err)
	}
	if err := jobs(func(tx store.Tx) error { return store.TouchMachineDeviceRequestPoll(ctx, tx, dr.ID, now, 10) }); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationMachineEnrollmentCodeSingleUseUnderConcurrency(t *testing.T) {
	env := setup(t)
	env.reset(t)
	st := env.open(t)
	ctx := t.Context()
	alice, bob := newUser(t, st, "Alice"), newUser(t, st, "Bob")
	code := &store.MachineEnrollmentCode{OwnerUserID: alice, CodeHash: []byte("code-" + t.Name()), Label: "ci", ExpiresAt: time.Now().Add(time.Hour)}
	if err := st.WithUser(ctx, alice, func(tx store.Tx) error { return store.CreateMachineEnrollmentCode(ctx, tx, code) }); err != nil {
		t.Fatal(err)
	}
	// Bob cannot see or revoke Alice's code.
	if err := st.WithUser(ctx, bob, func(tx store.Tx) error {
		return store.RevokeMachineEnrollmentCode(ctx, tx, code.ID, time.Now())
	}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("bob revokes alice's code: %v", err)
	}

	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := st.WithJobs(ctx, func(tx store.Tx) error {
				c, err := store.ConsumeMachineEnrollmentCode(ctx, tx, code.CodeHash, time.Now())
				if err != nil {
					return err
				}
				if c.OwnerUserID != alice {
					t.Errorf("owner = %s", c.OwnerUserID)
				}
				return nil
			})
			if err == nil {
				wins.Add(1)
			} else if !errors.Is(err, store.ErrNotFound) {
				t.Errorf("consume: %v", err)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d concurrent consumers won, want exactly 1", wins.Load())
	}

	// Expired, revoked and inactive-owner codes are not consumable.
	expired := &store.MachineEnrollmentCode{OwnerUserID: alice, CodeHash: []byte("expired-" + t.Name()), ExpiresAt: time.Now().Add(-time.Minute)}
	revoked := &store.MachineEnrollmentCode{OwnerUserID: alice, CodeHash: []byte("revoked-" + t.Name()), ExpiresAt: time.Now().Add(time.Hour)}
	disabledOwner := &store.MachineEnrollmentCode{OwnerUserID: bob, CodeHash: []byte("bob-" + t.Name()), ExpiresAt: time.Now().Add(time.Hour)}
	for _, c := range []*store.MachineEnrollmentCode{expired, revoked} {
		if err := st.WithUser(ctx, alice, func(tx store.Tx) error { return store.CreateMachineEnrollmentCode(ctx, tx, c) }); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.WithUser(ctx, bob, func(tx store.Tx) error { return store.CreateMachineEnrollmentCode(ctx, tx, disabledOwner) }); err != nil {
		t.Fatal(err)
	}
	if err := st.WithUser(ctx, alice, func(tx store.Tx) error { return store.RevokeMachineEnrollmentCode(ctx, tx, revoked.ID, time.Now()) }); err != nil {
		t.Fatal(err)
	}
	if err := st.WithJobs(ctx, func(tx store.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE users SET status = 'disabled' WHERE id = $1`, bob)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]*store.MachineEnrollmentCode{"expired": expired, "revoked": revoked, "inactive owner": disabledOwner} {
		err := st.WithJobs(ctx, func(tx store.Tx) error {
			_, err := store.ConsumeMachineEnrollmentCode(ctx, tx, c.CodeHash, time.Now())
			return err
		})
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("%s code consumed: %v", name, err)
		}
	}
	var codes []store.MachineEnrollmentCode
	if err := st.WithUser(ctx, alice, func(tx store.Tx) error {
		var err error
		codes, err = store.ListMachineEnrollmentCodes(ctx, tx, alice)
		return err
	}); err != nil || len(codes) != 3 {
		t.Fatalf("alice's codes = %d, %v", len(codes), err)
	}
}

func TestIntegrationMachineTokensTunnelsAndRevocation(t *testing.T) {
	env := setup(t)
	env.reset(t)
	st := env.open(t)
	ctx := t.Context()
	alice, bob := newUser(t, st, "Alice"), newUser(t, st, "Bob")
	m := newMachine(t, st, alice, "laptop")
	jobs := func(fn func(tx store.Tx) error) error { return st.WithJobs(ctx, fn) }
	now := time.Now().UTC()

	// Access token.
	hash := []byte("access-" + t.Name())
	if err := jobs(func(tx store.Tx) error {
		return store.CreateMachineAccessToken(ctx, tx, hash, m.ID, now.Add(10*time.Minute))
	}); err != nil {
		t.Fatal(err)
	}
	var tok *store.MachineAccess
	if err := jobs(func(tx store.Tx) error {
		var err error
		tok, err = store.GetMachineAccessToken(ctx, tx, hash, now)
		return err
	}); err != nil || tok.Machine.ID != m.ID || !tok.Live() || tok.Machine.OwnerName != "Alice" {
		t.Fatalf("token lookup = %+v, %v", tok, err)
	}
	if err := jobs(func(tx store.Tx) error {
		_, err := store.GetMachineAccessToken(ctx, tx, hash, now.Add(11*time.Minute))
		return err
	}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired token lookup = %v", err)
	}

	// Assertion jti replay.
	for i, want := range []bool{true, false} {
		var fresh bool
		if err := jobs(func(tx store.Tx) error {
			var err error
			fresh, err = store.RecordMachineAssertionJTI(ctx, tx, m.ID, "jti-1", now.Add(time.Minute), now)
			return err
		}); err != nil || fresh != want {
			t.Fatalf("jti use %d: fresh = %v, %v", i, fresh, err)
		}
	}

	// A tunnel linked to the machine: no token hash, unique per server name.
	tun := &store.MCPTunnel{OwnerUserID: alice, Name: "laptop/fusion", MachineID: m.ID, ServerName: "fusion"}
	if err := jobs(func(tx store.Tx) error { return store.CreateMCPTunnel(ctx, tx, tun) }); err != nil {
		t.Fatal(err)
	}
	if tun.TokenHash != nil || tun.MachineID != m.ID || tun.ServerName != "fusion" {
		t.Fatalf("machine tunnel = %+v", tun)
	}
	dupTun := &store.MCPTunnel{OwnerUserID: alice, Name: "laptop/fusion", MachineID: m.ID, ServerName: "fusion"}
	if err := jobs(func(tx store.Tx) error { return store.CreateMCPTunnel(ctx, tx, dupTun) }); err == nil {
		t.Fatal("a second live tunnel for the same machine server was stored")
	}
	// The tunnel's owner must be the machine's owner.
	stolen := &store.MCPTunnel{OwnerUserID: bob, Name: "x", MachineID: m.ID, ServerName: "other"}
	if err := jobs(func(tx store.Tx) error { return store.CreateMCPTunnel(ctx, tx, stolen) }); err == nil {
		t.Fatal("a tunnel of Bob linked to Alice's machine was stored")
	}
	var found *store.MCPTunnel
	if err := jobs(func(tx store.Tx) error {
		var err error
		found, err = store.GetMachineTunnel(ctx, tx, m.ID, "fusion")
		return err
	}); err != nil || found.ID != tun.ID {
		t.Fatalf("machine tunnel lookup = %+v, %v", found, err)
	}
	var ids []string
	var live bool
	if err := jobs(func(tx store.Tx) error {
		var err error
		ids, live, err = store.MachineTunnelIDs(ctx, tx, m.ID)
		return err
	}); err != nil || !live || len(ids) != 1 || ids[0] != tun.ID {
		t.Fatalf("machine tunnels = %v %v %v", ids, live, err)
	}

	// Transfer to a replacement machine.
	repl := &store.Machine{OwnerUserID: alice, Name: "laptop-2", PublicKey: bytes.Repeat([]byte{7}, 32), Fingerprint: "fp2", EnrolledVia: store.MachineEnrolledCode}
	if err := jobs(func(tx store.Tx) error {
		if err := store.CreateMachine(ctx, tx, repl); err != nil {
			return err
		}
		return store.TransferMachineTunnels(ctx, tx, m.ID, repl.ID)
	}); err != nil {
		t.Fatal(err)
	}
	if err := jobs(func(tx store.Tx) error {
		var err error
		ids, _, err = store.MachineTunnelIDs(ctx, tx, repl.ID)
		return err
	}); err != nil || len(ids) != 1 || ids[0] != tun.ID {
		t.Fatalf("after transfer = %v, %v", ids, err)
	}

	// Revocation: tunnels revoked, no longer live (tokens are found but not live).
	hash2 := []byte("access2-" + t.Name())
	if err := jobs(func(tx store.Tx) error {
		if err := store.CreateMachineAccessToken(ctx, tx, hash2, repl.ID, now.Add(10*time.Minute)); err != nil {
			return err
		}
		return store.RevokeMachine(ctx, tx, repl.ID, "", store.MachineRevokedByAdmin, now)
	}); err != nil {
		t.Fatal(err)
	}
	if err := jobs(func(tx store.Tx) error {
		var err error
		tok, err = store.GetMachineAccessToken(ctx, tx, hash2, now)
		return err
	}); err != nil || tok.Live() || tok.Machine.RevokeReason != store.MachineRevokedByAdmin {
		t.Fatalf("token of a revoked machine = %+v, %v (want found, not live)", tok, err)
	}
	if err := jobs(func(tx store.Tx) error {
		var err error
		ids, live, err = store.MachineTunnelIDs(ctx, tx, repl.ID)
		return err
	}); err != nil || live || len(ids) != 0 {
		t.Fatalf("revoked machine tunnels = %v live=%v %v", ids, live, err)
	}
	var tunAfter *store.MCPTunnel
	if err := jobs(func(tx store.Tx) error {
		var err error
		tunAfter, err = store.GetMCPTunnel(ctx, tx, tun.ID)
		return err
	}); err != nil || tunAfter.RevokedAt == nil {
		t.Fatalf("tunnel of a revoked machine = %+v, %v", tunAfter, err)
	}

	// An inactive owner makes a live machine not live.
	m3 := newMachine(t, st, bob, "desk")
	if err := jobs(func(tx store.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE users SET status = 'pending' WHERE id = $1`, bob)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := jobs(func(tx store.Tx) error {
		var err error
		_, live, err = store.MachineTunnelIDs(ctx, tx, m3.ID)
		return err
	}); err != nil || live {
		t.Fatalf("machine of a pending owner live = %v, %v", live, err)
	}
	var mm *store.Machine
	if err := jobs(func(tx store.Tx) error {
		var err error
		mm, err = store.GetMachine(ctx, tx, m3.ID)
		return err
	}); err != nil || mm.OwnerStatus != store.UserPending || mm.Live() {
		t.Fatalf("GetMachine = %+v, %v", mm, err)
	}
	if err := jobs(func(tx store.Tx) error { return store.TouchMachine(ctx, tx, m3.ID, now, "203.0.113.9") }); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationLegacyTokenLookupIgnoresMachineTunnels(t *testing.T) {
	env := setup(t)
	env.reset(t)
	st := env.open(t)
	ctx := t.Context()
	alice := newUser(t, st, "Alice")
	m := newMachine(t, st, alice, "laptop")
	tun := &store.MCPTunnel{OwnerUserID: alice, Name: "laptop/x", MachineID: m.ID, ServerName: "x"}
	if err := st.WithJobs(ctx, func(tx store.Tx) error { return store.CreateMCPTunnel(ctx, tx, tun) }); err != nil {
		t.Fatal(err)
	}
	err := st.WithJobs(ctx, func(tx store.Tx) error {
		_, err := store.GetMCPTunnelByTokenHash(ctx, tx, nil)
		return err
	})
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("lookup by an empty hash = %v, want ErrNotFound", err)
	}
	// A legacy tunnel needs a token hash.
	if err := st.WithJobs(ctx, func(tx store.Tx) error {
		return store.CreateMCPTunnel(ctx, tx, &store.MCPTunnel{OwnerUserID: alice, Name: "nohash"})
	}); err == nil {
		t.Fatal("a legacy tunnel without a token hash was stored")
	}
}
