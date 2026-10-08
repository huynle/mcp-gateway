//go:build integration

package store_test

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/store"
)

// The ledger-module queries (repo_ledger_ops.go): lookup by idempotency
// key within a window, conditional state transitions, attempts with an
// explicit start, listing by state, the stale sweep and the unique
// open-key index migration 00012 adds.
func TestIntegrationLedgerOperationsQueries(t *testing.T) {
	env := setup(t)
	env.reset(t)
	ctx := t.Context()
	st := env.open(t)
	userA := newUser(t, st, "alice")
	userB := newUser(t, st, "bob")
	appID := newVendorApp(t, st)
	connA := newConnection(t, st, userA, appID, "acct-a")
	connB := newConnection(t, st, userB, appID, "acct-b")
	var pvID string
	if err := st.WithJobs(ctx, func(tx store.Tx) error {
		pv := &store.PolicyVersion{VersionHash: "sha256:ledger", Cedar: "permit(principal, action, resource);", Source: []byte(`{}`)}
		if err := tx.PolicyVersions().Create(ctx, pv); err != nil {
			return err
		}
		pvID = pv.ID
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	tokenID := "0f0f0f0f-0f0f-4f0f-8f0f-0f0f0f0f0f0f"

	newOp := func(user, conn, key string, created time.Time) *store.LedgerOperation {
		return &store.LedgerOperation{
			UserID: user, ConnectionID: conn, Tool: "fake.create_item", State: store.LedgerInProgress,
			IdempotencyKey: key, WindowStart: created, WindowEnd: created.Add(24 * time.Hour),
			Digest: []byte("d"), PolicyVersionID: pvID, TokenID: &tokenID,
			Resource:  []byte(`{"id":"it-1"}`),
			CreatedAt: created, UpdatedAt: created,
		}
	}

	// Insert with explicit created_at/resource/token; lookup by key sees it
	// only within the window.
	var opA *store.LedgerOperation
	err := st.WithUser(ctx, userA, func(tx store.Tx) error {
		if err := store.LockLedgerKey(ctx, tx, "k1"); err != nil {
			return err
		}
		opA = newOp(userA, connA, "k1", now.Add(-time.Hour))
		if err := store.CreateLedgerOperation(ctx, tx, opA); err != nil {
			return err
		}
		got, err := store.LatestLedgerOperationByKey(ctx, tx, "k1", now.Add(-2*time.Hour))
		if err != nil || got.ID != opA.ID || !jsonEqual(got.Resource, `{"id":"it-1"}`) || got.TokenID == nil || *got.TokenID != tokenID || !got.CreatedAt.Equal(now.Add(-time.Hour)) {
			t.Errorf("latest by key = %+v, %v", got, err)
		}
		if _, err := store.LatestLedgerOperationByKey(ctx, tx, "k1", now.Add(-30*time.Minute)); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("latest by key outside window: err = %v, want ErrNotFound", err)
		}
		if _, err := store.LatestLedgerOperationByKey(ctx, tx, "nope", time.Time{}); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("latest by unknown key: err = %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("create + lookup: %v", err)
	}

	// The unique open-key index refuses a second open operation for the key.
	err = st.WithUser(ctx, userA, func(tx store.Tx) error {
		return store.CreateLedgerOperation(ctx, tx, newOp(userA, connA, "k1", now))
	})
	if !errors.Is(err, store.ErrLedgerKeyOpen) {
		t.Fatalf("second open op for k1: err = %v, want ErrLedgerKeyOpen", err)
	}

	// Row-level security: bob sees nothing of alice's.
	err = st.WithUser(ctx, userB, func(tx store.Tx) error {
		if _, err := store.LatestLedgerOperationByKey(ctx, tx, "k1", time.Time{}); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("bob sees alice's op by key: %v", err)
		}
		ok, err := store.TransitionLedgerOperation(ctx, tx, opA.ID, []string{store.LedgerInProgress}, store.LedgerTransition{State: store.LedgerFailed, At: now})
		if err != nil || ok {
			t.Errorf("bob transitions alice's op: ok=%v err=%v", ok, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Conditional transition: only from the listed states; records result
	// ids, error code, attempts and finished_at.
	err = st.WithUser(ctx, userA, func(tx store.Tx) error {
		ok, err := store.TransitionLedgerOperation(ctx, tx, opA.ID, []string{store.LedgerUnknown}, store.LedgerTransition{State: store.LedgerSucceeded, At: now})
		if err != nil || ok {
			t.Errorf("transition from wrong state: ok=%v err=%v", ok, err)
		}
		attempts := 3
		ok, err = store.TransitionLedgerOperation(ctx, tx, opA.ID, []string{store.LedgerInProgress, store.LedgerUnknown}, store.LedgerTransition{
			State: store.LedgerSucceeded, ResultIDs: []byte(`{"id":"it-1"}`), ReconcileAttempts: &attempts, Finished: true, At: now,
		})
		if err != nil || !ok {
			t.Fatalf("transition: ok=%v err=%v", ok, err)
		}
		got, err := store.GetLedgerOperation(ctx, tx, opA.ID)
		if err != nil || got.State != store.LedgerSucceeded || !jsonEqual(got.ResultIDs, `{"id":"it-1"}`) || got.ReconcileAttempts != 3 || got.FinishedAt == nil || !got.FinishedAt.Equal(now) || !got.UpdatedAt.Equal(now) {
			t.Errorf("after transition = %+v, %v", got, err)
		}
		// After it closed the key is open for a new operation (window aside).
		if err := store.CreateLedgerOperation(ctx, tx, newOp(userA, connA, "k1", now)); err != nil {
			t.Errorf("new op after close: %v", err)
		}
		code := "tool_error"
		att := &store.LedgerAttempt{OperationID: opA.ID, UserID: userA, AttemptNo: 1, Kind: store.AttemptCall, Outcome: store.LedgerSucceeded, ErrorCode: &code, StartedAt: now.Add(-time.Minute), FinishedAt: &now}
		if err := store.CreateLedgerAttempt(ctx, tx, att); err != nil {
			return err
		}
		atts, err := tx.Ledger().AttemptsForOperation(ctx, opA.ID)
		if err != nil || len(atts) != 1 || !atts[0].StartedAt.Equal(now.Add(-time.Minute)) || atts[0].ErrorCode == nil {
			t.Errorf("attempts = %+v, %v", atts, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Listing by state (bypass scope, across users) and the stale sweep.
	err = st.WithJobs(ctx, func(tx store.Tx) error {
		stale := newOp(userB, connB, "k-stale", now.Add(-10*time.Minute))
		fresh := newOp(userB, connB, "k-fresh", now.Add(-10*time.Second))
		for _, op := range []*store.LedgerOperation{stale, fresh} {
			if err := store.CreateLedgerOperation(ctx, tx, op); err != nil {
				return err
			}
		}
		list, err := store.ListLedgerOperations(ctx, tx, store.LedgerFilter{States: []string{store.LedgerInProgress}, Limit: 10})
		if err != nil || len(list) != 3 {
			t.Fatalf("list in_progress = %d ops, %v", len(list), err)
		}
		list, err = store.ListLedgerOperations(ctx, tx, store.LedgerFilter{UserID: userB, States: []string{store.LedgerInProgress}, CreatedBefore: now.Add(-2 * time.Minute)})
		if err != nil || len(list) != 1 || list[0].ID != stale.ID {
			t.Errorf("list stale for bob = %+v, %v", list, err)
		}
		swept, err := store.SweepStaleLedgerOperations(ctx, tx, now.Add(-2*time.Minute), now)
		if err != nil || len(swept) != 1 || swept[0].ID != stale.ID || swept[0].State != store.LedgerUnknown {
			t.Fatalf("sweep = %+v, %v (want bob's stale op only)", swept, err)
		}
		got, err := store.GetLedgerOperation(ctx, tx, stale.ID)
		if err != nil || got.State != store.LedgerUnknown || !got.UpdatedAt.Equal(now) {
			t.Errorf("stale after sweep = %+v, %v", got, err)
		}
		got, err = store.GetLedgerOperation(ctx, tx, fresh.ID)
		if err != nil || got.State != store.LedgerInProgress {
			t.Errorf("fresh after sweep = %+v, %v", got, err)
		}
		// Newest first for the user page.
		list, err = store.ListLedgerOperations(ctx, tx, store.LedgerFilter{UserID: userB, Limit: 1})
		if err != nil || len(list) != 1 || list[0].ID != fresh.ID {
			t.Errorf("newest for bob = %+v, %v", list, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// jsonEqual compares a jsonb column (PostgreSQL re-spaces it) with want.
func jsonEqual(got json.RawMessage, want string) bool {
	var a, b any
	if json.Unmarshal(got, &a) != nil || json.Unmarshal([]byte(want), &b) != nil {
		return false
	}
	return reflect.DeepEqual(a, b)
}
