//go:build integration

package store_test

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/store"
)

// Integration tests for Web Push (migration 00033, decision 0pzhidap):
// the VAPID key singleton and the user-scoped push subscriptions.

func pushHash(endpoint string) []byte {
	h := sha256.Sum256([]byte(endpoint))
	return h[:]
}

func pushID(t *testing.T) string {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func newPushSubscription(t *testing.T, st *store.Store, owner, endpoint string) *store.PushSubscription {
	t.Helper()
	s := &store.PushSubscription{
		ID: pushID(t), UserID: owner, EndpointSHA256: pushHash(endpoint), Sealed: testSecret("sub-" + endpoint),
		EndpointHost: "fcm.googleapis.com", DeviceLabel: "Android Chrome",
	}
	err := st.WithUser(t.Context(), owner, func(tx store.Tx) error { return store.CreatePushSubscription(t.Context(), tx, s) })
	if err != nil {
		t.Fatalf("create subscription %s: %v", endpoint, err)
	}
	if s.CreatedAt.IsZero() || s.UpdatedAt.IsZero() {
		t.Fatalf("created subscription = %+v", s)
	}
	return s
}

func TestIntegrationPushSubscriptionsRowSecurity(t *testing.T) {
	env := setup(t)
	env.reset(t)
	st := env.open(t)
	ctx := t.Context()
	alice, bob := newUser(t, st, "Alice"), newUser(t, st, "Bob")
	a1 := newPushSubscription(t, st, alice, "https://fcm.googleapis.com/fcm/send/a1")
	newPushSubscription(t, st, alice, "https://fcm.googleapis.com/fcm/send/a2")

	err := st.WithUser(ctx, bob, func(tx store.Tx) error {
		list, err := store.ListPushSubscriptions(ctx, tx, alice)
		if err != nil {
			return err
		}
		if len(list) != 0 {
			t.Errorf("bob lists %d of alice's subscriptions", len(list))
		}
		if _, err := store.GetPushSubscriptionByHash(ctx, tx, a1.EndpointSHA256); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("bob reads alice's subscription by hash = %v, want ErrNotFound", err)
		}
		if ok, err := store.DeletePushSubscription(ctx, tx, a1.ID); err != nil || ok {
			t.Errorf("bob deletes alice's subscription = %v, %v", ok, err)
		}
		if ok, err := store.DeletePushSubscriptionByHash(ctx, tx, a1.EndpointSHA256); err != nil || ok {
			t.Errorf("bob deletes alice's subscription by hash = %v, %v", ok, err)
		}
		if err := store.RecordPushDelivery(ctx, tx, a1.ID, false, time.Now()); err != nil {
			return err
		}
		if n, err := store.CountPushSubscriptions(ctx, tx, alice); err != nil || n != 0 {
			t.Errorf("bob counts alice's subscriptions = %d, %v", n, err)
		}
		// Inserting a row for alice from bob's scope violates the policy.
		forged := &store.PushSubscription{ID: pushID(t), UserID: alice, EndpointSHA256: pushHash("forged"), Sealed: testSecret("f"),
			EndpointHost: "fcm.googleapis.com", DeviceLabel: "x"}
		if err := store.CreatePushSubscription(ctx, tx, forged); err == nil {
			t.Error("bob created a subscription for alice")
		}
		return nil
	})
	// The forged insert aborted the transaction; that is the expected error.
	if err == nil {
		t.Log("transaction committed")
	}

	var list []store.PushSubscription
	if err := st.WithUser(ctx, alice, func(tx store.Tx) error {
		var err error
		list, err = store.ListPushSubscriptions(ctx, tx, alice)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].FailureCount != 0 || list[0].DeviceLabel != "Android Chrome" || list[0].Sealed.KeyID == "" {
		t.Fatalf("alice's subscriptions = %+v", list)
	}
}

func TestIntegrationPushSubscriptionsUpdateDeliveryAndDelete(t *testing.T) {
	env := setup(t)
	env.reset(t)
	st := env.open(t)
	ctx := t.Context()
	alice := newUser(t, st, "Alice")
	s := newPushSubscription(t, st, alice, "https://fcm.googleapis.com/fcm/send/x")

	at := time.Now().UTC().Truncate(time.Second)
	err := st.WithUser(ctx, alice, func(tx store.Tx) error {
		if err := store.LockPushSubscriptions(ctx, tx, alice); err != nil {
			return err
		}
		if err := store.RecordPushDelivery(ctx, tx, s.ID, false, at); err != nil {
			return err
		}
		if err := store.RecordPushDelivery(ctx, tx, s.ID, false, at); err != nil {
			return err
		}
		got, err := store.GetPushSubscriptionByHash(ctx, tx, s.EndpointSHA256)
		if err != nil {
			return err
		}
		if got.FailureCount != 2 || got.LastFailureAt == nil || got.LastSuccessAt != nil {
			t.Errorf("after two failures = %+v", got)
		}
		if err := store.RecordPushDelivery(ctx, tx, s.ID, true, at); err != nil {
			return err
		}
		got, _ = store.GetPushSubscriptionByHash(ctx, tx, s.EndpointSHA256)
		if got.FailureCount != 0 || got.LastSuccessAt == nil || !got.LastSuccessAt.Equal(at) {
			t.Errorf("after a success = %+v", got)
		}
		// Re-subscribe: new keys and label, failures reset.
		got.Sealed = testSecret("new-keys")
		got.DeviceLabel = "Pixel"
		if err := store.UpdatePushSubscription(ctx, tx, got); err != nil {
			return err
		}
		again, _ := store.GetPushSubscriptionByHash(ctx, tx, s.EndpointSHA256)
		if string(again.Sealed.WrappedDataKey) != "wrapped-new-keys" || again.DeviceLabel != "Pixel" || again.ID != s.ID {
			t.Errorf("after update = %+v", again)
		}
		if n, err := store.CountPushSubscriptions(ctx, tx, alice); err != nil || n != 1 {
			t.Errorf("count = %d, %v", n, err)
		}
		if ok, err := store.DeletePushSubscriptionByHash(ctx, tx, s.EndpointSHA256); err != nil || !ok {
			t.Errorf("delete by hash = %v, %v", ok, err)
		}
		if ok, err := store.DeletePushSubscription(ctx, tx, s.ID); err != nil || ok {
			t.Errorf("delete again = %v, %v", ok, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// One browser endpoint belongs to one user: a second user's subscription
// of the same endpoint is refused by the unique index until the jobs scope
// hands the endpoint over.
func TestIntegrationPushEndpointHandover(t *testing.T) {
	env := setup(t)
	env.reset(t)
	st := env.open(t)
	ctx := t.Context()
	alice, bob := newUser(t, st, "Alice"), newUser(t, st, "Bob")
	endpoint := "https://web.push.apple.com/shared"
	newPushSubscription(t, st, alice, endpoint)
	newPushSubscription(t, st, alice, "https://web.push.apple.com/other")

	dup := &store.PushSubscription{ID: pushID(t), UserID: bob, EndpointSHA256: pushHash(endpoint), Sealed: testSecret("b"),
		EndpointHost: "web.push.apple.com", DeviceLabel: "iPhone Safari"}
	if err := st.WithUser(ctx, bob, func(tx store.Tx) error { return store.CreatePushSubscription(ctx, tx, dup) }); !errors.Is(err, store.ErrPushEndpointTaken) {
		t.Fatalf("bob subscribing alice's endpoint without a handover = %v, want ErrPushEndpointTaken", err)
	}
	var released int64
	if err := st.WithJobs(ctx, func(tx store.Tx) error {
		var err error
		released, err = store.ReleasePushEndpoint(ctx, tx, pushHash(endpoint), bob)
		return err
	}); err != nil || released != 1 {
		t.Fatalf("release = %d, %v", released, err)
	}
	// The owner's own row is never released.
	if err := st.WithJobs(ctx, func(tx store.Tx) error {
		n, err := store.ReleasePushEndpoint(ctx, tx, pushHash("https://web.push.apple.com/other"), alice)
		if n != 0 {
			t.Errorf("released the owner's own row: %d", n)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.WithUser(ctx, bob, func(tx store.Tx) error { return store.CreatePushSubscription(ctx, tx, dup) }); err != nil {
		t.Fatalf("bob after handover: %v", err)
	}
	// The disable hook's delete.
	var n int64
	if err := st.WithJobs(ctx, func(tx store.Tx) error {
		var err error
		n, err = store.DeleteUserPushSubscriptions(ctx, tx, alice)
		return err
	}); err != nil || n != 1 {
		t.Fatalf("delete alice's subscriptions = %d, %v", n, err)
	}
	// Deleting the user row cascades.
	if _, err := env.super.Exec(ctx, `DELETE FROM users WHERE id = $1`, bob); err != nil {
		t.Fatal(err)
	}
	var left int
	if err := env.super.QueryRow(ctx, `SELECT count(*) FROM push_subscriptions`).Scan(&left); err != nil || left != 0 {
		t.Fatalf("subscriptions left after cascade = %d, %v", left, err)
	}
}

// Two replicas creating the VAPID key at the same time end up with one key.
func TestIntegrationWebPushKeyCreatedOnce(t *testing.T) {
	env := setup(t)
	env.reset(t)
	st := env.open(t)
	ctx := t.Context()
	if _, err := env.super.Exec(ctx, `DELETE FROM webpush_keys`); err != nil {
		t.Fatal(err)
	}
	if err := st.WithJobs(ctx, func(tx store.Tx) error {
		_, err := store.GetWebPushKey(ctx, tx)
		if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("empty table: GetWebPushKey = %v, want ErrNotFound", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	const racers = 2
	var wg sync.WaitGroup
	inserted := make([]bool, racers)
	errs := make([]error, racers)
	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			k := &store.WebPushKey{ID: pushID(t), PublicKey: fmt.Sprintf("public-%d", i), PrivateKey: testSecret(fmt.Sprint(i))}
			errs[i] = st.WithJobs(ctx, func(tx store.Tx) error {
				var err error
				inserted[i], err = store.CreateWebPushKey(ctx, tx, k)
				return err
			})
		}()
	}
	wg.Wait()
	wins := 0
	for i := range racers {
		if errs[i] != nil {
			t.Fatalf("racer %d: %v", i, errs[i])
		}
		if inserted[i] {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("%d racers inserted a key, want exactly 1", wins)
	}
	var n int
	if err := env.super.QueryRow(ctx, `SELECT count(*) FROM webpush_keys`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("keys = %d, %v", n, err)
	}
	// The app role reads it too (metadata view and table).
	if err := st.WithUser(ctx, newUser(t, st, "Carol"), func(tx store.Tx) error {
		k, err := store.GetWebPushKey(ctx, tx)
		if err != nil {
			return err
		}
		if k.PublicKey == "" || k.PrivateKey.KeyID == "" || k.CreatedAt.IsZero() {
			t.Errorf("key = %+v", k)
		}
		var views int
		return tx.QueryRow(ctx, `SELECT count(*) FROM admin_webpush_keys`).Scan(&views)
	}); err != nil {
		t.Fatal(err)
	}
}
