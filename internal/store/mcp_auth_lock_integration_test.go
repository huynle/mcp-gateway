//go:build integration

package store_test

import (
	"errors"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/store"
)

// LockMCPUserConnection (federation auth, task k3ff95ec) takes a row lock
// that serialises token refreshes across replicas and obeys row-level
// security like GetMCPUserConnection.
func TestIntegrationMCPUserConnectionLock(t *testing.T) {
	env := setup(t)
	env.reset(t)
	ctx := t.Context()
	st := env.open(t)
	f := newMCPFixture(t, st)

	locked := make(chan struct{})
	release := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- st.WithUser(ctx, f.alice, func(tx store.Tx) error {
			c, err := store.LockMCPUserConnection(ctx, tx, f.server.ID, f.alice)
			close(locked)
			if err != nil {
				return err
			}
			if c.ID != f.connA.ID {
				t.Errorf("locked connection %s, want %s", c.ID, f.connA.ID)
			}
			<-release
			return store.SetMCPUserConnectionStatus(ctx, tx, f.server.ID, f.alice, store.MCPConnectionNeedsReconnect)
		})
	}()
	<-locked

	secondGot := make(chan *store.MCPUserConnection, 1)
	secondErr := make(chan error, 1)
	go func() {
		secondErr <- st.WithUser(ctx, f.alice, func(tx store.Tx) error {
			c, err := store.LockMCPUserConnection(ctx, tx, f.server.ID, f.alice)
			if err == nil {
				secondGot <- c
			}
			return err
		})
	}()
	select {
	case <-secondGot:
		close(release)
		<-firstDone
		t.Fatal("second lock acquired while the first transaction holds it")
	case <-time.After(300 * time.Millisecond):
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatalf("first transaction: %v", err)
	}
	if err := <-secondErr; err != nil {
		t.Fatalf("second transaction: %v", err)
	}
	if c := <-secondGot; c.Status != store.MCPConnectionNeedsReconnect {
		t.Fatalf("waiter read status %q, want the first transaction's needs_reconnect", c.Status)
	}

	// Row-level security: bob cannot lock (or see) alice's connection.
	err := st.WithUser(ctx, f.bob, func(tx store.Tx) error {
		_, err := store.LockMCPUserConnection(ctx, tx, f.server.ID, f.alice)
		return err
	})
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("bob locking alice's connection = %v, want ErrNotFound", err)
	}
	// The jobs role sees it.
	err = st.WithJobs(ctx, func(tx store.Tx) error {
		_, err := store.LockMCPUserConnection(ctx, tx, f.server.ID, f.alice)
		return err
	})
	if err != nil {
		t.Fatalf("jobs lock: %v", err)
	}
}
