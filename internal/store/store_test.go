package store_test

import (
	"errors"
	"testing"

	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/store/migrations"
)

// The binary's expected schema version must track the embedded migrations so
// a new migration cannot land without bumping the constant (and vice versa).
func TestExpectedSchemaVersionMatchesEmbeddedMigrations(t *testing.T) {
	latest, err := migrations.Latest()
	if err != nil {
		t.Fatalf("migrations.Latest: %v", err)
	}
	if latest != store.ExpectedSchemaVersion {
		t.Fatalf("store.ExpectedSchemaVersion = %d, embedded migrations go up to %d", store.ExpectedSchemaVersion, latest)
	}
	if latest <= 0 {
		t.Fatalf("latest migration = %d, want > 0", latest)
	}
}

func TestWithUserRejectsInvalidIDsBeforeUsingTheDatabase(t *testing.T) {
	var st store.Store // zero value: no pools, any DB access would panic
	for _, id := range []string{"", "   ", "alice", "123", "00000000-0000-0000-0000-00000000000g", "' OR 1=1 --"} {
		err := st.WithUser(t.Context(), id, func(store.Tx) error {
			t.Fatalf("fn called for user ID %q", id)
			return nil
		})
		if !errors.Is(err, store.ErrInvalidUserID) {
			t.Errorf("WithUser(%q) = %v, want ErrInvalidUserID", id, err)
		}
	}
}

func TestWithJobsWithoutJobsURL(t *testing.T) {
	var st store.Store
	err := st.WithJobs(t.Context(), func(store.Tx) error {
		t.Fatal("fn called without a jobs pool")
		return nil
	})
	if !errors.Is(err, store.ErrJobsNotConfigured) {
		t.Errorf("WithJobs = %v, want ErrJobsNotConfigured", err)
	}
}

func TestNewRejectsBadURL(t *testing.T) {
	if _, err := store.New(t.Context(), "not a url"); err == nil {
		t.Error("New(\"not a url\") = nil error")
	}
	if _, err := store.New(t.Context(), "postgres://ok@localhost/db", store.WithJobsURL("::nope")); err == nil {
		t.Error("New with bad jobs URL = nil error")
	}
}
