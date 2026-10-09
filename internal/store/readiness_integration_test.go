//go:build integration

package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/store/migrations"
)

// TestIntegrationSchemaVersionReadyToleratesNewer: the "schema" readiness
// check (SchemaVersionReady) accepts a database that is ahead of the
// binary (a rolling upgrade runs the new migrations before the old pods
// are replaced; quirk 6xxvsoyp, idea vv0vurcl) and still refuses one
// that is behind. The startup gate (SchemaVersionMatches) stays strict.
func TestIntegrationSchemaVersionReadyToleratesNewer(t *testing.T) {
	env := setup(t)
	ctx := t.Context()
	env.reset(t)
	st := env.open(t)

	if err := st.SchemaVersionReady(ctx); err != nil {
		t.Fatalf("SchemaVersionReady on the expected version: %v", err)
	}

	// Ahead: a fake newer goose row, as a future release's migration
	// would leave it.
	if _, err := env.super.Exec(ctx, `INSERT INTO goose_db_version (version_id, is_applied) VALUES ($1, true)`, store.ExpectedSchemaVersion+1); err != nil {
		t.Fatalf("insert newer version: %v", err)
	}
	t.Cleanup(func() {
		_, _ = env.super.Exec(context.Background(), `DELETE FROM goose_db_version WHERE version_id = $1`, store.ExpectedSchemaVersion+1)
	})
	if err := st.SchemaVersionReady(ctx); err != nil {
		t.Errorf("SchemaVersionReady with a newer database = %v, want ready", err)
	}
	if err := st.SchemaVersionMatches(ctx); !errors.Is(err, store.ErrSchemaVersionMismatch) {
		t.Errorf("SchemaVersionMatches with a newer database = %v, want ErrSchemaVersionMismatch (startup stays strict)", err)
	}
	if _, err := env.super.Exec(ctx, `DELETE FROM goose_db_version WHERE version_id = $1`, store.ExpectedSchemaVersion+1); err != nil {
		t.Fatal(err)
	}

	// Behind: not ready.
	if err := migrations.Down(ctx, env.superURL); err != nil {
		t.Fatalf("down one: %v", err)
	}
	t.Cleanup(func() {
		if err := migrations.Up(context.Background(), env.superURL); err != nil {
			t.Fatalf("restore: %v", err)
		}
	})
	err := st.SchemaVersionReady(ctx)
	if !errors.Is(err, store.ErrSchemaVersionMismatch) {
		t.Fatalf("SchemaVersionReady after down = %v, want ErrSchemaVersionMismatch", err)
	}
	if !strings.Contains(err.Error(), "migrate") {
		t.Errorf("error %q should tell the operator to run migrations", err)
	}
}
