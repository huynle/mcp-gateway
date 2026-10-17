//go:build integration

package migrations_test

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/huynle/mcp-gateway/internal/store/migrations"
)

// TestIntegrationConcurrentUp runs two migrations at once against a fresh
// database, as two gateway pods' init containers would. The advisory
// session lock must serialise them: both succeed and the schema ends at the
// latest version.
func TestIntegrationConcurrentUp(t *testing.T) {
	base := os.Getenv("GATEWAY_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("GATEWAY_TEST_DATABASE_URL is unset")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	admin, err := sql.Open("pgx", base)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close() }()
	name := fmt.Sprintf("migrate_concurrent_%d", time.Now().UnixNano())
	if _, err := admin.ExecContext(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("create database: %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.ExecContext(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
	})
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	dsn := u.String()

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = migrations.Up(ctx, dsn)
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("migration %d: %v", i, err)
		}
	}

	var buf strings.Builder
	if err := migrations.Status(ctx, dsn, &buf); err != nil {
		t.Fatalf("status: %v", err)
	}
	if strings.Contains(buf.String(), "pending") {
		t.Fatalf("pending migrations after concurrent up:\n%s", buf.String())
	}
}
