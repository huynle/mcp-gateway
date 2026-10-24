//go:build integration

package elicit_test

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/huynle/mcp-gateway/internal/federation/elicit"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/store/migrations"
)

// The elicit integration tests run against their own database
// (gateway_elicit_test, created from GATEWAY_TEST_DATABASE_URL) so they
// never race the store package's TRUNCATE (quirk 01mepmn6).

const (
	elicitTestDB  = "gateway_elicit_test"
	itAppPassword = "gateway-app-test"
	itJobsPass    = "gateway-jobs-test"
)

func execRetrying(ctx context.Context, conn *pgx.Conn, stmt string) error {
	var err error
	for range 20 {
		if _, err = conn.Exec(ctx, stmt); err == nil || !strings.Contains(err.Error(), "concurrently updated") {
			return err
		}
		time.Sleep(100 * time.Millisecond)
	}
	return err
}

func TestIntegrationElicitServiceOverPostgres(t *testing.T) {
	raw := os.Getenv("GATEWAY_TEST_DATABASE_URL")
	if raw == "" {
		t.Skip("GATEWAY_TEST_DATABASE_URL not set; skipping integration test")
	}
	ctx := t.Context()
	admin, err := pgx.Connect(ctx, raw)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = admin.Close(ctx) }()
	var exists bool
	if err := admin.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)`, elicitTestDB).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		if _, err := admin.Exec(ctx, `CREATE DATABASE `+elicitTestDB); err != nil {
			t.Fatalf("create database: %v", err)
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + elicitTestDB
	if err := migrations.Up(ctx, u.String()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	super, err := pgx.Connect(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close(context.Background()) })
	for _, stmt := range []string{
		"ALTER ROLE gateway_app LOGIN PASSWORD '" + itAppPassword + "'",
		"ALTER ROLE gateway_jobs LOGIN PASSWORD '" + itJobsPass + "'",
		"TRUNCATE users, mcp_servers CASCADE",
	} {
		if err := execRetrying(ctx, super, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	appURL, jobsURL := *u, *u
	appURL.User = url.UserPassword("gateway_app", itAppPassword)
	jobsURL.User = url.UserPassword("gateway_jobs", itJobsPass)
	st, err := store.New(ctx, appURL.String(), store.WithJobsURL(jobsURL.String()))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(st.Close)
	var owner, other, server string
	for _, p := range []*string{&owner, &other} {
		if err := super.QueryRow(ctx, `INSERT INTO users (display_name) VALUES ('it') RETURNING id::text`).Scan(p); err != nil {
			t.Fatal(err)
		}
	}
	if err := super.QueryRow(ctx, `INSERT INTO mcp_servers (name, url, owner_user_id) VALUES ('notes', 'https://notes.example.test/mcp', $1)
		RETURNING id::text`, owner).Scan(&server); err != nil {
		t.Fatal(err)
	}

	svc, err := elicit.New(elicit.NewPostgresStore(st), elicit.Options{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	svc.SetClock(func() time.Time { return now })
	const target = "https://connect.example.test/start"

	link, rec, err := svc.Create(ctx, owner, "tok-1", server, target, "up-1", "hello")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	var hashLen, n int
	if err := super.QueryRow(ctx, `SELECT length(link_hash) FROM upstream_elicitations WHERE id = $1`, rec.ID).Scan(&hashLen); err != nil || hashLen != 32 {
		t.Errorf("stored link hash length = %d, %v", hashLen, err)
	}
	if _, err := svc.Lookup(ctx, other, link); !errors.Is(err, elicit.ErrNotFound) {
		t.Errorf("other user lookup = %v", err)
	}
	if got, err := svc.Open(ctx, owner, link); err != nil || got.URL != target || got.OpenedAt == nil {
		t.Errorf("open = %+v, %v", got, err)
	}
	if _, err := svc.Cancel(ctx, owner, link); err != nil {
		t.Errorf("cancel: %v", err)
	}
	if _, err := svc.Lookup(ctx, owner, link); !errors.Is(err, elicit.ErrNotFound) {
		t.Errorf("lookup after cancel = %v", err)
	}
	// The cap holds across transactions.
	for range elicit.MaxLivePerOwner {
		if _, _, err := svc.Create(ctx, owner, "tok-1", server, target, "", ""); err != nil {
			t.Fatalf("create: %v", err)
		}
	}
	if _, _, err := svc.Create(ctx, owner, "tok-1", server, target, "", ""); !errors.Is(err, elicit.ErrLimited) {
		t.Errorf("over the cap = %v", err)
	}
	// The expiry job purges a day after expiry.
	now = now.Add(elicit.LinkTTL + elicit.Retention)
	if err := svc.ExpiryJob(0).Run(ctx); err != nil {
		t.Fatalf("expiry job: %v", err)
	}
	if err := super.QueryRow(ctx, `SELECT count(*) FROM upstream_elicitations`).Scan(&n); err != nil || n != 0 {
		t.Errorf("rows after purge = %d, %v", n, err)
	}
}
