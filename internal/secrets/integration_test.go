//go:build integration

package secrets_test

import (
	"bytes"
	"context"
	"errors"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/secrets"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/store/migrations"
)

// The secrets integration tests run against their own database
// (gateway_secrets_test, created from GATEWAY_TEST_DATABASE_URL) so they
// never race the store package's TRUNCATE (quirk 01mepmn6).

const (
	secretsTestDB = "gateway_secrets_test"
	itAppPassword = "gateway-app-test"
	itJobsPass    = "gateway-jobs-test"
)

type pgWorld struct {
	st     *store.Store
	super  *pgx.Conn
	svc    *secrets.Service
	alice  string
	bob    string
	server string
}

func openWorld(t *testing.T) *pgWorld {
	t.Helper()
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
	if err := admin.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)`, secretsTestDB).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		if _, err := admin.Exec(ctx, `CREATE DATABASE `+secretsTestDB); err != nil {
			t.Fatalf("create database: %v", err)
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + secretsTestDB
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
	keys, err := crypto.NewStaticProvider("k1", map[string][]byte{"k1": bytes.Repeat([]byte{7}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := secrets.New(secrets.NewPostgresStore(st), keys, secrets.Options{})
	if err != nil {
		t.Fatal(err)
	}
	w := &pgWorld{st: st, super: super, svc: svc}
	for _, p := range []*string{&w.alice, &w.bob} {
		if err := super.QueryRow(ctx, `INSERT INTO users (display_name) VALUES ('it') RETURNING id::text`).Scan(p); err != nil {
			t.Fatal(err)
		}
	}
	if err := super.QueryRow(ctx, `INSERT INTO mcp_servers (name, url, owner_user_id) VALUES ('vault', 'https://vault.example.test/mcp', $1)
		RETURNING id::text`, w.alice).Scan(&w.server); err != nil {
		t.Fatal(err)
	}
	return w
}

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

func TestIntegrationSecretsServiceOverPostgres(t *testing.T) {
	w := openWorld(t)
	ctx := t.Context()
	b := secrets.Binding{ServerID: w.server, Tool: "vault.login", Arg: "password"}

	r, err := w.svc.Request(ctx, w.alice, harness, "vault password", b, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	// Bob cannot open, answer or use alice's request.
	if _, err := w.svc.LookupRequest(ctx, w.bob, r.RequestID); !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("bob lookup = %v", err)
	}
	if _, err := w.svc.Provide(ctx, w.bob, r.RequestID, []byte(value)); !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("bob provide = %v", err)
	}
	if st, err := w.svc.Status(ctx, w.bob, harness, r.Handle); err != nil || st.Status != secrets.StatusUnavailable {
		t.Errorf("bob status = %+v, %v", st, err)
	}
	if _, err := w.svc.Consume(ctx, w.alice, harness, r.Handle, b); !errors.Is(err, secrets.ErrPending) {
		t.Errorf("pending consume = %v", err)
	}
	if _, err := w.svc.Provide(ctx, w.alice, r.RequestID, []byte(value)); err != nil {
		t.Fatal(err)
	}
	var stored []byte
	if err := w.super.QueryRow(ctx, `SELECT value_ciphertext FROM secrets WHERE id = $1`, r.Secret.ID).Scan(&stored); err != nil ||
		bytes.Contains(stored, []byte(value)) {
		t.Fatalf("stored value = %v", err)
	}
	if _, err := w.svc.Consume(ctx, w.bob, harness, r.Handle, b); !errors.Is(err, secrets.ErrUnavailable) {
		t.Errorf("bob consume = %v", err)
	}

	// Exactly one of 10 concurrent consumers gets the one use.
	var wins, losses atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			c, err := w.svc.Consume(ctx, w.alice, harness, r.Handle, b)
			switch {
			case err == nil && string(c.Value) == value:
				wins.Add(1)
			case errors.Is(err, secrets.ErrUnavailable):
				losses.Add(1)
			default:
				t.Errorf("consume: %+v, %v", c, err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if wins.Load() != 1 || losses.Load() != 9 {
		t.Fatalf("wins %d, losses %d; want exactly one use", wins.Load(), losses.Load())
	}
	// Refund and use again; then the sweep wipes the used-up value.
	if err := w.svc.Refund(ctx, w.alice, r.Secret.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.Consume(ctx, w.alice, harness, r.Handle, b); err != nil {
		t.Fatalf("consume after refund: %v", err)
	}
	if res, err := w.svc.Expire(ctx); err != nil || res.Expired != 1 {
		t.Fatalf("expire = %+v, %v", res, err)
	}
	var state string
	var hasValue bool
	if err := w.super.QueryRow(ctx, `SELECT state, value_ciphertext IS NOT NULL FROM secrets WHERE id = $1`, r.Secret.ID).Scan(&state, &hasValue); err != nil ||
		state != secrets.StateExpired || hasValue {
		t.Fatalf("after expire: %s, value kept %v, %v", state, hasValue, err)
	}

	// The disable hook revokes inside the caller's jobs transaction.
	p, err := w.svc.Request(ctx, w.alice, harness, "second", b, 0, 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.Provide(ctx, w.alice, p.RequestID, []byte(value)); err != nil {
		t.Fatal(err)
	}
	if err := w.st.WithJobs(ctx, func(tx store.Tx) error { return w.svc.OnDisableUser(ctx, tx, w.alice) }); err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.Consume(ctx, w.alice, harness, p.Handle, b); !errors.Is(err, secrets.ErrUnavailable) {
		t.Fatalf("consume after disable = %v", err)
	}
	list, err := w.svc.List(ctx, w.alice)
	if err != nil || len(list) != 2 || list[0].State != secrets.StateRevoked || list[0].HasValue {
		t.Fatalf("list after disable = %+v, %v", list, err)
	}

	// Malformed ids are not found, not database errors.
	if _, err := w.svc.Revoke(ctx, w.alice, "not-a-uuid"); !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("revoke malformed = %v", err)
	}
	if err := w.svc.Refund(ctx, w.alice, "not-a-uuid"); !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("refund malformed = %v", err)
	}
}

func TestIntegrationSecretsRequestLimitHoldsUnderConcurrency(t *testing.T) {
	w := openWorld(t)
	ctx := t.Context()
	b := secrets.Binding{ServerID: w.server, Tool: "vault.login", Arg: "password"}
	var ok, limited atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := w.svc.Request(ctx, w.alice, harness, "x", b, 0, 1)
			switch {
			case err == nil:
				ok.Add(1)
			case errors.Is(err, secrets.ErrLimited):
				limited.Add(1)
			default:
				t.Errorf("request: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if ok.Load() != secrets.MaxPendingPerOwner || limited.Load() != 12-secrets.MaxPendingPerOwner {
		t.Fatalf("ok %d, limited %d; want %d pending at most", ok.Load(), limited.Load(), secrets.MaxPendingPerOwner)
	}
}
