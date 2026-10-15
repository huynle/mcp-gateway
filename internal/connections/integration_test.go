//go:build integration

package connections_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/store/migrations"
)

// The connections integration test runs against its own database
// (gateway_connections_test, created from GATEWAY_TEST_DATABASE_URL) so it
// never races the store package's TRUNCATE (quirk 01mepmn6). It needs a
// superuser URL and gives the two application roles a temporary LOGIN
// password (retrying "tuple concurrently updated", quirk aihn7hjb).

const (
	connTestDB  = "gateway_connections_test"
	appPassword = "gateway-app-test"
	jobsPass    = "gateway-jobs-test"
)

// pgEnv is the integration counterpart of testEnv: the service over the
// real store, plus a superuser connection for inspecting rows directly.
type pgEnv struct {
	st    *store.Store
	super *pgx.Conn
	svc   *connections.Service
	audit *audit.StoreRecorder
	logs  *bytes.Buffer
	alice string
	bob   string
}

func openPGEnv(t *testing.T) *pgEnv {
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
	if err := admin.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)`, connTestDB).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		if _, err := admin.Exec(ctx, `CREATE DATABASE `+connTestDB); err != nil {
			t.Fatalf("create database: %v", err)
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + connTestDB
	superURL := u.String()
	if err := migrations.Up(ctx, superURL); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	super, err := pgx.Connect(ctx, superURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close(context.Background()) })
	for _, stmt := range []string{
		"ALTER ROLE gateway_app LOGIN PASSWORD '" + appPassword + "'",
		"ALTER ROLE gateway_jobs LOGIN PASSWORD '" + jobsPass + "'",
		"TRUNCATE users, vendor_apps, connections, connection_secrets, connect_flows, audit_events CASCADE",
	} {
		if err := execRetryingConcurrentUpdate(ctx, super, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	appURL, jobsURL := *u, *u
	appURL.User = url.UserPassword("gateway_app", appPassword)
	jobsURL.User = url.UserPassword("gateway_jobs", jobsPass)
	st, err := store.New(ctx, appURL.String(), store.WithJobsURL(jobsURL.String()))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(st.Close)

	env := &pgEnv{st: st, super: super, logs: &bytes.Buffer{}}
	for name, id := range map[string]*string{"Alice": &env.alice, "Bob": &env.bob} {
		if err := st.WithJobs(ctx, func(tx store.Tx) error {
			u := &store.User{DisplayName: name}
			if err := tx.Users().Create(ctx, u); err != nil {
				return err
			}
			*id = u.ID
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	kp, err := crypto.NewStaticProvider("k1", map[string][]byte{"k1": bytes.Repeat([]byte{5}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	env.audit = audit.NewStoreRecorder(st)
	env.svc, err = connections.New(connections.Config{BaseURL: "http://gw.test"}, connections.NewPostgresStore(st), kp, connections.Options{
		Audit: env.audit, Log: slog.New(slog.NewTextHandler(env.logs, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	env.svc.SetToolCatalog(testCatalog(t), nil)
	return env
}

// execRetryingConcurrentUpdate runs stmt, retrying when PostgreSQL reports
// "tuple concurrently updated" (SQLSTATE XX000): every package's
// integration bootstrap ALTERs the same cluster-global roles and `go test`
// runs packages in parallel.
func execRetryingConcurrentUpdate(ctx context.Context, conn *pgx.Conn, stmt string) error {
	var err error
	for attempt := 0; attempt < 20; attempt++ {
		if _, err = conn.Exec(ctx, stmt); err == nil || !strings.Contains(err.Error(), "concurrently updated") {
			return err
		}
		time.Sleep(100 * time.Millisecond)
	}
	return err
}

// pgConnect is connect() over the integration environment.
func pgConnect(t *testing.T, env *pgEnv, v *fakeVendor, userID, account string, scopes ...string) (connections.Info, error) {
	t.Helper()
	te := &testEnv{svc: env.svc, logs: env.logs}
	_ = v
	return connect(t, te, userID, account, scopes...)
}

func TestIntegrationConnectRefreshRaceInvalidGrantDisconnect(t *testing.T) {
	env := openPGEnv(t)
	v := newFakeVendor(t)
	ctx := t.Context()
	app, err := env.svc.SaveVendorApp(ctx, env.alice, connections.VendorApp{
		Vendor: connections.VendorFake, ClientID: v.clientID, ClientSecret: v.secret,
		AuthURL: v.URL() + "/authorize", TokenURL: v.URL() + "/token", UserInfoURL: v.URL() + "/userinfo", RevokeURL: v.URL() + "/revoke",
		Scopes: []string{"read:user"}, Extra: map[string]string{connections.ExtraCompanyDomains: "acme.test", connections.ExtraNameField: "login"}, Enabled: true,
	})
	if err != nil {
		t.Fatalf("SaveVendorApp: %v", err)
	}

	// Connect: company label, encrypted bundle, audit row.
	info, err := pgConnect(t, env, v, env.alice, "acct-company", "repo")
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if info.Label != "company" || info.Status != store.ConnectionActive || strings.Join(info.Scopes, " ") != "read:user repo" {
		t.Fatalf("info = %+v", info)
	}
	bobConn, err := pgConnect(t, env, v, env.bob, "acct-personal")
	if err != nil {
		t.Fatalf("bob connect: %v", err)
	}
	if bobConn.Label != "personal" {
		t.Fatalf("bob = %+v", bobConn)
	}

	// No plaintext anywhere: every issued token and the client secret are
	// absent from every bytea/text column of the three tables and the logs.
	assertNoPlaintext := func() {
		t.Helper()
		var dump string
		if err := env.super.QueryRow(ctx, `
			SELECT string_agg(x, '|') FROM (
				SELECT encode(secret_ciphertext, 'escape') || client_id || config::text || encode(secret_wrapped_key, 'escape') FROM vendor_apps
				UNION ALL
				SELECT encode(secret_ciphertext, 'escape') || encode(secret_wrapped_key, 'escape') || encode(secret_nonce, 'escape') FROM connection_secrets
				UNION ALL
				SELECT row_to_json(c)::text FROM connections c
				UNION ALL
				SELECT row_to_json(f)::text FROM connect_flows f
			) t(x)`).Scan(&dump); err != nil {
			t.Fatal(err)
		}
		for _, raw := range append(v.allTokens(), v.secret) {
			if strings.Contains(dump, raw) {
				t.Fatalf("plaintext %q found in the database", raw)
			}
			if strings.Contains(env.logs.String(), raw) {
				t.Fatalf("plaintext %q found in the logs", raw)
			}
		}
	}
	assertNoPlaintext()

	// RLS: bob's scope sees none of alice's rows, and the account source
	// lists only the caller's own connections.
	var n int
	if err := env.st.WithUser(ctx, env.bob, func(tx store.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM connection_secrets WHERE connection_id = $1`, info.ID).Scan(&n)
	}); err != nil || n != 0 {
		t.Fatalf("bob sees alice's secret: %d, %v", n, err)
	}
	if _, err := env.svc.TokenSource(ctx, env.bob, info.ID).Token(); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("bob token err = %v", err)
	}
	accts, err := env.svc.ListAccounts(ctx, env.alice, "fake")
	if err != nil || len(accts) != 1 || accts[0].ID != info.ID || accts[0].Label != "company" {
		t.Fatalf("alice accounts = %+v, %v", accts, err)
	}
	if accts, _ := env.svc.ListAccounts(ctx, env.bob, "fake"); len(accts) != 1 || accts[0].ID != bobConn.ID {
		t.Fatalf("bob accounts = %+v", accts)
	}

	// Refresh race on real PostgreSQL: SELECT ... FOR UPDATE serialises the
	// refresh, so 8 concurrent callers make one vendor call and share the
	// new token.
	env.svc.SetClock(func() time.Time { return time.Now().Add(2 * time.Hour) })
	v.refreshDelay = 100 * time.Millisecond
	var wg sync.WaitGroup
	results := make([]string, 8)
	errs := make([]error, 8)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tok, err := env.svc.TokenSource(ctx, env.alice, info.ID).Token()
			if err == nil {
				results[i] = tok.AccessToken
			}
			errs[i] = err
		}(i)
	}
	wg.Wait()
	for i := range results {
		if errs[i] != nil || results[i] != results[0] {
			t.Fatalf("caller %d: %q, %v (first %q)", i, results[i], errs[i], results[0])
		}
	}
	if n := v.refreshCalls.Load(); n != 1 {
		t.Fatalf("refresh calls = %d, want 1", n)
	}
	// The rotated refresh token was persisted (the vendor killed the old one).
	env.svc.SetClock(func() time.Time { return time.Now().Add(4 * time.Hour) })
	if _, err := env.svc.TokenSource(ctx, env.alice, info.ID).Token(); err != nil {
		t.Fatalf("second refresh: %v", err)
	}
	if n := v.refreshCalls.Load(); n != 2 {
		t.Fatalf("refresh calls = %d, want 2", n)
	}
	assertNoPlaintext()

	// AAD tamper: the same ciphertext under another connection id (bob's
	// row) does not decrypt; neither does a flipped byte.
	if _, err := env.super.Exec(ctx, `
		UPDATE connection_secrets b SET secret_key_id = a.secret_key_id, secret_wrapped_key = a.secret_wrapped_key,
			secret_nonce = a.secret_nonce, secret_ciphertext = a.secret_ciphertext
		FROM connection_secrets a WHERE a.connection_id = $1 AND b.connection_id = $2`, info.ID, bobConn.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := env.svc.TokenSource(ctx, env.bob, bobConn.ID).Token(); err == nil || !errors.Is(err, crypto.ErrDecrypt) {
		t.Fatalf("moved ciphertext err = %v, want ErrDecrypt", err)
	}
	if _, err := env.super.Exec(ctx, `UPDATE connection_secrets SET secret_ciphertext = set_byte(secret_ciphertext, 0, (get_byte(secret_ciphertext, 0) # 255)) WHERE connection_id = $1`, bobConn.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := env.svc.TokenSource(ctx, env.bob, bobConn.ID).Token(); !errors.Is(err, crypto.ErrDecrypt) {
		t.Fatalf("flipped byte err = %v, want ErrDecrypt", err)
	}

	// invalid_grant marks needs_reconnect and the account disappears from
	// the source; reconnecting revives it.
	v.invalidGrant.Store(true)
	env.svc.SetClock(func() time.Time { return time.Now().Add(6 * time.Hour) })
	if _, err := env.svc.TokenSource(ctx, env.alice, info.ID).Token(); !errors.Is(err, connections.ErrNeedsReconnect) {
		t.Fatalf("invalid_grant err = %v", err)
	}
	var status string
	if err := env.super.QueryRow(ctx, `SELECT status FROM connections WHERE id = $1`, info.ID).Scan(&status); err != nil || status != store.ConnectionNeedsReconnect {
		t.Fatalf("status = %s, %v", status, err)
	}
	if accts, _ := env.svc.ListAccounts(ctx, env.alice, "fake"); len(accts) != 0 {
		t.Fatalf("needs_reconnect account still listed: %+v", accts)
	}
	v.invalidGrant.Store(false)
	again, err := pgConnect(t, env, v, env.alice, "acct-company")
	if err != nil || again.ID != info.ID || again.Status != store.ConnectionActive {
		t.Fatalf("reconnect = %+v, %v", again, err)
	}

	// Disconnect: the secret row is gone, the connection row is revoked,
	// the audit rows (connected x2, disconnected) remain.
	if err := env.svc.Disconnect(ctx, env.alice, info.ID); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	if err := env.super.QueryRow(ctx, `SELECT count(*) FROM connection_secrets WHERE connection_id = $1`, info.ID).Scan(&n); err != nil || n != 0 {
		t.Fatalf("secret rows after disconnect = %d, %v", n, err)
	}
	if err := env.super.QueryRow(ctx, `SELECT status FROM connections WHERE id = $1`, info.ID).Scan(&status); err != nil || status != store.ConnectionRevoked {
		t.Fatalf("status after disconnect = %s, %v", status, err)
	}
	if revoked := v.revokedTokens(); len(revoked) != 1 {
		t.Fatalf("revoked at vendor = %v", revoked)
	}
	events, err := env.audit.ListForUser(ctx, env.alice, audit.Filter{}, audit.Page{})
	if err != nil {
		t.Fatal(err)
	}
	actions := map[string]int{}
	for _, ev := range events {
		actions[ev.ResourceIdentity["action"]]++
		if ev.ResourceIdentity["action"] == "disconnected" && ev.AccountID != info.ID {
			t.Fatalf("disconnect audit = %+v", ev)
		}
	}
	if actions["connected"] != 2 || actions["disconnected"] != 1 || actions["vendor_app_saved"] != 1 {
		t.Fatalf("audit actions = %v", actions)
	}
	if bobEvents, _ := env.audit.ListForUser(ctx, env.bob, audit.Filter{}, audit.Page{}); len(bobEvents) != 1 {
		t.Fatalf("bob sees %d events", len(bobEvents))
	}
	_ = app
}

func TestIntegrationFlowsAreUserScopedAndKeepAliveRefreshes(t *testing.T) {
	env := openPGEnv(t)
	v := newFakeVendor(t)
	ctx := t.Context()
	if _, err := env.svc.SaveVendorApp(ctx, env.alice, connections.VendorApp{
		Vendor: connections.VendorFake, ClientID: v.clientID, ClientSecret: v.secret,
		AuthURL: v.URL() + "/authorize", TokenURL: v.URL() + "/token", UserInfoURL: v.URL() + "/userinfo",
		Extra: map[string]string{connections.ExtraCompanyDomains: "acme.test"}, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	// A flow alice started is invisible to bob (RLS on connect_flows), and
	// bob's callback cannot consume it.
	redirect, err := env.svc.Start(ctx, connections.StartRequest{UserID: env.alice, Vendor: "fake"})
	if err != nil {
		t.Fatal(err)
	}
	state := mustQuery(t, redirect).Get("state")
	var n int
	if err := env.st.WithUser(ctx, env.bob, func(tx store.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM connect_flows`).Scan(&n)
	}); err != nil || n != 0 {
		t.Fatalf("bob sees %d flows, %v", n, err)
	}
	if _, err := env.svc.Callback(ctx, connections.CallbackRequest{UserID: env.bob, Vendor: "fake", State: state, Code: "x"}); !errors.Is(err, connections.ErrFlowInvalid) {
		t.Fatalf("bob callback err = %v", err)
	}
	if err := env.super.QueryRow(ctx, `SELECT count(*) FROM connect_flows WHERE state = $1`, state).Scan(&n); err != nil || n != 1 {
		t.Fatalf("alice's flow consumed by bob: %d, %v", n, err)
	}
	// A replayed state is refused once consumed.
	code := v.issueCode("acct-company", "", "http://gw.test/connect/fake/callback")
	if _, err := env.svc.Callback(ctx, connections.CallbackRequest{UserID: env.alice, Vendor: "fake", State: state, Code: code}); !errors.Is(err, connections.ErrFlowInvalid) {
		// The fake vendor enforces PKCE only when a challenge was recorded;
		// an empty challenge means the exchange succeeds. Either way the
		// state is consumed below.
		_ = err
	}
	if _, err := env.svc.Callback(ctx, connections.CallbackRequest{UserID: env.alice, Vendor: "fake", State: state, Code: "x"}); !errors.Is(err, connections.ErrFlowInvalid) {
		t.Fatalf("replay err = %v", err)
	}

	// Keep-alive refreshes only connections idle for 30 days.
	stale, err := pgConnect(t, env, v, env.alice, "acct-company")
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := pgConnect(t, env, v, env.bob, "acct-personal")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.super.Exec(ctx, `UPDATE connections SET last_refreshed_at = now() - interval '31 days' WHERE id = $1`, stale.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := env.super.Exec(ctx, `UPDATE connect_flows SET expires_at = now() - interval '1 hour'`); err != nil {
		t.Fatal(err)
	}
	if _, err := env.svc.Start(ctx, connections.StartRequest{UserID: env.alice, Vendor: "fake"}); err != nil {
		t.Fatal(err)
	}
	if _, err := env.super.Exec(ctx, `UPDATE connect_flows SET expires_at = now() - interval '1 hour'`); err != nil {
		t.Fatal(err)
	}
	before := v.refreshCalls.Load()
	if err := env.svc.KeepAliveJob().Run(ctx); err != nil {
		t.Fatalf("keep-alive: %v", err)
	}
	if n := v.refreshCalls.Load() - before; n != 1 {
		t.Fatalf("keep-alive refreshes = %d, want 1", n)
	}
	var last time.Time
	if err := env.super.QueryRow(ctx, `SELECT last_refreshed_at FROM connections WHERE id = $1`, stale.ID).Scan(&last); err != nil || time.Since(last) > time.Minute {
		t.Fatalf("stale not refreshed: %v, %v", last, err)
	}
	if err := env.super.QueryRow(ctx, `SELECT count(*) FROM connect_flows`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("expired flows left = %d, %v", n, err)
	}
	_ = fresh

	// Disable hook inside the bypass scope: both of alice's... (she has
	// one) secrets go, bob's stays.
	if err := env.st.WithJobs(ctx, func(tx store.Tx) error { return env.svc.DisableHook()(ctx, tx, env.alice) }); err != nil {
		t.Fatalf("disable hook: %v", err)
	}
	if err := env.super.QueryRow(ctx, `SELECT count(*) FROM connection_secrets`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("secrets after disable = %d, %v", n, err)
	}
	var status string
	if err := env.super.QueryRow(ctx, `SELECT status FROM connections WHERE id = $1`, stale.ID).Scan(&status); err != nil || status != store.ConnectionRevoked {
		t.Fatalf("alice status after disable = %s, %v", status, err)
	}
}
