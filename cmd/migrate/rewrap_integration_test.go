//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/huynle/mcp-gateway/internal/authserver"
	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/crypto/cryptotest"
	"github.com/huynle/mcp-gateway/internal/rewrap"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/store/migrations"
)

// The command's integration test runs against its own database
// (gateway_migrate_rewrap_test) so it never races another package's
// TRUNCATE (quirk 01mepmn6).
const (
	rewrapCmdTestDB = "gateway_migrate_rewrap_test"
	appPassword     = "gateway-app-test"
	jobsPassword    = "gateway-jobs-test"
)

type cmdEnv struct {
	superURL, appURL, jobsURL string
	super                     *pgx.Conn
	st                        *store.Store
}

func openCmdEnv(t *testing.T) *cmdEnv {
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
	if err := admin.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)`, rewrapCmdTestDB).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		if _, err := admin.Exec(ctx, `CREATE DATABASE `+rewrapCmdTestDB); err != nil {
			t.Fatalf("create database: %v", err)
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + rewrapCmdTestDB
	env := &cmdEnv{superURL: u.String()}
	if err := migrations.Up(ctx, env.superURL); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if env.super, err = pgx.Connect(ctx, env.superURL); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = env.super.Close(context.Background()) })
	for _, stmt := range []string{
		"ALTER ROLE gateway_app LOGIN PASSWORD '" + appPassword + "'",
		"ALTER ROLE gateway_jobs LOGIN PASSWORD '" + jobsPassword + "'",
		"TRUNCATE users, vendor_apps, signing_keys, mcp_servers, policy_versions, audit_events CASCADE",
	} {
		if err := execRetrying(ctx, env.super, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	appURL, jobsURL := *u, *u
	appURL.User = url.UserPassword("gateway_app", appPassword)
	jobsURL.User = url.UserPassword("gateway_jobs", jobsPassword)
	env.appURL, env.jobsURL = appURL.String(), jobsURL.String()
	if env.st, err = store.New(ctx, env.appURL, store.WithJobsURL(env.jobsURL)); err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(env.st.Close)
	return env
}

// execRetrying retries "tuple concurrently updated" (quirk aihn7hjb).
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

func (e *cmdEnv) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := e.super.Exec(t.Context(), sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func (e *cmdEnv) one(t *testing.T, sql string, args ...any) string {
	t.Helper()
	var s string
	if err := e.super.QueryRow(t.Context(), sql, args...).Scan(&s); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return s
}

func connectionsService(t *testing.T, st *store.Store, kp crypto.KeyProvider) *connections.Service {
	t.Helper()
	svc, err := connections.New(connections.Config{BaseURL: "http://gw.test"}, connections.NewPostgresStore(st), kp,
		connections.Options{Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func runCmd(t *testing.T, env map[string]string, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := run(args, envFrom(env), &out)
	return out.String(), err
}

// TestIntegrationRewrapFileToVault is the cutover drill: data written under
// the file provider is re-wrapped to Vault transit through the migrating
// provider, verified with the Vault-only configuration, and read back by
// the gateway's own services with nothing but Vault.
func TestIntegrationRewrapFileToVault(t *testing.T) {
	env := openCmdEnv(t)
	ctx := t.Context()

	// Before: the gateway runs with the file provider.
	keyFile := filepath.Join(t.TempDir(), "keys.json")
	if err := crypto.GenerateKeyFile(keyFile, "2026-01"); err != nil {
		t.Fatal(err)
	}
	fileKP, err := crypto.LoadKeyFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	alice := env.one(t, `INSERT INTO users (display_name) VALUES ('Alice') RETURNING id::text`)

	// Vendor app secret bundle and a connection with a token bundle,
	// through the connections service.
	fileConns := connectionsService(t, env.st, fileKP)
	conn, err := fileConns.SeedAccount(ctx, alice, connections.Seed{ExternalAccountID: "acct-1", Label: store.AccountCompany})
	if err != nil {
		t.Fatalf("SeedAccount: %v", err)
	}
	bundle, err := json.Marshal(map[string]any{"access_token": "tok-alice-secret", "token_type": "Bearer", "expiry": time.Now().Add(24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	tokEnv, err := crypto.Encrypt(ctx, fileKP, crypto.AAD{UserID: alice, Kind: "connection", RecordID: conn.ID, App: connections.VendorFake}, bundle)
	if err != nil {
		t.Fatal(err)
	}
	env.exec(t, `INSERT INTO connection_secrets (connection_id, user_id, secret_key_id, secret_wrapped_key, secret_nonce, secret_ciphertext)
		VALUES ($1, $2, $3, $4, $5, $6)`, conn.ID, alice, tokEnv.KeyID, tokEnv.WrappedDataKey, tokEnv.Nonce, tokEnv.Ciphertext)

	// The authorization server's signing key.
	fileKeys := authserver.NewKeys(authserver.NewPostgresStore(env.st), fileKP, authserver.KeysOptions{Log: slog.New(slog.DiscardHandler)})
	signing, err := fileKeys.Current(ctx)
	if err != nil {
		t.Fatalf("signing key: %v", err)
	}

	// An approval payload and the three federation secrets (direct rows).
	sealed := map[string]crypto.AAD{}
	seal := func(aad crypto.AAD) crypto.Envelope {
		e, err := crypto.Encrypt(ctx, fileKP, aad, []byte("payload-"+aad.Kind))
		if err != nil {
			t.Fatal(err)
		}
		sealed[aad.Kind+"/"+aad.RecordID] = aad
		return e
	}
	pv := env.one(t, `INSERT INTO policy_versions (version_hash, cedar) VALUES ('h-' || gen_random_uuid(), '') RETURNING id::text`)
	approval := env.one(t, `SELECT gen_random_uuid()::text`)
	e := seal(crypto.AAD{UserID: alice, Kind: "approvals", RecordID: approval})
	env.exec(t, `INSERT INTO approvals (id, user_id, connection_id, tool, digest, payload_key_id, payload_wrapped_key, payload_nonce, payload_ciphertext, policy_version_id, expires_at)
		VALUES ($1, $2, $3, 'fake.write', '\x00', $4, $5, $6, $7, $8, now() + interval '1 hour')`, approval, alice, conn.ID, e.KeyID, e.WrappedDataKey, e.Nonce, e.Ciphertext, pv)
	server := env.one(t, `INSERT INTO mcp_servers (name, url, owner_user_id) VALUES ('docs', 'https://mcp.example.test', $1) RETURNING id::text`, alice)
	e = seal(crypto.AAD{Kind: "mcp_server_shared_secrets", RecordID: server})
	env.exec(t, `INSERT INTO mcp_server_shared_secrets (server_id, owner_user_id, secret_key_id, secret_wrapped_key, secret_nonce, secret_ciphertext)
		VALUES ($1, $2, $3, $4, $5, $6)`, server, alice, e.KeyID, e.WrappedDataKey, e.Nonce, e.Ciphertext)
	e = seal(crypto.AAD{Kind: "mcp_server_user_connections", RecordID: server})
	env.exec(t, `INSERT INTO mcp_server_user_connections (server_id, user_id, secret_key_id, secret_wrapped_key, secret_nonce, secret_ciphertext)
		VALUES ($1, $2, $3, $4, $5, $6)`, server, alice, e.KeyID, e.WrappedDataKey, e.Nonce, e.Ciphertext)
	e = seal(crypto.AAD{Kind: "mcp_server_oauth_clients", RecordID: server})
	env.exec(t, `INSERT INTO mcp_server_oauth_clients (server_id, owner_user_id, method, client_id, secret_key_id, secret_wrapped_key, secret_nonce, secret_ciphertext)
		VALUES ($1, $2, 'static', 'cid', $3, $4, $5, $6)`, server, alice, e.KeyID, e.WrappedDataKey, e.Nonce, e.Ciphertext)
	// A provided ephemeral secret (internal/secrets).
	secret := env.one(t, `SELECT gen_random_uuid()::text`)
	e = seal(crypto.AAD{UserID: alice, Kind: "secrets", RecordID: secret})
	env.exec(t, `INSERT INTO secrets (id, owner_user_id, harness_id, label, server_id, tool, uses_total, uses_left, ttl_seconds,
			link_expires_at, expires_at, provided_at, request_hash, handle_hash, state,
			value_key_id, value_wrapped_key, value_nonce, value_ciphertext)
		VALUES ($1::uuid, $2, 'tok', 'sudo', $3, 'docs.run', 1, 1, 900, now() + interval '10 minutes', now() + interval '15 minutes', now(),
			sha256(('req-' || $1::text)::bytea), sha256(('sec-' || $1::text)::bytea), 'provided', $4, $5, $6, $7)`,
		secret, alice, server, e.KeyID, e.WrappedDataKey, e.Nonce, e.Ciphertext)

	// Every registered table now holds file-key envelopes only.
	countWhere := func(cond string) int {
		t.Helper()
		total := 0
		for _, c := range rewrap.Columns {
			var n int
			q := fmt.Sprintf(`SELECT count(*) FROM %s WHERE %s IS NOT NULL AND %s %s`, c.Table, c.KeyIDColumn(), c.KeyIDColumn(), cond)
			if err := env.super.QueryRow(ctx, q).Scan(&n); err != nil {
				t.Fatal(err)
			}
			if n == 0 && cond == "= '2026-01'" {
				t.Errorf("seed left %s without a file-key envelope", c.Table)
			}
			total += n
		}
		return total
	}
	if n := countWhere("= '2026-01'"); n != len(rewrap.Columns) {
		t.Fatalf("seeded %d file-key envelopes, want one per table (%d)", n, len(rewrap.Columns))
	}

	// Cutover: deploy with provider=migrate (file + OpenBao/Vault transit).
	fv, srv := cryptotest.NewFakeVault(t)
	migrateEnv := map[string]string{
		"GATEWAY_MIGRATE_DATABASE_URL": env.superURL,
		"GATEWAY_KEY_PROVIDER":         "migrate",
		"GATEWAY_KEY_FILE":             keyFile,
		"GATEWAY_VAULT_ADDR":           srv.URL,
		"GATEWAY_VAULT_TOKEN":          fv.Token(),
		"GATEWAY_VAULT_TRANSIT_KEY":    fv.KeyName(),
	}
	secrets := []string{"tok-alice-secret", "fake-placeholder", "payload-", "vault:v", fv.Token()}
	noSecrets := func(name, out string) {
		t.Helper()
		for _, s := range secrets {
			if strings.Contains(out, s) {
				t.Errorf("%s output leaks %q:\n%s", name, s, out)
			}
		}
	}

	// Dry run: reports, changes nothing.
	out, err := runCmd(t, migrateEnv, "rewrap", "--dry-run")
	if err != nil {
		t.Fatalf("dry run: %v\n%s", err, out)
	}
	noSecrets("dry run", out)
	for _, c := range rewrap.Columns {
		if !strings.Contains(out, c.Table) {
			t.Errorf("dry run does not report %s:\n%s", c.Table, out)
		}
	}
	if !strings.Contains(out, "2026-01=1") || !strings.Contains(out, "current key v1") {
		t.Errorf("dry run should show counts by key ID and the target key:\n%s", out)
	}
	if n := countWhere("= '2026-01'"); n != len(rewrap.Columns) {
		t.Fatalf("dry run changed rows: %d file-key envelopes left", n)
	}

	// Re-wrap, in batches of 2.
	out, err = runCmd(t, migrateEnv, "rewrap", "--batch", "2")
	if err != nil {
		t.Fatalf("rewrap: %v\n%s", err, out)
	}
	noSecrets("rewrap", out)
	if !strings.Contains(out, fmt.Sprintf("total: %d rewrapped", len(rewrap.Columns))) {
		t.Errorf("rewrap output:\n%s", out)
	}
	if n := countWhere(`!~ '^v[0-9]+$'`); n != 0 {
		t.Errorf("%d envelopes still under non-vault key IDs", n)
	}

	// Idempotent: nothing left to do.
	out, err = runCmd(t, migrateEnv, "rewrap")
	if err != nil || !strings.Contains(out, "total: 0 rewrapped") {
		t.Errorf("second rewrap: %v\n%s", err, out)
	}

	// Verify with the post-cutover configuration (vault only), as the jobs role.
	vaultEnv := maps.Clone(migrateEnv)
	delete(vaultEnv, "GATEWAY_MIGRATE_DATABASE_URL")
	delete(vaultEnv, "GATEWAY_KEY_FILE")
	vaultEnv["GATEWAY_JOBS_DATABASE_URL"] = env.jobsURL
	vaultEnv["GATEWAY_KEY_PROVIDER"] = "vault"
	out, err = runCmd(t, vaultEnv, "rewrap", "--verify")
	if err != nil {
		t.Fatalf("verify with vault only: %v\n%s", err, out)
	}
	noSecrets("verify", out)
	if !strings.Contains(out, "0 failed") {
		t.Errorf("verify output:\n%s", out)
	}

	// The retired file key alone can no longer open anything, and verify says so.
	fileEnv := map[string]string{"GATEWAY_JOBS_DATABASE_URL": env.jobsURL, "GATEWAY_KEY_PROVIDER": "file", "GATEWAY_KEY_FILE": keyFile}
	out, err = runCmd(t, fileEnv, "rewrap", "--verify")
	if !errors.Is(err, rewrap.ErrVerifyFailed) {
		t.Errorf("verify with the file key after cutover: want ErrVerifyFailed, got %v\n%s", err, out)
	}

	// The gateway, configured with Vault only, reads everything back.
	vaultKP, err := crypto.NewProviderFromEnv(envFrom(vaultEnv))
	if err != nil {
		t.Fatal(err)
	}
	vaultConns := connectionsService(t, env.st, vaultKP)
	tok, err := vaultConns.TokenSource(ctx, alice, conn.ID).Token()
	if err != nil || tok.AccessToken != "tok-alice-secret" {
		t.Errorf("connection token after cutover: %v (got %v)", err, tok != nil)
	}
	appSecrets, err := vaultConns.VendorSecrets(ctx, connections.VendorFake, "", connections.SecretClientSecret)
	if err != nil || appSecrets[connections.SecretClientSecret] != "fake-placeholder" {
		t.Errorf("vendor app secret after cutover: %v", err)
	}
	vaultKeys := authserver.NewKeys(authserver.NewPostgresStore(env.st), vaultKP, authserver.KeysOptions{Log: slog.New(slog.DiscardHandler)})
	got, err := vaultKeys.Current(ctx)
	if err != nil || got.KID != signing.KID || !got.Private.Equal(signing.Private) {
		t.Errorf("signing key after cutover: %v", err)
	}
	for _, c := range rewrap.Columns {
		if c.Table == "vendor_apps" || c.Table == "connection_secrets" || c.Table == "signing_keys" {
			continue
		}
		rows, err := env.super.Query(ctx, fmt.Sprintf(`SELECT %[1]s::text, %[2]s_key_id, %[2]s_wrapped_key, %[2]s_nonce, %[2]s_ciphertext FROM %[3]s WHERE %[2]s_key_id IS NOT NULL`, c.PK, c.Prefix, c.Table))
		if err != nil {
			t.Fatal(err)
		}
		type row struct {
			pk  string
			env crypto.Envelope
		}
		var list []row
		for rows.Next() {
			var r row
			if err := rows.Scan(&r.pk, &r.env.KeyID, &r.env.WrappedDataKey, &r.env.Nonce, &r.env.Ciphertext); err != nil {
				t.Fatal(err)
			}
			list = append(list, r)
		}
		rows.Close()
		for _, r := range list {
			recordID := r.pk
			if c.Table == "mcp_server_user_connections" {
				recordID = server
			}
			aad, ok := sealed[c.Table+"/"+recordID]
			if !ok {
				t.Fatalf("no AAD recorded for %s %s", c.Table, recordID)
			}
			plain, err := crypto.Decrypt(ctx, vaultKP, aad, r.env)
			if err != nil || string(plain) != "payload-"+c.Table {
				t.Errorf("%s after cutover: %v", c.Table, err)
			}
		}
	}
}
