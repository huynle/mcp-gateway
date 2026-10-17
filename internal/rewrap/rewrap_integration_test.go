//go:build integration

package rewrap_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/rewrap"
	"github.com/huynle/mcp-gateway/internal/store/migrations"
)

// The re-wrap integration tests run against their own database
// (gateway_rewrap_test, created from GATEWAY_TEST_DATABASE_URL) so they
// never race another package's TRUNCATE (quirk 01mepmn6).

const (
	rewrapTestDB = "gateway_rewrap_test"
	appPassword  = "gateway-app-test"
	jobsPassword = "gateway-jobs-test"
)

type pgEnv struct {
	super *pgx.Conn
	jobs  *pgxpool.Pool
	app   *pgxpool.Pool
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
	if err := admin.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)`, rewrapTestDB).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		if _, err := admin.Exec(ctx, `CREATE DATABASE `+rewrapTestDB); err != nil {
			t.Fatalf("create database: %v", err)
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + rewrapTestDB
	if err := migrations.Up(ctx, u.String()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	super, err := pgx.Connect(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close(context.Background()) })
	for _, stmt := range []string{
		"ALTER ROLE gateway_app LOGIN PASSWORD '" + appPassword + "'",
		"ALTER ROLE gateway_jobs LOGIN PASSWORD '" + jobsPassword + "'",
		"TRUNCATE users, vendor_apps, signing_keys, mcp_servers, policy_versions CASCADE",
	} {
		if err := execRetrying(ctx, super, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	appURL, jobsURL := *u, *u
	appURL.User = url.UserPassword("gateway_app", appPassword)
	jobsURL.User = url.UserPassword("gateway_jobs", jobsPassword)
	env := &pgEnv{super: super}
	if env.jobs, err = pgxpool.New(ctx, jobsURL.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(env.jobs.Close)
	if env.app, err = pgxpool.New(ctx, appURL.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(env.app.Close)
	return env
}

// execRetrying retries "tuple concurrently updated" (quirk aihn7hjb): every
// package's bootstrap ALTERs the same cluster-global roles.
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

// sealedRow is one seeded envelope with what is needed to open it again.
type sealedRow struct {
	col       rewrap.Column
	pk        string
	aad       crypto.AAD
	plaintext []byte
	env       crypto.Envelope
}

// seeder inserts rows with envelopes sealed under kp into every
// registered table.
type seeder struct {
	t    *testing.T
	conn *pgx.Conn
	kp   crypto.KeyProvider
	rows []sealedRow
	n    int
}

func (s *seeder) seal(col rewrap.Column, recordID string) crypto.Envelope {
	s.t.Helper()
	s.n++
	aad := crypto.AAD{Kind: col.Table, RecordID: recordID}
	plain := []byte(fmt.Sprintf("secret-%s-%d", col.Table, s.n))
	env, err := crypto.Encrypt(s.t.Context(), s.kp, aad, plain)
	if err != nil {
		s.t.Fatal(err)
	}
	s.rows = append(s.rows, sealedRow{col: col, pk: recordID, aad: aad, plaintext: plain, env: env})
	return env
}

func (s *seeder) one(sql string, args ...any) string {
	s.t.Helper()
	var id string
	if err := s.conn.QueryRow(s.t.Context(), sql, args...).Scan(&id); err != nil {
		s.t.Fatalf("%s: %v", sql, err)
	}
	return id
}

func (s *seeder) exec(sql string, args ...any) {
	s.t.Helper()
	if _, err := s.conn.Exec(s.t.Context(), sql, args...); err != nil {
		s.t.Fatalf("%s: %v", sql, err)
	}
}

func column(t *testing.T, table string) rewrap.Column {
	t.Helper()
	for _, c := range rewrap.Columns {
		if c.Table == table {
			return c
		}
	}
	t.Fatalf("no registry entry for %s", table)
	return rewrap.Column{}
}

// seedAll writes `copies` complete row graphs: every envelope table gets
// rows, plus approvals and OAuth clients without an envelope (NULL).
func seedAll(t *testing.T, env *pgEnv, kp crypto.KeyProvider, copies int) *seeder {
	t.Helper()
	s := &seeder{t: t, conn: env.super, kp: kp}
	for i := range copies {
		user := s.one(`INSERT INTO users (display_name) VALUES ('rewrap user') RETURNING id::text`)

		appID := s.one(`SELECT gen_random_uuid()::text`)
		e := s.seal(column(t, "vendor_apps"), appID)
		s.exec(`INSERT INTO vendor_apps (id, vendor, name, client_id, secret_key_id, secret_wrapped_key, secret_nonce, secret_ciphertext)
			VALUES ($1, 'github', $2, 'cid', $3, $4, $5, $6)`, appID, fmt.Sprintf("app-%d", i), e.KeyID, e.WrappedDataKey, e.Nonce, e.Ciphertext)

		conn := s.one(`INSERT INTO connections (user_id, vendor_app_id, external_account_id, label) VALUES ($1, $2, 'acct', 'company') RETURNING id::text`, user, appID)
		e = s.seal(column(t, "connection_secrets"), conn)
		s.exec(`INSERT INTO connection_secrets (connection_id, user_id, secret_key_id, secret_wrapped_key, secret_nonce, secret_ciphertext)
			VALUES ($1, $2, $3, $4, $5, $6)`, conn, user, e.KeyID, e.WrappedDataKey, e.Nonce, e.Ciphertext)

		pv := s.one(`INSERT INTO policy_versions (version_hash, cedar) VALUES ('h-' || gen_random_uuid(), '') RETURNING id::text`)
		approval := s.one(`SELECT gen_random_uuid()::text`)
		e = s.seal(column(t, "approvals"), approval)
		s.exec(`INSERT INTO approvals (id, user_id, connection_id, tool, digest, payload_key_id, payload_wrapped_key, payload_nonce, payload_ciphertext, policy_version_id, expires_at)
			VALUES ($1, $2, $3, 'fake.write', '\x00', $4, $5, $6, $7, $8, now() + interval '1 hour')`, approval, user, conn, e.KeyID, e.WrappedDataKey, e.Nonce, e.Ciphertext, pv)
		s.exec(`INSERT INTO approvals (user_id, connection_id, tool, digest, policy_version_id, expires_at, status)
			VALUES ($1, $2, 'fake.write', '\x01', $3, now(), 'denied')`, user, conn, pv)

		sk := s.one(`SELECT gen_random_uuid()::text`)
		e = s.seal(column(t, "signing_keys"), sk)
		s.exec(`INSERT INTO signing_keys (id, kid, algorithm, public_key, private_key_id, private_wrapped_key, private_nonce, private_ciphertext)
			VALUES ($1::uuid, 'kid-' || $1::text, 'ES256', '\x00', $2, $3, $4, $5)`, sk, e.KeyID, e.WrappedDataKey, e.Nonce, e.Ciphertext)

		server := s.one(`INSERT INTO mcp_servers (name, url, owner_user_id) VALUES ($1, 'https://mcp.example.test', $2) RETURNING id::text`, fmt.Sprintf("srv-%d", i), user)
		e = s.seal(column(t, "mcp_server_shared_secrets"), server)
		s.exec(`INSERT INTO mcp_server_shared_secrets (server_id, owner_user_id, secret_key_id, secret_wrapped_key, secret_nonce, secret_ciphertext)
			VALUES ($1, $2, $3, $4, $5, $6)`, server, user, e.KeyID, e.WrappedDataKey, e.Nonce, e.Ciphertext)
		uc := s.one(`SELECT gen_random_uuid()::text`)
		e = s.seal(column(t, "mcp_server_user_connections"), uc)
		s.exec(`INSERT INTO mcp_server_user_connections (id, server_id, user_id, secret_key_id, secret_wrapped_key, secret_nonce, secret_ciphertext)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`, uc, server, user, e.KeyID, e.WrappedDataKey, e.Nonce, e.Ciphertext)
		e = s.seal(column(t, "mcp_server_oauth_clients"), server)
		s.exec(`INSERT INTO mcp_server_oauth_clients (server_id, owner_user_id, method, client_id, secret_key_id, secret_wrapped_key, secret_nonce, secret_ciphertext)
			VALUES ($1, $2, 'static', 'cid', $3, $4, $5, $6)`, server, user, e.KeyID, e.WrappedDataKey, e.Nonce, e.Ciphertext)
		public := s.one(`INSERT INTO mcp_servers (name, url, owner_user_id) VALUES ($1, 'https://mcp2.example.test', $2) RETURNING id::text`, fmt.Sprintf("pub-%d", i), user)
		s.exec(`INSERT INTO mcp_server_oauth_clients (server_id, owner_user_id, method, client_id) VALUES ($1, $2, 'dcr', 'public')`, public, user)
	}
	return s
}

// load reads a seeded row's envelope back from the database.
func load(t *testing.T, conn *pgx.Conn, r sealedRow) crypto.Envelope {
	t.Helper()
	c := r.col
	var e crypto.Envelope
	q := fmt.Sprintf(`SELECT %[1]s_key_id, %[1]s_wrapped_key, %[1]s_nonce, %[1]s_ciphertext FROM %[2]s WHERE %[3]s = $1`, c.Prefix, c.Table, c.PK)
	if err := conn.QueryRow(t.Context(), q, r.pk).Scan(&e.KeyID, &e.WrappedDataKey, &e.Nonce, &e.Ciphertext); err != nil {
		t.Fatalf("load %s %s: %v", c.Table, r.pk, err)
	}
	return e
}

func keyFiles(t *testing.T) (oldOnly, both, newOnly *crypto.StaticProvider) {
	t.Helper()
	oldKey, newKey := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	var err error
	if oldOnly, err = crypto.NewStaticProvider("old", map[string][]byte{"old": oldKey}); err != nil {
		t.Fatal(err)
	}
	if both, err = crypto.NewStaticProvider("new", map[string][]byte{"old": oldKey, "new": newKey}); err != nil {
		t.Fatal(err)
	}
	if newOnly, err = crypto.NewStaticProvider("new", map[string][]byte{"new": newKey}); err != nil {
		t.Fatal(err)
	}
	return oldOnly, both, newOnly
}

func byTable(reports []rewrap.TableReport) map[string]rewrap.TableReport {
	out := map[string]rewrap.TableReport{}
	for _, r := range reports {
		out[r.Column.Table] = r
	}
	return out
}

func TestIntegrationRegistryMatchesSchema(t *testing.T) {
	env := openPGEnv(t)
	ctx := t.Context()
	rows, err := env.super.Query(ctx, `
		SELECT c.table_name, left(c.column_name, length(c.column_name) - length('_wrapped_key'))
		FROM information_schema.columns c
		JOIN information_schema.tables t USING (table_schema, table_name)
		WHERE c.table_schema = 'public' AND t.table_type = 'BASE TABLE' AND c.column_name LIKE '%\_wrapped\_key'`)
	if err != nil {
		t.Fatal(err)
	}
	inSchema := map[string]bool{}
	for rows.Next() {
		var table, prefix string
		if err := rows.Scan(&table, &prefix); err != nil {
			t.Fatal(err)
		}
		inSchema[table+"."+prefix] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for _, c := range rewrap.Columns {
		id := c.Table + "." + c.Prefix
		if !inSchema[id] {
			t.Errorf("registry entry %s has no %s column in the schema", id, c.WrappedKeyColumn())
		}
		delete(inSchema, id)
		// The PK must be the table's single-column uuid primary key: the
		// re-wrap pages and updates by it.
		var n int
		if err := env.super.QueryRow(ctx, `
			SELECT count(*) FROM pg_index i
			JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY (i.indkey)
			WHERE i.indrelid = $1::regclass AND i.indisprimary AND array_length(i.indkey, 1) = 1
			  AND a.attname = $2 AND a.atttypid = 'uuid'::regtype`, c.Table, c.PK).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Errorf("%s.%s is not the table's single-column uuid primary key", c.Table, c.PK)
		}
	}
	for id := range inSchema {
		t.Errorf("schema has envelope column group %s that rewrap.Columns does not list", id)
	}
}

func TestIntegrationRewrapMovesEveryEnvelopeAndIsIdempotent(t *testing.T) {
	env := openPGEnv(t)
	ctx := t.Context()
	oldOnly, both, newOnly := keyFiles(t)
	seeded := seedAll(t, env, oldOnly, 3)

	// Plan: counts per key ID, nothing changes.
	plan, err := rewrap.Plan(ctx, env.jobs, both)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan) != len(rewrap.Columns) {
		t.Fatalf("plan covers %d columns, want %d", len(plan), len(rewrap.Columns))
	}
	for _, r := range plan {
		if r.Envelopes != 3 || r.ByKeyID["old"] != 3 || r.Current != 0 {
			t.Errorf("plan %s = %+v; want 3 envelopes under old", r.Column.Table, r)
		}
	}
	for _, r := range seeded.rows {
		if got := load(t, env.super, r); got.KeyID != "old" {
			t.Fatalf("plan changed %s: key %q", r.col.Table, got.KeyID)
		}
	}

	// Run in batches of 2 so paging is exercised.
	reports, err := rewrap.Run(ctx, env.jobs, both, rewrap.Options{BatchSize: 2})
	if err != nil {
		t.Fatal(err)
	}
	for table, r := range byTable(reports) {
		if r.Rewrapped != 3 || r.Failed != 0 || r.Conflicts != 0 {
			t.Errorf("run %s = %+v; want 3 rewrapped", table, r)
		}
	}
	for _, r := range seeded.rows {
		got := load(t, env.super, r)
		if got.KeyID != "new" {
			t.Errorf("%s %s: key ID %q after rewrap", r.col.Table, r.pk, got.KeyID)
		}
		if !bytes.Equal(got.Nonce, r.env.Nonce) || !bytes.Equal(got.Ciphertext, r.env.Ciphertext) {
			t.Errorf("%s %s: rewrap touched nonce or ciphertext", r.col.Table, r.pk)
		}
		plain, err := crypto.Decrypt(ctx, newOnly, r.aad, got)
		if err != nil || !bytes.Equal(plain, r.plaintext) {
			t.Errorf("%s %s: decrypt with the new key only: %v", r.col.Table, r.pk, err)
		}
	}
	var nulls int
	if err := env.super.QueryRow(ctx, `SELECT (SELECT count(*) FROM approvals WHERE payload_key_id IS NULL) + (SELECT count(*) FROM mcp_server_oauth_clients WHERE secret_key_id IS NULL)`).Scan(&nulls); err != nil {
		t.Fatal(err)
	}
	if nulls != 6 {
		t.Errorf("rows without an envelope = %d, want 6 untouched", nulls)
	}

	// Idempotent: a second run finds nothing to do.
	again, err := rewrap.Run(ctx, env.jobs, both, rewrap.Options{BatchSize: 2})
	if err != nil {
		t.Fatal(err)
	}
	for table, r := range byTable(again) {
		if r.Rewrapped != 0 || r.Current != 3 {
			t.Errorf("second run %s = %+v; want 0 rewrapped, 3 current", table, r)
		}
	}

	// Verify: the post-cutover provider opens everything; the retired one
	// opens nothing and says so per table.
	ok, err := rewrap.Verify(ctx, env.jobs, newOnly)
	if err != nil {
		t.Fatalf("verify with the new key: %v", err)
	}
	for table, r := range byTable(ok) {
		if r.Envelopes != 3 || r.Current != 3 || r.Failed != 0 {
			t.Errorf("verify %s = %+v", table, r)
		}
	}
	bad, err := rewrap.Verify(ctx, env.jobs, oldOnly)
	if !errors.Is(err, rewrap.ErrVerifyFailed) {
		t.Fatalf("verify with the retired key: want ErrVerifyFailed, got %v", err)
	}
	for table, r := range byTable(bad) {
		if r.Failed != 3 {
			t.Errorf("verify with retired key %s = %+v; want 3 failed", table, r)
		}
	}
}

func TestIntegrationRewrapContinuesPastUnreadableEnvelope(t *testing.T) {
	env := openPGEnv(t)
	ctx := t.Context()
	oldOnly, both, _ := keyFiles(t)
	seeded := seedAll(t, env, oldOnly, 2)
	var victim sealedRow
	for _, r := range seeded.rows {
		if r.col.Table == "connection_secrets" {
			victim = r
			break
		}
	}
	if _, err := env.super.Exec(ctx, `UPDATE connection_secrets SET secret_key_id = 'retired' WHERE connection_id = $1`, victim.pk); err != nil {
		t.Fatal(err)
	}
	reports, err := rewrap.Run(ctx, env.jobs, both, rewrap.Options{BatchSize: 1})
	if !errors.Is(err, rewrap.ErrIncomplete) {
		t.Fatalf("want ErrIncomplete, got %v", err)
	}
	r := byTable(reports)["connection_secrets"]
	if r.Failed != 1 || r.Rewrapped != 1 {
		t.Errorf("connection_secrets = %+v; want 1 failed, 1 rewrapped", r)
	}
	if got := load(t, env.super, victim); got.KeyID != "retired" {
		t.Errorf("unreadable row changed: %q", got.KeyID)
	}
	if strings.Contains(err.Error(), string(victim.plaintext)) {
		t.Errorf("error leaks plaintext: %v", err)
	}
	for table, r := range byTable(reports) {
		if table != "connection_secrets" && r.Rewrapped != 2 {
			t.Errorf("%s = %+v; other tables must still be rewrapped", table, r)
		}
	}
}

func TestIntegrationRewrapDoesNotOverwriteConcurrentChange(t *testing.T) {
	env := openPGEnv(t)
	ctx := t.Context()
	oldOnly, both, _ := keyFiles(t)
	seeded := seedAll(t, env, oldOnly, 1)
	r := seeded.rows[0]
	fresh, err := crypto.Encrypt(ctx, both, r.aad, []byte("written by the gateway meanwhile"))
	if err != nil {
		t.Fatal(err)
	}
	// The gateway rewrote the row after the re-wrap read it: the stale
	// update must not apply.
	applied, err := rewrap.UpdateIfUnchanged(ctx, env.jobs, r.col, r.pk, r.env, crypto.Envelope{KeyID: "new", WrappedDataKey: []byte("stale")})
	if err != nil || !applied {
		t.Fatalf("unchanged row: applied=%v err=%v", applied, err)
	}
	c := r.col
	if _, err := env.super.Exec(ctx, fmt.Sprintf(`UPDATE %[1]s SET %[2]s_key_id = $1, %[2]s_wrapped_key = $2, %[2]s_nonce = $3, %[2]s_ciphertext = $4 WHERE %[3]s = $5`, c.Table, c.Prefix, c.PK),
		fresh.KeyID, fresh.WrappedDataKey, fresh.Nonce, fresh.Ciphertext, r.pk); err != nil {
		t.Fatal(err)
	}
	applied, err = rewrap.UpdateIfUnchanged(ctx, env.jobs, r.col, r.pk, r.env, crypto.Envelope{KeyID: "new", WrappedDataKey: []byte("stale")})
	if err != nil || applied {
		t.Fatalf("changed row: applied=%v err=%v; want not applied", applied, err)
	}
	if got := load(t, env.super, r); !bytes.Equal(got.WrappedDataKey, fresh.WrappedDataKey) {
		t.Error("concurrent write was overwritten")
	}
}

func TestIntegrationRewrapRefusesRoleSubjectToRLS(t *testing.T) {
	env := openPGEnv(t)
	ctx := t.Context()
	_, both, _ := keyFiles(t)
	if _, err := rewrap.Run(ctx, env.app, both, rewrap.Options{}); !errors.Is(err, rewrap.ErrRowLevelSecurity) {
		t.Errorf("Run as gateway_app: want ErrRowLevelSecurity, got %v", err)
	}
	if _, err := rewrap.Plan(ctx, env.app, both); !errors.Is(err, rewrap.ErrRowLevelSecurity) {
		t.Errorf("Plan as gateway_app: want ErrRowLevelSecurity, got %v", err)
	}
	if _, err := rewrap.Verify(ctx, env.app, both); !errors.Is(err, rewrap.ErrRowLevelSecurity) {
		t.Errorf("Verify as gateway_app: want ErrRowLevelSecurity, got %v", err)
	}
}
