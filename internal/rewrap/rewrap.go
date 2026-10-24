// Package rewrap moves every stored envelope to the key provider's current
// root key. It is the re-wrap job that root key rotation and the move from
// the file provider to Vault / OpenBao need (docs/crypto.md): data keys are
// unwrapped under the key ID recorded in the row and wrapped again under the
// current key; nonce and ciphertext never change and no plaintext is
// touched, so no AAD is needed.
//
// Columns is the registry of every envelope-encrypted column group in the
// schema. Tests compare it with the migrations and with the live schema, so
// a new encrypted column cannot be forgotten.
//
// All entry points refuse a database role that is subject to row-level
// security: under FORCE ROW LEVEL SECURITY such a role would silently see
// no user-scoped rows and report a job "done" that never ran. Use the owner
// (migrate) or the gateway_jobs role. Reports carry counts and key IDs only,
// never key material, wrapped keys or plaintext.
package rewrap

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/huynle/mcp-gateway/internal/crypto"
)

// Column is one envelope column group: <Prefix>_key_id, <Prefix>_wrapped_key,
// <Prefix>_nonce and <Prefix>_ciphertext in Table, whose single-column uuid
// primary key is PK. Nullable groups are NULL when the row holds no secret
// (consumed approvals, public OAuth clients); those rows are skipped.
type Column struct {
	Table    string
	PK       string
	Prefix   string
	Nullable bool
}

// KeyIDColumn is the column naming the root key that wraps the data key.
func (c Column) KeyIDColumn() string { return c.Prefix + "_key_id" }

// WrappedKeyColumn is the column holding the wrapped data key.
func (c Column) WrappedKeyColumn() string { return c.Prefix + "_wrapped_key" }

// Columns lists every envelope-encrypted column group (migrations 00004,
// 00005, 00006, 00014, 00031, 00033). Keep it in sync with the schema; the
// registry tests fail otherwise.
var Columns = []Column{
	{Table: "vendor_apps", PK: "id", Prefix: "secret"},                                     // vendor app client secret bundles
	{Table: "connection_secrets", PK: "connection_id", Prefix: "secret"},                   // app connection token bundles
	{Table: "approvals", PK: "id", Prefix: "payload", Nullable: true},                      // pending/approved call arguments
	{Table: "signing_keys", PK: "id", Prefix: "private"},                                   // OAuth signing private keys
	{Table: "mcp_server_shared_secrets", PK: "server_id", Prefix: "secret"},                // federation shared credentials
	{Table: "mcp_server_user_connections", PK: "id", Prefix: "secret"},                     // federation per-user credentials
	{Table: "mcp_server_oauth_clients", PK: "server_id", Prefix: "secret", Nullable: true}, // federation OAuth client secrets
	{Table: "secrets", PK: "id", Prefix: "value", Nullable: true},                          // ephemeral secret values (provided rows)
	{Table: "webpush_keys", PK: "id", Prefix: "private"},                                   // Web Push VAPID private key
	{Table: "push_subscriptions", PK: "id", Prefix: "sub"},                                 // Web Push subscriptions (endpoint + keys)
}

var (
	// ErrRowLevelSecurity means the connected role neither is a superuser
	// nor has BYPASSRLS, so user-scoped rows would be invisible.
	ErrRowLevelSecurity = errors.New("rewrap: database role is subject to row-level security; connect as the owner/superuser or gateway_jobs")
	// ErrIncomplete means Run left envelopes it could not unwrap (unknown
	// key ID, corrupt blob); see the per-table Failed counts.
	ErrIncomplete = errors.New("rewrap: some envelopes could not be re-wrapped")
	// ErrVerifyFailed means Verify found envelopes the provider cannot
	// unwrap; see the per-table Failed counts.
	ErrVerifyFailed = errors.New("rewrap: some envelopes cannot be unwrapped")
)

// DB is what the re-wrap needs from a connection or pool (*pgx.Conn and
// *pgxpool.Pool satisfy it).
type DB interface {
	Execer
	Begin(ctx context.Context) (pgx.Tx, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Execer runs a statement; pgx.Tx, *pgx.Conn and *pgxpool.Pool satisfy it.
type Execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// DefaultBatchSize is the number of rows re-wrapped per transaction.
const DefaultBatchSize = 100

// Options tunes Run.
type Options struct {
	// BatchSize is the number of rows per transaction; DefaultBatchSize
	// when zero or negative.
	BatchSize int
}

// TableReport summarizes one column group. Plan fills Envelopes, Current
// and ByKeyID; Run fills Envelopes, Current (already current before the
// run), Rewrapped, Conflicts and Failed; Verify fills Envelopes, Current,
// Failed and FailedByKeyID.
type TableReport struct {
	Column Column
	// Envelopes counts rows holding an envelope (NULL groups excluded).
	Envelopes int
	// Current counts envelopes under the provider's current key.
	Current int
	// ByKeyID counts envelopes per root key ID.
	ByKeyID map[string]int
	// Rewrapped counts envelopes moved to the current key.
	Rewrapped int
	// Conflicts counts rows changed by someone else between read and
	// update; they were left alone and a later run picks them up.
	Conflicts int
	// Failed counts envelopes whose data key could not be unwrapped.
	Failed int
	// FailedByKeyID counts Verify failures per root key ID.
	FailedByKeyID map[string]int
}

// RequireBypassRLS fails with ErrRowLevelSecurity unless the connected role
// sees every row.
func RequireBypassRLS(ctx context.Context, db DB) error {
	var ok bool
	if err := db.QueryRow(ctx, `SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&ok); err != nil {
		return fmt.Errorf("rewrap: check database role: %w", err)
	}
	if !ok {
		return ErrRowLevelSecurity
	}
	return nil
}

// Plan counts envelopes per table and key ID without changing anything
// (the dry run).
func Plan(ctx context.Context, db DB, p crypto.KeyProvider) ([]TableReport, error) {
	if err := RequireBypassRLS(ctx, db); err != nil {
		return nil, err
	}
	current, err := p.CurrentKeyID(ctx)
	if err != nil {
		return nil, fmt.Errorf("rewrap: current key ID: %w", err)
	}
	reports := make([]TableReport, 0, len(Columns))
	for _, c := range Columns {
		r, err := countByKeyID(ctx, db, c, current)
		if err != nil {
			return reports, err
		}
		reports = append(reports, r)
	}
	return reports, nil
}

func countByKeyID(ctx context.Context, db DB, c Column, current string) (TableReport, error) {
	r := TableReport{Column: c, ByKeyID: map[string]int{}}
	keyCol := pgx.Identifier{c.KeyIDColumn()}.Sanitize()
	q := fmt.Sprintf(`SELECT %[1]s, count(*) FROM %[2]s WHERE %[1]s IS NOT NULL GROUP BY 1`, keyCol, pgx.Identifier{c.Table}.Sanitize())
	rows, err := db.Query(ctx, q)
	if err != nil {
		return r, fmt.Errorf("rewrap: count %s: %w", c.Table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return r, fmt.Errorf("rewrap: count %s: %w", c.Table, err)
		}
		r.ByKeyID[id] = n
		r.Envelopes += n
		if id == current {
			r.Current += n
		}
	}
	if err := rows.Err(); err != nil {
		return r, fmt.Errorf("rewrap: count %s: %w", c.Table, err)
	}
	return r, nil
}

// Run re-wraps every envelope not under the provider's current key, table
// by table in batches of opts.BatchSize rows, each batch in its own
// transaction. It is idempotent and resumable: rows already current are
// skipped, so an interrupted run is simply started again. Rows changed
// concurrently are left for the next run (Conflicts). Envelopes that cannot
// be unwrapped (unknown key ID, corrupt blob) are counted as Failed and the
// run continues; it then returns ErrIncomplete with the reports. Any other
// error (database, provider unavailable) stops the run.
func Run(ctx context.Context, db DB, p crypto.KeyProvider, opts Options) ([]TableReport, error) {
	if err := RequireBypassRLS(ctx, db); err != nil {
		return nil, err
	}
	batch := opts.BatchSize
	if batch <= 0 {
		batch = DefaultBatchSize
	}
	current, err := p.CurrentKeyID(ctx)
	if err != nil {
		return nil, fmt.Errorf("rewrap: current key ID: %w", err)
	}
	reports := make([]TableReport, 0, len(Columns))
	incomplete := false
	for _, c := range Columns {
		r, err := countByKeyID(ctx, db, c, current)
		if err != nil {
			return reports, err
		}
		r.ByKeyID = nil
		err = rewrapColumn(ctx, db, p, c, current, batch, &r)
		reports = append(reports, r)
		if err != nil {
			return reports, err
		}
		incomplete = incomplete || r.Failed > 0
	}
	if incomplete {
		return reports, ErrIncomplete
	}
	return reports, nil
}

// pending is one row whose envelope is not under the current key.
type pending struct {
	pk  string
	env crypto.Envelope
}

func rewrapColumn(ctx context.Context, db DB, p crypto.KeyProvider, c Column, current string, batch int, r *TableReport) error {
	var after *string
	for {
		rows, err := pendingBatch(ctx, db, c, current, after, batch)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			return nil
		}
		last := rows[len(rows)-1].pk
		after = &last
		if err := rewrapBatch(ctx, db, p, c, rows, r); err != nil {
			return err
		}
	}
}

// pendingBatch reads the next page (by primary key) of envelopes whose key
// ID is not current. Only key ID and wrapped key are needed.
func pendingBatch(ctx context.Context, db DB, c Column, current string, after *string, limit int) ([]pending, error) {
	keyCol, wrapCol, pk := pgx.Identifier{c.KeyIDColumn()}.Sanitize(), pgx.Identifier{c.WrappedKeyColumn()}.Sanitize(), pgx.Identifier{c.PK}.Sanitize()
	q := fmt.Sprintf(`SELECT %[3]s::text, %[1]s, %[2]s FROM %[4]s
		WHERE %[1]s IS NOT NULL AND %[1]s <> $1 AND ($2::uuid IS NULL OR %[3]s > $2::uuid)
		ORDER BY %[3]s LIMIT $3`, keyCol, wrapCol, pk, pgx.Identifier{c.Table}.Sanitize())
	rows, err := db.Query(ctx, q, current, after, limit)
	if err != nil {
		return nil, fmt.Errorf("rewrap: read %s: %w", c.Table, err)
	}
	defer rows.Close()
	var out []pending
	for rows.Next() {
		var row pending
		if err := rows.Scan(&row.pk, &row.env.KeyID, &row.env.WrappedDataKey); err != nil {
			return nil, fmt.Errorf("rewrap: read %s: %w", c.Table, err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rewrap: read %s: %w", c.Table, err)
	}
	return out, nil
}

// rewrapBatch re-wraps rows in one transaction through crypto.RewrapEach.
// A per-envelope unwrap failure is counted and skipped; anything else rolls
// the batch back.
func rewrapBatch(ctx context.Context, db DB, p crypto.KeyProvider, c Column, rows []pending, r *TableReport) (err error) {
	tx, err := db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("rewrap: %s: begin: %w", c.Table, err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback(ctx)
		}
	}()
	envs := make([]crypto.Envelope, len(rows))
	for i, row := range rows {
		envs[i] = row.env
	}
	var rewrapped, conflicts int
	for offset := 0; offset < len(envs); {
		stats, rerr := crypto.RewrapEach(ctx, p, envs[offset:], func(ctx context.Context, i int, updated crypto.Envelope) error {
			row := rows[offset+i]
			applied, err := UpdateIfUnchanged(ctx, tx, c, row.pk, row.env, updated)
			if err != nil {
				return err
			}
			if applied {
				rewrapped++
			} else {
				conflicts++
			}
			return nil
		})
		if rerr == nil {
			break
		}
		if stats.Scanned == 0 || !unreadable(rerr) {
			return fmt.Errorf("rewrap: %s: %w", c.Table, rerr)
		}
		r.Failed++
		offset += stats.Scanned
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("rewrap: %s: commit: %w", c.Table, err)
	}
	r.Rewrapped += rewrapped
	r.Conflicts += conflicts
	return nil
}

// unreadable reports whether err concerns one envelope (its key ID or blob)
// rather than the provider or the database.
func unreadable(err error) bool {
	return errors.Is(err, crypto.ErrUnknownKeyID) || errors.Is(err, crypto.ErrDecrypt) || errors.Is(err, crypto.ErrInvalidDataKey)
}

// UpdateIfUnchanged stores updated's key ID and wrapped key for the row pk
// of c, but only while the row still holds old's key ID and wrapped key (an
// optimistic compare-and-swap, so a secret the gateway rewrote meanwhile is
// never overwritten with a stale data key). It reports whether the row was
// updated.
func UpdateIfUnchanged(ctx context.Context, db Execer, c Column, pk string, old, updated crypto.Envelope) (bool, error) {
	keyCol, wrapCol := pgx.Identifier{c.KeyIDColumn()}.Sanitize(), pgx.Identifier{c.WrappedKeyColumn()}.Sanitize()
	q := fmt.Sprintf(`UPDATE %[3]s SET %[1]s = $1, %[2]s = $2 WHERE %[4]s = $3::uuid AND %[1]s = $4 AND %[2]s = $5`,
		keyCol, wrapCol, pgx.Identifier{c.Table}.Sanitize(), pgx.Identifier{c.PK}.Sanitize())
	tag, err := db.Exec(ctx, q, updated.KeyID, updated.WrappedDataKey, pk, old.KeyID, old.WrappedDataKey)
	if err != nil {
		return false, fmt.Errorf("rewrap: update %s: %w", c.Table, err)
	}
	return tag.RowsAffected() == 1, nil
}

// verifyBatchSize is the page size Verify reads.
const verifyBatchSize = 500

// Verify unwraps every envelope's data key with p (and wipes it) and
// counts failures per table and key ID. It returns ErrVerifyFailed when any
// envelope fails. Run it with the configuration you are about to switch to
// (e.g. GATEWAY_KEY_PROVIDER=vault) before retiring the old keys.
func Verify(ctx context.Context, db DB, p crypto.KeyProvider) ([]TableReport, error) {
	if err := RequireBypassRLS(ctx, db); err != nil {
		return nil, err
	}
	current, err := p.CurrentKeyID(ctx)
	if err != nil {
		return nil, fmt.Errorf("rewrap: current key ID: %w", err)
	}
	reports := make([]TableReport, 0, len(Columns))
	failed := false
	for _, c := range Columns {
		r := TableReport{Column: c, FailedByKeyID: map[string]int{}}
		var after *string
		for {
			// "" never equals a real key ID, so every envelope is read.
			rows, err := pendingBatch(ctx, db, c, "", after, verifyBatchSize)
			if err != nil {
				return append(reports, r), err
			}
			if len(rows) == 0 {
				break
			}
			last := rows[len(rows)-1].pk
			after = &last
			for _, row := range rows {
				r.Envelopes++
				if row.env.KeyID == current {
					r.Current++
				}
				dk, err := p.UnwrapDataKey(ctx, row.env.KeyID, row.env.WrappedDataKey)
				clear(dk)
				if ctxErr := ctx.Err(); ctxErr != nil {
					return append(reports, r), ctxErr
				}
				if err != nil || len(dk) != crypto.DataKeySize {
					r.Failed++
					r.FailedByKeyID[row.env.KeyID]++
				}
			}
		}
		failed = failed || r.Failed > 0
		reports = append(reports, r)
	}
	if failed {
		return reports, ErrVerifyFailed
	}
	return reports, nil
}
