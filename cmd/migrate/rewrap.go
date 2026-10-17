package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/rewrap"
)

// rewrapMode selects what `migrate rewrap` does.
type rewrapMode int

const (
	// modeRewrap moves every envelope to the provider's current key.
	modeRewrap rewrapMode = iota
	// modeDryRun only counts envelopes per table and key ID.
	modeDryRun
	// modeVerify unwraps every envelope and counts failures.
	modeVerify
)

// parseRewrapArgs parses `rewrap [--dry-run | --verify] [--batch N]`.
func parseRewrapArgs(args []string) (rewrapMode, int, error) {
	fs := flag.NewFlagSet("rewrap", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dryRun := fs.Bool("dry-run", false, "count envelopes per table and key ID; change nothing")
	verify := fs.Bool("verify", false, "unwrap every envelope with the configured provider; report failures")
	batch := fs.Int("batch", rewrap.DefaultBatchSize, "rows per transaction")
	if err := fs.Parse(args); err != nil {
		return 0, 0, fmt.Errorf("%w: rewrap: %w", errUsage, err)
	}
	switch {
	case fs.NArg() > 0:
		return 0, 0, fmt.Errorf("%w: rewrap takes no arguments", errUsage)
	case *dryRun && *verify:
		return 0, 0, fmt.Errorf("%w: rewrap: --dry-run and --verify are exclusive", errUsage)
	case *batch < 1:
		return 0, 0, fmt.Errorf("%w: rewrap: --batch must be positive", errUsage)
	case *dryRun:
		return modeDryRun, *batch, nil
	case *verify:
		return modeVerify, *batch, nil
	default:
		return modeRewrap, *batch, nil
	}
}

// resolveRewrapURL picks a connection string whose role bypasses row-level
// security: the owner (migrate) URL, else the gateway_jobs URL. The
// request-path GATEWAY_DATABASE_URL (gateway_app) is never used: under
// FORCE ROW LEVEL SECURITY it would see no user-scoped rows.
func resolveRewrapURL(getenv func(string) string) (string, error) {
	for _, key := range []string{"GATEWAY_MIGRATE_DATABASE_URL", "GATEWAY_JOBS_DATABASE_URL"} {
		if v := getenv(key); v != "" {
			return v, nil
		}
	}
	return "", errors.New("rewrap needs GATEWAY_MIGRATE_DATABASE_URL (owner) or GATEWAY_JOBS_DATABASE_URL (gateway_jobs); GATEWAY_DATABASE_URL is subject to row-level security and is not used")
}

// runRewrap implements `migrate rewrap`: it builds the key provider from
// the GATEWAY_KEY_* / GATEWAY_VAULT_* environment exactly like the gateway
// and re-wraps (or counts, or verifies) every envelope in rewrap.Columns.
// Output is counts and key IDs per table, never secrets.
func runRewrap(ctx context.Context, args []string, getenv func(string) string, stdout io.Writer) error {
	mode, batch, err := parseRewrapArgs(args)
	if err != nil {
		return err
	}
	url, err := resolveRewrapURL(getenv)
	if err != nil {
		return err
	}
	if getenv(crypto.EnvKeyProvider) == "" {
		return fmt.Errorf("rewrap: set %s (file, vault or migrate) to the provider whose current key envelopes should move to", crypto.EnvKeyProvider)
	}
	kp, err := crypto.NewProviderFromEnv(getenv)
	if err != nil {
		return fmt.Errorf("rewrap: key provider: %w", err)
	}
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		return fmt.Errorf("rewrap: connect: %w", err)
	}
	defer func() { _ = conn.Close(context.Background()) }()
	current, err := kp.CurrentKeyID(ctx)
	if err != nil {
		return fmt.Errorf("rewrap: current key ID: %w", err)
	}

	switch mode {
	case modeDryRun:
		reports, err := rewrap.Plan(ctx, conn, kp)
		printPlan(stdout, current, reports)
		return err
	case modeVerify:
		reports, err := rewrap.Verify(ctx, conn, kp)
		printVerify(stdout, current, reports)
		return err
	default:
		reports, err := rewrap.Run(ctx, conn, kp, rewrap.Options{BatchSize: batch})
		printRun(stdout, current, reports)
		return err
	}
}

func label(c rewrap.Column) string { return c.Table + "." + c.Prefix }

// byKeyID renders "id=n,id=n" sorted by key ID.
func byKeyID(m map[string]int) string {
	if len(m) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(m))
	for _, id := range slices.Sorted(maps.Keys(m)) {
		parts = append(parts, fmt.Sprintf("%s=%d", id, m[id]))
	}
	return strings.Join(parts, ",")
}

func printPlan(w io.Writer, current string, reports []rewrap.TableReport) {
	_, _ = fmt.Fprintf(w, "rewrap dry run: current key %s\n", current)
	var total, todo int
	for _, r := range reports {
		pending := r.Envelopes - r.Current
		total += r.Envelopes
		todo += pending
		_, _ = fmt.Fprintf(w, "  %-36s %d envelopes, %d to re-wrap; by key: %s\n", label(r.Column), r.Envelopes, pending, byKeyID(r.ByKeyID))
	}
	_, _ = fmt.Fprintf(w, "total: %d envelopes, %d to re-wrap\n", total, todo)
}

func printRun(w io.Writer, current string, reports []rewrap.TableReport) {
	_, _ = fmt.Fprintf(w, "rewrap: current key %s\n", current)
	var rewrapped, conflicts, failed int
	for _, r := range reports {
		rewrapped += r.Rewrapped
		conflicts += r.Conflicts
		failed += r.Failed
		_, _ = fmt.Fprintf(w, "  %-36s %d envelopes, %d rewrapped, %d already current, %d conflicts, %d failed\n",
			label(r.Column), r.Envelopes, r.Rewrapped, r.Current, r.Conflicts, r.Failed)
	}
	_, _ = fmt.Fprintf(w, "total: %d rewrapped, %d conflicts, %d failed\n", rewrapped, conflicts, failed)
	if conflicts > 0 {
		_, _ = fmt.Fprintln(w, "rows changed while the re-wrap ran were left alone: run it again")
	}
	if failed > 0 {
		_, _ = fmt.Fprintln(w, "some envelopes could not be unwrapped (unknown key ID or corrupt): run `rewrap --verify` to see which key IDs")
	}
}

func printVerify(w io.Writer, current string, reports []rewrap.TableReport) {
	_, _ = fmt.Fprintf(w, "verify: current key %s\n", current)
	var total, notCurrent, failed int
	for _, r := range reports {
		total += r.Envelopes
		notCurrent += r.Envelopes - r.Current
		failed += r.Failed
		_, _ = fmt.Fprintf(w, "  %-36s %d envelopes, %d current, %d failed; failed by key: %s\n",
			label(r.Column), r.Envelopes, r.Current, r.Failed, byKeyID(r.FailedByKeyID))
	}
	_, _ = fmt.Fprintf(w, "total: %d envelopes, %d not under the current key, %d failed\n", total, notCurrent, failed)
}
