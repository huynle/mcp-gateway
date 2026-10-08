// Command migrate applies the gateway's embedded goose migrations. It is the
// pre-upgrade job (Kubernetes Job, Compose one-shot service, `make migrate`);
// the gateway binary never migrates and refuses to start when the schema
// version differs from the one it was built against.
//
// Usage:
//
//	migrate up            apply all pending migrations
//	migrate down          roll back the most recent migration
//	migrate down-to N     roll back until the database is at version N (0 = empty)
//	migrate status        list migrations and whether they are applied
//	migrate version       print the database's current version
//
// The connection string comes from GATEWAY_MIGRATE_DATABASE_URL, falling back
// to GATEWAY_DATABASE_URL. It must connect as the database owner or a
// superuser: migration 00001 creates the gateway_app and gateway_jobs roles
// and BYPASSRLS can only be granted by a superuser. The gateway itself runs
// as gateway_app, so in a shared .env the two variables usually differ.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/store/migrations"
)

func main() {
	if err := run(os.Args[1:], os.Getenv); err != nil {
		fmt.Fprintln(os.Stderr, "migrate:", err)
		os.Exit(1)
	}
}

// errUsage is returned for unknown or malformed commands.
var errUsage = errors.New("usage: migrate up|down|down-to N|status|version (reads GATEWAY_MIGRATE_DATABASE_URL or GATEWAY_DATABASE_URL)")

// resolveURL picks the connection string: the migrate-specific variable wins
// over the gateway's.
func resolveURL(getenv func(string) string) (string, error) {
	for _, key := range []string{"GATEWAY_MIGRATE_DATABASE_URL", "GATEWAY_DATABASE_URL"} {
		if v := getenv(key); v != "" {
			return v, nil
		}
	}
	return "", errors.New("GATEWAY_MIGRATE_DATABASE_URL (or GATEWAY_DATABASE_URL) must be set to an owner/superuser connection string")
}

func run(args []string, getenv func(string) string) error {
	if len(args) == 0 {
		return errUsage
	}
	url, err := resolveURL(getenv)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	switch args[0] {
	case "up":
		if err := migrations.Up(ctx, url); err != nil {
			return err
		}
		return report(ctx, url)
	case "down":
		if err := migrations.Down(ctx, url); err != nil {
			return err
		}
		return report(ctx, url)
	case "down-to":
		if len(args) != 2 {
			return errUsage
		}
		target, err := strconv.ParseInt(args[1], 10, 64)
		if err != nil || target < 0 {
			return fmt.Errorf("%w: down-to needs a non-negative version", errUsage)
		}
		if err := migrations.DownTo(ctx, url, target); err != nil {
			return err
		}
		return report(ctx, url)
	case "status":
		return migrations.Status(ctx, url, os.Stdout)
	case "version":
		return report(ctx, url)
	default:
		return errUsage
	}
}

// report prints the database version next to the one the gateway expects so
// an operator sees immediately whether the service will start.
func report(ctx context.Context, url string) error {
	v, err := migrations.Version(ctx, url)
	if err != nil {
		return err
	}
	fmt.Printf("database schema version %d (gateway expects %d)\n", v, store.ExpectedSchemaVersion)
	return nil
}
