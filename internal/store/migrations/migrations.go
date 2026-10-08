// Package migrations embeds the gateway's linear goose SQL migrations and
// runs them. It is imported by cmd/migrate (the pre-upgrade job) and by the
// store integration tests, never by the gateway binary: the service checks
// the schema version at startup and never migrates itself (plan 36bakiw8
// section 6, decision v6piaxdb).
//
// Migrations run as the database owner or a superuser: 00001 creates the
// gateway_app (NOBYPASSRLS) and gateway_jobs (BYPASSRLS) roles, and BYPASSRLS
// can only be granted by a superuser.
package migrations

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io"
	"io/fs"
	"strconv"
	"strings"
	"text/tabwriter"

	_ "github.com/jackc/pgx/v5/stdlib" // database/sql driver "pgx" for goose
	"github.com/pressly/goose/v3"
)

// FS holds every *.sql migration, named NNNNN_description.sql.
//
//go:embed *.sql
var FS embed.FS

// Latest returns the highest migration version embedded in the binary.
func Latest() (int64, error) {
	entries, err := fs.ReadDir(FS, ".")
	if err != nil {
		return 0, err
	}
	var latest int64
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".sql") {
			continue
		}
		prefix, _, ok := strings.Cut(name, "_")
		if !ok {
			return 0, fmt.Errorf("migration %q: name must be NNNNN_description.sql", name)
		}
		v, err := strconv.ParseInt(prefix, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("migration %q: %w", name, err)
		}
		if v > latest {
			latest = v
		}
	}
	if latest == 0 {
		return 0, fmt.Errorf("no migrations embedded")
	}
	return latest, nil
}

// Up applies every pending migration.
func Up(ctx context.Context, databaseURL string) error {
	return run(ctx, databaseURL, func(p *goose.Provider) error {
		_, err := p.Up(ctx)
		return err
	})
}

// Down rolls back the most recent migration.
func Down(ctx context.Context, databaseURL string) error {
	return run(ctx, databaseURL, func(p *goose.Provider) error {
		_, err := p.Down(ctx)
		return err
	})
}

// DownTo rolls back migrations until the database is at version; 0 removes
// everything.
func DownTo(ctx context.Context, databaseURL string, version int64) error {
	return run(ctx, databaseURL, func(p *goose.Provider) error {
		_, err := p.DownTo(ctx, version)
		return err
	})
}

// Version returns the database's current migration version.
func Version(ctx context.Context, databaseURL string) (int64, error) {
	var v int64
	err := run(ctx, databaseURL, func(p *goose.Provider) error {
		var err error
		v, err = p.GetDBVersion(ctx)
		return err
	})
	return v, err
}

// Status writes a table of every embedded migration and whether it is applied.
func Status(ctx context.Context, databaseURL string, w io.Writer) error {
	return run(ctx, databaseURL, func(p *goose.Provider) error {
		results, err := p.Status(ctx)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		if _, err := fmt.Fprintln(tw, "VERSION\tAPPLIED AT\tSOURCE"); err != nil {
			return err
		}
		for _, r := range results {
			applied := "pending"
			if r.State == goose.StateApplied {
				applied = r.AppliedAt.UTC().Format("2006-01-02 15:04:05")
			}
			if _, err := fmt.Fprintf(tw, "%d\t%s\t%s\n", r.Source.Version, applied, r.Source.Path); err != nil {
				return err
			}
		}
		return tw.Flush()
	})
}

func run(ctx context.Context, databaseURL string, fn func(*goose.Provider) error) error {
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return fmt.Errorf("migrations: open: %w", err)
	}
	defer func() { _ = db.Close() }()
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("migrations: connect: %w", err)
	}
	p, err := goose.NewProvider(goose.DialectPostgres, db, FS)
	if err != nil {
		return fmt.Errorf("migrations: %w", err)
	}
	if err := fn(p); err != nil {
		return fmt.Errorf("migrations: %w", err)
	}
	return nil
}
