package rewrap_test

import (
	"io/fs"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/rewrap"
	"github.com/huynle/mcp-gateway/internal/store/migrations"
)

var (
	tableStmtRE   = regexp.MustCompile(`(?i)\b(?:CREATE|ALTER)\s+TABLE\s+(?:IF\s+(?:NOT\s+)?EXISTS\s+)?(?:ONLY\s+)?([a-z_][a-z0-9_]*)`)
	wrappedColRE  = regexp.MustCompile(`(?i)\b([a-z_][a-z0-9_]*)_wrapped_key\b`)
	keyIDColRE    = regexp.MustCompile(`(?i)\b([a-z_][a-z0-9_]*)_key_id\s+text\b`)
	sqlCommentRE  = regexp.MustCompile(`--[^\n]*`)
	gooseDownMark = "-- +goose Down"
)

// envelopeColumnsInMigrations scans the Up half of every embedded migration
// for envelope column groups (<prefix>_wrapped_key) and returns them as
// "table.prefix", attributing each to the table of the closest preceding
// CREATE/ALTER TABLE statement.
func envelopeColumnsInMigrations(t *testing.T) map[string]bool {
	t.Helper()
	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		raw, err := fs.ReadFile(migrations.FS, e.Name())
		if err != nil {
			t.Fatal(err)
		}
		up, _, _ := strings.Cut(string(raw), gooseDownMark)
		up = sqlCommentRE.ReplaceAllString(up, "")
		tables := tableStmtRE.FindAllStringSubmatchIndex(up, -1)
		for _, m := range wrappedColRE.FindAllStringSubmatchIndex(up, -1) {
			table := ""
			for _, tm := range tables {
				if tm[0] < m[0] {
					table = up[tm[2]:tm[3]]
				}
			}
			if table == "" {
				t.Errorf("%s: envelope column %q outside any CREATE/ALTER TABLE", e.Name(), up[m[0]:m[1]])
				continue
			}
			found[strings.ToLower(table)+"."+strings.ToLower(up[m[2]:m[3]])] = true
		}
	}
	return found
}

// TestRegistryCoversEveryEnvelopeColumnInMigrations fails when a migration
// adds an envelope-encrypted column group the re-wrap registry does not
// know: such a column would keep its old key ID after `migrate rewrap` and
// break when the old root key is retired. Add it to rewrap.Columns.
func TestRegistryCoversEveryEnvelopeColumnInMigrations(t *testing.T) {
	inMigrations := envelopeColumnsInMigrations(t)
	if len(inMigrations) == 0 {
		t.Fatal("found no envelope columns in the migrations; the scanner is broken")
	}
	registered := map[string]bool{}
	for _, c := range rewrap.Columns {
		id := c.Table + "." + c.Prefix
		if registered[id] {
			t.Errorf("registry lists %s twice", id)
		}
		registered[id] = true
	}
	var missing, stale []string
	for id := range inMigrations {
		if !registered[id] {
			missing = append(missing, id)
		}
	}
	for id := range registered {
		if !inMigrations[id] {
			stale = append(stale, id)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	if len(missing) > 0 {
		t.Errorf("envelope columns in migrations but not in rewrap.Columns: %v", missing)
	}
	if len(stale) > 0 {
		t.Errorf("rewrap.Columns lists columns no migration creates: %v", stale)
	}
}

// TestRegistryKnownInventory pins the current inventory so a change to it
// is a deliberate, reviewed edit.
func TestRegistryKnownInventory(t *testing.T) {
	want := []string{
		"approvals.payload (pk id, nullable)",
		"connection_secrets.secret (pk connection_id)",
		"mcp_server_oauth_clients.secret (pk server_id, nullable)",
		"mcp_server_shared_secrets.secret (pk server_id)",
		"mcp_server_user_connections.secret (pk id)",
		"secrets.value (pk id, nullable)",
		"signing_keys.private (pk id)",
		"vendor_apps.secret (pk id)",
	}
	var got []string
	for _, c := range rewrap.Columns {
		s := c.Table + "." + c.Prefix + " (pk " + c.PK
		if c.Nullable {
			s += ", nullable"
		}
		got = append(got, s+")")
	}
	sort.Strings(got)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("registry:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestColumnNames(t *testing.T) {
	c := rewrap.Column{Table: "signing_keys", PK: "id", Prefix: "private"}
	if c.KeyIDColumn() != "private_key_id" || c.WrappedKeyColumn() != "private_wrapped_key" {
		t.Errorf("columns = %s, %s", c.KeyIDColumn(), c.WrappedKeyColumn())
	}
}

// TestEveryWrappedKeyHasAKeyID guards the naming convention the scanner
// relies on: each <prefix>_wrapped_key has a <prefix>_key_id beside it.
func TestEveryWrappedKeyHasAKeyID(t *testing.T) {
	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		raw, err := fs.ReadFile(migrations.FS, e.Name())
		if err != nil {
			t.Fatal(err)
		}
		up, _, _ := strings.Cut(string(raw), gooseDownMark)
		up = sqlCommentRE.ReplaceAllString(up, "")
		keyIDs := map[string]bool{}
		for _, m := range keyIDColRE.FindAllStringSubmatch(up, -1) {
			keyIDs[strings.ToLower(m[1])] = true
		}
		for _, m := range wrappedColRE.FindAllStringSubmatch(up, -1) {
			if !keyIDs[strings.ToLower(m[1])] {
				t.Errorf("%s: %s_wrapped_key without a %s_key_id text column", e.Name(), m[1], m[1])
			}
		}
	}
}
