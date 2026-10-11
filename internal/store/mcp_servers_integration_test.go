//go:build integration

package store_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/store/migrations"
)

// Integration tests for the user-added MCP server tables (migration 00014,
// Brain plan 0omkv2e1, decision yhd5kcaz): row-level security keeps every
// user's servers, credentials, snapshots and tunnels private until an admin
// publishes a server to a role, and the admin views carry no secrets.

// isPermissionDenied reports a missing privilege (SQLSTATE 42501 without the
// row-level security wording): gateway_app lacks the grant.
func isPermissionDenied(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "42501" && strings.Contains(pgErr.Message, "permission denied")
}

func pgCode(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}

// newRoleFor creates a role through the bypass role and assigns it to the
// given users (role administration is an admin action).
func newRoleFor(t *testing.T, st *store.Store, name string, userIDs ...string) string {
	t.Helper()
	var id string
	err := st.WithJobs(t.Context(), func(tx store.Tx) error {
		r := &store.Role{Name: name, Definition: []byte(`{}`)}
		if err := tx.Roles().Create(t.Context(), r); err != nil {
			return err
		}
		id = r.ID
		for _, u := range userIDs {
			if err := tx.Roles().Assign(t.Context(), &store.RoleAssignment{UserID: u, RoleID: r.ID}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("create role %s: %v", name, err)
	}
	return id
}

// newMCPServer creates a private server owned by owner through the user scope.
func newMCPServer(t *testing.T, st *store.Store, owner, name string) *store.MCPServer {
	t.Helper()
	s := &store.MCPServer{
		Name:           name,
		URL:            "https://" + name + ".example.com/mcp",
		OwnerUserID:    owner,
		CredentialMode: store.MCPCredentialPerUser,
		AuthKind:       store.MCPAuthOAuth,
		AuthConfig:     []byte(`{"scopes":["read"]}`),
		HeaderConfig:   []byte(`{"static":{"X-Client":"gateway"},"per_user":["X-Brain-Project"]}`),
	}
	err := st.WithUser(t.Context(), owner, func(tx store.Tx) error {
		return store.CreateMCPServer(t.Context(), tx, s)
	})
	if err != nil {
		t.Fatalf("create mcp server %s: %v", name, err)
	}
	return s
}

// mcpFixture is one private server of alice with every kind of child row.
type mcpFixture struct {
	alice, bob, carol string
	server            *store.MCPServer
	connA             *store.MCPUserConnection
	snap              *store.MCPSnapshot
	tunnel            *store.MCPTunnel
}

func newMCPFixture(t *testing.T, st *store.Store) *mcpFixture {
	t.Helper()
	ctx := t.Context()
	f := &mcpFixture{
		alice: newUser(t, st, "alice"),
		bob:   newUser(t, st, "bob"),
		carol: newUser(t, st, "carol"),
	}
	f.server = newMCPServer(t, st, f.alice, "brain")
	err := st.WithUser(ctx, f.alice, func(tx store.Tx) error {
		if err := store.SetMCPServerSharedSecret(ctx, tx, &store.MCPServerSharedSecret{
			ServerID: f.server.ID, Secret: testSecret("shared"), SecretKeys: []string{"Authorization"},
		}); err != nil {
			return err
		}
		if err := store.UpsertMCPOAuthClient(ctx, tx, &store.MCPOAuthClient{
			ServerID: f.server.ID, Method: store.MCPOAuthClientDCR, ClientID: "dcr-client-1",
			ClientSecret: ptr(testSecret("oauth-client")), Issuer: "https://auth.example.com",
		}); err != nil {
			return err
		}
		f.connA = &store.MCPUserConnection{
			ServerID: f.server.ID, UserID: f.alice, Scopes: []string{"read"},
			Secret: testSecret("conn-a"), ExpiresAt: ptr(time.Now().Add(time.Hour)),
		}
		if err := store.UpsertMCPUserConnection(ctx, tx, f.connA); err != nil {
			return err
		}
		f.snap = &store.MCPSnapshot{
			ServerID: f.server.ID,
			Tools:    []byte(`[{"name":"search","annotations":{"readOnlyHint":true}}]`),
		}
		if err := store.CreateMCPSnapshot(ctx, tx, f.snap); err != nil {
			return err
		}
		f.tunnel = &store.MCPTunnel{OwnerUserID: f.alice, Name: "laptop", TokenHash: []byte("tunnel-hash-a")}
		return store.CreateMCPTunnel(ctx, tx, f.tunnel)
	})
	if err != nil {
		t.Fatalf("mcp fixture: %v", err)
	}
	return f
}

// assertHiddenFrom checks that user sees none of alice's private rows.
func (f *mcpFixture) assertHiddenFrom(t *testing.T, st *store.Store, user, who string) {
	t.Helper()
	ctx := t.Context()
	err := st.WithUser(ctx, user, func(tx store.Tx) error {
		if _, err := store.GetMCPServer(ctx, tx, f.server.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("%s GetMCPServer = %v, want ErrNotFound", who, err)
		}
		if _, err := store.GetMCPServerByName(ctx, tx, f.server.Name); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("%s GetMCPServerByName = %v, want ErrNotFound", who, err)
		}
		vis, err := store.ListVisibleMCPServers(ctx, tx, user)
		if err != nil {
			return err
		}
		if len(vis) != 0 {
			t.Errorf("%s sees %d servers, want 0", who, len(vis))
		}
		if _, err := store.GetMCPSnapshot(ctx, tx, f.snap.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("%s GetMCPSnapshot = %v, want ErrNotFound", who, err)
		}
		if _, err := store.LatestMCPSnapshot(ctx, tx, f.server.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("%s LatestMCPSnapshot = %v, want ErrNotFound", who, err)
		}
		f.assertSecretsHidden(t, tx, who)
		for _, table := range []string{"mcp_servers", "mcp_server_roles", "mcp_server_snapshots"} {
			var n int
			if err := tx.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&n); err != nil {
				return err
			}
			if n != 0 {
				t.Errorf("%s sees %d rows of %s", who, n, table)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithUser(%s): %v", who, err)
	}
}

// assertSecretsHidden checks the rows that stay owner-only even once the
// server is published: credentials, alice's connection and her tunnel.
func (f *mcpFixture) assertSecretsHidden(t *testing.T, tx store.Tx, who string) {
	t.Helper()
	ctx := t.Context()
	if _, err := store.GetMCPServerSharedSecret(ctx, tx, f.server.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("%s GetMCPServerSharedSecret = %v, want ErrNotFound", who, err)
	}
	if _, err := store.GetMCPOAuthClient(ctx, tx, f.server.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("%s GetMCPOAuthClient = %v, want ErrNotFound", who, err)
	}
	if _, err := store.GetMCPUserConnection(ctx, tx, f.server.ID, f.alice); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("%s GetMCPUserConnection(alice) = %v, want ErrNotFound", who, err)
	}
	if _, err := store.GetMCPTunnel(ctx, tx, f.tunnel.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("%s GetMCPTunnel = %v, want ErrNotFound", who, err)
	}
	for _, table := range []string{"mcp_server_shared_secrets", "mcp_server_oauth_clients", "mcp_tunnels"} {
		var n int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if n != 0 {
			t.Errorf("%s sees %d rows of %s", who, n, table)
		}
	}
}

// --- isolation --------------------------------------------------------------

func TestIntegrationMCPServerPrivateIsolation(t *testing.T) {
	env := setup(t)
	env.reset(t)
	ctx := t.Context()
	st := env.open(t)
	f := newMCPFixture(t, st)
	newRoleFor(t, st, "engineer", f.bob) // bob holds a role, but nothing is published to it

	// The owner sees everything of her own.
	err := st.WithUser(ctx, f.alice, func(tx store.Tx) error {
		got, err := store.GetMCPServer(ctx, tx, f.server.ID)
		if err != nil {
			return err
		}
		if got.Audience != store.MCPAudiencePrivate || got.Status != store.MCPServerActive || got.Transport != store.MCPTransportAuto {
			t.Errorf("new server = %+v, want private/active/auto", got)
		}
		if string(got.HeaderConfig) == "" || got.OwnerUserID != f.alice {
			t.Errorf("server round trip = %+v", got)
		}
		mine, err := store.ListMyMCPServers(ctx, tx, f.alice)
		if err != nil || len(mine) != 1 {
			t.Errorf("ListMyMCPServers = %v, %v", mine, err)
		}
		sec, err := store.GetMCPServerSharedSecret(ctx, tx, f.server.ID)
		if err != nil || string(sec.Secret.Ciphertext) != "ciphertext-shared" || len(sec.SecretKeys) != 1 {
			t.Errorf("shared secret = %+v, %v", sec, err)
		}
		oc, err := store.GetMCPOAuthClient(ctx, tx, f.server.ID)
		if err != nil || oc.ClientSecret == nil || string(oc.ClientSecret.Ciphertext) != "ciphertext-oauth-client" {
			t.Errorf("oauth client = %+v, %v", oc, err)
		}
		conn, err := store.GetMCPUserConnection(ctx, tx, f.server.ID, f.alice)
		if err != nil || string(conn.Secret.Ciphertext) != "ciphertext-conn-a" || conn.Status != store.MCPConnectionActive {
			t.Errorf("connection = %+v, %v", conn, err)
		}
		if _, err := store.GetMCPTunnel(ctx, tx, f.tunnel.ID); err != nil {
			t.Errorf("own tunnel: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithUser(alice): %v", err)
	}

	f.assertHiddenFrom(t, st, f.bob, "bob")
	f.assertHiddenFrom(t, st, f.carol, "carol")

	// Bob cannot change or delete alice's server: the statements match nothing.
	err = st.WithUser(ctx, f.bob, func(tx store.Tx) error {
		forged := *f.server
		forged.URL = "https://evil.example.com/mcp"
		if err := store.UpdateMCPServer(ctx, tx, &forged); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("bob UpdateMCPServer = %v, want ErrNotFound", err)
		}
		if err := store.DeleteMCPServer(ctx, tx, f.server.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("bob DeleteMCPServer = %v, want ErrNotFound", err)
		}
		if err := store.RevokeMCPTunnel(ctx, tx, f.tunnel.ID, time.Now()); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("bob RevokeMCPTunnel = %v, want ErrNotFound", err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithUser(bob): %v", err)
	}

	// Bob cannot connect to a server he cannot see, nor create a server, a
	// tunnel or a shared secret in alice's name (each in its own
	// transaction: a failed statement aborts it, quirk 01mepmn6).
	for name, fn := range map[string]func(tx store.Tx) error{
		"connection to invisible server": func(tx store.Tx) error {
			return store.UpsertMCPUserConnection(ctx, tx, &store.MCPUserConnection{ServerID: f.server.ID, UserID: f.bob, Secret: testSecret("b")})
		},
		"server owned by alice": func(tx store.Tx) error {
			return store.CreateMCPServer(ctx, tx, &store.MCPServer{Name: "forged", URL: "https://x.example.com", OwnerUserID: f.alice})
		},
		"tunnel owned by alice": func(tx store.Tx) error {
			return store.CreateMCPTunnel(ctx, tx, &store.MCPTunnel{OwnerUserID: f.alice, Name: "x", TokenHash: []byte("forged")})
		},
	} {
		err := st.WithUser(ctx, f.bob, fn)
		if !isRLSViolation(err) {
			t.Errorf("bob inserting %s = %v, want RLS violation", name, err)
		}
	}
	err = st.WithUser(ctx, f.bob, func(tx store.Tx) error {
		return store.SetMCPServerSharedSecret(ctx, tx, &store.MCPServerSharedSecret{ServerID: f.server.ID, Secret: testSecret("x")})
	})
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("bob setting alice's shared secret = %v, want ErrNotFound", err)
	}

	// Alice's rows are unchanged.
	err = st.WithUser(ctx, f.alice, func(tx store.Tx) error {
		got, err := store.GetMCPServer(ctx, tx, f.server.ID)
		if err != nil {
			return err
		}
		if got.URL != f.server.URL {
			t.Errorf("alice's server URL = %q, modified by bob", got.URL)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationMCPServerPublishedVisibility(t *testing.T) {
	env := setup(t)
	env.reset(t)
	ctx := t.Context()
	st := env.open(t)
	f := newMCPFixture(t, st)
	engineers := newRoleFor(t, st, "engineer", f.bob)
	newRoleFor(t, st, "sales", f.carol)

	// Publishing is an admin action (decision yhd5kcaz): gateway_app has no
	// privilege on mcp_server_roles writes, not even for the owner.
	err := st.WithUser(ctx, f.alice, func(tx store.Tx) error {
		return store.PublishMCPServer(ctx, tx, f.server.ID, []string{engineers})
	})
	if !isPermissionDenied(err) {
		t.Fatalf("owner publishing through gateway_app = %v, want permission denied", err)
	}
	err = st.WithJobs(ctx, func(tx store.Tx) error {
		return store.PublishMCPServer(ctx, tx, f.server.ID, []string{engineers})
	})
	if err != nil {
		t.Fatalf("admin publish: %v", err)
	}

	// Bob (engineer) now sees the server and its snapshots, but not the
	// owner's credentials, connection or tunnel.
	err = st.WithUser(ctx, f.bob, func(tx store.Tx) error {
		got, err := store.GetMCPServer(ctx, tx, f.server.ID)
		if err != nil {
			t.Errorf("bob GetMCPServer after publish: %v", err)
		} else if got.Audience != store.MCPAudiencePublished {
			t.Errorf("audience = %q, want published", got.Audience)
		}
		vis, err := store.ListVisibleMCPServers(ctx, tx, f.bob)
		if err != nil {
			return err
		}
		if len(vis) != 1 || vis[0].ID != f.server.ID {
			t.Errorf("bob visible servers = %+v, want alice's", vis)
		}
		mine, err := store.ListMyMCPServers(ctx, tx, f.bob)
		if err != nil || len(mine) != 0 {
			t.Errorf("bob ListMyMCPServers = %v, %v; want none", mine, err)
		}
		if _, err := store.GetMCPSnapshot(ctx, tx, f.snap.ID); err != nil {
			t.Errorf("bob GetMCPSnapshot after publish: %v", err)
		}
		roles, err := store.ListMCPServerRoles(ctx, tx, f.server.ID)
		if err != nil || len(roles) != 1 || roles[0] != engineers {
			t.Errorf("bob ListMCPServerRoles = %v, %v", roles, err)
		}
		f.assertSecretsHidden(t, tx, "bob")
		// Visible is not writable.
		forged := *f.server
		forged.URL = "https://evil.example.com/mcp"
		if err := store.UpdateMCPServer(ctx, tx, &forged); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("bob UpdateMCPServer on published server = %v, want ErrNotFound", err)
		}
		if err := store.DeleteMCPServer(ctx, tx, f.server.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("bob DeleteMCPServer on published server = %v, want ErrNotFound", err)
		}
		if err := store.ApproveMCPSnapshot(ctx, tx, f.snap.ID, f.bob, nil); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("bob ApproveMCPSnapshot = %v, want ErrNotFound", err)
		}
		// Bob may connect his own account now.
		return store.UpsertMCPUserConnection(ctx, tx, &store.MCPUserConnection{
			ServerID: f.server.ID, UserID: f.bob, Scopes: []string{"read"}, Secret: testSecret("conn-b"),
		})
	})
	if err != nil {
		t.Fatalf("WithUser(bob): %v", err)
	}

	// Bob cannot write alice's shared secret even though he sees the server.
	err = st.WithUser(ctx, f.bob, func(tx store.Tx) error {
		return store.SetMCPServerSharedSecret(ctx, tx, &store.MCPServerSharedSecret{ServerID: f.server.ID, Secret: testSecret("x")})
	})
	if !isRLSViolation(err) {
		t.Errorf("bob setting the shared secret of a published server = %v, want RLS violation", err)
	}

	// Carol (sales) still sees nothing; alice cannot see bob's connection;
	// once published the owner can no longer approve snapshots herself.
	f.assertHiddenFrom(t, st, f.carol, "carol")
	err = st.WithUser(ctx, f.alice, func(tx store.Tx) error {
		if _, err := store.GetMCPUserConnection(ctx, tx, f.server.ID, f.bob); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("alice reading bob's connection = %v, want ErrNotFound", err)
		}
		if err := store.ApproveMCPSnapshot(ctx, tx, f.snap.ID, f.alice, nil); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("owner approving a published server's snapshot = %v, want ErrNotFound", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Unpublishing hides the server from bob again; his own connection row
	// stays his (he can still read and delete it).
	err = st.WithJobs(ctx, func(tx store.Tx) error {
		return store.UnpublishMCPServer(ctx, tx, f.server.ID, nil)
	})
	if err != nil {
		t.Fatalf("unpublish: %v", err)
	}
	err = st.WithUser(ctx, f.bob, func(tx store.Tx) error {
		if _, err := store.GetMCPServer(ctx, tx, f.server.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("bob GetMCPServer after unpublish = %v, want ErrNotFound", err)
		}
		if _, err := store.GetMCPSnapshot(ctx, tx, f.snap.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("bob GetMCPSnapshot after unpublish = %v, want ErrNotFound", err)
		}
		conns, err := store.ListMCPUserConnections(ctx, tx, f.bob)
		if err != nil || len(conns) != 1 {
			t.Errorf("bob ListMCPUserConnections after unpublish = %v, %v", conns, err)
		}
		n, err := store.DeleteMCPUserConnection(ctx, tx, f.server.ID, f.bob)
		if err != nil || n != 1 {
			t.Errorf("bob DeleteMCPUserConnection = %d, %v", n, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	err = st.WithJobs(ctx, func(tx store.Tx) error {
		got, err := store.GetMCPServer(ctx, tx, f.server.ID)
		if err != nil {
			return err
		}
		if got.Audience != store.MCPAudiencePrivate {
			t.Errorf("audience after unpublish = %q, want private", got.Audience)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationMCPServerAdminListing(t *testing.T) {
	env := setup(t)
	env.reset(t)
	ctx := t.Context()
	st := env.open(t)
	f := newMCPFixture(t, st)
	newMCPServer(t, st, f.bob, "bobs-tools")

	err := st.WithJobs(ctx, func(tx store.Tx) error {
		all, err := store.ListAllMCPServers(ctx, tx)
		if err != nil {
			return err
		}
		if len(all) != 2 {
			t.Errorf("ListAllMCPServers = %d servers, want 2", len(all))
		}
		var n int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM admin_mcp_servers").Scan(&n); err != nil {
			return err
		}
		if n != 2 {
			t.Errorf("admin_mcp_servers has %d rows for jobs, want 2", n)
		}
		var shared bool
		if err := tx.QueryRow(ctx, "SELECT has_shared_credential FROM admin_mcp_servers WHERE id = $1", f.server.ID).Scan(&shared); err != nil {
			return err
		}
		if !shared {
			t.Error("admin_mcp_servers.has_shared_credential = false for a server with a shared secret")
		}
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM admin_mcp_tunnels").Scan(&n); err != nil {
			return err
		}
		if n != 1 {
			t.Errorf("admin_mcp_tunnels has %d rows for jobs, want 1", n)
		}
		// Status changes are recorded with a class, never upstream text.
		if err := store.SetMCPServerStatus(ctx, tx, f.server.ID, store.MCPServerError, ptr("upstream_unavailable")); err != nil {
			return err
		}
		got, err := store.GetMCPServer(ctx, tx, f.server.ID)
		if err != nil {
			return err
		}
		if got.Status != store.MCPServerError || got.LastErrorClass == nil || *got.LastErrorClass != "upstream_unavailable" {
			t.Errorf("after SetMCPServerStatus = %+v", got)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithJobs: %v", err)
	}
	// security_invoker: through gateway_app the views show only own rows.
	err = st.WithUser(ctx, f.bob, func(tx store.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM admin_mcp_servers").Scan(&n); err != nil {
			return err
		}
		if n != 1 {
			t.Errorf("admin_mcp_servers has %d rows for bob, want 1", n)
		}
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM admin_mcp_tunnels").Scan(&n); err != nil {
			return err
		}
		if n != 0 {
			t.Errorf("admin_mcp_tunnels has %d rows for bob, want 0", n)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationMCPAdminViewsExposeNoSecrets(t *testing.T) {
	env := setup(t)
	ctx := t.Context()
	for _, view := range []string{"admin_mcp_servers", "admin_mcp_tunnels"} {
		rows, err := env.super.Query(ctx, `SELECT column_name FROM information_schema.columns
			WHERE table_schema = 'public' AND table_name = $1`, view)
		if err != nil {
			t.Fatal(err)
		}
		var cols []string
		for rows.Next() {
			var c string
			if err := rows.Scan(&c); err != nil {
				t.Fatal(err)
			}
			cols = append(cols, c)
		}
		rows.Close()
		if len(cols) == 0 {
			t.Errorf("view %s missing", view)
		}
		for _, c := range cols {
			for _, bad := range []string{"secret", "ciphertext", "nonce", "wrapped", "hash", "key_id", "token"} {
				if strings.Contains(c, bad) {
					t.Errorf("%s.%s exposes a secret column", view, c)
				}
			}
		}
		var invoker bool
		err = env.super.QueryRow(ctx, `SELECT coalesce('security_invoker=true' = ANY(reloptions), false)
			FROM pg_class WHERE relname = $1`, view).Scan(&invoker)
		if err != nil || !invoker {
			t.Errorf("%s security_invoker = %v, %v; want true", view, invoker, err)
		}
	}
}

// --- schema -----------------------------------------------------------------

func TestIntegrationMCPMigrationDownUp(t *testing.T) {
	env := setup(t)
	ctx := t.Context()
	tables := []string{"mcp_servers", "mcp_server_roles", "mcp_server_shared_secrets", "mcp_server_user_connections",
		"mcp_server_oauth_clients", "mcp_server_snapshots", "mcp_tunnels", "netguard_allow_hosts"}
	exists := func(rel string) bool {
		var ok bool
		if err := env.super.QueryRow(ctx, `SELECT to_regclass('public.' || $1) IS NOT NULL`, rel).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if err := migrations.DownTo(ctx, env.superURL, 13); err != nil {
		t.Fatalf("down to 13: %v", err)
	}
	t.Cleanup(func() { _ = migrations.Up(t.Context(), env.superURL) })
	for _, rel := range append(tables, "admin_mcp_servers", "admin_mcp_tunnels") {
		if exists(rel) {
			t.Errorf("%s still exists after down", rel)
		}
	}
	if err := migrations.Up(ctx, env.superURL); err != nil {
		t.Fatalf("up: %v", err)
	}
	for _, rel := range append(tables, "admin_mcp_servers", "admin_mcp_tunnels") {
		if !exists(rel) {
			t.Errorf("%s missing after up", rel)
		}
	}
	// Every table is forced into row-level security except the global allow-list.
	for _, rel := range tables {
		var enabled, forced bool
		if err := env.super.QueryRow(ctx, `SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = $1`, rel).Scan(&enabled, &forced); err != nil {
			t.Fatal(err)
		}
		if want := rel != "netguard_allow_hosts"; enabled != want || forced != want {
			t.Errorf("%s: rls enabled=%v forced=%v, want %v", rel, enabled, forced, want)
		}
	}
}

func TestIntegrationMCPServerNameRules(t *testing.T) {
	env := setup(t)
	env.reset(t)
	ctx := t.Context()
	st := env.open(t)
	alice := newUser(t, st, "alice")
	bob := newUser(t, st, "bob")
	newMCPServer(t, st, alice, "brain")

	// Names are unique across all users (they are the tool prefix), even
	// when the other user's server is invisible.
	err := st.WithUser(ctx, bob, func(tx store.Tx) error {
		return store.CreateMCPServer(ctx, tx, &store.MCPServer{Name: "brain", URL: "https://b.example.com", OwnerUserID: bob})
	})
	if pgCode(err) != "23505" {
		t.Errorf("duplicate name = %v, want unique violation", err)
	}
	for _, bad := range []string{"Brain", "has space", "dot.ted", "", "émoji", strings.Repeat("a", 64)} {
		err := st.WithUser(ctx, bob, func(tx store.Tx) error {
			return store.CreateMCPServer(ctx, tx, &store.MCPServer{Name: bad, URL: "https://b.example.com", OwnerUserID: bob})
		})
		if pgCode(err) != "23514" {
			t.Errorf("name %q = %v, want check violation", bad, err)
		}
	}
	for _, good := range []string{"a", "my_tools-2", strings.Repeat("z", 63)} {
		newMCPServer(t, st, bob, good)
	}
	err = st.WithUser(ctx, bob, func(tx store.Tx) error {
		return store.CreateMCPServer(ctx, tx, &store.MCPServer{Name: "badmode", URL: "https://b.example.com", OwnerUserID: bob, CredentialMode: "everyone"})
	})
	if pgCode(err) != "23514" {
		t.Errorf("credential_mode everyone = %v, want check violation", err)
	}
}

func TestIntegrationMCPServerDeleteCascades(t *testing.T) {
	env := setup(t)
	env.reset(t)
	ctx := t.Context()
	st := env.open(t)
	f := newMCPFixture(t, st)
	engineers := newRoleFor(t, st, "engineer", f.bob)
	if err := st.WithJobs(ctx, func(tx store.Tx) error {
		return store.PublishMCPServer(ctx, tx, f.server.ID, []string{engineers})
	}); err != nil {
		t.Fatal(err)
	}
	// Bob's connection (invisible to alice) and an audit event of a call.
	err := st.WithUser(ctx, f.bob, func(tx store.Tx) error {
		if err := store.UpsertMCPUserConnection(ctx, tx, &store.MCPUserConnection{ServerID: f.server.ID, UserID: f.bob, Secret: testSecret("conn-b")}); err != nil {
			return err
		}
		return tx.Audit().Create(ctx, &store.AuditEvent{UserID: &f.bob, Tool: ptr("brain.search"), Decision: "allow", Outcome: ptr("succeeded")})
	})
	if err != nil {
		t.Fatal(err)
	}

	err = st.WithUser(ctx, f.alice, func(tx store.Tx) error {
		return store.DeleteMCPServer(ctx, tx, f.server.ID)
	})
	if err != nil {
		t.Fatalf("owner delete: %v", err)
	}
	for _, table := range []string{"mcp_servers", "mcp_server_roles", "mcp_server_shared_secrets", "mcp_server_user_connections",
		"mcp_server_oauth_clients", "mcp_server_snapshots"} {
		var n int
		if err := env.super.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("%s has %d rows after deleting the server", table, n)
		}
	}
	var n int
	if err := env.super.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE tool = 'brain.search'").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("audit events after server delete = %d, want 1 (untouched)", n)
	}
	if err := env.super.QueryRow(ctx, "SELECT count(*) FROM mcp_tunnels").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("tunnels after server delete = %d, want 1 (tunnels belong to users, not servers)", n)
	}
}

// --- snapshots --------------------------------------------------------------

func TestIntegrationMCPSnapshotLifecycle(t *testing.T) {
	env := setup(t)
	env.reset(t)
	ctx := t.Context()
	st := env.open(t)
	alice := newUser(t, st, "alice")
	srv := newMCPServer(t, st, alice, "brain")

	err := st.WithUser(ctx, alice, func(tx store.Tx) error {
		if _, err := store.ApprovedMCPSnapshot(ctx, tx, srv.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("ApprovedMCPSnapshot before any = %v, want ErrNotFound", err)
		}
		var snaps []*store.MCPSnapshot
		for i := 0; i < 3; i++ {
			s := &store.MCPSnapshot{ServerID: srv.ID, Tools: []byte(`[]`)}
			if err := store.CreateMCPSnapshot(ctx, tx, s); err != nil {
				return err
			}
			if s.Version != i+1 || s.Status != store.MCPSnapshotPending {
				t.Errorf("snapshot %d: version %d status %q", i, s.Version, s.Status)
			}
			snaps = append(snaps, s)
		}
		review := []byte(`{"search":{"enabled":true,"kind":"read"}}`)
		if err := store.ApproveMCPSnapshot(ctx, tx, snaps[0].ID, alice, review); err != nil {
			return err
		}
		if err := store.ApproveMCPSnapshot(ctx, tx, snaps[1].ID, alice, review); err != nil {
			return err
		}
		approved, err := store.ApprovedMCPSnapshot(ctx, tx, srv.ID)
		if err != nil {
			return err
		}
		if approved.ID != snaps[1].ID || approved.ApprovedBy == nil || *approved.ApprovedBy != alice || approved.ApprovedAt == nil {
			t.Errorf("approved = %+v, want v2 approved by alice", approved)
		}
		if !strings.Contains(string(approved.Review), "search") {
			t.Errorf("review = %s", approved.Review)
		}
		first, err := store.GetMCPSnapshot(ctx, tx, snaps[0].ID)
		if err != nil {
			return err
		}
		if first.Status != store.MCPSnapshotSuperseded {
			t.Errorf("v1 status = %q, want superseded", first.Status)
		}
		latest, err := store.LatestMCPSnapshot(ctx, tx, srv.ID)
		if err != nil {
			return err
		}
		if latest.Version != 3 || latest.Status != store.MCPSnapshotPending {
			t.Errorf("latest = v%d %s, want v3 pending", latest.Version, latest.Status)
		}
		hist, err := store.ListMCPSnapshots(ctx, tx, srv.ID)
		if err != nil {
			return err
		}
		if len(hist) != 3 || hist[0].Version != 3 || hist[2].Version != 1 {
			t.Errorf("history = %d entries, want 3 newest first", len(hist))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithUser: %v", err)
	}

	// At most one approved snapshot per server, whatever the path.
	err = st.WithJobs(ctx, func(tx store.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE mcp_server_snapshots SET status = 'approved' WHERE server_id = $1 AND version = 3`, srv.ID)
		return err
	})
	if pgCode(err) != "23505" {
		t.Errorf("second approved snapshot = %v, want unique violation", err)
	}
	// (server_id, version) is unique.
	err = st.WithJobs(ctx, func(tx store.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO mcp_server_snapshots (server_id, version) VALUES ($1, 1)`, srv.ID)
		return err
	})
	if pgCode(err) != "23505" {
		t.Errorf("duplicate version = %v, want unique violation", err)
	}
}

// --- tunnels ----------------------------------------------------------------

func TestIntegrationMCPTunnels(t *testing.T) {
	env := setup(t)
	env.reset(t)
	ctx := t.Context()
	st := env.open(t)
	alice := newUser(t, st, "alice")
	tun := &store.MCPTunnel{OwnerUserID: alice, Name: "laptop", TokenHash: []byte("hash-1")}
	err := st.WithUser(ctx, alice, func(tx store.Tx) error {
		if err := store.CreateMCPTunnel(ctx, tx, tun); err != nil {
			return err
		}
		list, err := store.ListMCPTunnels(ctx, tx, alice)
		if err != nil || len(list) != 1 {
			t.Errorf("ListMCPTunnels = %v, %v", list, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// The tunnel endpoint authenticates by token hash before any user is
	// known, through the bypass role.
	seen := time.Now().Truncate(time.Microsecond)
	err = st.WithJobs(ctx, func(tx store.Tx) error {
		got, err := store.GetMCPTunnelByTokenHash(ctx, tx, []byte("hash-1"))
		if err != nil {
			return err
		}
		if got.ID != tun.ID || got.RevokedAt != nil {
			t.Errorf("by hash = %+v", got)
		}
		if _, err := store.GetMCPTunnelByTokenHash(ctx, tx, []byte("nope")); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("unknown hash = %v, want ErrNotFound", err)
		}
		return store.TouchMCPTunnel(ctx, tx, tun.ID, seen)
	})
	if err != nil {
		t.Fatal(err)
	}
	err = st.WithUser(ctx, alice, func(tx store.Tx) error {
		if err := store.RevokeMCPTunnel(ctx, tx, tun.ID, time.Now()); err != nil {
			return err
		}
		got, err := store.GetMCPTunnel(ctx, tx, tun.ID)
		if err != nil {
			return err
		}
		if got.RevokedAt == nil || got.LastSeenAt == nil || !got.LastSeenAt.Equal(seen) {
			t.Errorf("after touch+revoke = %+v", got)
		}
		// Revoking twice keeps the first timestamp and reports not found.
		if err := store.RevokeMCPTunnel(ctx, tx, tun.ID, time.Now()); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("second revoke = %v, want ErrNotFound", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// --- netguard allow-list ----------------------------------------------------

func TestIntegrationNetguardAllowHosts(t *testing.T) {
	env := setup(t)
	env.reset(t)
	ctx := t.Context()
	st := env.open(t)
	admin := newUser(t, st, "admin")

	h := &store.NetguardAllowHost{Pattern: "10.20.0.0/16", Note: "lab", CreatedBy: &admin}
	err := st.WithJobs(ctx, func(tx store.Tx) error {
		if err := store.CreateNetguardAllowHost(ctx, tx, h); err != nil {
			return err
		}
		if err := store.CreateNetguardAllowHost(ctx, tx, &store.NetguardAllowHost{Pattern: "brain.lan"}); err != nil {
			return err
		}
		h.Note = "lab network"
		if err := store.UpdateNetguardAllowHost(ctx, tx, h); err != nil {
			return err
		}
		got, err := store.GetNetguardAllowHost(ctx, tx, h.ID)
		if err != nil || got.Note != "lab network" {
			t.Errorf("get = %+v, %v", got, err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithJobs: %v", err)
	}
	// Every user scope can read the allow-list (netguard checks it at dial
	// time) but only admins (bypass role) change it.
	err = st.WithUser(ctx, admin, func(tx store.Tx) error {
		list, err := store.ListNetguardAllowHosts(ctx, tx)
		if err != nil {
			return err
		}
		if len(list) != 2 {
			t.Errorf("ListNetguardAllowHosts = %d, want 2", len(list))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	err = st.WithUser(ctx, admin, func(tx store.Tx) error {
		return store.CreateNetguardAllowHost(ctx, tx, &store.NetguardAllowHost{Pattern: "evil.lan"})
	})
	if !isPermissionDenied(err) {
		t.Errorf("gateway_app insert allow host = %v, want permission denied", err)
	}
	err = st.WithJobs(ctx, func(tx store.Tx) error {
		if err := store.DeleteNetguardAllowHost(ctx, tx, h.ID); err != nil {
			return err
		}
		if err := store.DeleteNetguardAllowHost(ctx, tx, h.ID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("second delete = %v, want ErrNotFound", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	err = st.WithJobs(ctx, func(tx store.Tx) error {
		return store.CreateNetguardAllowHost(ctx, tx, &store.NetguardAllowHost{Pattern: ""})
	})
	if pgCode(err) != "23514" {
		t.Errorf("empty pattern = %v, want check violation", err)
	}
}
