//go:build integration || e2e

// The plugins scenarios add servers through the servers portal, whose
// add form and Detect accept only https URLs, and the gateway reaches
// them through netguard, which verifies TLS against the system roots and
// cannot be given other roots. So the fake upstreams are httptest TLS
// servers, and this test binary replaces the system roots with the
// httptest certificate (x509.SetFallbackRoots under
// x509usefallbackroots=1, the documented way to force it on macOS and
// Windows too). Nothing in the e2e package reaches the internet.

//go:debug x509usefallbackroots=1

package e2e

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	fedadmin "github.com/huynle/mcp-gateway/internal/federation/admin"
	"github.com/huynle/mcp-gateway/internal/federation/auth"
	fedportal "github.com/huynle/mcp-gateway/internal/federation/portal"
	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/policy"
	"github.com/huynle/mcp-gateway/internal/portal"
	"github.com/huynle/mcp-gateway/internal/store"
)

// stdioServerEnv makes the re-executed test binary a stdio MCP server (the
// tunnel scenario's `mcp-gateway-tunnel --stdio` target).
const stdioServerEnv = "MCP_GATEWAY_E2E_STDIO_SERVER"

func TestMain(m *testing.M) {
	if os.Getenv(stdioServerEnv) == "1" {
		if err := stdioServer().Run(context.Background(), &sdk.StdioTransport{}); err != nil {
			fmt.Fprintln(os.Stderr, "stdio server:", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	// Every httptest TLS server uses the same certificate: trust it as
	// the only root, before any TLS verification happens.
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	srv.Close()
	x509.SetFallbackRoots(roots)
	os.Exit(m.Run())
}

type echoIn struct {
	Text string `json:"text"`
}

// stdioServer is the local stdio MCP server behind the tunnel.
func stdioServer() *sdk.Server {
	s := sdk.NewServer(&sdk.Implementation{Name: "laptop", Version: "1"}, nil)
	sdk.AddTool(s, &sdk.Tool{Name: "echo", Description: "Echo the text.", Annotations: &sdk.ToolAnnotations{ReadOnlyHint: true}},
		func(_ context.Context, _ *sdk.CallToolRequest, in echoIn) (*sdk.CallToolResult, any, error) {
			return textResult("stdio echo: " + in.Text), nil, nil
		})
	return s
}

// connectFinish is cmd/gateway's: the end of the upstream OAuth connect
// flow goes back to the server's portal page.
func connectFinish(w http.ResponseWriter, r *http.Request, serverID string, err error) {
	target := "/servers"
	if serverID != "" {
		target = "/servers/" + url.PathEscape(serverID)
	}
	if err != nil {
		http.Redirect(w, r, target+"?connect=failed", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, target+"?connect=ok", http.StatusSeeOther)
}

// mountFederationPages mounts what cmd/gateway's withFederationPages and
// withFederationAdmin mount: the upstream OAuth connect routes, the
// servers portal and the admin pages for servers, tunnels and the
// allow-list.
func (w *world) mountFederationPages(p *portal.Portal, session func(*http.Request) (string, string), log *slog.Logger) {
	w.t.Helper()
	fed := w.fed
	user := func(r *http.Request) (string, bool) {
		id, _ := session(r)
		return id, id != ""
	}
	p.MountUser("GET /servers/{id}/connect", fed.Auth.StartConnect(user))
	p.MountUser("GET "+auth.CallbackPath, fed.Auth.Callback(user))
	factory, err := fedportal.NewClientFactory(fedportal.FactoryOptions{
		Credentials: fed.Auth, Tunnels: fed.Tunnels, HTTPClient: fed.Guard.Client(), Log: log,
	})
	if err != nil {
		w.t.Fatal(err)
	}
	identityFn := func(r *http.Request) (string, string, bool) {
		id, csrf := session(r)
		return id, csrf, identity.PrincipalFrom(r.Context()).IsAdmin()
	}
	fedportal.NewPortal(fedportal.Deps{
		Store: fedportal.NewStore(w.st), Snapshots: fed.Snapshots, Auth: fed.Auth, Tunnels: fed.Tunnels,
		ClientFactory: factory, Hook: serverChangedHook{w: w, log: log}, Permissions: fed.Permissions,
		Policy: w.policy, Identity: identityFn, Log: log, BaseURL: baseURL,
	}).Mount(p.MountUser)
	as := fedadmin.NewStore(w.st)
	fedadmin.NewAdmin(fedadmin.Deps{
		Store: as, Roles: as, Snapshots: fed.Snapshots, Auth: fed.Auth, Tunnels: fed.Tunnels, ClientFactory: factory,
		Hook: fed.Manager, AllowList: fed.AllowList, Identity: identityFn, Audit: w.rec, Log: log,
	}).Mount(p.MountAdmin)
}

// roleServerBuilders may add MCP servers (and nothing else).
const roleServerBuilders = "server_builders"

// grantAddServers gives u, besides their roles, one an admin marked "May
// add MCP servers" (the admin path: the policy service saves the role,
// the bypass scope assigns it).
func (w *world) grantAddServers(u user) {
	w.t.Helper()
	ctx := w.t.Context()
	if err := w.policy.SaveRole(ctx, w.admin.id, policy.Role{Name: roleServerBuilders, Description: "May add MCP servers", MayAddServers: true}); err != nil {
		w.t.Fatalf("SaveRole %s: %v", roleServerBuilders, err)
	}
	err := w.st.WithJobs(ctx, func(tx store.Tx) error {
		r, err := store.FindRoleByName(ctx, tx, roleServerBuilders)
		if err != nil {
			return err
		}
		return store.AssignRoleIfMissing(ctx, tx, u.id, r.ID, nil)
	})
	if err != nil {
		w.t.Fatalf("assign %s: %v", roleServerBuilders, err)
	}
}

// serverChangedHook is cmd/gateway's adapter of the Manager to the
// portal's hook.
type serverChangedHook struct {
	w   *world
	log *slog.Logger
}

func (h serverChangedHook) ServerChanged(ctx context.Context, serverID string) {
	if err := h.w.fed.Manager.ServerChanged(ctx, serverID); err != nil {
		h.log.Warn("server change not applied yet", "event", "federation.server_changed_failed",
			"server_id", serverID, "error", observability.RedactError(err))
	}
}

// --- portal forms --------------------------------------------------------------

// page is one portal response.
type page struct {
	status   int
	body     string
	location string
}

// do sends a portal request as u; a non-nil form makes it a POST with the
// CSRF token added.
func (w *world) do(u user, method, path string, form url.Values) page {
	w.t.Helper()
	var body io.Reader
	if form != nil {
		f := url.Values{}
		for k, v := range form {
			f[k] = v
		}
		f.Set("_csrf", u.csrf)
		body = strings.NewReader(f.Encode())
	}
	req, _ := http.NewRequestWithContext(w.t.Context(), method, w.srv.URL+path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if u.cookie != nil {
		req.AddCookie(u.cookie)
	}
	res, err := noRedirect.Do(req)
	if err != nil {
		w.t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(res.Body)
	return page{status: res.StatusCode, body: string(b), location: res.Header.Get("Location")}
}

func (w *world) page(u user, path string) page { return w.do(u, http.MethodGet, path, nil) }

func (w *world) submit(u user, path string, form url.Values) page {
	return w.do(u, http.MethodPost, path, form)
}

// mustRedirect asserts a 303 to a location starting with prefix.
func mustRedirect(t *testing.T, what string, p page, prefix string) {
	t.Helper()
	if p.status != http.StatusSeeOther || !strings.HasPrefix(p.location, prefix) {
		t.Fatalf("%s = %d %q, want 303 to %s…\n%s", what, p.status, p.location, prefix, snippet(p.body))
	}
}

var errorParaRE = regexp.MustCompile(`(?s)<p class="error"[^>]*>.*?</p>`)

// snippet keeps failure output readable: the page's error paragraph, else
// its start.
func snippet(body string) string {
	if m := errorParaRE.FindString(body); m != "" {
		return m
	}
	if len(body) > 800 {
		return body[:800]
	}
	return body
}

var serverIDRE = regexp.MustCompile(`^/servers/([0-9a-f-]{36})\?created=1$`)

// addServer submits the add form as u and returns the new server's ID.
func (w *world) addServer(u user, form url.Values) string {
	w.t.Helper()
	p := w.submit(u, "/servers/new", form)
	m := serverIDRE.FindStringSubmatch(p.location)
	if p.status != http.StatusSeeOther || m == nil {
		w.t.Fatalf("add server %s = %d %q\n%s", form.Get("name"), p.status, p.location, snippet(p.body))
	}
	return m[1]
}

// detect presses "Detect authentication" on the add form and returns the
// page.
func (w *world) detect(u user, serverURL string) string {
	w.t.Helper()
	p := w.submit(u, "/servers/new", url.Values{"action": {"detect"}, "url_mode": {"https"}, "url": {serverURL}})
	if p.status != http.StatusOK {
		w.t.Fatalf("detect %s = %d\n%s", serverURL, p.status, snippet(p.body))
	}
	return p.body
}

// refresh presses Refresh on the server page (owner) and returns the
// review page it redirects to.
func (w *world) refresh(u user, serverID string) string {
	w.t.Helper()
	mustRedirect(w.t, "refresh", w.submit(u, "/servers/"+serverID+"/refresh", url.Values{}), "/servers/"+serverID+"/review")
	p := w.page(u, "/servers/"+serverID+"/review")
	if p.status != http.StatusOK {
		w.t.Fatalf("review page = %d\n%s", p.status, snippet(p.body))
	}
	return p.body
}

var (
	enableRE  = regexp.MustCompile(`name="enable" value="(\d+)"( checked)? aria-label="Enable ([^"]+)"`)
	versionRE = regexp.MustCompile(`name="version" value="(\d+)"`)
)

// reviewForm parses a review page: the version, tool name -> form index,
// and the pre-checked tools.
func reviewForm(t *testing.T, body string) (version string, index map[string]string, checked []string) {
	t.Helper()
	v := versionRE.FindStringSubmatch(body)
	if v == nil {
		t.Fatalf("review page without an approve form:\n%s", snippet(body))
	}
	index = map[string]string{}
	for _, m := range enableRE.FindAllStringSubmatch(body, -1) {
		index[m[3]] = m[1]
		if m[2] != "" {
			checked = append(checked, m[3])
		}
	}
	return v[1], index, checked
}

// approve submits the owner's review form with exactly the given tools
// checked (every other tool disabled).
func (w *world) approve(u user, serverID, body string, enable ...string) {
	w.t.Helper()
	version, index, _ := reviewForm(w.t, body)
	form := url.Values{"version": {version}}
	for _, name := range enable {
		i, ok := index[name]
		if !ok {
			w.t.Fatalf("tool %q not on the review page (have %v)", name, index)
		}
		form.Add("enable", i)
	}
	mustRedirect(w.t, "approve", w.submit(u, "/servers/"+serverID+"/review", form), "/servers/"+serverID+"?approved=1")
}

// approveAll submits the owner's review form with "Approve with all tools
// enabled" (action=approve_all) and nothing checked.
func (w *world) approveAll(u user, serverID, body string) {
	w.t.Helper()
	if !strings.Contains(body, `name="action" value="approve_all"`) {
		w.t.Fatalf("review page without approve_all:\n%s", snippet(body))
	}
	version, _, _ := reviewForm(w.t, body)
	mustRedirect(w.t, "approve all", w.submit(u, "/servers/"+serverID+"/review", url.Values{"version": {version}, "action": {"approve_all"}}),
		"/servers/"+serverID+"?approved=1")
}

// allowLoopback allow-lists 127.0.0.1 (where the fake upstreams listen)
// on the admin allow-list page, as an admin would for an internal host.
func (w *world) allowLoopback() {
	w.t.Helper()
	mustRedirect(w.t, "allow-list 127.0.0.1",
		w.submit(w.admin, "/admin/network/allow-hosts", url.Values{"pattern": {"127.0.0.1"}, "note": {"e2e fake upstreams"}}),
		"/admin/network/allow-hosts?done=added")
}

// toolText calls a tool and returns its text, failing on any error.
func (w *world) toolText(cs *sdk.ClientSession, tool string, args map[string]any) string {
	w.t.Helper()
	res, err := w.call(cs, tool, args)
	if err != nil {
		w.t.Fatalf("%s: %v", tool, err)
	}
	if res.IsError {
		w.t.Fatalf("%s: tool error %q", tool, text(w.t, res))
	}
	return text(w.t, res)
}

// roleID reads a role's ID by name (the admin publish form posts IDs).
func (w *world) roleID(name string) string {
	w.t.Helper()
	var id string
	err := w.st.WithJobs(w.t.Context(), func(tx store.Tx) error {
		role, err := store.FindRoleByName(w.t.Context(), tx, name)
		if err != nil {
			return err
		}
		id = role.ID
		return nil
	})
	if err != nil {
		w.t.Fatal(err)
	}
	return id
}

// grant appends tool rules to a role through the policy service (what the
// role editor saves).
func (w *world) grant(roleName string, rules ...policy.ToolRule) {
	w.t.Helper()
	role, err := w.policy.Role(w.t.Context(), roleName)
	if err != nil {
		w.t.Fatal(err)
	}
	role.Rules = append(role.Rules, rules...)
	if err := w.policy.SaveRole(w.t.Context(), w.admin.id, role); err != nil {
		w.t.Fatal(err)
	}
}

// signInAs signs a further user in and gives them role.
func (w *world) signInAs(sub, name, role string) user {
	w.t.Helper()
	u := w.signIn(sub, name)
	if err := w.idSvc.SetUserRole(w.t.Context(), w.admin.id, u.id, role); err != nil {
		w.t.Fatal(err)
	}
	w.policy.Invalidate()
	return u
}

// toolError calls a tool that must fail as a tool result (isError) and
// returns its text.
func (w *world) toolError(cs *sdk.ClientSession, tool string, args map[string]any) string {
	w.t.Helper()
	res, err := w.call(cs, tool, args)
	if err != nil {
		w.t.Fatalf("%s: %v, want a tool error result", tool, err)
	}
	if !res.IsError {
		w.t.Fatalf("%s succeeded (%q), want a tool error", tool, text(w.t, res))
	}
	return text(w.t, res)
}

// hasAudit reports whether u has an audit row for tool with the outcome
// and error class ("" matches any).
func (w *world) hasAudit(u user, tool, outcome, class string) bool {
	for _, ev := range w.events(u) {
		if ev.Tool == tool && (outcome == "" || ev.Outcome == outcome) && (class == "" || ev.ErrorClass == class) {
			return true
		}
	}
	return false
}

// --- fake upstreams ----------------------------------------------------------------

// statelessMCP serves s over Streamable HTTP (stateless, JSON answers).
func statelessMCP(s *sdk.Server) http.Handler {
	return sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return s }, &sdk.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
}

func textResult(s string) *sdk.CallToolResult {
	return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: s}}}
}
