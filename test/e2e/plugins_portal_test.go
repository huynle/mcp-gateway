//go:build integration || e2e

package e2e

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/store"
)

const ledgerAliceKey = "alice-ledger-key-e2e"

// TestE2EPluginsPortalAddDetectConnectReviewAndApprove is the servers
// portal acceptance scenario (task w2cd39bc, plan 0omkv2e1), through the
// portal's HTTP handlers and the official MCP client against the
// in-process gateway:
//
//  1. alice detects three servers on the add form (a Brain-shaped OAuth
//     server with dynamic client registration, an API-key-only server, a
//     server without auth) and adds them; the API key and no-auth servers
//     are refreshed, approved and called;
//  2. she connects the OAuth server through /servers/{id}/connect, the
//     server's authorization server (DCR, PKCE S256, resource) and the
//     callback: the connection is stored and its tools are callable with
//     the upstream token;
//  3. her write needs an approval (portal approve, as in v1) and is
//     ledgered;
//  4. the upstream changes a tool's schema and adds a tool: Refresh shows
//     the diff on the review page, the changed tool is refused until she
//     re-enables it, then it is callable with the new schema.
func TestE2EPluginsPortalAddDetectConnectReviewAndApprove(t *testing.T) {
	w := newWorld(t, options{federation: true})
	w.forbid(ledgerAliceKey, "upstream API key")
	w.allowLoopback()
	brain := newBrainUpstream(t, w.forbid)
	ledgerUp := newKeyUpstream(t, "ledger", "X-Ledger-Key", map[string]string{ledgerAliceKey: "alice"})
	clock := sdk.NewServer(&sdk.Implementation{Name: "clock", Version: "1"}, nil)
	sdk.AddTool(clock, &sdk.Tool{Name: "now", Description: "The time.", Annotations: &sdk.ToolAnnotations{ReadOnlyHint: true}},
		func(context.Context, *sdk.CallToolRequest, struct{}) (*sdk.CallToolResult, any, error) {
			return textResult("noon"), nil, nil
		})
	clockSrv := newOpenUpstream(t, clock)

	// 1. Detect on the add form.
	body := w.detect(w.alice, brain.mcpURL())
	for _, want := range []string{"Detected: <strong>oauth</strong>", "dynamic client registration", "PKCE S256", `value="oauth" checked`} {
		if !strings.Contains(body, want) {
			t.Errorf("detect (Brain-shaped OAuth server) lacks %q:\n%s", want, detectNotice(body))
		}
	}
	body = w.detect(w.alice, ledgerUp.srv.URL+"/mcp")
	if !strings.Contains(body, "Detected: <strong>api_key</strong>") || strings.Contains(body, "<strong>oauth</strong>") || !strings.Contains(body, `value="api_key" checked`) {
		t.Errorf("detect (API-key-only server):\n%s", detectNotice(body))
	}
	body = w.detect(w.alice, clockSrv.URL)
	if !strings.Contains(body, "Detected: <strong>none</strong>.") || !strings.Contains(body, `value="none" checked`) {
		t.Errorf("detect (no-auth server):\n%s", detectNotice(body))
	}

	brainID := w.addServer(w.alice, url.Values{"name": {"brain"}, "url_mode": {"https"}, "url": {brain.mcpURL()},
		"auth_kind": {"oauth"}, "credential_mode": {"per_user"}})
	ledgerID := w.addServer(w.alice, url.Values{"name": {"ledger"}, "url_mode": {"https"}, "url": {ledgerUp.srv.URL + "/mcp"},
		"auth_kind": {"api_key"}, "credential_mode": {"per_user"}, "api_key_in": {"header"}, "api_key_name": {"X-Ledger-Key"}})
	clockID := w.addServer(w.alice, url.Values{"name": {"clock"}, "url_mode": {"https"}, "url": {clockSrv.URL},
		"auth_kind": {"none"}, "credential_mode": {"per_user"}})
	for id, want := range map[string]string{brainID: "needs connect", ledgerID: "needs connect", clockID: "no connection needed"} {
		if p := w.page(w.alice, "/servers/"+id); p.status != http.StatusOK || !strings.Contains(p.body, want) || !strings.Contains(p.body, "private") {
			t.Errorf("server page %s = %d, want %q:\n%s", id, p.status, want, snippet(p.body))
		}
	}

	// The no-auth server: refresh, approve, call.
	review := w.refresh(w.alice, clockID)
	if _, _, checked := reviewForm(t, review); len(checked) != 0 {
		t.Errorf("first review pre-checks %v; new tools must start unchecked", checked)
	}
	w.approve(w.alice, clockID, review, "now")
	alice := w.client(w.alice)
	if got := w.toolText(alice, "clock.now", map[string]any{}); got != "noon" {
		t.Errorf("clock.now = %q", got)
	}

	// The API key server: Refresh needs her key first.
	p := w.submit(w.alice, "/servers/"+ledgerID+"/refresh", url.Values{})
	if p.status != http.StatusBadGateway || !strings.Contains(p.body, "Connect to the server first.") {
		t.Errorf("refresh without a key = %d\n%s", p.status, snippet(p.body))
	}
	mustRedirect(t, "save API key", w.submit(w.alice, "/servers/"+ledgerID+"/credential", url.Values{"api_key": {ledgerAliceKey}}),
		"/servers/"+ledgerID+"?connected=1")
	w.approve(w.alice, ledgerID, w.refresh(w.alice, ledgerID), "lookup")
	if got := w.toolText(alice, "ledger.lookup", map[string]any{"q": "acme"}); got != "lookup acme with alice" {
		t.Errorf("ledger.lookup = %q", got)
	}
	for _, h := range ledgerUp.headers() {
		if h.Get("Authorization") != "" || h.Get("Cookie") != "" {
			t.Errorf("API key upstream received gateway credentials: %v", h)
		}
	}

	// 2. OAuth connect through the portal.
	p = w.page(w.alice, "/servers/"+brainID+"/connect")
	if p.status != http.StatusFound {
		t.Fatalf("connect = %d %q\n%s", p.status, p.location, snippet(p.body))
	}
	back := brain.authorize(t, p.location)
	if back.Path != "/servers/oauth/callback" || !strings.HasPrefix(back.String(), baseURL) {
		t.Fatalf("redirect URI = %s, want %s/servers/oauth/callback", back, baseURL)
	}
	// The browser follows the redirect to the gateway (BaseURL is the
	// public name of the in-process server).
	mustRedirect(t, "callback", w.page(w.alice, back.Path+"?"+back.RawQuery), "/servers/"+brainID+"?connect=ok")
	if brain.registrations != 1 {
		t.Errorf("dynamic client registrations = %d, want 1", brain.registrations)
	}
	if p := w.page(w.alice, "/servers/"+brainID); !strings.Contains(p.body, ">connected<") {
		t.Errorf("server page after connect:\n%s", snippet(p.body))
	}
	if n := countMCPUserConnections(t, w, brainID); n != 1 {
		t.Errorf("stored OAuth connections = %d, want 1", n)
	}
	review = w.refresh(w.alice, brainID)
	_, index, _ := reviewForm(t, review)
	if len(index) != 2 || index["recall"] == "" || index["save"] == "" {
		t.Fatalf("review tools = %v", index)
	}
	w.approve(w.alice, brainID, review, "recall", "save")
	alice = w.client(w.alice)
	tools := toolNames(t, alice)
	if !contains(tools, "brain.recall") || !contains(tools, "brain.save") {
		t.Fatalf("alice's tools = %v", tools)
	}
	if got := w.toolText(alice, "brain.recall", map[string]any{"q": "plans"}); got != "recall: plans" {
		t.Errorf("brain.recall = %q", got)
	}
	// Bob cannot see alice's private servers.
	bob := w.client(w.bob)
	for _, name := range toolNames(t, bob) {
		if strings.HasPrefix(name, "brain.") || strings.HasPrefix(name, "ledger.") || strings.HasPrefix(name, "clock.") {
			t.Errorf("bob sees alice's private tool %s", name)
		}
	}
	if p := w.page(w.bob, "/servers/"+brainID); p.status != http.StatusNotFound {
		t.Errorf("bob's view of alice's server page = %d, want 404", p.status)
	}

	// 3. A write needs an approval, then runs once and is ledgered.
	_, err := w.call(alice, "brain.save", map[string]any{"title": "e2e-note"})
	id := approvalRequired(t, err)
	if len(brain.savedTitles()) != 0 {
		t.Fatal("the write reached the upstream before its approval")
	}
	if code, _ := w.post(w.alice, "/approvals/"+id+"/approve", true); code != http.StatusSeeOther {
		t.Fatalf("approve = %d", code)
	}
	if got := w.toolText(alice, "brain.save", map[string]any{"title": "e2e-note", "approval_id": id}); got != "saved" {
		t.Errorf("approved write = %q", got)
	}
	if got := brain.savedTitles(); !slices.Equal(got, []string{"e2e-note"}) {
		t.Errorf("upstream writes = %v", got)
	}
	if op := w.opFor(w.alice, "brain.save", store.LedgerSucceeded); op == nil {
		t.Error("the approved write has no succeeded ledger operation")
	}

	// 4. The upstream changes recall's schema and adds forget.
	brain.v2.Store(true)
	review = w.refresh(w.alice, brainID)
	for _, want := range []string{"Version 2 is waiting for review (approved: version 1)", `<span class="changed">changed:`, `<span class="added">added</span>`} {
		if !strings.Contains(review, want) {
			t.Errorf("review after refresh lacks %q", want)
		}
	}
	if !regexp.MustCompile(`(?s)<code>recall</code></strong>.{0,80}<span class="changed">changed:`).MatchString(review) ||
		!regexp.MustCompile(`(?s)<code>forget</code></strong>.{0,80}<span class="added">added</span>`).MatchString(review) {
		t.Errorf("review does not mark recall changed and forget added:\n%s", review)
	}
	if _, _, checked := reviewForm(t, review); len(checked) != 0 {
		t.Errorf("refresh review pre-checks %v; changed, new and write tools must start unchecked", checked)
	}
	// Until it is approved, the pinned (old) schema still applies.
	_, err = w.call(alice, "brain.recall", map[string]any{"q": "plans", "limit": 2})
	_ = rpcError(t, err, mcp.CodeInvalidParams)
	// Alice approves the new version without re-enabling the changed tool.
	w.approve(w.alice, brainID, review, "save")
	alice = w.client(w.alice)
	if tools := toolNames(t, alice); contains(tools, "brain.recall") || contains(tools, "brain.forget") || !contains(tools, "brain.save") {
		t.Errorf("tools after approving without recall = %v", tools)
	}
	_, err = w.call(alice, "brain.recall", map[string]any{"q": "plans", "limit": 2})
	_ = rpcError(t, err, mcp.CodeToolNotFound)
	// She re-enables it (and forget).
	review = w.page(w.alice, "/servers/"+brainID+"/review").body
	if !strings.Contains(review, "Version 2 is the approved snapshot") {
		t.Errorf("review page after approval:\n%s", snippet(review))
	}
	w.approve(w.alice, brainID, review, "recall", "save", "forget")
	alice = w.client(w.alice)
	if got := w.toolText(alice, "brain.recall", map[string]any{"q": "plans", "limit": 2}); got != "recall v2: plans" {
		t.Errorf("re-enabled brain.recall = %q", got)
	}
	_, err = w.call(alice, "brain.forget", map[string]any{"title": "x"})
	approvalRequired(t, err)

	// Only the upstream token ever reached the upstream.
	brain.mu.Lock()
	bearers := append([]string(nil), brain.bearers...)
	brain.mu.Unlock()
	if len(bearers) == 0 {
		t.Fatal("the OAuth upstream saw no authorized request")
	}
	for _, b := range bearers {
		if !strings.HasPrefix(b, "Bearer brain-at-") {
			t.Errorf("upstream Authorization %q is not its own token", b[:min(len(b), 16)])
		}
	}
}

// detectNotice is the detection result block of the add form.
func detectNotice(body string) string {
	if m := regexp.MustCompile(`(?s)<div class="(notice|error)" role="status">.*?</div>`).FindString(body); m != "" {
		return m
	}
	return snippet(body)
}

// countMCPUserConnections counts the stored per-user connections of a
// server (through the bypass scope).
func countMCPUserConnections(t *testing.T, w *world, serverID string) int {
	t.Helper()
	var n int
	err := w.st.WithJobs(t.Context(), func(tx store.Tx) error {
		return tx.QueryRow(t.Context(), `SELECT count(*) FROM mcp_server_user_connections WHERE server_id = $1`, serverID).Scan(&n)
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}
