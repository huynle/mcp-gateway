//go:build integration || e2e || security

package security

// The gateway.* management tools (Brain task 99b5yzdb) under attack:
// secrets passed as arguments, SSRF through detect_auth and add_server
// (the real netguard, no allow-list entry), and cross-user reach to
// another user's server by name or ID (IDOR).

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

// gatewayToolsOn switches u's gateway tools on (u may add servers) and
// returns an MCP client.
func (w *world) gatewayToolsOn(u user) *sdk.ClientSession {
	w.t.Helper()
	if err := w.gw.Setting(w.perms).SetGatewayToolsEnabled(w.t.Context(), u.id, true); err != nil {
		w.t.Fatalf("switch gateway tools on for %s: %v", u.id, err)
	}
	return w.client(u)
}

// gwError calls a gateway tool that must fail as a tool result and
// returns its text.
func (w *world) gwError(cs *sdk.ClientSession, tool string, args map[string]any) string {
	w.t.Helper()
	res, err := w.call(cs, tool, args)
	if err != nil {
		w.t.Fatalf("%s: %v, want a tool error result", tool, err)
	}
	if !res.IsError {
		w.t.Fatalf("%s succeeded: %s", tool, text(w.t, res))
	}
	return text(w.t, res)
}

// toolText calls a tool that must succeed and returns its text.
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

func (w *world) serverCount() int {
	w.t.Helper()
	var n int
	err := w.st.WithJobs(w.t.Context(), func(tx store.Tx) error {
		all, err := store.ListAllMCPServers(w.t.Context(), tx)
		n = len(all)
		return err
	})
	if err != nil {
		w.t.Fatal(err)
	}
	return n
}

// TestSecurityGatewayToolsSecretArguments: every way of slipping a secret
// into add_server is refused before anything is stored, the answer never
// echoes it, and it never reaches the logs or the audit trail
// (scanForLeaks at cleanup).
func TestSecurityGatewayToolsSecretArguments(t *testing.T) {
	w := newWorld(t, options{federation: true})
	alice := w.gatewayToolsOn(w.alice)
	const secret = "sk-live-gwtools-9f8e7d6c5b4a"
	w.forbid(secret, "secret passed to a gateway tool")
	base := func(extra map[string]any) map[string]any {
		args := map[string]any{"name": "victim", "url": "https://api.example.com/mcp", "auth_kind": "api_key", "credential_mode": "per_user"}
		for k, v := range extra {
			args[k] = v
		}
		return args
	}
	for _, extra := range []map[string]any{
		{"api_key": secret},
		{"apiKey": secret},
		{"x-api-key": secret},
		{"token": secret},
		{"bearer_token": secret},
		{"password": secret},
		{"client_secret": secret},
		{"credentials": map[string]any{"value": secret}},
		{"headers": map[string]any{"Authorization": "Bearer " + secret}},
		{"Authorization": "Bearer " + secret},
		{"cookie": "session=" + secret},
		{"url": "https://api.example.com/mcp?api_key=" + secret},
		{"url": "https://api.example.com/mcp?access_token=" + secret},
		{"url": "https://user:" + secret + "@api.example.com/mcp"},
		{"static_header_names": []any{"Authorization: Bearer " + secret}},
		{"api_key_name": "Bearer " + secret},
	} {
		msg := w.gwError(alice, "gateway.add_server", base(extra))
		if strings.Contains(msg, secret) || !strings.Contains(msg, "browser") {
			t.Errorf("%v: answer %q echoes the secret or does not point to the browser", keys(extra), msg)
		}
	}
	// The secret is not in the wire answer either.
	token := w.token(w.alice, tokens.CreateRequest{})
	_, _, body := w.rawCall(token, "gateway.add_server", base(map[string]any{"token": secret}))
	if strings.Contains(string(body), secret) {
		t.Errorf("wire answer echoes the secret: %s", body)
	}
	if n := w.serverCount(); n != 0 {
		t.Fatalf("%d servers stored from refused arguments", n)
	}
}

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestSecurityGatewayToolsSSRF: detect_auth and add_server never reach an
// internal address through the real netguard (no allow-list entry): the
// metadata address, loopback (literal, ambiguous numeric, IPv6, a name
// resolving to it), private ranges. The loopback upstream is never hit,
// nothing is stored, and the refusal is the class-level SSRF message.
func TestSecurityGatewayToolsSSRF(t *testing.T) {
	w := newWorld(t, options{federation: true})
	alice := w.gatewayToolsOn(w.alice)
	var hits atomic.Int32
	internal := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		rw.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(internal.Close)
	port := internal.Listener.Addr().(interface{ String() string }).String()
	_, port, _ = strings.Cut(port, ":")

	targets := []string{
		internal.URL + "/mcp", // https://127.0.0.1:<port>
		"https://169.254.169.254/latest/meta-data/",
		"https://2130706433:" + port + "/mcp",
		"https://0x7f.1:" + port + "/mcp",
		"https://[::1]:" + port + "/mcp",
		"https://10.0.0.1/mcp",
		"https://192.168.1.1/mcp",
		"https://[::ffff:127.0.0.1]:" + port + "/mcp",
	}
	for _, u := range targets {
		msg := w.gwError(alice, "gateway.detect_auth", map[string]any{"url": u})
		if !strings.Contains(msg, "SSRF") && !strings.Contains(msg, "blocked") {
			t.Errorf("detect_auth %s = %q, want the network-policy refusal", u, msg)
		}
		w.gwError(alice, "gateway.add_server", map[string]any{"name": "ssrf", "url": u, "auth_kind": "none", "credential_mode": "per_user"})
	}
	// A name that resolves to loopback passes the literal check but is
	// refused at dial time.
	msg := w.gwError(alice, "gateway.detect_auth", map[string]any{"url": "https://localhost:" + port + "/mcp"})
	if !strings.Contains(msg, "SSRF") && !strings.Contains(msg, "blocked") && !strings.Contains(msg, "could not be reached") {
		t.Errorf("detect_auth localhost = %q", msg)
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("the internal server was reached %d times", n)
	}
	if n := w.serverCount(); n != 0 {
		t.Errorf("%d servers stored for internal addresses", n)
	}
}

// TestSecurityGatewayToolsCrossUser: alice cannot see, read, connect to,
// refresh or delete bob's private server by name or ID: every answer is
// the same as for a server that does not exist. She cannot point a new
// server at bob's tunnel. Owner-only tools refuse a server bob published
// to her. A user without the permission gets no gateway tools at all.
func TestSecurityGatewayToolsCrossUser(t *testing.T) {
	w := newWorld(t, options{federation: true})
	alice := w.gatewayToolsOn(w.alice)
	bobs := w.addServer(w.bob, "bobsrv", "https://bob.example.com/mcp", nil)
	missing := "00000000-0000-4000-8000-000000000000"

	list := w.toolText(alice, "gateway.list_servers", nil)
	if strings.Contains(list, bobs.ID) || strings.Contains(list, "bobsrv") {
		t.Errorf("alice's list shows bob's server: %s", list)
	}
	for _, tool := range []string{"gateway.get_server", "gateway.connect_link", "gateway.refresh_server", "gateway.delete_server"} {
		for _, pair := range [][2]string{{"bobsrv", "nosuchsrv"}, {bobs.ID, missing}} {
			got := w.gwRefusal(w.alice, alice, tool, pair[0])
			want := w.gwRefusal(w.alice, alice, tool, pair[1])
			if strings.ReplaceAll(got, pair[0], "X") != strings.ReplaceAll(want, pair[1], "X") || !strings.Contains(got, "no server") {
				t.Errorf("%s: bob's %q = %q; missing %q = %q", tool, pair[0], got, pair[1], want)
			}
		}
	}
	// Bob's server is untouched: still there, never refreshed.
	if w.serverCount() != 1 {
		t.Error("bob's server was deleted")
	}
	if _, err := w.fed.Snapshots.Latest(t.Context(), snapshot.System(), bobs.ID); err == nil {
		t.Error("bob's server was refreshed by alice")
	}

	// Bob's tunnel is not alice's to use.
	tun, _, err := w.fed.Tunnels.CreateTunnel(t.Context(), w.bob.id, "bobs-laptop")
	if err != nil {
		t.Fatal(err)
	}
	msg := w.gwError(alice, "gateway.add_server", map[string]any{"name": "steal", "url": "tunnel://" + tun.ID + "/mcp", "auth_kind": "none", "credential_mode": "per_user"})
	if !strings.Contains(msg, "your own tunnels") {
		t.Errorf("tunnel of another user = %q", msg)
	}

	// Published to alice: readable, but refresh and delete are the owner's.
	w.publish(bobs, nil, roleMember)
	if got := w.toolText(alice, "gateway.get_server", map[string]any{"server": "bobsrv"}); !strings.Contains(got, `"owner":false`) {
		t.Errorf("published server = %s", got)
	}
	for _, tool := range []string{"gateway.refresh_server", "gateway.delete_server"} {
		if got := w.gwRefusal(w.alice, alice, tool, "bobsrv"); !strings.Contains(got, "that you own") {
			t.Errorf("%s on bob's published server = %q", tool, got)
		}
	}
	if w.serverCount() != 1 {
		t.Error("bob's published server was deleted by alice")
	}
}

// gwRefusal calls tool with {"server": arg} and returns the tool error
// text. delete_server needs an approval before the tool runs (the policy
// stage comes first): the approval reveals nothing (it is asked for
// whatever the server), so the caller approves it on the portal and
// retries, and the refusal is the retry's answer.
func (w *world) gwRefusal(u user, cs *sdk.ClientSession, tool, arg string) string {
	w.t.Helper()
	args := map[string]any{"server": arg}
	res, err := w.call(cs, tool, args)
	if err != nil {
		id := approvalRequired(w.t, err)
		if code, _, _ := w.post(u, "/approvals/"+id+"/approve", nil); code != http.StatusSeeOther {
			w.t.Fatalf("approve %s = %d", tool, code)
		}
		args["approval_id"] = id
		if res, err = w.call(cs, tool, args); err != nil {
			w.t.Fatalf("%s %q retried with the approval: %v", tool, arg, err)
		}
	}
	if !res.IsError {
		b, _ := json.Marshal(res.Content)
		w.t.Fatalf("%s %q succeeded: %s", tool, arg, b)
	}
	return text(w.t, res)
}
