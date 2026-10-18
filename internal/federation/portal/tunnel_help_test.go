package portal

import (
	"html"
	"net/url"
	"strings"
	"testing"
)

const (
	brewInstall = "brew install huynle/tap/mcp-gateway"
	curlInstall = "curl -fsSL https://github.com/huynle/mcp-gateway/releases/latest/download/install.sh | sh"
)

// After creating a tunnel the page shows how to install the CLI and the
// exact commands with the gateway URL, the token (once) and the server
// address prefilled, each with a copy button driven by the same-origin
// copy.js (no inline script).
func TestTunnelCreateShowsInstallAndRunCommands(t *testing.T) {
	e := newEnv(t)
	r := e.post("/servers/tunnels", alice, url.Values{"name": {"laptop"}})
	if r.code != 200 {
		t.Fatalf("status %d: %s", r.code, r.body)
	}
	token := "mgt_ABCDEFGH_" + strings.Repeat("s", 43)
	id := e.st.tunnels[0].ID
	body := html.UnescapeString(r.body)
	mustContain(t, body, brewInstall, curlInstall,
		"MCP_GATEWAY_TUNNEL_TOKEN="+token+` mcp-gateway tunnel --gateway https://gw.example --stdio "<your server command>"`,
		"MCP_GATEWAY_TUNNEL_TOKEN="+token+" mcp-gateway tunnel --gateway https://gw.example --http http://localhost:PORT/mcp",
		"tunnel://"+id,
		`data-copy=`, `src="/static/copy.js?v=`)
	if strings.Contains(r.body, "<script>") || strings.Contains(r.body, "onclick=") {
		t.Error("inline script on the tunnel page")
	}
	// Every copy button copies exactly the text of a command shown.
	if n := strings.Count(r.body, "data-copy-target="); n < 5 {
		t.Errorf("%d copy buttons, want one per command (>= 5)", n)
	}
}

// The tunnel list shows the run command for each live tunnel with a token
// placeholder (the token is never shown again) and the install commands.
func TestTunnelListShowsRunCommandWithoutToken(t *testing.T) {
	e := newEnv(t)
	tun, token, err := e.tun.CreateTunnel(t.Context(), alice, "laptop")
	if err != nil {
		t.Fatal(err)
	}
	r := e.get("/servers", alice)
	body := html.UnescapeString(r.body)
	mustNotContain(t, body, token)
	mustContain(t, body, brewInstall, curlInstall,
		`MCP_GATEWAY_TUNNEL_TOKEN=<token shown once> mcp-gateway tunnel --gateway https://gw.example --stdio "<your server command>"`,
		"MCP_GATEWAY_TUNNEL_TOKEN=<token shown once> mcp-gateway tunnel --gateway https://gw.example --http http://localhost:PORT/mcp",
		"tunnel://"+tun.ID, `src="/static/copy.js?v=`)
}

// Without tunnels there is nothing to run, so no install help either.
func TestNoTunnelsNoInstallHelp(t *testing.T) {
	e := newEnv(t)
	body := html.UnescapeString(e.get("/servers", alice).body)
	mustNotContain(t, body, brewInstall)
}
