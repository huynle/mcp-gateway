package portal

import (
	"net/url"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/store"
)

func browseEnv(t *testing.T) (*env, *store.MCPServer) {
	e := newEnv(t)
	s := e.st.add(store.MCPServer{Name: "notes", URL: "https://notes.example/mcp", OwnerUserID: alice, AuthKind: store.MCPAuthNone})
	e.snap.approved(s.ID, &snapshot.Snapshot{
		Resources: []snapshot.Resource{
			{URI: "blob://img", Name: "logo", MIMEType: "image/png"},
			{URI: "file:///a.txt", Name: "a", Description: "<b>bold</b> claim", MIMEType: "text/plain"},
			{URI: "file:///broken", Name: "broken"},
		},
		ResourceTemplates: []snapshot.ResourceTemplate{{URITemplate: "file:///{path}", Name: "files", Description: "any file"}},
		Prompts: []snapshot.Prompt{{Name: "summarize", Description: "Summarize <i>a</i> topic",
			Arguments: []snapshot.PromptArgument{{Name: "topic", Description: "what", Required: true}, {Name: "style"}}}},
	}, snapshot.Review{})
	e.fac.sess.resources = map[string]*mcp.ReadResourceResult{
		"file:///a.txt": {Contents: []*mcp.ResourceContents{{URI: "file:///a.txt", MIMEType: "text/plain",
			Text: "<script>x</script>\x1b[2J" + strings.Repeat("B", 100000)}}},
		"blob://img": {Contents: []*mcp.ResourceContents{{URI: "blob://img", MIMEType: "image/png", Blob: make([]byte, 3000)}}},
	}
	e.fac.sess.prompts = map[string]*mcp.GetPromptResult{
		"summarize": {Description: "d", Messages: []*mcp.PromptMessage{
			{Role: "user", Content: &mcp.TextContent{Text: "Summarize <b>go</b>"}},
			{Role: "assistant", Content: &mcp.ImageContent{MIMEType: "image/jpeg", Data: make([]byte, 10)}},
		}},
	}
	return e, s
}

func TestResourcesPageListsTheApprovedSnapshot(t *testing.T) {
	e, s := browseEnv(t)
	r := e.get("/servers/"+s.ID+"/resources", alice)
	if r.code != 200 {
		t.Fatalf("status %d", r.code)
	}
	mustContain(t, r.body, "file:///a.txt", "blob://img", "image/png", "&lt;b&gt;bold&lt;/b&gt; claim", "file:///{path}", "files",
		"summarize", "Summarize &lt;i&gt;a&lt;/i&gt; topic", "topic", "required", `action="/servers/`+s.ID+`/resources/read"`,
		`href="/servers/`+s.ID+`/prompts/summarize"`)
	mustNotContain(t, r.body, "<b>bold")
	if len(e.fac.opened) != 0 {
		t.Error("listing contacted the upstream")
	}

	none := e.st.add(store.MCPServer{Name: "empty", URL: "https://e.example/mcp", OwnerUserID: alice, AuthKind: store.MCPAuthNone})
	mustContain(t, e.get("/servers/"+none.ID+"/resources", alice).body, "No reviewed snapshot")
}

func TestReadResourcePreviewIsBoundedAndEscaped(t *testing.T) {
	e, s := browseEnv(t)
	r := e.post("/servers/"+s.ID+"/resources/read", alice, url.Values{"uri": {"file:///a.txt"}})
	if r.code != 200 {
		t.Fatalf("status %d: %s", r.code, r.body)
	}
	mustContain(t, r.body, "&lt;script&gt;x&lt;/script&gt;", "text/plain", "truncated")
	mustNotContain(t, r.body, "<script>x", "\x1b", strings.Repeat("B", maxPreviewRunes+1))
	if !e.fac.sess.closed || len(e.fac.sess.reads) != 1 || e.fac.sess.reads[0] != "file:///a.txt" {
		t.Errorf("reads %v closed %v", e.fac.sess.reads, e.fac.sess.closed)
	}

	r = e.post("/servers/"+s.ID+"/resources/read", alice, url.Values{"uri": {"blob://img"}})
	mustContain(t, r.body, "3000 bytes", "image/png")

	// Upstream errors are class-level, never the upstream's text.
	r = e.post("/servers/"+s.ID+"/resources/read", alice, url.Values{"uri": {"file:///broken"}})
	if r.code != 502 {
		t.Errorf("broken: %d", r.code)
	}
	mustNotContain(t, r.body, "secret internal detail")

	// Only resources of the approved snapshot can be read.
	before := len(e.fac.opened)
	r = e.post("/servers/"+s.ID+"/resources/read", alice, url.Values{"uri": {"file:///etc/passwd"}})
	if r.code != 422 || len(e.fac.opened) != before {
		t.Errorf("unlisted uri: %d, opened %v", r.code, e.fac.opened)
	}
	mustContain(t, r.body, "not a resource of the reviewed snapshot")
}

func TestPromptPreview(t *testing.T) {
	e, s := browseEnv(t)
	r := e.get("/servers/"+s.ID+"/prompts/summarize", alice)
	if r.code != 200 {
		t.Fatalf("status %d", r.code)
	}
	mustContain(t, r.body, `name="arg_0"`, `name="arg_1"`, "topic", "style", `action="/servers/`+s.ID+`/prompts/summarize"`)
	if len(e.fac.opened) != 0 {
		t.Error("GET contacted the upstream")
	}

	r = e.post("/servers/"+s.ID+"/prompts/summarize", alice, url.Values{"arg_0": {"go"}})
	if r.code != 200 {
		t.Fatalf("post %d: %s", r.code, r.body)
	}
	if len(e.fac.sess.gets) != 1 || e.fac.sess.gets[0]["topic"] != "go" || len(e.fac.sess.gets[0]) != 1 {
		t.Errorf("get prompt args %v", e.fac.sess.gets)
	}
	mustContain(t, r.body, "user", "Summarize &lt;b&gt;go&lt;/b&gt;", "assistant", "image/jpeg", `value="go"`)
	mustNotContain(t, r.body, "<b>go")

	r = e.post("/servers/"+s.ID+"/prompts/summarize", alice, url.Values{"arg_1": {"short"}})
	if r.code != 422 {
		t.Errorf("missing required: %d", r.code)
	}
	mustContain(t, r.body, "is required")
	if r := e.get("/servers/"+s.ID+"/prompts/unknown", alice); r.code != 404 {
		t.Errorf("unknown prompt: %d", r.code)
	}
}

func TestTunnelCreateShowsTokenOnceAndCommand(t *testing.T) {
	e := newEnv(t)
	r := e.post("/servers/tunnels", alice, url.Values{"name": {"laptop"}})
	if r.code != 200 {
		t.Fatalf("status %d: %s", r.code, r.body)
	}
	token := "mgt_ABCDEFGH_" + strings.Repeat("s", 43)
	mustContain(t, r.body, token, "mcp-gateway-tunnel --gateway https://gw.example --token "+token+" --stdio", "MCP_GATEWAY_TUNNEL_TOKEN="+token,
		"shown only once", "laptop")
	if r.hdr.Get("Cache-Control") != "no-store" {
		t.Error("token page cacheable")
	}
	id := e.st.tunnels[0].ID
	mustContain(t, r.body, "tunnel://"+id)

	r = e.get("/servers", alice)
	mustNotContain(t, r.body, token)
	mustContain(t, r.body, "laptop", id, "offline")
	e.tun.online[id] = true
	mustContain(t, e.get("/servers", alice).body, "online")

	for _, name := range []string{"", strings.Repeat("n", 101), "bad\x01name"} {
		if r := e.post("/servers/tunnels", alice, url.Values{"name": {name}}); r.code != 422 {
			t.Errorf("name %q: %d", name, r.code)
		}
	}
}

func TestTunnelRevoke(t *testing.T) {
	e := newEnv(t)
	mine, _, _ := e.tun.CreateTunnel(t.Context(), alice, "laptop")
	theirs, _, _ := e.tun.CreateTunnel(t.Context(), bob, "box")
	if r := e.post("/servers/tunnels/revoke", alice, url.Values{"id": {theirs.ID}}); r.code != 404 {
		t.Errorf("revoke other's: %d", r.code)
	}
	r := e.post("/servers/tunnels/revoke", alice, url.Values{"id": {mine.ID}})
	if r.code != 303 || r.hdr.Get("Location") != "/servers?revoked=1" || len(e.tun.revoked) != 1 {
		t.Errorf("revoke: %d %q %v", r.code, r.hdr.Get("Location"), e.tun.revoked)
	}
	mustNotContain(t, e.get("/servers", alice).body, mine.ID)
}
