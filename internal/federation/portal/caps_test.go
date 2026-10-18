package portal

import (
	"fmt"
	"net/url"
	"testing"

	"github.com/huynle/mcp-gateway/internal/caps"
)

func TestCreateServerAtCapShowsLimitMessage(t *testing.T) {
	e := newEnv(t)
	e.st.createErr = fmt.Errorf("wrapped: %w", &caps.ExceededError{Resource: caps.Servers, Limit: 10})
	r := e.post("/servers/new", alice, addForm("action", "create", "name", "notes", "url", "https://notes.example/mcp", "auth_kind", "none"))
	if r.code != 422 {
		t.Fatalf("status %d", r.code)
	}
	mustContain(t, r.body, "You have reached the limit of 10 MCP servers", "ask an admin")
	if len(e.hook.changed) != 0 {
		t.Error("hook ran for a refused server")
	}
}

func TestCreateTunnelAtCapShowsLimitMessage(t *testing.T) {
	e := newEnv(t)
	e.tun.createErr = &caps.ExceededError{Resource: caps.Tunnels, Limit: 5}
	r := e.post("/servers/tunnels", alice, url.Values{"name": {"laptop"}})
	if r.code != 422 {
		t.Fatalf("status %d", r.code)
	}
	mustContain(t, r.body, "You have reached the limit of 5 tunnels", "ask an admin")
	mustNotContain(t, r.body, "mgt_")
}
