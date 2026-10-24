package connector

import (
	"testing"

	"github.com/huynle/mcp-gateway/internal/store"
)

// The portal paths of a server, shared by the servers portal, the
// gateway.* management tools and the credential-link errors.
func TestServerPaths(t *testing.T) {
	for got, want := range map[string]string{
		ServerPath("s1"):     "/servers/s1",
		ConnectionPath("s1"): "/servers/s1#connection",
		ConnectPath("s1"):    "/servers/s1/connect",
		ReviewPath("s1"):     "/servers/s1/review",
		EditPath("s1"):       "/servers/s1/edit",
	} {
		if got != want {
			t.Errorf("path = %q, want %q", got, want)
		}
	}
}

// ConnectLink is the OAuth sign-in for a per-user OAuth server and the
// "My connection" form for every other server (per-user api key, bearer
// or headers; per-user header values on a shared server).
func TestConnectLink(t *testing.T) {
	cases := []struct {
		mode, kind, want string
	}{
		{store.MCPCredentialPerUser, store.MCPAuthOAuth, "https://gw.example/servers/s1/connect"},
		{store.MCPCredentialPerUser, store.MCPAuthAPIKey, "https://gw.example/servers/s1#connection"},
		{store.MCPCredentialPerUser, store.MCPAuthBearer, "https://gw.example/servers/s1#connection"},
		{store.MCPCredentialPerUser, store.MCPAuthHeaders, "https://gw.example/servers/s1#connection"},
		{store.MCPCredentialShared, store.MCPAuthOAuth, "https://gw.example/servers/s1#connection"},
		{store.MCPCredentialShared, store.MCPAuthNone, "https://gw.example/servers/s1#connection"},
	}
	for _, tc := range cases {
		s := &store.MCPServer{ID: "s1", CredentialMode: tc.mode, AuthKind: tc.kind}
		for _, base := range []string{"https://gw.example", "https://gw.example/"} {
			if got := ConnectLink(base, s); got != tc.want {
				t.Errorf("ConnectLink(%q, %s/%s) = %q, want %q", base, tc.mode, tc.kind, got, tc.want)
			}
		}
		if got, want := ConnectPathOf(s), tc.want[len("https://gw.example"):]; got != want {
			t.Errorf("ConnectPathOf(%s/%s) = %q, want %q", tc.mode, tc.kind, got, want)
		}
	}
}

// EditLink is the owner's settings page.
func TestEditLink(t *testing.T) {
	for _, base := range []string{"https://gw.example", "https://gw.example/"} {
		if got := EditLink(base, "s1"); got != "https://gw.example/servers/s1/edit" {
			t.Errorf("EditLink(%q) = %q", base, got)
		}
	}
}
