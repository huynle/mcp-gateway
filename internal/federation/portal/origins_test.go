package portal

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/store"
)

// The owner-managed elicitation origins of a server (migration 00032,
// docs/plans/2026-10-23-credential-links-and-elicitation-relay-design.md):
// pages the server may send its users to besides its own domain.

const originsHelp = "Pages this server may send you to, besides its own domain (https://host[:port]). Needed for machine/tunnel servers."

func privateServer(e *env, origins ...string) *store.MCPServer {
	return e.st.add(store.MCPServer{Name: "notes", URL: "https://notes.example/mcp", OwnerUserID: alice, AuthKind: store.MCPAuthNone,
		AuthConfig: []byte(`{}`), HeaderConfig: []byte(`{}`), ElicitationOrigins: origins})
}

func editForm(origins string) map[string][]string {
	f := addForm("url", "https://notes.example/mcp", "auth_kind", "none")
	f.Set("elicitation_origins", origins)
	return f
}

func TestEditFormShowsElicitationOrigins(t *testing.T) {
	e := newEnv(t)
	s := privateServer(e, "https://auth.example.net", "https://t.example.org:8443")
	r := e.get("/servers/"+s.ID+"/edit", alice)
	if r.code != 200 {
		t.Fatalf("edit: %d", r.code)
	}
	mustContain(t, r.body, "Allowed elicitation origins", originsHelp,
		`<textarea name="elicitation_origins"`, ">https://auth.example.net\nhttps://t.example.org:8443</textarea>")
	// The add form has no such field (new servers start with none).
	mustNotContain(t, e.get("/servers/new", alice).body, `name="elicitation_origins"`)
}

func TestEditSavesNormalisedOrigins(t *testing.T) {
	e := newEnv(t)
	s := privateServer(e)
	r := e.post("/servers/"+s.ID+"/edit", alice, editForm("HTTPS://Auth.Example.NET/\r\n  https://t.example.org:8443 \n\nhttps://auth.example.net\nhttps://x.example.com:443"))
	if r.code != 303 {
		t.Fatalf("save: %d %s", r.code, r.body)
	}
	want := []string{"https://auth.example.net", "https://t.example.org:8443", "https://x.example.com"}
	if got := e.serverByName("notes").ElicitationOrigins; !slices.Equal(got, want) {
		t.Errorf("origins = %q, want %q", got, want)
	}
	// Saving the same list again does not write it.
	calls := e.st.originsCalls
	if r := e.post("/servers/"+s.ID+"/edit", alice, editForm(strings.Join(want, "\n"))); r.code != 303 || e.st.originsCalls != calls {
		t.Errorf("unchanged save: %d, %d writes", r.code, e.st.originsCalls-calls)
	}
	// A form without the field keeps them.
	if r := e.post("/servers/"+s.ID+"/edit", alice, addForm("url", "https://notes.example/mcp", "auth_kind", "none")); r.code != 303 {
		t.Fatalf("save without field: %d", r.code)
	}
	if got := e.serverByName("notes").ElicitationOrigins; !slices.Equal(got, want) {
		t.Errorf("origins after a save without the field = %q", got)
	}
	// An empty field clears them.
	if r := e.post("/servers/"+s.ID+"/edit", alice, editForm("")); r.code != 303 {
		t.Fatalf("clear: %d", r.code)
	}
	if got := e.serverByName("notes").ElicitationOrigins; len(got) != 0 {
		t.Errorf("origins after clear = %q", got)
	}
}

func TestEditRefusesInvalidOrigins(t *testing.T) {
	for _, bad := range []string{
		"http://auth.example.net", "https://auth.example.net/path", "https://auth.example.net/?q=1", "https://auth.example.net#f",
		"https://user@auth.example.net", "https://10.0.0.1", "https://[::1]", "https://localhost", "auth.example.net",
		"https://auth.example.net:0", "https://auth.example.net:99999", "https://exämple.com", "https://bad_host.example",
		"https://" + strings.Repeat("a", 260) + ".example", "https://.example.com", "https://auth..example.com",
	} {
		e := newEnv(t)
		s := privateServer(e, "https://kept.example.com")
		r := e.post("/servers/"+s.ID+"/edit", alice, editForm("https://ok.example.com\n"+bad))
		if r.code != 422 || !strings.Contains(r.body, "is not an allowed origin") {
			t.Errorf("%q: %d", bad, r.code)
			continue
		}
		// The posted text stays in the form; nothing was stored.
		mustContain(t, r.body, "https://ok.example.com")
		if got := e.serverByName("notes").ElicitationOrigins; !slices.Equal(got, []string{"https://kept.example.com"}) || e.st.originsCalls != 0 {
			t.Errorf("%q: origins = %q", bad, got)
		}
	}
	e := newEnv(t)
	s := privateServer(e)
	var many []string
	for i := range maxOrigins + 1 {
		many = append(many, fmt.Sprintf("https://h%d.example.com", i))
	}
	if r := e.post("/servers/"+s.ID+"/edit", alice, editForm(strings.Join(many, "\n"))); r.code != 422 || !strings.Contains(r.body, "Up to 20 origins") {
		t.Errorf("21 origins: %d", r.code)
	}
	if maxOrigins != 20 {
		t.Errorf("maxOrigins = %d", maxOrigins)
	}
}

func TestEditUsesTheInjectedOriginValidator(t *testing.T) {
	var asked []string
	e := newEnvWith(t, func(d *Deps) {
		d.OriginValidator = func(o string) (string, error) {
			asked = append(asked, o)
			if strings.Contains(o, "evil") {
				return "", errors.New("evil")
			}
			return "https://normalised." + strings.TrimPrefix(o, "https://"), nil
		}
	})
	s := privateServer(e)
	if r := e.post("/servers/"+s.ID+"/edit", alice, editForm("https://a.example\nhttp://b.example")); r.code != 303 {
		t.Fatalf("save: %d %s", r.code, r.body)
	}
	if got := e.serverByName("notes").ElicitationOrigins; !slices.Equal(got, []string{"https://normalised.a.example", "https://normalised.http://b.example"}) {
		t.Errorf("origins = %q", got)
	}
	if !slices.Equal(asked, []string{"https://a.example", "http://b.example"}) {
		t.Errorf("validator asked %q", asked)
	}
	if r := e.post("/servers/"+s.ID+"/edit", alice, editForm("https://evil.example")); r.code != 422 || !strings.Contains(r.body, "is not an allowed origin") {
		t.Errorf("refused by validator: %d", r.code)
	}
}

func TestEditOriginsOwnerOnly(t *testing.T) {
	e := newEnv(t)
	s := privateServer(e)
	if r := e.post("/servers/"+s.ID+"/edit", bob, editForm("https://a.example.com")); r.code != 404 {
		t.Errorf("bob: %d", r.code)
	}
	if len(e.serverByName("notes").ElicitationOrigins) != 0 {
		t.Error("bob changed the origins")
	}
}

func TestEditOriginsStoreErrors(t *testing.T) {
	e := newEnv(t)
	s := privateServer(e)
	e.st.originsErr = store.ErrMCPServerLocked
	r := e.post("/servers/"+s.ID+"/edit", alice, editForm("https://a.example.com"))
	if r.code != 422 || !strings.Contains(r.body, lockedNote) {
		t.Errorf("locked: %d", r.code)
	}
}

func TestPublishedServerOriginsAreLocked(t *testing.T) {
	e := newEnv(t)
	s := publishedBearerServer(e)
	e.st.mu.Lock()
	e.st.servers[s.ID].ElicitationOrigins = []string{"https://auth.example.net"}
	e.st.mu.Unlock()
	r := e.get("/servers/"+s.ID+"/edit", alice)
	mustContain(t, r.body, "Allowed elicitation origins", "https://auth.example.net")
	mustNotContain(t, r.body, `name="elicitation_origins"`)
	// A changed list is refused like the other locked settings.
	form := addForm("url", "https://wiki.example/mcp", "auth_kind", "bearer", "credential_mode", "shared", "static_headers", "X-Client: gateway")
	form.Set("elicitation_origins", "https://evil.example.com")
	if r := e.post("/servers/"+s.ID+"/edit", alice, form); r.code != 422 || !strings.Contains(r.body, lockedNote) {
		t.Errorf("changed origins on a published server: %d", r.code)
	}
	// The read-only form's own POST (credential mode only) still works.
	if r := e.post("/servers/"+s.ID+"/edit", alice, map[string][]string{"credential_mode": {"per_user"}}); r.code != 303 {
		t.Errorf("credential mode switch: %d %s", r.code, r.body)
	}
	if got := e.serverByName("wiki").ElicitationOrigins; !slices.Equal(got, []string{"https://auth.example.net"}) {
		t.Errorf("origins = %q", got)
	}
}

func TestServerPageShowsOriginsToViewers(t *testing.T) {
	e := newEnv(t)
	s := publishedBearerServer(e)
	e.st.mu.Lock()
	e.st.servers[s.ID].ElicitationOrigins = []string{"https://auth.example.net", "https://t.example.org:8443"}
	e.st.mu.Unlock()
	for _, u := range []string{alice, bob} {
		r := e.get("/servers/"+s.ID, u)
		if r.code != 200 {
			t.Fatalf("%s: %d", u, r.code)
		}
		mustContain(t, r.body, "Elicitation origins", "<code>https://auth.example.net</code>", "<code>https://t.example.org:8443</code>")
	}
	priv := privateServer(e)
	mustNotContain(t, e.get("/servers/"+priv.ID, alice).body, "Elicitation origins")
}
