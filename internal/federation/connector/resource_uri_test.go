package connector

import (
	"net/url"
	"strings"
	"testing"

	"github.com/yosida95/uritemplate/v3"
)

func TestGatewayResourceURIRoundTrips(t *testing.T) {
	upstreams := []string{
		"file:///home/alice/notes.md",
		"notes://readme",
		"https://api.example.com/v1/items?id=7&sort=desc#top",
		"db://table/row?where=a%3Db&x=%2F",
		"urn:isbn:0451450523",
		"notes://with space/and ünïcode/✓",
		"weird:%00%ff/\\back\\slash?q=a?b#c#d",
		"mcpgw://other/nested:uri", // a gateway URI behind another gateway
		"x:",
	}
	for _, server := range []string{"notes", "my_srv", "9-lives", strings.Repeat("a", 63)} {
		for _, up := range upstreams {
			gw := GatewayResourceURI(server, up)
			if !strings.HasPrefix(gw, ResourceURIScheme+"://"+server+"/") {
				t.Errorf("GatewayResourceURI(%q, %q) = %q: not namespaced", server, up, gw)
			}
			gotServer, gotUp, ok := ParseGatewayResourceURI(gw)
			if !ok || gotServer != server || gotUp != up {
				t.Errorf("ParseGatewayResourceURI(%q) = %q, %q, %v; want %q, %q", gw, gotServer, gotUp, ok, server, up)
			}
		}
	}
}

// A gateway URI built from a well-formed upstream URI is itself a URI
// generic parsers accept: the server is the authority.
func TestGatewayResourceURIParsesAsURL(t *testing.T) {
	for _, up := range []string{"file:///a/b", "https://x.example/y?z=1#f", "notes://readme"} {
		u, err := url.Parse(GatewayResourceURI("my_srv", up))
		if err != nil {
			t.Fatalf("url.Parse: %v", err)
		}
		if u.Scheme != ResourceURIScheme || u.Host != "my_srv" {
			t.Errorf("parsed %q: scheme %q host %q", up, u.Scheme, u.Host)
		}
	}
}

func TestParseGatewayResourceURIRefusesOthers(t *testing.T) {
	for _, uri := range []string{
		"",
		"notes://readme",               // not a gateway URI
		"MCPGW://notes/notes://readme", // the gateway only issues lowercase
		"mcpgw://notes",                // no upstream
		"mcpgw://notes/",               // empty upstream
		"mcpgw:///notes://readme",      // empty server
		"mcpgw://No_Caps/x:y",          // invalid server name
		"mcpgw://a.b/x:y",              // dots are not server names
		"mcpgw://notes:80/x:y",         // no ports
		"mcpgw://user@notes/x:y",       // no userinfo
		"mcpgw:notes/x:y",              // no authority
		"mcpgw://" + strings.Repeat("a", 64) + "/x:y", // too long
	} {
		if s, u, ok := ParseGatewayResourceURI(uri); ok {
			t.Errorf("ParseGatewayResourceURI(%q) = %q, %q, true; want refused", uri, s, u)
		}
	}
}

// A template rewritten for the gateway, filled in by a client, maps back to
// exactly what the upstream template gives for the same values.
func TestGatewayResourceTemplateExpansionMapsBack(t *testing.T) {
	cases := []struct {
		tmpl string
		vals map[string]string
	}{
		{"notes://note/{id}", map[string]string{"id": "42"}},
		{"file:///{path}", map[string]string{"path": "a/b c.md"}},
		{"file:///{+path}", map[string]string{"path": "a/b c.md"}},
		{"https://api.example.com/items{?q,limit}", map[string]string{"q": "x&y=z", "limit": "5"}},
		{"db://{table}/{id}{#frag}", map[string]string{"table": "t", "id": "ü/1", "frag": "top"}},
		{"{+base}/raw", map[string]string{"base": "s3://bucket"}},
	}
	for _, c := range cases {
		gwTmpl := GatewayResourceTemplate("notes", c.tmpl)
		vals := uritemplate.Values{}
		for k, v := range c.vals {
			vals.Set(k, uritemplate.String(v))
		}
		want := expand(t, c.tmpl, vals)
		filled := expand(t, gwTmpl, vals)
		server, up, ok := ParseGatewayResourceURI(filled)
		if !ok || server != "notes" || up != want {
			t.Errorf("template %q: filled %q maps to %q, %q, %v; want notes, %q", c.tmpl, filled, server, up, ok, want)
			continue
		}
		if !templateMatches(c.tmpl, up) {
			t.Errorf("template %q does not match its own expansion %q", c.tmpl, up)
		}
	}
}

func expand(t *testing.T, tmpl string, vals uritemplate.Values) string {
	t.Helper()
	tm, err := uritemplate.New(tmpl)
	if err != nil {
		t.Fatalf("template %q: %v", tmpl, err)
	}
	s, err := tm.Expand(vals)
	if err != nil {
		t.Fatalf("expand %q: %v", tmpl, err)
	}
	return s
}

func TestTemplateMatches(t *testing.T) {
	cases := []struct {
		tmpl, uri string
		want      bool
	}{
		{"notes://note/{id}", "notes://note/42", true},
		{"notes://note/{id}", "notes://note/42/extra", false}, // simple expansion never yields "/"
		{"notes://note/{id}", "notes://other/42", false},
		{"notes://note/{id}", "notes://note/42?x=1", false},
		{"file:///{+path}", "file:///a/b/c", true},
		{"https://x/{?q}", "https://x/?q=1", true},
		{"{bad", "anything", false}, // an invalid template matches nothing
		{"notes://readme", "notes://readme", true},
		{"notes://readme", "notes://readmeX", false},
	}
	for _, c := range cases {
		if got := templateMatches(c.tmpl, c.uri); got != c.want {
			t.Errorf("templateMatches(%q, %q) = %v, want %v", c.tmpl, c.uri, got, c.want)
		}
	}
}

func TestGatewayPromptNameRoundTrips(t *testing.T) {
	for _, c := range []struct{ server, prompt string }{
		{"notes", "summarize"},
		{"my_srv", "with.dots.inside"},
		{"x", "Upper Case & spaces"},
	} {
		name := GatewayPromptName(c.server, c.prompt)
		s, p, ok := ParseGatewayPromptName(name)
		if !ok || s != c.server || p != c.prompt {
			t.Errorf("ParseGatewayPromptName(%q) = %q, %q, %v", name, s, p, ok)
		}
	}
	for _, name := range []string{"", "summarize", ".summarize", "notes.", "No.x", "a b.c"} {
		if s, p, ok := ParseGatewayPromptName(name); ok {
			t.Errorf("ParseGatewayPromptName(%q) = %q, %q, true; want refused", name, s, p)
		}
	}
}

// The audit identity names the server and the URI without its query or
// fragment (which may carry search terms or tokens), plus a hash of the
// full URI so reads of the same resource can be correlated.
func TestResourceAuditIdentity(t *testing.T) {
	id := resourceIdentity("notes", "https://x.example/a/b?token=secret#frag")
	if id["server"] != "notes" || id["uri"] != "https://x.example/a/b" {
		t.Errorf("identity = %v", id)
	}
	if len(id["uri_sha256"]) != 64 || strings.Contains(strings.Join(mapValues(id), " "), "secret") {
		t.Errorf("identity = %v: want a sha256 hex and no query", id)
	}
	if other := resourceIdentity("notes", "https://x.example/a/b?token=other"); other["uri_sha256"] == id["uri_sha256"] {
		t.Error("different URIs share a hash")
	}
}

func mapValues(m map[string]string) []string {
	var out []string
	for _, v := range m {
		out = append(out, v)
	}
	return out
}
