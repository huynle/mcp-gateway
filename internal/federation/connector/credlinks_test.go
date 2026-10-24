package connector

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/federation/auth"
	"github.com/huynle/mcp-gateway/internal/federation/client"
	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/store"
)

const gw = "https://gw.example"

// linkFixture is the manager fixture with the credential-links flag set,
// and bob able to use alice's server (a published server's non-owner).
func linkFixture(t *testing.T, on bool) *fixture {
	t.Helper()
	f := newFixture(t)
	f.m.o.CredentialLinks = on
	f.st.visible[bob] = []string{srvID}
	if err := f.m.ServerChanged(t.Context(), srvID); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) setServer(t *testing.T, edit func(*store.MCPServer)) *store.MCPServer {
	t.Helper()
	s, err := f.st.GetServer(t.Context(), srvID)
	if err != nil {
		t.Fatal(err)
	}
	edit(s)
	f.st.put(*s)
	if err := f.m.ServerChanged(t.Context(), srvID); err != nil {
		t.Fatal(err)
	}
	return s
}

func asToolError(t *testing.T, err error) *mcp.ToolError {
	t.Helper()
	var te *mcp.ToolError
	if !errors.As(err, &te) {
		t.Fatalf("err = %v (%T), want a *mcp.ToolError", err, err)
	}
	return te
}

// wantLink checks a -32042 answer: same class, the link in data.url, in
// one elicitation and in the message, data.server, a gwc_ id. It returns
// the message.
func wantLink(t *testing.T, err error, class, url string) string {
	t.Helper()
	te := asToolError(t, err)
	if te.Code != sdk.CodeURLElicitationRequired || te.Class() != class {
		t.Fatalf("answer = %d %s (%q), want -32042 %s", te.Code, te.Class(), te.Message, class)
	}
	if te.Data["url"] != url || te.Data["server"] != "notes" {
		t.Errorf("data = %v, want url %s and server notes", te.Data, url)
	}
	list, _ := te.Data["elicitations"].([]any)
	if len(list) != 1 {
		t.Fatalf("elicitations = %v", te.Data["elicitations"])
	}
	e := list[0].(map[string]any)
	if e["mode"] != "url" || e["url"] != url || !strings.HasPrefix(e["elicitationId"].(string), "gwc_") || !strings.Contains(e["message"].(string), "notes") {
		t.Errorf("elicitation = %v", e)
	}
	if !strings.Contains(te.Message, url) || !strings.HasPrefix(te.Message, "notes: ") || !strings.HasSuffix(te.Message, ", then retry") {
		t.Errorf("message = %q, want the link in its text", te.Message)
	}
	return te.Message
}

func elicitationID(t *testing.T, err error) string {
	t.Helper()
	te := asToolError(t, err)
	list, _ := te.Data["elicitations"].([]any)
	if len(list) == 0 {
		t.Fatalf("no elicitations in %v", te.Data)
	}
	return list[0].(map[string]any)["elicitationId"].(string)
}

// today is an answer as the gateway gave it before credential links.
type today struct {
	code  int64
	class string
	msg   string
}

func wantToday(t *testing.T, err error, w today) {
	t.Helper()
	te := asToolError(t, err)
	if te.Code != w.code || te.Class() != w.class || te.Message != w.msg || te.Data != nil {
		t.Errorf("answer = %d %s %q %v, want exactly %d %s %q (no data)", te.Code, te.Class(), te.Message, te.Data, w.code, w.class, w.msg)
	}
}

var (
	notConnectedToday = today{mcp.CodeNoAccount, "auth_required",
		"notes.create_note needs your notes account: connect it on the portal (" + gw + "/servers/" + srvID + ") and retry"}
	reconnectToday = today{mcp.CodeNoAccount, "needs_reconnect",
		"your notes connection has expired or was rejected: reconnect it on the portal (" + gw + "/servers/" + srvID + ") and retry"}
	notConfiguredToday  = today{mcp.CodeNoAccount, "server_not_configured", "notes: the server's authentication is not set up; ask its owner"}
	sharedRejectedToday = today{mcp.CodeNoAccount, "shared_credential_rejected",
		"notes: the server rejected the shared credential; ask the server's owner or an admin to update it"}
	unavailableToday = today{mcp.CodeInternal, "credentials_unavailable", "the credentials for notes could not be loaded"}
)

// Flag off: every credential answer is byte for byte what it was, for the
// owner and for everyone else.
func TestCredentialLinksOffIsUnchanged(t *testing.T) {
	f := linkFixture(t, false)
	cases := []struct {
		err  error
		want today
	}{
		{auth.ErrNotConnected, notConnectedToday},
		{auth.ErrNeedsReconnect, reconnectToday},
		{auth.ErrNotConfigured, notConfiguredToday},
		{fmt.Errorf("%w: no shared credential", auth.ErrSharedMissing), notConfiguredToday},
		{fmt.Errorf("%w: auth kind", auth.ErrModeInvalid), notConfiguredToday},
		{fmt.Errorf("%w: shared OAuth tokens", auth.ErrUnsupported), notConfiguredToday},
		{errors.New("database down"), unavailableToday},
		// Never returned by the lenient service the flag-off gateway
		// uses; mapped like any unknown failure.
		{auth.ErrUserHeaderMissing, unavailableToday},
	}
	for _, user := range []string{alice, bob} {
		for _, tc := range cases {
			f.creds.errs[user] = tc.err
			_, err := f.call(t, user, "notes.create_note", map[string]any{"title": "t"})
			wantToday(t, err, tc.want)
		}
		delete(f.creds.errs, user)
	}
	s, _ := f.st.GetServer(t.Context(), srvID)
	for _, user := range []string{alice, bob} {
		wantToday(t, f.m.callError(user, s, snapshot.KindWrite, auth.ErrNeedsReconnect), reconnectToday)
		wantToday(t, f.m.callError(user, s, snapshot.KindWrite, auth.ErrSharedCredentialRejected), sharedRejectedToday)
		wantToday(t, f.m.callError(user, s, snapshot.KindWrite, &client.Error{Class: client.ClassAuthRequired, Op: "tools/call", Status: 403}),
			today{mcp.CodeNoAccount, "auth_required",
				"notes asked for authentication: connect or reconnect your account on the portal (" + gw + "/servers/" + srvID + ") and retry"})
		// A no-auth server answering 401 stays the generic upstream error.
		if got := toolErrClass(f.m.callError(user, s, snapshot.KindWrite, fmt.Errorf("%w: x", auth.ErrNowRequiresAuth))); got != "handler:upstream_error" {
			t.Errorf("flag off, now requires auth = %s, want handler:upstream_error", got)
		}
	}
	if err := f.m.Accounts(nil).(mcp.MissingAccounter).MissingAccount(t.Context(), alice, "notes"); err != nil {
		t.Errorf("flag off MissingAccount = %v, want nil (no_account as today)", err)
	}
}

// Flag on, user-fixable problems: -32042 with the connection link, same
// class, for whoever calls (owner or not).
func TestCredentialLinksUserFixable(t *testing.T) {
	f := linkFixture(t, true)
	connection := gw + "/servers/" + srvID + "#connection"
	for _, user := range []string{alice, bob} {
		f.creds.errs[user] = auth.ErrNotConnected
		_, err := f.call(t, user, "notes.create_note", map[string]any{"title": "t"})
		if msg := wantLink(t, err, "auth_required", connection); !strings.Contains(msg, "connect your account") {
			t.Errorf("message = %q", msg)
		}
		f.creds.errs[user] = auth.ErrNeedsReconnect
		_, err = f.call(t, user, "notes.create_note", map[string]any{"title": "t"})
		wantLink(t, err, "needs_reconnect", connection)
		f.creds.errs[user] = auth.ErrUserHeaderMissing
		_, err = f.call(t, user, "notes.create_note", map[string]any{"title": "t"})
		wantLink(t, err, ClassUserHeaderMissing, connection)
		delete(f.creds.errs, user)
	}
	s, _ := f.st.GetServer(t.Context(), srvID)
	wantLink(t, f.m.callError(bob, s, snapshot.KindWrite, auth.ErrNeedsReconnect), "needs_reconnect", connection)
	wantLink(t, f.m.callError(bob, s, snapshot.KindWrite, &client.Error{Class: client.ClassAuthRequired, Op: "tools/call", Status: 403}),
		"auth_required", connection)

	// OAuth: the link starts the sign-in; header values still go to the
	// connection section.
	f.setServer(t, func(s *store.MCPServer) { s.AuthKind = store.MCPAuthOAuth })
	f.creds.errs[bob] = auth.ErrNotConnected
	_, err := f.call(t, bob, "notes.create_note", map[string]any{"title": "t"})
	wantLink(t, err, "auth_required", gw+"/servers/"+srvID+"/connect")
	f.creds.errs[bob] = auth.ErrUserHeaderMissing
	_, err = f.call(t, bob, "notes.create_note", map[string]any{"title": "t"})
	wantLink(t, err, ClassUserHeaderMissing, connection)

	// credentials_unavailable is not a credential problem anyone can fix.
	f.creds.errs[alice] = errors.New("database down")
	_, err = f.call(t, alice, "notes.create_note", map[string]any{"title": "t"})
	wantToday(t, err, unavailableToday)
}

// Elicitation ids are stable per (user, server, class) and differ across
// users and classes.
func TestCredentialLinksElicitationIDs(t *testing.T) {
	f := linkFixture(t, true)
	id := func(user string, cause error) string {
		f.creds.errs[user] = cause
		defer delete(f.creds.errs, user)
		_, err := f.call(t, user, "notes.create_note", map[string]any{"title": "t"})
		return elicitationID(t, err)
	}
	a1, a2 := id(alice, auth.ErrNotConnected), id(alice, auth.ErrNotConnected)
	b1 := id(bob, auth.ErrNotConnected)
	a3 := id(alice, auth.ErrNeedsReconnect)
	if a1 != a2 {
		t.Errorf("id not stable: %s vs %s", a1, a2)
	}
	if a1 == b1 || a1 == a3 {
		t.Errorf("ids collide: alice %s, bob %s, alice reconnect %s", a1, b1, a3)
	}
	if strings.Contains(a1, alice) || strings.Contains(a1, srvID) {
		t.Errorf("id carries the ids in clear: %s", a1)
	}
}

// Flag on, owner-only problems: the owner gets -32042 with the edit
// link; everyone else gets today's answer, byte for byte (no edit link).
func TestCredentialLinksOwnerOnly(t *testing.T) {
	f := linkFixture(t, true)
	edit := gw + "/servers/" + srvID + "/edit"
	shared := f.setServer(t, func(s *store.MCPServer) { s.CredentialMode = store.MCPCredentialShared })
	causes := []error{
		fmt.Errorf("%w: no shared credential", auth.ErrSharedMissing),
		fmt.Errorf("%w: auth kind", auth.ErrModeInvalid),
		fmt.Errorf("%w: shared OAuth tokens", auth.ErrUnsupported),
		auth.ErrNotConfigured,
	}
	for _, cause := range causes {
		f.creds.errs[alice], f.creds.errs[bob] = cause, cause
		_, err := f.call(t, alice, "notes.create_note", map[string]any{"title": "t"})
		if msg := wantLink(t, err, "server_not_configured", edit); strings.Contains(msg, "ask its owner") {
			t.Errorf("owner told to ask the owner: %q", msg)
		}
		_, err = f.call(t, bob, "notes.create_note", map[string]any{"title": "t"})
		wantToday(t, err, notConfiguredToday)
	}
	delete(f.creds.errs, alice)
	delete(f.creds.errs, bob)

	wantLink(t, f.m.callError(alice, shared, snapshot.KindWrite, auth.ErrSharedCredentialRejected), "shared_credential_rejected", edit)
	wantToday(t, f.m.callError(bob, shared, snapshot.KindWrite, auth.ErrSharedCredentialRejected), sharedRejectedToday)
	// A shared server cannot be fixed by its users: an upstream
	// authentication refusal is the owner's.
	wantLink(t, f.m.callError(alice, shared, snapshot.KindWrite, &client.Error{Class: client.ClassAuthRequired, Op: "tools/call", Status: 403}),
		"auth_required", edit)
	if te := asToolError(t, f.m.callError(bob, shared, snapshot.KindWrite, &client.Error{Class: client.ClassAuthRequired, Op: "tools/call", Status: 403})); te.Data != nil {
		t.Errorf("non-owner got data: %v", te.Data)
	}

	// A no-auth server answering 401: server_not_configured (owner-fixable),
	// no longer upstream_error.
	none := f.setServer(t, func(s *store.MCPServer) { s.AuthKind = store.MCPAuthNone })
	now := fmt.Errorf("%w: the server now requires authentication", auth.ErrNowRequiresAuth)
	if msg := wantLink(t, f.m.callError(alice, none, snapshot.KindWrite, now), "server_not_configured", edit); !strings.Contains(msg, "now requires authentication") {
		t.Errorf("message = %q", msg)
	}
	wantToday(t, f.m.callError(bob, none, snapshot.KindWrite, now), notConfiguredToday)

	// The invalid tunnel URL answer (endpoint) goes through the same rule.
	tunnelErr := mcp.NewToolError(mcp.CodeNoAccount, "server_not_configured", "notes: the server's tunnel URL is invalid")
	wantLink(t, f.m.credentialLink(alice, none, errTunnelURL, tunnelErr), "server_not_configured", edit)
	if got := f.m.credentialLink(bob, none, errTunnelURL, tunnelErr); !errors.Is(got, tunnelErr) || asToolError(t, got).Data != nil {
		t.Errorf("non-owner tunnel answer = %v, want unchanged", got)
	}
	// Other answers pass through untouched.
	other := &upstreamError{class: "tunnel_unavailable", msg: "x"}
	if got := f.m.credentialLink(alice, none, errTunnelURL, other); !errors.Is(got, other) {
		t.Errorf("tunnel_unavailable changed: %v", got)
	}
}

// The account stage's hook: a per-user server the caller may use and has
// no connection to answers -32042 no_account with the connect link.
func TestCredentialLinksMissingAccount(t *testing.T) {
	f := linkFixture(t, true)
	fallback := connectors.NewStaticAccountSource()
	src := f.m.Accounts(fallback)
	ma, ok := src.(mcp.MissingAccounter)
	if !ok {
		t.Fatal("federation accounts do not implement mcp.MissingAccounter")
	}
	ctx := t.Context()
	for _, user := range []string{alice, bob} {
		wantLink(t, ma.MissingAccount(ctx, user, "notes"), "no_account", gw+"/servers/"+srvID+"#connection")
	}
	f.setServer(t, func(s *store.MCPServer) { s.AuthKind = store.MCPAuthOAuth })
	wantLink(t, ma.MissingAccount(ctx, bob, "notes"), "no_account", gw+"/servers/"+srvID+"/connect")

	// Nothing to say: a user who cannot see the server (no hint that it
	// exists), an unknown app, a built-in app.
	f.st.visible[bob] = nil
	_ = f.m.ServerChanged(ctx, srvID)
	for _, c := range []struct{ user, app string }{{bob, "notes"}, {alice, "nope"}, {alice, "github"}} {
		if err := ma.MissingAccount(ctx, c.user, c.app); err != nil {
			t.Errorf("MissingAccount(%s, %s) = %v, want nil", c.user, c.app, err)
		}
	}
	// Shared and no-auth servers always have an account: nothing to say.
	f.setServer(t, func(s *store.MCPServer) { s.CredentialMode = store.MCPCredentialShared })
	if err := ma.MissingAccount(ctx, alice, "notes"); err != nil {
		t.Errorf("shared: %v", err)
	}
}

// Resources and prompts use the same mapping.
func TestCredentialLinksResources(t *testing.T) {
	f := linkFixture(t, true)
	rp := f.m.ResourceProvider(f.pol)
	ctx := t.Context()
	f.creds.errs[alice] = auth.ErrNotConnected
	_, err := rp.ReadResource(ctx, principal(alice), "mcpgw://notes/notes://readme", (&admits{}).hook())
	wantLink(t, err, "auth_required", gw+"/servers/"+srvID+"#connection")
	_, err = rp.GetPrompt(ctx, principal(alice), "notes.summarize", nil, (&admits{}).hook())
	wantLink(t, err, "auth_required", gw+"/servers/"+srvID+"#connection")
	f.creds.errs[alice] = fmt.Errorf("%w: no shared credential", auth.ErrSharedMissing)
	_, err = rp.ReadResource(ctx, principal(alice), "mcpgw://notes/notes://readme", (&admits{}).hook())
	wantLink(t, err, "server_not_configured", gw+"/servers/"+srvID+"/edit")

	off := linkFixture(t, false)
	off.creds.errs[alice] = auth.ErrNotConnected
	_, err = off.m.ResourceProvider(off.pol).ReadResource(ctx, principal(alice), "mcpgw://notes/notes://readme", (&admits{}).hook())
	te := asToolError(t, err)
	if te.Code != mcp.CodeNoAccount || te.Class() != "auth_required" || te.Data != nil ||
		te.Message != "notes.resources/read needs your notes account: connect it on the portal ("+gw+"/servers/"+srvID+") and retry" {
		t.Errorf("flag off resource answer = %d %s %q %v", te.Code, te.Class(), te.Message, te.Data)
	}
}

// The -32042 data holds only maps, slices and strings (the secrets stage
// scrubs it) and serializes to the spec shape.
func TestCredentialLinksDataShape(t *testing.T) {
	f := linkFixture(t, true)
	f.creds.errs[alice] = auth.ErrNotConnected
	_, err := f.call(t, alice, "notes.create_note", map[string]any{"title": "t"})
	te := asToolError(t, err)
	b, jerr := json.Marshal(te.Data)
	if jerr != nil {
		t.Fatal(jerr)
	}
	var back map[string]any
	_ = json.Unmarshal(b, &back)
	if !reflect.DeepEqual(back, te.Data) {
		t.Errorf("data does not round-trip as plain JSON: %v vs %v", back, te.Data)
	}
}
