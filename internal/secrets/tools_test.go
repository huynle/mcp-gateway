package secrets_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/policy"
	"github.com/huynle/mcp-gateway/internal/secrets"
	"github.com/huynle/mcp-gateway/internal/secrets/ref"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

const (
	baseURL       = "https://gw.example"
	machineServer = "00000000-0000-4000-8000-0000000000f2"
)

// fakeTargets maps registered tools to (server id, upstream tool).
type fakeTargets map[string][2]string

func (f fakeTargets) SecretTarget(app, tool string) (string, string, bool) {
	t, ok := f[app+"."+tool]
	return t[0], t[1], ok
}

var targets = fakeTargets{
	"vault.login":                  {server, "vault.login"},
	"vault.hidden":                 {server, "hidden"},
	"box-actions.sudo-apt-upgrade": {machineServer, "sudo-apt-upgrade"},
}

// hideVisibility hides the tools named in it and is otherwise
// ScopeVisibility.
type hideVisibility map[string]bool

func (h hideVisibility) Visible(ctx context.Context, p *tokens.Principal, t connectors.Tool) bool {
	return !h[t.FullName()] && mcp.ScopeVisibility{}.Visible(ctx, p, t)
}

func handlerTool(app, name, schema string) connectors.Tool {
	return connectors.Tool{App: app, Name: name, Kind: connectors.KindWrite, InputSchema: json.RawMessage(schema),
		Reconcile: connectors.Reconciliation{Kind: connectors.ReconcileNone},
		Handler: func(context.Context, connectors.Call) (connectors.Result, error) {
			return connectors.Result{}, nil
		}}
}

type toolFixture struct {
	*fixture
	reg  *connectors.Registry
	tool connectors.Tool
}

func newToolFixture(t *testing.T) *toolFixture {
	t.Helper()
	f := newFixture(t)
	reg := connectors.NewRegistry()
	for _, tl := range []connectors.Tool{
		handlerTool("vault", "login", `{"type":"object","properties":{"user":{"type":"string"},"password":{"type":"string"}}}`),
		handlerTool("vault", "hidden", `{"type":"object","properties":{"password":{"type":"string"}}}`),
		handlerTool("box-actions", "sudo-apt-upgrade", `{"type":"object","properties":{"secret":{"type":"string"}},"additionalProperties":false}`),
		handlerTool("github", "create_issue", `{"type":"object","properties":{"body":{"type":"string"}}}`),
	} {
		if err := reg.Register(tl); err != nil {
			t.Fatal(err)
		}
	}
	c, err := secrets.NewConnector(secrets.ConnectorDeps{
		Service: f.svc, Tools: reg, Visibility: hideVisibility{"vault.hidden": true}, Targets: targets, BaseURL: baseURL + "/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Register(reg); err != nil {
		t.Fatal(err)
	}
	tool, ok := reg.Get("secrets.request")
	if !ok {
		t.Fatal("secrets.request not registered")
	}
	return &toolFixture{fixture: f, reg: reg, tool: tool}
}

func (f *toolFixture) call(t *testing.T, args map[string]any) error {
	t.Helper()
	owner, tokenID := alice, harness
	ctx := tokens.WithPrincipal(context.Background(), &tokens.Principal{UserID: owner, TokenID: tokenID})
	res, err := f.tool.Handler(ctx, connectors.Call{Principal: connectors.Principal{UserID: owner, TokenID: tokenID}, Tool: "secrets.request", Args: args})
	if err == nil {
		t.Fatalf("secrets.request returned a result %+v, want an error", res)
	}
	return err
}

func toolError(t *testing.T, err error) *mcp.ToolError {
	t.Helper()
	var te *mcp.ToolError
	if !errors.As(err, &te) {
		t.Fatalf("error %v (%T) is not a *mcp.ToolError", err, err)
	}
	return te
}

func TestRequestToolMetadata(t *testing.T) {
	f := newToolFixture(t)
	tl := f.tool
	if tl.App != policy.SecretsApp || secrets.App != policy.SecretsApp || tl.Name != secrets.ToolRequest || tl.Kind != connectors.KindRead || !tl.NoAccount {
		t.Errorf("tool = %s kind %s NoAccount %v", tl.FullName(), tl.Kind, tl.NoAccount)
	}
	if _, ok := f.reg.Get("secrets.list_accounts"); ok {
		t.Error("secrets.list_accounts registered; the app has no accounts")
	}
	var schema struct {
		Properties map[string]any `json:"properties"`
		Required   []string       `json:"required"`
	}
	if err := json.Unmarshal(tl.InputSchema, &schema); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"label", "tool", "arg", "ttl", "uses"} {
		if schema.Properties[p] == nil {
			t.Errorf("schema lacks %s", p)
		}
	}
	if got := tl.ResourceIdentity(map[string]any{"tool": "vault.login"}); got["tool"] != "vault.login" {
		t.Errorf("identity = %v", got)
	}
	if got := tl.ResourceIdentity(map[string]any{"tool": "x y {}"}); got["tool"] != "invalid" {
		t.Errorf("identity of a malformed name = %v", got)
	}
}

func TestRequestToolValidation(t *testing.T) {
	ok := map[string]any{"label": "vault password", "tool": "vault.login", "arg": "password"}
	with := func(k string, v any) map[string]any {
		m := map[string]any{}
		for kk, vv := range ok {
			m[kk] = vv
		}
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
		return m
	}
	cases := map[string]map[string]any{
		"no label":           with("label", nil),
		"blank label":        with("label", "   "),
		"long label":         with("label", strings.Repeat("x", 81)),
		"label not a string": with("label", 7),
		"bad ttl":            with("ttl", "soon"),
		"ttl too long":       with("ttl", "2h"),
		"ttl too short":      with("ttl", "10s"),
		"ttl not a string":   with("ttl", 900),
		"zero uses":          with("uses", float64(0)),
		"too many uses":      with("uses", float64(11)),
		"fractional uses":    with("uses", 1.5),
		"uses not a number":  with("uses", "2"),
		"no tool":            with("tool", nil),
		"no arg":             with("arg", nil),
		"arg not in schema":  with("arg", "token"),
		"gateway arg":        with("arg", "account"),
		"built-in app tool":  with("tool", "github.create_issue"),
		"secrets itself":     with("tool", "secrets.request"),
	}
	f := newToolFixture(t)
	for name, args := range cases {
		te := toolError(t, f.call(t, args))
		if te.Code != mcp.CodeInvalidParams {
			t.Errorf("%s: code %d (%s: %s), want invalid params", name, te.Code, te.Class(), te.Message)
		}
	}
	// An unknown and an invisible tool get the same answer (only the name
	// they echo differs).
	unknown := toolError(t, f.call(t, with("tool", "vault.nope")))
	hidden := toolError(t, f.call(t, with("tool", "vault.hidden")))
	if unknown.Code != mcp.CodeInvalidParams || unknown.Class() != hidden.Class() ||
		strings.ReplaceAll(unknown.Message, "vault.nope", "X") != strings.ReplaceAll(hidden.Message, "vault.hidden", "X") {
		t.Errorf("unknown %d %s %q vs hidden %d %s %q", unknown.Code, unknown.Class(), unknown.Message, hidden.Code, hidden.Class(), hidden.Message)
	}
	// Without a principal in the context nothing is visible.
	res, err := f.tool.Handler(context.Background(), connectors.Call{Principal: connectors.Principal{UserID: alice, TokenID: harness}, Args: ok})
	if te := toolError(t, err); te.Code != mcp.CodeInvalidParams || te.Class() != unknown.Class() {
		t.Errorf("no principal: %v %v", res, err)
	}
	if list, _ := f.svc.List(context.Background(), alice); len(list) != 0 {
		t.Errorf("invalid requests stored %d records", len(list))
	}
}

func TestRequestToolAnswersSecretRequired(t *testing.T) {
	f := newToolFixture(t)
	te := toolError(t, f.call(t, map[string]any{
		"label": "vault password", "tool": "vault.login", "arg": "password", "ttl": "30m", "uses": float64(3)}))
	if te.Code != mcp.CodeSecretRequired || mcp.CodeSecretRequired != -32042 || te.Class() != "secret_required" {
		t.Fatalf("answer = %d %s %q", te.Code, te.Class(), te.Message)
	}
	raw, err := json.Marshal(te.Data)
	if err != nil {
		t.Fatal(err)
	}
	var data struct {
		Elicitations []struct {
			Mode          string `json:"mode"`
			ElicitationID string `json:"elicitationId"`
			URL           string `json:"url"`
			Message       string `json:"message"`
		} `json:"elicitations"`
		URL         string `json:"url"`
		Handle      string `json:"handle"`
		Fingerprint string `json:"fingerprint"`
		ExpiresAt   string `json:"expires_at"`
	}
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatal(err)
	}
	if !ref.Valid(data.Handle) {
		t.Fatalf("handle %q is not valid", data.Handle)
	}
	requestID := secrets.RequestIDForHandle(data.Handle)
	wantURL := baseURL + "/s/" + requestID
	if data.URL != wantURL {
		t.Errorf("url = %q, want %q", data.URL, wantURL)
	}
	if want := ref.Fingerprint(requestID); data.Fingerprint != want || strings.Count(want, "-") != 3 {
		t.Errorf("fingerprint = %q, want %q (the entry page's)", data.Fingerprint, want)
	}
	list, _ := f.svc.List(context.Background(), alice)
	if len(list) != 1 {
		t.Fatalf("stored %d records", len(list))
	}
	rec := list[0]
	if len(data.Elicitations) != 1 || data.Elicitations[0].Mode != "url" || data.Elicitations[0].URL != wantURL ||
		data.Elicitations[0].ElicitationID != rec.ID || !strings.Contains(data.Elicitations[0].Message, data.Fingerprint) {
		t.Errorf("elicitations = %+v", data.Elicitations)
	}
	if exp, err := time.Parse(time.RFC3339, data.ExpiresAt); err != nil || !exp.Equal(rec.LinkExpiresAt) {
		t.Errorf("expires_at = %q (%v), want the link expiry %v", data.ExpiresAt, err, rec.LinkExpiresAt)
	}
	wantMsg := "Ask the user to open " + wantURL + " and enter the secret (check the words: " + data.Fingerprint +
		"). Then retry the call with {\"password\": {\"$secret\": \"" + data.Handle + "\"}}."
	if te.Message != wantMsg {
		t.Errorf("message = %q\nwant      %q", te.Message, wantMsg)
	}
	if rec.Binding != (secrets.Binding{ServerID: server, Tool: "vault.login", Arg: "password"}) || rec.TTL != 30*time.Minute ||
		rec.UsesTotal != 3 || rec.Label != "vault password" || rec.HarnessID != harness || rec.OwnerUserID != alice {
		t.Errorf("record = %+v", rec)
	}
	// The status of the handle is the caller's pending request.
	st, err := f.svc.Status(context.Background(), alice, harness, data.Handle)
	if err != nil || st.Status != secrets.StatusPending || st.RequestID != requestID {
		t.Errorf("status = %+v, %v", st, err)
	}
}

func TestRequestToolMachineAction(t *testing.T) {
	f := newToolFixture(t)
	te := toolError(t, f.call(t, map[string]any{"label": "sudo", "tool": "box-actions.sudo-apt-upgrade", "arg": "secret"}))
	if te.Code != mcp.CodeSecretRequired {
		t.Fatalf("answer = %d %s %q", te.Code, te.Class(), te.Message)
	}
	list, _ := f.svc.List(context.Background(), alice)
	if len(list) != 1 || list[0].Binding != (secrets.Binding{ServerID: machineServer, Tool: "sudo-apt-upgrade", Arg: "secret"}) ||
		list[0].TTL != secrets.DefaultTTL || list[0].UsesTotal != 1 {
		t.Errorf("records = %+v", list)
	}
	if !strings.Contains(te.Message, `{"secret": {"$secret": "sec_`) {
		t.Errorf("message = %q", te.Message)
	}
}

func TestRequestToolLimited(t *testing.T) {
	f := newToolFixture(t)
	args := map[string]any{"label": "vault password", "tool": "vault.login", "arg": "password"}
	for i := 0; i < secrets.MaxPendingPerOwner; i++ {
		if te := toolError(t, f.call(t, args)); te.Code != mcp.CodeSecretRequired {
			t.Fatalf("request %d: %d %s", i, te.Code, te.Message)
		}
	}
	te := toolError(t, f.call(t, args))
	if te.Code != mcp.CodeRateLimited || mcp.CodeRateLimited != -32029 || te.Class() != "secret_requests_limited" || te.RetryAfterSeconds() <= 0 {
		t.Errorf("over the limit: %d %s retry %d", te.Code, te.Class(), te.RetryAfterSeconds())
	}
}
