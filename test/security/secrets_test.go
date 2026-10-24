//go:build integration || e2e || security

package security

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/policy"
	"github.com/huynle/mcp-gateway/internal/portal"
	"github.com/huynle/mcp-gateway/internal/secrets"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

// --- wiring (cmd/gateway's secrets.go) ------------------------------------------------

// wireSecrets builds the service and registers the secrets app with the
// pipeline's visibility (decider), as cmd/gateway's newSecrets does.
func (w *world) wireSecrets(keys crypto.KeyProvider, decider mcp.Decider, log *slog.Logger) {
	w.t.Helper()
	if w.fed == nil {
		w.t.Fatal("options.secrets needs options.federation")
	}
	svc, err := secrets.New(secrets.NewPostgresStore(w.st), keys, secrets.Options{Log: log})
	if err != nil {
		w.t.Fatal(err)
	}
	app, err := secrets.NewConnector(secrets.ConnectorDeps{
		Service: svc, Tools: w.reg, Visibility: mcp.PolicyVisibility{Decider: decider, Log: log},
		Targets: w.fed.Manager, BaseURL: baseURL, Log: log,
	})
	if err != nil {
		w.t.Fatal(err)
	}
	if err := app.Register(w.reg); err != nil {
		w.t.Fatal(err)
	}
	w.secretSvc = svc
}

// insertSecretStage is cmd/gateway's withSecretStage.
func (w *world) insertSecretStage(p *mcp.Pipeline, log *slog.Logger) {
	w.t.Helper()
	stage, err := secrets.NewStage(secrets.StageOptions{
		Service: w.secretSvc, Targets: w.fed.Manager, BaseURL: baseURL, Hook: auditUseHook{rec: w.rec}, Log: log,
	})
	if err != nil {
		w.t.Fatal(err)
	}
	if err := p.Insert(mcp.Before, mcp.StageDispatch, stage); err != nil {
		w.t.Fatal(err)
	}
}

// mountSecretPages is cmd/gateway's withSecretPages.
func (w *world) mountSecretPages(p *portal.Portal, session func(*http.Request) (string, string), log *slog.Logger) {
	secrets.NewPortal(w.secretSvc, session, secrets.PortalOptions{
		Log: log, Audit: w.rec, NotFound: p.NotFoundHandler(),
		FailureLimiter: secrets.NewAddressLimiter(secrets.EntryFailureBurst, secrets.EntryFailureWindow, nil),
	}).Mount(p.MountUser)
	w.idSvc.OnDisable(w.secretSvc.OnDisableUser)
}

// auditUseHook records secret.used like cmd/gateway's secretsFeature.
type auditUseHook struct{ rec audit.Recorder }

func (h auditUseHook) SecretUsed(ctx context.Context, u secrets.Use) {
	_ = h.rec.Record(ctx, audit.Event{
		UserID: u.UserID, TokenID: u.HarnessID,
		ResourceIdentity: map[string]string{"action": "secret.used", "secret_id": u.SecretID, "label": u.Label, "tool": u.Tool},
		Outcome:          "succeeded", RequestID: observability.RequestIDFromContext(ctx),
	})
}

// --- the vault upstream -------------------------------------------------------------

// secretValue has characters that the URL and base64 forms change.
const secretValue = "hunter2 c0rrect/horse+battery&staple"

// secretForms are the forms of secretValue that must never leak.
var secretForms = map[string]string{
	"raw":          secretValue,
	"base64":       base64.StdEncoding.EncodeToString([]byte(secretValue)),
	"base64url":    base64.RawURLEncoding.EncodeToString([]byte(secretValue)),
	"query-escape": url.QueryEscape(secretValue),
	"path-escape":  url.PathEscape(secretValue),
}

type vaultIn struct {
	Password string         `json:"password"`
	Note     string         `json:"note,omitempty"`
	Options  map[string]any `json:"options,omitempty"`
}

// vault records every password its tools receive. login and unlock are
// reads; rotate is a write (the owner layer asks for approval).
type vault struct {
	mu   sync.Mutex
	seen []string
}

func (v *vault) received() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]string(nil), v.seen...)
}

func (v *vault) server(*http.Request) *sdk.Server {
	s := sdk.NewServer(&sdk.Implementation{Name: "vault", Version: "1"}, nil)
	handler := func(verb string) func(context.Context, *sdk.CallToolRequest, vaultIn) (*sdk.CallToolResult, any, error) {
		return func(_ context.Context, _ *sdk.CallToolRequest, in vaultIn) (*sdk.CallToolResult, any, error) {
			v.mu.Lock()
			v.seen = append(v.seen, in.Password)
			v.mu.Unlock()
			b64 := base64.StdEncoding.EncodeToString([]byte(in.Password))
			return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: verb + " with " + in.Password + " (" + b64 + ") " + url.QueryEscape(in.Password)}}}, nil, nil
		}
	}
	read := &sdk.ToolAnnotations{ReadOnlyHint: true}
	sdk.AddTool(s, &sdk.Tool{Name: "login", Description: "Log in.", Annotations: read}, handler("logged in"))
	sdk.AddTool(s, &sdk.Tool{Name: "unlock", Description: "Unlock.", Annotations: read}, handler("unlocked"))
	sdk.AddTool(s, &sdk.Tool{Name: "rotate", Description: "Rotate the password."}, handler("rotated"))
	return s
}

// newSecretsWorld is a federation world with secrets and alice's vault
// server reviewed with every tool.
func newSecretsWorld(t *testing.T) (*world, *vault, *store.MCPServer) {
	t.Helper()
	w := newWorld(t, options{federation: true, secrets: true})
	w.allowLoopback()
	v := &vault{}
	up := newUpstream(t, v.server)
	srv := w.addServer(w.alice, "vault", up.URL(), nil)
	w.review(w.alice, srv, "login", "unlock", "rotate")
	for what, form := range secretForms {
		w.forbid(form, "secret value ("+what+")")
	}
	return w, v, srv
}

func secretRef(handle string) map[string]any { return map[string]any{"$secret": handle} }

// requestSecret runs secrets.request and returns the -32042 data.
func (w *world) requestSecret(cs *sdk.ClientSession, tool, arg string, uses int) (link, handle string) {
	w.t.Helper()
	_, err := w.call(cs, "secrets.request", map[string]any{"label": "vault password", "tool": tool, "arg": arg, "uses": uses})
	je := rpcError(w.t, err, mcp.CodeSecretRequired)
	var data struct {
		URL    string `json:"url"`
		Handle string `json:"handle"`
	}
	if err := json.Unmarshal(je.Data, &data); err != nil || !strings.HasPrefix(data.URL, baseURL+"/s/") || data.Handle == "" {
		w.t.Fatalf("-32042 data %s: %v", je.Data, err)
	}
	path := strings.TrimPrefix(data.URL, baseURL)
	w.forbid(strings.TrimPrefix(path, "/s/"), "entry link request id")
	return path, data.Handle
}

// provide saves secretValue on the entry page as u.
func (w *world) provide(u user, path string) {
	w.t.Helper()
	status, _, body := w.post(u, path, url.Values{"action": {"save"}, "value": {secretValue}})
	if status != http.StatusOK {
		w.t.Fatalf("save = %d:\n%s", status, body)
	}
}

// unavailable asserts err is -32037 and returns its message.
func unavailable(t *testing.T, what string, err error) string {
	t.Helper()
	if err == nil {
		t.Fatalf("%s succeeded, want -32037", what)
	}
	return rpcError(t, err, mcp.CodeSecretUnavailable).Message
}

func randomRequestID() string {
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	b := make([]byte, 43)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

// TestSecuritySecretHandleIsBoundToOwnerHarnessAndTarget: a provided
// handle is refused with the one -32037 answer when another user (who
// can call the same tool) or another harness of the owner uses it, for
// another tool, another argument, or nested inside an argument. None of
// those refusals reaches the upstream or spends the use; the owner's
// harness then uses it once.
func TestSecuritySecretHandleIsBoundToOwnerHarnessAndTarget(t *testing.T) {
	w, v, srv := newSecretsWorld(t)
	w.publish(srv, []policy.ToolRule{{App: "vault", Tool: policy.Wildcard, Outcome: policy.OutcomeAllow}}, roleRestricted)

	harnessA := w.client(w.alice)
	path, handle := w.requestSecret(harnessA, "vault.login", "password", 1)
	w.provide(w.alice, path)

	var msgs []string
	_, err := w.call(w.client(w.bob), "vault.login", map[string]any{"password": secretRef(handle)})
	msgs = append(msgs, unavailable(t, "bob with alice's handle", err))
	_, err = w.call(w.client(w.alice), "vault.login", map[string]any{"password": secretRef(handle)})
	msgs = append(msgs, unavailable(t, "alice's other harness", err))
	_, err = w.call(harnessA, "vault.unlock", map[string]any{"password": secretRef(handle)})
	msgs = append(msgs, unavailable(t, "another tool", err))
	_, err = w.call(harnessA, "vault.login", map[string]any{"password": "not-the-secret", "note": secretRef(handle)})
	msgs = append(msgs, unavailable(t, "another argument", err))
	_, err = w.call(harnessA, "vault.login", map[string]any{"password": "not-the-secret", "options": map[string]any{"pw": secretRef(handle)}})
	msgs = append(msgs, unavailable(t, "nested ref", err))
	_, err = w.call(harnessA, "vault.login", map[string]any{"password": secretRef("sec_" + randomRequestID())})
	msgs = append(msgs, unavailable(t, "unknown handle", err))
	for i, m := range msgs {
		if m != msgs[0] {
			t.Errorf("refusal %d = %q, want the same text as %q", i, m, msgs[0])
		}
	}
	if seen := v.received(); len(seen) != 0 {
		t.Fatalf("refused calls reached the upstream: %q", seen)
	}

	res, err := w.call(harnessA, "vault.login", map[string]any{"password": secretRef(handle)})
	if err != nil || res.IsError {
		t.Fatalf("owner's harness = %v, %v", res, err)
	}
	if got := text(t, res); strings.Contains(got, secretValue) || !strings.Contains(got, "[secret]") {
		t.Errorf("result = %q", got)
	}
	if seen := v.received(); len(seen) != 1 || seen[0] != secretValue {
		t.Errorf("upstream received %q, want the value once", seen)
	}
}

// TestSecuritySecretEntryPageHardening: the entry page is framed-proof
// and uncached; another user opening the link gets byte for byte the
// portal's unknown-page 404 and cannot answer it; a POST without the CSRF
// token is refused; guessing ids is the same 404 until the per-address
// budget is gone, then 429 with Retry-After.
func TestSecuritySecretEntryPageHardening(t *testing.T) {
	w, _, _ := newSecretsWorld(t)
	path, _ := w.requestSecret(w.client(w.alice), "vault.login", "password", 1)

	status, h, body := w.get(w.alice, path)
	if status != http.StatusOK || !strings.Contains(body, `type="password"`) {
		t.Fatalf("entry page = %d:\n%s", status, body)
	}
	if h.Get("X-Frame-Options") != "DENY" || !strings.Contains(h.Get("Content-Security-Policy"), "frame-ancestors 'none'") ||
		h.Get("Cache-Control") != "no-store" || h.Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("entry page headers = %v", h)
	}

	failures := 0
	status, _, unknownPage := w.get(w.bob, "/no-such-page")
	if status != http.StatusNotFound {
		t.Fatalf("unknown portal page = %d", status)
	}
	same404 := func(what string, status int, body string) {
		t.Helper()
		if status != http.StatusNotFound || body != unknownPage {
			t.Errorf("%s = %d, want the portal's unknown-page 404:\n%s", what, status, body)
		}
	}
	status, _, body = w.get(w.bob, path)
	same404("bob opens alice's link", status, body)
	status, _, body = w.post(w.bob, path, url.Values{"action": {"save"}, "value": {secretValue}})
	same404("bob saves on alice's link", status, body)
	status, _, body = w.post(w.bob, path, url.Values{"action": {"deny"}})
	same404("bob denies alice's link", status, body)
	status, _, body = w.get(w.bob, "/s/"+randomRequestID())
	same404("bob guesses an id", status, body)
	failures += 4

	// Without the CSRF token: refused, nothing stored.
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, w.srv.URL+path,
		strings.NewReader(url.Values{"action": {"save"}, "value": {secretValue}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(w.alice.cookie)
	res, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("POST without CSRF = %d, want 403", res.StatusCode)
	}
	if status, _, _ := w.get(w.alice, path); status != http.StatusOK {
		t.Errorf("entry after the refused POSTs = %d, want the request still pending", status)
	}
	if n := w.queryString(`SELECT count(*)::text FROM secrets WHERE state <> 'pending' OR value_ciphertext IS NOT NULL`); n != "0" {
		t.Errorf("%s secrets changed by refused POSTs", n)
	}

	// Guessing: the 404 until the budget is spent, then 429.
	limited := false
	for failures < secrets.EntryFailureBurst+1 {
		status, h, body := w.get(w.bob, "/s/"+randomRequestID())
		if status == http.StatusTooManyRequests {
			if h.Get("Retry-After") == "" {
				t.Error("429 without Retry-After")
			}
			limited = true
			break
		}
		same404("guess", status, body)
		failures++
	}
	if !limited {
		status, h, _ := w.get(w.bob, "/s/"+randomRequestID())
		if status != http.StatusTooManyRequests || h.Get("Retry-After") == "" {
			t.Fatalf("after %d failed lookups = %d, want 429 with Retry-After", failures, status)
		}
	}
	// The limit is per address: alice, from the same address, waits too.
	if status, _, _ := w.get(w.alice, path); status != http.StatusTooManyRequests {
		t.Errorf("same address, real link = %d, want 429", status)
	}
}

// TestSecurityReadOnlyTokenCannotRequestSecrets: a read-only token does
// not see secrets.request and cannot call it.
func TestSecurityReadOnlyTokenCannotRequestSecrets(t *testing.T) {
	w, _, _ := newSecretsWorld(t)
	if !contains(toolNames(t, w.client(w.alice)), "secrets.request") {
		t.Fatal("secrets.request not listed for a full token")
	}
	ro := w.clientWith(w.token(w.alice, tokens.CreateRequest{Name: "read-only", ReadOnly: true}))
	if names := toolNames(t, ro); contains(names, "secrets.request") {
		t.Errorf("read-only token lists secrets.request: %v", names)
	}
	_, err := w.call(ro, "secrets.request", map[string]any{"label": "vault password", "tool": "vault.login", "arg": "password"})
	if err == nil {
		t.Fatal("read-only token called secrets.request")
	}
	if code := rpcCode(err); code == mcp.CodeSecretRequired {
		t.Errorf("read-only token got -32042: %v", err)
	}
	if n := w.queryString(`SELECT count(*)::text FROM secrets`); n != "0" {
		t.Errorf("read-only token stored %s secret requests", n)
	}
}

// TestSecuritySecretWithApprovalAndLeakSweep: a write tool used with a
// secret asks for approval; the approval stores the handle, never the
// value; once approved the retry delivers the value. Afterwards no form of
// the value is in the log, audit, ledger, approvals or secrets rows.
func TestSecuritySecretWithApprovalAndLeakSweep(t *testing.T) {
	w, v, _ := newSecretsWorld(t)
	ctx := t.Context()
	alice := w.client(w.alice)
	path, handle := w.requestSecret(alice, "vault.rotate", "password", 1)
	w.provide(w.alice, path)

	_, err := w.call(alice, "vault.rotate", map[string]any{"password": secretRef(handle)})
	approvalID := approvalRequired(t, err)
	if seen := v.received(); len(seen) != 0 {
		t.Fatalf("the write ran before its approval: %q", seen)
	}
	pending, err := w.approval.Pending(ctx, w.alice.id)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range pending {
		if p.ID != approvalID {
			continue
		}
		found = true
		ref, _ := p.Args["password"].(map[string]any)
		if len(p.Args) != 1 || len(ref) != 1 || ref["$secret"] != handle {
			t.Errorf("approval payload = %v, want only the handle", p.Args)
		}
		b, _ := json.Marshal(p)
		if strings.Contains(string(b), secretValue) {
			t.Errorf("approval holds the value: %s", b)
		}
	}
	if !found {
		t.Fatalf("approval %s not pending: %+v", approvalID, pending)
	}
	if _, err := w.approval.Approve(ctx, w.alice.id, approvalID); err != nil {
		t.Fatal(err)
	}
	res, err := w.call(alice, "vault.rotate", map[string]any{"password": secretRef(handle)})
	if err != nil || res.IsError {
		t.Fatalf("approved retry = %v, %v", res, err)
	}
	got := text(t, res)
	for what, form := range secretForms {
		if strings.Contains(got, form) {
			t.Errorf("agent result holds the %s form: %q", what, got)
		}
	}
	if seen := v.received(); len(seen) != 1 || seen[0] != secretValue {
		t.Errorf("upstream received %q, want the value once", seen)
	}
	if op := w.opFor(w.alice, "vault.rotate", store.LedgerSucceeded); op == nil {
		t.Error("approved write not ledgered as succeeded")
	}

	// The leak sweep: the log, then every row of the tables the call
	// touched, as text.
	logs := w.logs.String()
	for _, table := range []string{"audit_events", "ledger_operations", "ledger_attempts", "approvals", "secrets"} {
		rows := tableText(t, table)
		if rows == "" && table != "ledger_attempts" {
			t.Errorf("%s: no rows to sweep", table)
		}
		for what, form := range secretForms {
			if strings.Contains(rows, form) {
				t.Errorf("%s holds the %s form of the value", table, what)
			}
			if strings.Contains(logs, form) {
				t.Errorf("the log holds the %s form of the value", what)
			}
		}
		if table == "secrets" && (strings.Contains(rows, handle) || strings.Contains(rows, strings.TrimPrefix(path, "/s/"))) {
			t.Error("the secrets table holds a raw handle or request id")
		}
	}
}

// rpcCode is err's JSON-RPC code, or 0.
func rpcCode(err error) int64 {
	var je *jsonrpc.Error
	if errors.As(err, &je) {
		return je.Code
	}
	return 0
}

// tableText is every row of table as JSON text, read as the superuser
// (row security would hide other users' rows).
func tableText(t *testing.T, table string) string {
	t.Helper()
	u, err := url.Parse(os.Getenv("GATEWAY_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + testDB
	conn, err := pgx.Connect(t.Context(), u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(context.Background()) }()
	var out string
	if err := conn.QueryRow(t.Context(), `SELECT coalesce(string_agg(row_to_json(t)::text, E'\n'), '') FROM `+pgx.Identifier{table}.Sanitize()+` t`).Scan(&out); err != nil {
		t.Fatalf("read %s: %v", table, err)
	}
	return out
}
