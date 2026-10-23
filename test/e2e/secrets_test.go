//go:build integration || e2e

package e2e

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/portal"
	"github.com/huynle/mcp-gateway/internal/secrets"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

// --- wiring (cmd/gateway's secrets.go) ------------------------------------------------

// wireSecrets builds the service and registers the secrets app with the
// pipeline's visibility, as cmd/gateway's newSecrets does.
func (w *world) wireSecrets(keys crypto.KeyProvider, reg *connectors.Registry, decider mcp.Decider, log *slog.Logger) {
	w.t.Helper()
	if w.fed == nil {
		w.t.Fatal("options.secrets needs options.federation")
	}
	svc, err := secrets.New(secrets.NewPostgresStore(w.st), keys, secrets.Options{Log: log})
	if err != nil {
		w.t.Fatal(err)
	}
	app, err := secrets.NewConnector(secrets.ConnectorDeps{
		Service: svc, Tools: reg, Visibility: mcp.PolicyVisibility{Decider: decider, Log: log},
		Targets: w.fed.Manager, BaseURL: baseURL, Log: log,
	})
	if err != nil {
		w.t.Fatal(err)
	}
	if err := app.Register(reg); err != nil {
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

type vaultIn struct {
	Password string `json:"password"`
}

// vault is an upstream whose login tool echoes the password it received,
// raw and base64-encoded, and remembers it.
type vault struct {
	mu   sync.Mutex
	seen []string
}

func (v *vault) received() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]string(nil), v.seen...)
}

func newVaultUpstream(t *testing.T) (*vault, string) {
	t.Helper()
	v := &vault{}
	s := sdk.NewServer(&sdk.Implementation{Name: "vault", Version: "1"}, nil)
	sdk.AddTool(s, &sdk.Tool{Name: "login", Description: "Log in with a password.", Annotations: &sdk.ToolAnnotations{ReadOnlyHint: true}},
		func(_ context.Context, _ *sdk.CallToolRequest, in vaultIn) (*sdk.CallToolResult, any, error) {
			v.mu.Lock()
			v.seen = append(v.seen, in.Password)
			v.mu.Unlock()
			return textResult("logged in with " + in.Password + " (" + base64.StdEncoding.EncodeToString([]byte(in.Password)) + ")"), nil, nil
		})
	return v, newOpenUpstream(t, s).URL
}

// secretAsk is the -32042 answer's data.
type secretAsk struct {
	URL          string `json:"url"`
	Handle       string `json:"handle"`
	Fingerprint  string `json:"fingerprint"`
	Elicitations []struct {
		Mode          string `json:"mode"`
		ElicitationID string `json:"elicitationId"`
		URL           string `json:"url"`
	} `json:"elicitations"`
}

func secretRequired(t *testing.T, err error) secretAsk {
	t.Helper()
	je := rpcError(t, err, mcp.CodeSecretRequired)
	var ask secretAsk
	if err := json.Unmarshal(je.Data, &ask); err != nil {
		t.Fatalf("-32042 data %s: %v", je.Data, err)
	}
	if ask.URL == "" || !strings.HasPrefix(ask.Handle, "sec_") || ask.Fingerprint == "" ||
		len(ask.Elicitations) != 1 || ask.Elicitations[0].Mode != "url" || ask.Elicitations[0].URL != ask.URL {
		t.Fatalf("-32042 data = %s", je.Data)
	}
	if !strings.Contains(je.Message, ask.URL) {
		t.Errorf("-32042 message lacks the link: %q", je.Message)
	}
	return ask
}

// entryPath is the path of an entry link on this world's server.
func entryPath(t *testing.T, link string) string {
	t.Helper()
	if !strings.HasPrefix(link, baseURL+"/s/") {
		t.Fatalf("entry link %q is not under %s/s/", link, baseURL)
	}
	return strings.TrimPrefix(link, baseURL)
}

func secretRef(handle string) map[string]any { return map[string]any{"$secret": handle} }

// newSecretsWorld is a world with secrets and alice's vault server
// approved with its login tool.
func newSecretsWorld(t *testing.T) (*world, *vault) {
	t.Helper()
	w := newWorld(t, options{federation: true, secrets: true})
	w.allowLoopback()
	v, u := newVaultUpstream(t)
	id := w.addServer(w.alice, url.Values{"name": {"vault"}, "url_mode": {"https"}, "url": {u},
		"auth_kind": {"none"}, "credential_mode": {"per_user"}})
	w.approve(w.alice, id, w.refresh(w.alice, id), "login")
	return w, v
}

// TestE2ESecretsUsableButUnreadable: secrets.request answers -32042 with
// the link, handle and fingerprint; the owner sees the same fingerprint
// on /s/{id} and saves; the retry with the handle reaches the upstream
// with the plaintext, and the agent's result holds "[secret]" but neither
// the value nor its base64. A second use of a one-use secret is -32037;
// a denied request is -32030.
func TestE2ESecretsUsableButUnreadable(t *testing.T) {
	w, v := newSecretsWorld(t)
	const value = "hunter2 c0rrect/horse+battery&staple"
	b64 := base64.StdEncoding.EncodeToString([]byte(value))
	w.forbid(value, "secret value")
	w.forbid(b64, "secret value (base64)")
	w.forbid(url.QueryEscape(value), "secret value (url-escaped)")
	w.forbid(url.PathEscape(value), "secret value (path-escaped)")

	alice := w.client(w.alice)
	if !contains(toolNames(t, alice), "secrets.request") {
		t.Fatalf("secrets.request not listed: %v", toolNames(t, alice))
	}
	_, err := w.call(alice, "secrets.request", map[string]any{"label": "vault password", "tool": "vault.login", "arg": "password", "uses": 1})
	ask := secretRequired(t, err)
	path := entryPath(t, ask.URL)
	w.forbid(strings.TrimPrefix(path, "/s/"), "entry link request id")

	// Not entered yet: the same -32042, same link.
	_, err = w.call(alice, "vault.login", map[string]any{"password": secretRef(ask.Handle)})
	if again := secretRequired(t, err); again.URL != ask.URL || again.Handle != ask.Handle {
		t.Errorf("retry before entry = %+v, want the same link and handle", again)
	}
	if len(v.received()) != 0 {
		t.Fatalf("the upstream was called before the secret was entered: %v", v.received())
	}

	// The owner opens the link and sees the same fingerprint.
	p := w.page(w.alice, path)
	if p.status != http.StatusOK || !strings.Contains(p.body, ask.Fingerprint) || !strings.Contains(p.body, "vault password") {
		t.Fatalf("entry page = %d, fingerprint %q:\n%s", p.status, ask.Fingerprint, snippet(p.body))
	}
	if p := w.submit(w.alice, path, url.Values{"action": {"save"}, "value": {value}}); p.status != http.StatusOK || strings.Contains(p.body, value) {
		t.Fatalf("save = %d:\n%s", p.status, snippet(p.body))
	}

	// The retry with the handle: plaintext upstream, scrubbed result.
	res, err := w.call(alice, "vault.login", map[string]any{"password": secretRef(ask.Handle)})
	if err != nil || res.IsError {
		t.Fatalf("login with the handle = %v, %v", res, err)
	}
	got := text(t, res)
	if !strings.Contains(got, "[secret]") || strings.Contains(got, value) || strings.Contains(got, b64) {
		t.Errorf("agent result = %q, want [secret] and neither the value nor its base64", got)
	}
	if seen := v.received(); len(seen) != 1 || seen[0] != value {
		t.Fatalf("upstream received %q, want the plaintext once", seen)
	}
	used := false
	for _, ev := range w.events(w.alice) {
		if ev.ResourceIdentity["action"] == "secret.used" && ev.ResourceIdentity["label"] == "vault password" {
			used = true
		}
	}
	if !used {
		t.Error("no secret.used audit row")
	}

	// One use only.
	_, err = w.call(alice, "vault.login", map[string]any{"password": secretRef(ask.Handle)})
	_ = rpcError(t, err, mcp.CodeSecretUnavailable)
	if n := len(v.received()); n != 1 {
		t.Errorf("upstream calls after the used-up retry = %d, want 1", n)
	}

	// Deny path.
	_, err = w.call(alice, "secrets.request", map[string]any{"label": "other password", "tool": "vault.login", "arg": "password"})
	denied := secretRequired(t, err)
	if p := w.submit(w.alice, entryPath(t, denied.URL), url.Values{"action": {"deny"}}); p.status != http.StatusOK {
		t.Fatalf("deny = %d:\n%s", p.status, snippet(p.body))
	}
	_, err = w.call(alice, "vault.login", map[string]any{"password": secretRef(denied.Handle)})
	_ = rpcError(t, err, mcp.CodeDenied)
	if n := len(v.received()); n != 1 {
		t.Errorf("upstream calls after the denied retry = %d, want 1", n)
	}
}

// TestE2ESecretsRequiredIsAnErrorForSDKClients: the official go-sdk
// client gets -32042 back from CallTool as a *jsonrpc.Error at once, with
// or without an elicitation handler; it never waits for
// notifications/elicitation/complete (which the stateless gateway never
// sends).
func TestE2ESecretsRequiredIsAnErrorForSDKClients(t *testing.T) {
	w, _ := newSecretsWorld(t)
	handled := make(chan *sdk.ElicitRequest, 4)
	opts := &sdk.ClientOptions{ElicitationHandler: func(_ context.Context, req *sdk.ElicitRequest) (*sdk.ElicitResult, error) {
		handled <- req
		return &sdk.ElicitResult{Action: "accept"}, nil
	}}
	transport := &sdk.StreamableClientTransport{Endpoint: w.srv.URL + "/mcp", HTTPClient: bearerClient(w.token(w.alice, tokens.CreateRequest{Name: "elicit"}))}
	withHandler, err := sdk.NewClient(&sdk.Implementation{Name: "e2e-elicit", Version: "0"}, opts).Connect(t.Context(), transport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = withHandler.Close() }()

	for name, cs := range map[string]*sdk.ClientSession{"plain": w.client(w.alice), "elicitation handler": withHandler} {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		start := time.Now()
		_, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "secrets.request",
			Arguments: map[string]any{"label": "vault password", "tool": "vault.login", "arg": "password"}})
		cancel()
		var je *jsonrpc.Error
		if !errors.As(err, &je) || je.Code != mcp.CodeSecretRequired {
			t.Fatalf("%s client: err = %v (%T), want the -32042 *jsonrpc.Error", name, err, err)
		}
		if d := time.Since(start); d > 5*time.Second {
			t.Errorf("%s client: -32042 took %s (waiting for elicitation/complete?)", name, d)
		}
	}
	select {
	case req := <-handled:
		t.Errorf("the SDK ran the elicitation handler for -32042: %+v", req.Params)
	default:
	}
}
