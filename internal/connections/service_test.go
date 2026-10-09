package connections_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/connections/connectionstest"
	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/store"
)

const (
	userAlice = "11111111-1111-4111-8111-111111111111"
	userBob   = "22222222-2222-4222-8222-222222222222"
)

// memAudit records events in memory.
type memAudit struct{ events []audit.Event }

func (m *memAudit) Record(_ context.Context, ev audit.Event) error {
	m.events = append(m.events, ev)
	return nil
}

// allowAll is a personal-account policy that permits everything.
type allowAll struct{}

func (allowAll) PersonalAccountsAllowed(context.Context, string, string) (bool, error) {
	return true, nil
}

type testEnv struct {
	svc   *connections.Service
	store *connectionstest.MemStore
	audit *memAudit
	logs  *bytes.Buffer
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	kp, err := crypto.NewStaticProvider("k1", map[string][]byte{"k1": bytes.Repeat([]byte{7}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	logs := &bytes.Buffer{}
	log := slog.New(slog.NewTextHandler(logs, nil))
	mem := connectionstest.NewMemStore()
	rec := &memAudit{}
	svc, err := connections.New(connections.Config{BaseURL: "http://gw.test"}, mem, kp, connections.Options{
		Audit: rec, Policy: allowAll{}, Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &testEnv{svc: svc, store: mem, audit: rec, logs: logs}
}

func TestSaveVendorAppEncryptsSecretAndNeverReturnsIt(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	in := connections.VendorApp{
		Vendor: "github", Variant: "", ClientID: "cid-123", ClientSecret: "sekrit-abc",
		AuthURL: "https://example.test/authorize", TokenURL: "https://example.test/token",
		Scopes: []string{"read:user"}, Enabled: true,
	}
	saved, err := env.svc.SaveVendorApp(ctx, userAlice, in)
	if err != nil {
		t.Fatalf("SaveVendorApp: %v", err)
	}
	if saved.ID == "" || saved.Variant != connections.DefaultVariant || !saved.HasSecret || saved.ClientSecret != "" {
		t.Fatalf("saved = %+v", saved)
	}
	// Nothing in the store holds the plaintext secret.
	for _, row := range env.store.VendorAppRows() {
		if bytes.Contains(row.ClientSecret.Ciphertext, []byte("sekrit-abc")) || strings.Contains(string(row.Config), "sekrit-abc") {
			t.Fatalf("plaintext secret stored: %+v", row)
		}
		if len(row.ClientSecret.Ciphertext) == 0 || row.ClientSecret.KeyID != "k1" {
			t.Fatalf("secret not encrypted: %+v", row.ClientSecret)
		}
	}
	got, err := env.svc.VendorApp(ctx, "github", "")
	if err != nil {
		t.Fatal(err)
	}
	if got.ClientSecret != "" || !got.HasSecret || got.ClientID != "cid-123" || got.AuthURL != in.AuthURL || got.Scopes[0] != "read:user" {
		t.Fatalf("VendorApp = %+v", got)
	}
	// Saving again without a secret keeps the old one; the audit trail
	// names the admin and the app, never the secret.
	in.ClientSecret = ""
	in.ClientID = "cid-456"
	again, err := env.svc.SaveVendorApp(ctx, userAlice, in)
	if err != nil {
		t.Fatal(err)
	}
	if again.ID != saved.ID || !again.HasSecret || again.ClientID != "cid-456" {
		t.Fatalf("second save = %+v", again)
	}
	if len(env.audit.events) != 2 || env.audit.events[0].UserID != userAlice || env.audit.events[0].ResourceIdentity["action"] != "vendor_app_saved" || env.audit.events[0].ResourceIdentity["vendor"] != "github" {
		t.Fatalf("audit = %+v", env.audit.events)
	}
	if strings.Contains(env.logs.String(), "sekrit") {
		t.Fatalf("secret leaked into logs: %s", env.logs.String())
	}
	// Reads of all apps list it under the vendor.
	apps, err := env.svc.VendorApps(ctx)
	if err != nil || len(apps) != 1 || apps[0].Vendor != "github" {
		t.Fatalf("VendorApps = %+v, %v", apps, err)
	}
	if _, err := env.svc.SaveVendorApp(ctx, userAlice, connections.VendorApp{Vendor: "nope", ClientID: "x", ClientSecret: "y"}); err == nil {
		t.Fatal("unknown vendor accepted")
	}
	if _, err := env.svc.SaveVendorApp(ctx, userAlice, connections.VendorApp{Vendor: "google", Variant: "internal", ClientID: "x"}); err == nil {
		t.Fatal("first save without a secret accepted")
	}
	if _, err := env.svc.VendorApp(ctx, "slack", ""); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing app err = %v", err)
	}
}

// denyPersonal refuses personal accounts for the named app.
type denyPersonal struct{ app string }

func (d denyPersonal) PersonalAccountsAllowed(_ context.Context, _ string, app string) (bool, error) {
	return app != d.app, nil
}

// registerFakeApp registers the fake vendor as vendor "fake" with alice's
// company domain acme.test.
func registerFakeApp(t *testing.T, env *testEnv, v *fakeVendor) connections.VendorApp {
	t.Helper()
	app, err := env.svc.SaveVendorApp(context.Background(), userAlice, connections.VendorApp{
		Vendor: connections.VendorFake, ClientID: v.clientID, ClientSecret: v.secret,
		AuthURL: v.URL() + "/authorize", TokenURL: v.URL() + "/token", UserInfoURL: v.URL() + "/userinfo", RevokeURL: v.URL() + "/revoke",
		Scopes:  []string{"read:user"},
		Extra:   map[string]string{connections.ExtraCompanyDomains: "acme.test", connections.ExtraNameField: "login", "prompt": "consent"},
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("SaveVendorApp: %v", err)
	}
	return app
}

// connect runs start + the vendor's authorize hop + callback for the user
// and returns the connection.
func connect(t *testing.T, env *testEnv, userID, account string, scopes ...string) (connections.Info, error) {
	t.Helper()
	ctx := context.Background()
	redirect, err := env.svc.Start(ctx, connections.StartRequest{UserID: userID, Vendor: connections.VendorFake, Scopes: scopes})
	if err != nil {
		return connections.Info{}, err
	}
	u, err := url.Parse(redirect)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("login_as", account)
	u.RawQuery = q.Encode()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("authorize status %d", res.StatusCode)
	}
	back, err := url.Parse(res.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(back.String(), "http://gw.test/connect/fake/callback?") {
		t.Fatalf("vendor redirected to %s", back)
	}
	return env.svc.Callback(ctx, connections.CallbackRequest{UserID: userID, Vendor: connections.VendorFake, State: back.Query().Get("state"), Code: back.Query().Get("code")})
}

func TestConnectCompanyAccountStoresEncryptedTokens(t *testing.T) {
	env := newTestEnv(t)
	v := newFakeVendor(t)
	app := registerFakeApp(t, env, v)

	redirect, err := env.svc.Start(context.Background(), connections.StartRequest{UserID: userAlice, Vendor: "fake", Scopes: []string{"repo"}})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	u, _ := url.Parse(redirect)
	q := u.Query()
	if !strings.HasPrefix(redirect, v.URL()+"/authorize?") || q.Get("state") == "" || q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" ||
		q.Get("redirect_uri") != "http://gw.test/connect/fake/callback" || q.Get("scope") != "read:user repo" || q.Get("prompt") != "consent" || q.Get("client_id") != v.clientID {
		t.Fatalf("authorize URL = %s", redirect)
	}
	if env.store.FlowCount() != 1 {
		t.Fatalf("flows stored = %d", env.store.FlowCount())
	}

	info, err := connect(t, env, userAlice, "acct-company", "repo")
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if info.ID == "" || info.Vendor != "fake" || info.Variant != app.Variant || info.ExternalAccountID != "acct-company" || info.Label != "company" ||
		info.DisplayName != "alice" || info.Status != "active" || strings.Join(info.Scopes, " ") != "read:user repo" {
		t.Fatalf("info = %+v", info)
	}
	if env.store.FlowCount() != 1 { // connect's own flow was consumed; the one started above is still pending
		t.Fatalf("flow not consumed: %d left", env.store.FlowCount())
	}
	// The token bundle is encrypted: no issued token appears in the
	// stored rows or the logs.
	secrets := env.store.SecretRows()
	if len(secrets) != 1 || secrets[0].ConnectionID != info.ID || secrets[0].UserID != userAlice || secrets[0].Secret.KeyID != "k1" || secrets[0].TokenExpiresAt == nil {
		t.Fatalf("secrets = %+v", secrets)
	}
	for _, tok := range v.allTokens() {
		if bytes.Contains(secrets[0].Secret.Ciphertext, []byte(tok)) {
			t.Fatalf("plaintext token %q in ciphertext", tok)
		}
		if strings.Contains(env.logs.String(), tok) {
			t.Fatalf("token %q leaked into logs:\n%s", tok, env.logs.String())
		}
	}
	// The audit trail has the connect with the label.
	last := env.audit.events[len(env.audit.events)-1]
	if last.UserID != userAlice || last.AccountID != info.ID || last.AccountLabel != "company" || last.ResourceIdentity["action"] != "connected" || last.ResourceIdentity["vendor"] != "fake" {
		t.Fatalf("audit = %+v", last)
	}
	// Reconnecting the same account with more scopes is the same
	// connection with the union of scopes (incremental consent).
	again, err := connect(t, env, userAlice, "acct-company", "write:org")
	if err != nil {
		t.Fatal(err)
	}
	if again.ID != info.ID || strings.Join(again.Scopes, " ") != "read:user repo write:org" {
		t.Fatalf("reconnect = %+v", again)
	}
	if n := len(env.store.ConnectionRows()); n != 1 {
		t.Fatalf("connections = %d", n)
	}
	// A second, personal account is a second connection.
	personal, err := connect(t, env, userAlice, "acct-personal")
	if err != nil {
		t.Fatal(err)
	}
	if personal.ID == info.ID || personal.Label != "personal" || personal.DisplayName != "alice-home" {
		t.Fatalf("personal = %+v", personal)
	}
}

func TestConnectPersonalRefusedWhenRoleDeniesIt(t *testing.T) {
	env := newTestEnv(t)
	v := newFakeVendor(t)
	registerFakeApp(t, env, v)
	env.svc.SetPolicy(denyPersonal{app: "fake"})

	if _, err := connect(t, env, userAlice, "acct-company"); err != nil {
		t.Fatalf("company: %v", err)
	}
	_, err := connect(t, env, userAlice, "acct-personal")
	if !errors.Is(err, connections.ErrPersonalRefused) {
		t.Fatalf("personal err = %v", err)
	}
	if n := len(env.store.ConnectionRows()); n != 1 {
		t.Fatalf("connections = %d, want only the company one", n)
	}
	if n := len(env.store.SecretRows()); n != 1 {
		t.Fatalf("secrets = %d", n)
	}
	last := env.audit.events[len(env.audit.events)-1]
	if last.Outcome != "denied" || last.AccountLabel != "personal" || last.ResourceIdentity["action"] != "connect_refused" || last.ErrorClass != "personal_account_denied" {
		t.Fatalf("audit = %+v", last)
	}
}

func TestCallbackRejectsBadStateOtherUserAndVendorErrors(t *testing.T) {
	env := newTestEnv(t)
	v := newFakeVendor(t)
	registerFakeApp(t, env, v)
	ctx := context.Background()

	redirect, err := env.svc.Start(ctx, connections.StartRequest{UserID: userAlice, Vendor: "fake"})
	if err != nil {
		t.Fatal(err)
	}
	state := mustQuery(t, redirect).Get("state")
	challenge := mustQuery(t, redirect).Get("code_challenge")

	// Unknown state.
	_, err = env.svc.Callback(ctx, connections.CallbackRequest{UserID: userAlice, Vendor: "fake", State: "nope", Code: "x"})
	if !errors.Is(err, connections.ErrFlowInvalid) {
		t.Fatalf("bad state err = %v", err)
	}
	// Another user's session cannot finish alice's flow, and the attempt
	// does not consume it... but Bob's callback is refused either way.
	_, err = env.svc.Callback(ctx, connections.CallbackRequest{UserID: userBob, Vendor: "fake", State: state, Code: "x"})
	if !errors.Is(err, connections.ErrFlowInvalid) {
		t.Fatalf("other user err = %v", err)
	}
	// The vendor said no.
	_, err = env.svc.Callback(ctx, connections.CallbackRequest{UserID: userAlice, Vendor: "fake", State: state, Error: "access_denied"})
	if !errors.Is(err, connections.ErrVendorDenied) {
		t.Fatalf("vendor denied err = %v", err)
	}
	if env.store.FlowCount() != 0 {
		t.Fatal("flow survived a vendor error")
	}
	// A code whose PKCE verifier does not match the stored challenge is
	// refused by the vendor and surfaces as a flow error; so is a replay
	// of a consumed state.
	redirect, _ = env.svc.Start(ctx, connections.StartRequest{UserID: userAlice, Vendor: "fake"})
	state2 := mustQuery(t, redirect).Get("state")
	code := v.issueCode("acct-company", challenge /* belongs to the first flow */, "http://gw.test/connect/fake/callback")
	_, err = env.svc.Callback(ctx, connections.CallbackRequest{UserID: userAlice, Vendor: "fake", State: state2, Code: code})
	if !errors.Is(err, connections.ErrFlowInvalid) {
		t.Fatalf("pkce mismatch err = %v", err)
	}
	_, err = env.svc.Callback(ctx, connections.CallbackRequest{UserID: userAlice, Vendor: "fake", State: state2, Code: code})
	if !errors.Is(err, connections.ErrFlowInvalid) {
		t.Fatalf("replay err = %v", err)
	}
	// Expired flows are refused.
	redirect, _ = env.svc.Start(ctx, connections.StartRequest{UserID: userAlice, Vendor: "fake"})
	state3 := mustQuery(t, redirect).Get("state")
	env.svc.SetClock(func() time.Time { return time.Now().Add(time.Hour) })
	_, err = env.svc.Callback(ctx, connections.CallbackRequest{UserID: userAlice, Vendor: "fake", State: state3, Code: "x"})
	if !errors.Is(err, connections.ErrFlowInvalid) {
		t.Fatalf("expired err = %v", err)
	}
	// Starting for an unconfigured vendor fails cleanly.
	if _, err := env.svc.Start(ctx, connections.StartRequest{UserID: userAlice, Vendor: "github"}); !errors.Is(err, connections.ErrNotConfigured) {
		t.Fatalf("unconfigured err = %v", err)
	}
}

func mustQuery(t *testing.T, raw string) url.Values {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query()
}

// TestAuthParamsSendOnlyAuthorizationParameters (quirk sxbr5or5): binder
// hints in Extra (company_domains, default_label, the field names, the
// GitHub binder's company_orgs) are configuration for the gateway and
// never become authorization request parameters; real parameters
// (access_type, prompt, audience, ...) still are.
func TestAuthParamsSendOnlyAuthorizationParameters(t *testing.T) {
	app := connections.VendorApp{Extra: map[string]string{
		"prompt": "consent", "access_type": "offline", "audience": "api.example.test",
		connections.ExtraCompanyDomains: "acme.test", connections.ExtraDefaultLabel: "company", connections.ExtraScopeParam: "user_scope",
		connections.ExtraIDField: "id", connections.ExtraNameField: "login", connections.ExtraEmailField: "email",
		connections.ExtraCompanyOrgs: "acme,acme-labs", "": "ignored",
	}}
	var got []string
	for _, kv := range app.AuthParams() {
		got = append(got, kv[0]+"="+kv[1])
	}
	if want := "access_type=offline,audience=api.example.test,prompt=consent"; strings.Join(got, ",") != want {
		t.Errorf("AuthParams = %v, want %s", got, want)
	}

	// Through the flow: the authorize URL carries prompt but no company_orgs.
	env := newTestEnv(t)
	v := newFakeVendor(t)
	saved := registerFakeApp(t, env, v)
	saved.Extra[connections.ExtraCompanyOrgs] = "acme"
	saved.ClientSecret = v.secret
	if _, err := env.svc.SaveVendorApp(context.Background(), userAlice, saved); err != nil {
		t.Fatalf("SaveVendorApp: %v", err)
	}
	redirect, err := env.svc.Start(context.Background(), connections.StartRequest{UserID: userAlice, Vendor: connections.VendorFake})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	u, err := url.Parse(redirect)
	if err != nil {
		t.Fatal(err)
	}
	if q := u.Query(); q.Get("prompt") != "consent" || q.Has(connections.ExtraCompanyOrgs) || q.Has(connections.ExtraCompanyDomains) {
		t.Errorf("authorize query = %v, want prompt=consent and no binder hints", q)
	}
}
