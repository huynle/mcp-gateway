package connectors_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// stubConnector dispatches by tool name in Call; its Tools leave Handler
// nil, which is the documented convention RegisterConnector binds.
type stubConnector struct {
	app   string
	tools []connectors.Tool
	calls []string
}

func (s *stubConnector) App() string              { return s.app }
func (s *stubConnector) Tools() []connectors.Tool { return s.tools }
func (s *stubConnector) Call(_ context.Context, call connectors.Call) (connectors.Result, error) {
	s.calls = append(s.calls, call.Tool+"@"+call.Account)
	return connectors.Result{Content: "dispatched " + call.Tool}, nil
}

func newStubConnector() *stubConnector {
	s := &stubConnector{app: "stub"}
	s.tools = []connectors.Tool{
		{
			App: "stub", Name: "list_things", Description: "lists things", Kind: connectors.KindRead,
			InputSchema:      json.RawMessage(`{"type":"object","properties":{}}`),
			ResourceIdentity: func(map[string]any) map[string]string { return map[string]string{} },
			Bounds:           connectors.Bounds{MaxPageSize: 10, MaxResultBytes: 1024},
		},
		{
			App: "stub", Name: "make_thing", Description: "makes a thing", Kind: connectors.KindWrite,
			InputSchema:      json.RawMessage(`{"type":"object","properties":{}}`),
			ResourceIdentity: func(map[string]any) map[string]string { return map[string]string{} },
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileNone},
			Bounds:           connectors.Bounds{MaxResultBytes: 1024},
		},
	}
	return s
}

func TestRegisterConnectorBindsToolsAndAddsListAccounts(t *testing.T) {
	reg := connectors.NewRegistry()
	src := connectors.NewStaticAccountSource()
	c := newStubConnector()
	if err := connectors.RegisterConnector(reg, c, src); err != nil {
		t.Fatalf("RegisterConnector: %v", err)
	}
	var names []string
	for _, tool := range reg.List() {
		names = append(names, tool.FullName())
	}
	want := []string{"stub.list_accounts", "stub.list_things", "stub.make_thing"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("registered = %v, want %v", names, want)
	}

	// A tool with a nil Handler is bound to the connector's Call.
	tool, _ := reg.Get("stub.make_thing")
	res, err := tool.Handler(context.Background(), connectors.Call{Tool: "stub.make_thing", Account: "a1"})
	if err != nil || res.Content != "dispatched stub.make_thing" {
		t.Errorf("bound handler: res=%v err=%v", res, err)
	}
	if !reflect.DeepEqual(c.calls, []string{"stub.make_thing@a1"}) {
		t.Errorf("connector calls = %v", c.calls)
	}

	// list_accounts is a read that needs no account and has an identity hook.
	la, _ := reg.Get("stub.list_accounts")
	if la.Kind != connectors.KindRead || !la.NoAccount || la.ResourceIdentity == nil || la.Description == "" {
		t.Errorf("list_accounts = %+v", la)
	}
	if id := la.ResourceIdentity(map[string]any{"x": "y"}); id["app"] != "stub" {
		t.Errorf("list_accounts resource identity = %v", id)
	}
	if la.Bounds.MaxResultBytes <= 0 {
		t.Errorf("list_accounts bounds = %+v", la.Bounds)
	}
}

func TestRegisterConnectorKeepsExplicitHandler(t *testing.T) {
	reg := connectors.NewRegistry()
	c := newStubConnector()
	c.tools[0].Handler = func(context.Context, connectors.Call) (connectors.Result, error) {
		return connectors.Result{Content: "explicit"}, nil
	}
	if err := connectors.RegisterConnector(reg, c, connectors.NewStaticAccountSource()); err != nil {
		t.Fatal(err)
	}
	tool, _ := reg.Get("stub.list_things")
	res, _ := tool.Handler(context.Background(), connectors.Call{})
	if res.Content != "explicit" {
		t.Errorf("explicit handler replaced: %v", res.Content)
	}
}

func TestRegisterConnectorRejectsToolFromOtherApp(t *testing.T) {
	c := newStubConnector()
	c.tools[0].App = "other"
	err := connectors.RegisterConnector(connectors.NewRegistry(), c, connectors.NewStaticAccountSource())
	if !errors.Is(err, connectors.ErrInvalidTool) {
		t.Errorf("err = %v, want ErrInvalidTool", err)
	}
}

func TestRegisterConnectorRejectsOwnListAccounts(t *testing.T) {
	c := newStubConnector()
	c.tools[0].Name = connectors.ListAccountsName
	err := connectors.RegisterConnector(connectors.NewRegistry(), c, connectors.NewStaticAccountSource())
	if !errors.Is(err, connectors.ErrInvalidTool) {
		t.Errorf("err = %v, want ErrInvalidTool", err)
	}
}

func TestRegisterConnectorRequiresAccountSource(t *testing.T) {
	err := connectors.RegisterConnector(connectors.NewRegistry(), newStubConnector(), nil)
	if err == nil {
		t.Error("nil account source accepted")
	}
}

func TestListAccountsToolReturnsOnlyCallersAccountsWithoutSecrets(t *testing.T) {
	reg := connectors.NewRegistry()
	src := connectors.NewStaticAccountSource()
	src.Add("alice", connectors.Account{ID: "acc-company", App: "stub", Label: connectors.LabelCompany, DisplayName: "Alice @ ACME", Scopes: []string{"read"}})
	src.Add("alice", connectors.Account{ID: "acc-personal", App: "stub", Label: connectors.LabelPersonal, DisplayName: "alice.personal"})
	src.Add("alice", connectors.Account{ID: "acc-other-app", App: "other", Label: connectors.LabelCompany, DisplayName: "elsewhere"})
	src.Add("bob", connectors.Account{ID: "acc-bob", App: "stub", Label: connectors.LabelCompany, DisplayName: "Bob"})
	if err := connectors.RegisterConnector(reg, newStubConnector(), src); err != nil {
		t.Fatal(err)
	}
	tool, _ := reg.Get("stub.list_accounts")
	res, err := tool.Handler(context.Background(), connectors.Call{Principal: connectors.Principal{UserID: "alice"}, Tool: "stub.list_accounts"})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(res.Content)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Accounts []map[string]any `json:"accounts"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("content %s: %v", raw, err)
	}
	var ids []string
	for _, a := range out.Accounts {
		ids = append(ids, fmt.Sprint(a["id"]))
		if a["label"] == nil || a["display_name"] == nil {
			t.Errorf("account %v lacks label/display_name", a)
		}
		for k := range a {
			if strings.Contains(k, "token") || strings.Contains(k, "scope") || strings.Contains(k, "secret") {
				t.Errorf("account exposes %q", k)
			}
		}
	}
	sort.Strings(ids)
	if !reflect.DeepEqual(ids, []string{"acc-company", "acc-personal"}) {
		t.Errorf("ids = %v (must be alice's stub accounts only)", ids)
	}
	if res.Empty {
		t.Error("Empty set with two accounts")
	}

	// Nobody's accounts: an empty read, not an error.
	res, err = tool.Handler(context.Background(), connectors.Call{Principal: connectors.Principal{UserID: "carol"}})
	if err != nil || !res.Empty {
		t.Errorf("no accounts: res=%+v err=%v", res, err)
	}
}

func TestStaticAccountSourceIsolatesUsersAndApps(t *testing.T) {
	src := connectors.NewStaticAccountSource()
	src.Add("alice", connectors.Account{ID: "a1", App: "github", Label: connectors.LabelCompany})
	src.Add("alice", connectors.Account{ID: "a2", App: "slack", Label: connectors.LabelCompany})
	src.Add("alice", connectors.Account{ID: "a1", App: "github", Label: connectors.LabelPersonal}) // same id: replaces
	got, err := src.ListAccounts(context.Background(), "alice", "github")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "a1" || got[0].Label != connectors.LabelPersonal {
		t.Errorf("ListAccounts(alice, github) = %+v", got)
	}
	if got, _ := src.ListAccounts(context.Background(), "bob", "github"); len(got) != 0 {
		t.Errorf("bob sees %+v", got)
	}
	// Returned slices are copies: mutating one must not change the source.
	got[0].DisplayName = "mutated"
	again, _ := src.ListAccounts(context.Background(), "alice", "github")
	if again[0].DisplayName == "mutated" {
		t.Error("ListAccounts returned shared state")
	}
}

func TestRateLimitedError(t *testing.T) {
	err := fmt.Errorf("calling vendor: %w", &connectors.RateLimited{App: "github", RetryAfter: 3 * time.Second})
	var rl *connectors.RateLimited
	if !errors.As(err, &rl) || rl.RetryAfter != 3*time.Second || rl.App != "github" {
		t.Fatalf("errors.As failed on %v", err)
	}
	if !strings.Contains(err.Error(), "rate limited") || !strings.Contains(err.Error(), "3s") {
		t.Errorf("message = %q", err.Error())
	}
}

func TestErrOutcomeUnknownIsSentinel(t *testing.T) {
	err := fmt.Errorf("fake: %w", connectors.ErrOutcomeUnknown)
	if !errors.Is(err, connectors.ErrOutcomeUnknown) {
		t.Error("errors.Is failed")
	}
}

func TestReconcileKindValid(t *testing.T) {
	for _, k := range []connectors.ReconcileKind{connectors.ReconcileNone, connectors.ReconcileStableID, connectors.ReconcileClientID, connectors.ReconcileMarker} {
		if !k.Valid() {
			t.Errorf("%q should be valid", k)
		}
	}
	if connectors.ReconcileKind("").Valid() || connectors.ReconcileKind("magic").Valid() {
		t.Error("empty / unknown kinds must be invalid")
	}
}

func TestNewAccountIDIsUUIDv4(t *testing.T) {
	re := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	seen := map[string]bool{}
	for range 100 {
		id := connectors.NewAccountID()
		if !re.MatchString(id) {
			t.Fatalf("NewAccountID() = %q, not a canonical UUID v4", id)
		}
		if seen[id] {
			t.Fatalf("duplicate id %q", id)
		}
		seen[id] = true
	}
}
