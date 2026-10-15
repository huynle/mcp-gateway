package connectors_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// hintingSource is a StaticAccountSource that also answers AccessHint:
// fixed hints by account id, an error for "acc-broken".
type hintingSource struct {
	*connectors.StaticAccountSource
	hints map[string]connectors.AccessHint
}

func (h hintingSource) AccessHint(_ context.Context, _ string, acct connectors.Account) (connectors.AccessHint, error) {
	if acct.ID == "acc-broken" {
		return connectors.AccessHint{}, errors.New("catalog down")
	}
	return h.hints[acct.ID], nil
}

// TestListAccountsCarriesAccessHints: when the account source knows that
// an account cannot run some of the app's tools until the user grants
// more access, list_accounts says how many and where to grant them; the
// other accounts, and a hint that failed, carry nothing extra. No key
// names a scope or a token.
func TestListAccountsCarriesAccessHints(t *testing.T) {
	src := hintingSource{StaticAccountSource: connectors.NewStaticAccountSource(), hints: map[string]connectors.AccessHint{
		"acc-locked": {LockedTools: 3, GrantURL: "https://gw.example/connections"},
	}}
	for _, id := range []string{"acc-locked", "acc-fine", "acc-broken"} {
		src.Add("alice", connectors.Account{ID: id, App: "stub", Label: connectors.LabelCompany, DisplayName: id, Scopes: []string{"read"}})
	}
	reg := connectors.NewRegistry()
	if err := connectors.RegisterConnector(reg, newStubConnector(), src); err != nil {
		t.Fatal(err)
	}
	tool, _ := reg.Get("stub.list_accounts")
	res, err := tool.Handler(context.Background(), connectors.Call{Principal: connectors.Principal{UserID: "alice"}, Tool: "stub.list_accounts"})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(res.Content)
	var out struct {
		Accounts []map[string]any `json:"accounts"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	byID := map[string]map[string]any{}
	for _, a := range out.Accounts {
		byID[a["id"].(string)] = a
		for k := range a {
			if strings.Contains(k, "token") || strings.Contains(k, "scope") || strings.Contains(k, "secret") {
				t.Errorf("account exposes %q", k)
			}
		}
	}
	if a := byID["acc-locked"]; a["locked_tools"] != float64(3) || a["grant_more_access"] != "https://gw.example/connections" {
		t.Errorf("locked account = %v", a)
	}
	for _, id := range []string{"acc-fine", "acc-broken"} {
		if a := byID[id]; len(a) != 3 {
			t.Errorf("%s = %v, want id, label and display_name only", id, a)
		}
	}
}

// TestRegistryScopeGrantable: every scope is grantable by default; an
// app's ScopeGrantable decides per label; nil restores the default.
func TestRegistryScopeGrantable(t *testing.T) {
	reg := connectors.NewRegistry()
	if !reg.Grantable("ms", connectors.LabelPersonal, "Team.ReadBasic.All") {
		t.Error("default refuses a scope")
	}
	reg.SetScopeGrantable("ms", func(label connectors.AccountLabel, scope string) bool {
		return label != connectors.LabelPersonal || !strings.HasPrefix(scope, "Team.")
	})
	if reg.Grantable("ms", connectors.LabelPersonal, "Team.ReadBasic.All") || !reg.Grantable("ms", connectors.LabelCompany, "Team.ReadBasic.All") ||
		!reg.Grantable("ms", connectors.LabelPersonal, "Mail.Read") || !reg.Grantable("other", connectors.LabelPersonal, "Team.ReadBasic.All") {
		t.Error("ScopeGrantable not applied per app and label")
	}
	reg.SetScopeGrantable("ms", nil)
	if !reg.Grantable("ms", connectors.LabelPersonal, "Team.ReadBasic.All") {
		t.Error("nil did not restore the default")
	}
}
