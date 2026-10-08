package mcp_test

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/fake"
	"github.com/huynle/mcp-gateway/internal/mcp"
)

// TestFakeConnectorEndToEnd drives the gateway exactly as a harness does:
// the SDK client over Streamable HTTP, the fake connector registered with
// RegisterConnector, the account stage and the real limiter in the
// pipeline. user-1 (fullToken) has one account and never names it; user-2
// (readOnlyToken) has two and must.
func TestFakeConnectorEndToEnd(t *testing.T) {
	f := fake.New(fake.Options{})
	f.SeedAccount("user-1", connectors.Account{ID: "fake-one", Label: connectors.LabelCompany, DisplayName: "Only account"})
	f.SeedAccount("user-2", connectors.Account{ID: "fake-a", Label: connectors.LabelCompany, DisplayName: "Work"})
	f.SeedAccount("user-2", connectors.Account{ID: "fake-b", Label: connectors.LabelPersonal, DisplayName: "Home"})
	reg := connectors.NewRegistry()
	if err := connectors.RegisterConnector(reg, f, f.Accounts()); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(newHandler(t, reg, func(o *mcp.Options) {
		o.Accounts = f.Accounts()
		o.RateLimiter = mcp.NewRateLimiter(mcp.RateLimitConfig{})
	}))
	defer srv.Close()
	ctx := t.Context()

	cs := connect(t, srv.URL, fullToken, "2025-11-25")
	list, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range list.Tools {
		names = append(names, tool.Name)
	}
	for _, want := range []string{"fake.list_accounts", "fake.list_items", "fake.get_item", "fake.create_item", "fake.post_note", "fake.flaky_write"} {
		if !strings.Contains(strings.Join(names, ","), want) {
			t.Errorf("tools/list lacks %s: %v", want, names)
		}
	}

	// list_accounts needs no account and shows only the caller's.
	res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "fake.list_accounts"})
	if err != nil {
		t.Fatalf("list_accounts: %v", err)
	}
	var accounts struct {
		Accounts []struct {
			ID, Label   string
			DisplayName string `json:"display_name"`
		}
	}
	if err := json.Unmarshal([]byte(text(t, res)), &accounts); err != nil {
		t.Fatal(err)
	}
	if len(accounts.Accounts) != 1 || accounts.Accounts[0].ID != "fake-one" || accounts.Accounts[0].Label != "company" || accounts.Accounts[0].DisplayName != "Only account" {
		t.Errorf("accounts = %+v", accounts)
	}

	// Single account: auto-resolved, no "account" argument.
	res, err = cs.CallTool(ctx, &sdk.CallToolParams{Name: "fake.list_items"})
	if err != nil {
		t.Fatalf("list_items: %v", err)
	}
	if res.IsError || res.Meta[mcp.MetaReadKey] == nil {
		t.Errorf("empty list_items: isError=%v meta=%v", res.IsError, res.Meta)
	}
	res, err = cs.CallTool(ctx, &sdk.CallToolParams{Name: "fake.create_item", Arguments: map[string]any{"id": "it-1", "name": "first"}})
	if err != nil || res.IsError {
		t.Fatalf("create_item: err=%v res=%+v", err, res)
	}
	if items := f.State().Items("fake-one"); len(items) != 1 || items[0].ID != "it-1" {
		t.Errorf("state after create = %+v", items)
	}
	res, err = cs.CallTool(ctx, &sdk.CallToolParams{Name: "fake.list_items"})
	if err != nil || res.IsError {
		t.Fatalf("list_items: err=%v res=%+v", err, res)
	}
	var page struct {
		Items []fake.Item `json:"items"`
	}
	if err := json.Unmarshal([]byte(text(t, res)), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].Name != "first" {
		t.Errorf("page = %+v", page)
	}
	// Another user's account is "unknown" to this caller.
	if _, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "fake.get_item", Arguments: map[string]any{"id": "it-1", "account": "fake-a"}}); err == nil || !strings.Contains(err.Error(), `unknown account "fake-a"`) {
		t.Errorf("foreign account: err = %v", err)
	}

	// Two accounts: the harness must choose, and the error tells it what
	// it owns. The read-only token sees no write tools.
	cs2 := connect(t, srv.URL, readOnlyToken, "2025-11-25")
	_, err = cs2.CallTool(ctx, &sdk.CallToolParams{Name: "fake.list_items"})
	if err == nil || !strings.Contains(err.Error(), "account required") || !strings.Contains(err.Error(), "fake-a (Work, company)") || !strings.Contains(err.Error(), "fake-b (Home, personal)") {
		t.Errorf("two accounts without choice: err = %v", err)
	}
	if strings.Contains(err.Error(), "fake-one") {
		t.Errorf("error lists another user's account: %v", err)
	}
	res, err = cs2.CallTool(ctx, &sdk.CallToolParams{Name: "fake.list_items", Arguments: map[string]any{"account": "fake-b"}})
	if err != nil || res.IsError {
		t.Fatalf("chosen account: err=%v res=%+v", err, res)
	}
	if _, err := cs2.CallTool(ctx, &sdk.CallToolParams{Name: "fake.create_item", Arguments: map[string]any{"account": "fake-b", "name": "x"}}); err == nil || !strings.Contains(err.Error(), "unknown tool") {
		t.Errorf("read-only token calling a write: err = %v", err)
	}

	// A connector failure is a tool result the model can read; a vendor
	// rate limit is a protocol error with retry_after.
	f.InjectFault("get_item", fake.Fault{Mode: fake.FaultFail, Message: "boom"})
	res, err = cs.CallTool(ctx, &sdk.CallToolParams{Name: "fake.get_item", Arguments: map[string]any{"id": "it-1"}})
	if err != nil || !res.IsError || !strings.Contains(text(t, res), "boom") {
		t.Errorf("failed read: err=%v res=%+v", err, res)
	}
	f.InjectFault("get_item", fake.Fault{Mode: fake.FaultRateLimited, RetryAfter: 5 * time.Second})
	if _, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "fake.get_item", Arguments: map[string]any{"id": "it-1"}}); err == nil || !strings.Contains(err.Error(), "rate limiting") {
		t.Fatalf("rate limited read: err = %v", err)
	}
	// Even an unrelated fake tool now waits.
	if _, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "fake.list_items"}); err == nil || !strings.Contains(err.Error(), "rate limited") {
		t.Errorf("app paused: err = %v", err)
	}
}
