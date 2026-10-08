package fake_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/connectortest"
	"github.com/huynle/mcp-gateway/internal/connectors/fake"
)

const (
	alice = "user-alice"
	acct  = "fake-acct-1"
)

func newFake(t *testing.T) *fake.Connector {
	t.Helper()
	c := fake.New(fake.Options{})
	c.SeedAccount(alice, connectors.Account{ID: acct, Label: connectors.LabelCompany, DisplayName: "Alice @ Fake"})
	return c
}

func call(tool, account string, args map[string]any) connectors.Call {
	if args == nil {
		args = map[string]any{}
	}
	return connectors.Call{Principal: connectors.Principal{UserID: alice, TokenID: "tok"}, Tool: "fake." + tool, Account: account, Args: args}
}

// decode marshals a result's content and decodes it into v.
func decode(t *testing.T, res connectors.Result, v any) {
	t.Helper()
	raw, err := json.Marshal(res.Content)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
}

type itemsPage struct {
	Items      []fake.Item `json:"items"`
	NextCursor string      `json:"next_cursor"`
}

func TestFakePassesContract(t *testing.T) {
	connectortest.ContractTest(t, newFake(t))
}

func TestFakeAppAndAccounts(t *testing.T) {
	c := newFake(t)
	if c.App() != fake.App || fake.App != "fake" {
		t.Errorf("App = %q", c.App())
	}
	list, err := c.Accounts().ListAccounts(context.Background(), alice, "fake")
	if err != nil || len(list) != 1 || list[0].ID != acct || list[0].App != "fake" {
		t.Errorf("accounts = %+v, %v", list, err)
	}
	if list, _ := c.Accounts().ListAccounts(context.Background(), "nobody", "fake"); len(list) != 0 {
		t.Errorf("unknown user has accounts %+v", list)
	}
}

func TestFakeAutoAccountSeedsOnePerUser(t *testing.T) {
	c := fake.New(fake.Options{AutoAccount: true})
	first, err := c.Accounts().ListAccounts(context.Background(), "someone", "fake")
	if err != nil || len(first) != 1 || first[0].Label != connectors.LabelCompany {
		t.Fatalf("auto account = %+v, %v", first, err)
	}
	second, _ := c.Accounts().ListAccounts(context.Background(), "someone", "fake")
	if len(second) != 1 || second[0].ID != first[0].ID {
		t.Errorf("auto account not stable: %+v vs %+v", first, second)
	}
	other, _ := c.Accounts().ListAccounts(context.Background(), "else", "fake")
	if len(other) != 1 || other[0].ID == first[0].ID {
		t.Errorf("auto accounts not per user: %+v vs %+v", other, first)
	}
	if list, _ := c.Accounts().ListAccounts(context.Background(), "someone", "github"); len(list) != 0 {
		t.Errorf("auto account for another app: %+v", list)
	}
}

func TestFakeUnknownToolAndMissingAccount(t *testing.T) {
	c := newFake(t)
	if _, err := c.Call(context.Background(), call("nope", acct, nil)); !errors.Is(err, connectors.ErrUnknownTool) {
		t.Errorf("unknown tool err = %v", err)
	}
	if _, err := c.Call(context.Background(), call("list_items", "", nil)); err == nil || !strings.Contains(err.Error(), "account") {
		t.Errorf("missing account err = %v", err)
	}
}

func TestFakeCreateGetListItems(t *testing.T) {
	c := newFake(t)
	ctx := context.Background()

	res, err := c.Call(ctx, call("list_items", acct, nil))
	if err != nil || !res.Empty {
		t.Fatalf("empty list: res=%+v err=%v", res, err)
	}

	res, err = c.Call(ctx, call("create_item", acct, map[string]any{"id": "it-1", "name": "first", "body": "hello"}))
	if err != nil {
		t.Fatal(err)
	}
	var created fake.Item
	decode(t, res, &created)
	if created.ID != "it-1" || created.Name != "first" || created.Body != "hello" {
		t.Errorf("created = %+v", created)
	}
	// Duplicate id is a conflict, reported as a tool error.
	if _, err := c.Call(ctx, call("create_item", acct, map[string]any{"id": "it-1", "name": "again"})); err == nil || !strings.Contains(err.Error(), "exists") {
		t.Errorf("duplicate create err = %v", err)
	}
	// Without an id or an operation the fake generates one.
	res, err = c.Call(ctx, call("create_item", acct, map[string]any{"name": "second"}))
	if err != nil {
		t.Fatal(err)
	}
	var gen fake.Item
	decode(t, res, &gen)
	if gen.ID == "" || gen.ID == "it-1" {
		t.Errorf("generated id = %q", gen.ID)
	}

	res, err = c.Call(ctx, call("get_item", acct, map[string]any{"id": "it-1"}))
	if err != nil {
		t.Fatal(err)
	}
	var got fake.Item
	decode(t, res, &got)
	if got.ID != "it-1" || got.Body != "hello" {
		t.Errorf("get_item = %+v", got)
	}
	if _, err := c.Call(ctx, call("get_item", acct, map[string]any{"id": "missing"})); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("missing item err = %v", err)
	}

	res, err = c.Call(ctx, call("list_items", acct, nil))
	if err != nil || res.Empty {
		t.Fatalf("list: res=%+v err=%v", res, err)
	}
	var page itemsPage
	decode(t, res, &page)
	if len(page.Items) != 2 || page.NextCursor != "" {
		t.Errorf("page = %+v", page)
	}

	// State is per account: another account sees nothing.
	c.SeedAccount(alice, connectors.Account{ID: "fake-acct-2", Label: connectors.LabelPersonal, DisplayName: "personal"})
	res, _ = c.Call(ctx, call("list_items", "fake-acct-2", nil))
	if !res.Empty {
		t.Error("items leaked across accounts")
	}
	st := c.State()
	if len(st.Items(acct)) != 2 || len(st.Items("fake-acct-2")) != 0 {
		t.Errorf("State().Items = %d / %d", len(st.Items(acct)), len(st.Items("fake-acct-2")))
	}
}

func TestFakeListItemsPaginatesAndClampsPageSize(t *testing.T) {
	c := newFake(t)
	ctx := context.Background()
	for i := range 7 {
		if _, err := c.Call(ctx, call("create_item", acct, map[string]any{"id": fmt.Sprintf("it-%02d", i), "name": "n"})); err != nil {
			t.Fatal(err)
		}
	}
	tool := toolNamed(t, c, "list_items")
	if tool.Bounds.MaxPageSize <= 0 {
		t.Fatalf("list_items must declare MaxPageSize, got %+v", tool.Bounds)
	}

	var seen []string
	cursor := ""
	pages := 0
	for {
		res, err := c.Call(ctx, call("list_items", acct, map[string]any{"page_size": 3, "cursor": cursor}))
		if err != nil {
			t.Fatal(err)
		}
		var page itemsPage
		decode(t, res, &page)
		if len(page.Items) > 3 {
			t.Fatalf("page_size 3 returned %d items", len(page.Items))
		}
		for _, it := range page.Items {
			seen = append(seen, it.ID)
		}
		pages++
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	if pages != 3 || len(seen) != 7 || seen[0] != "it-00" || seen[6] != "it-06" {
		t.Errorf("pages=%d seen=%v", pages, seen)
	}

	// A page size above the bound is clamped, not rejected.
	res, err := c.Call(ctx, call("list_items", acct, map[string]any{"page_size": 10_000}))
	if err != nil {
		t.Fatal(err)
	}
	var page itemsPage
	decode(t, res, &page)
	if len(page.Items) > tool.Bounds.MaxPageSize {
		t.Errorf("page of %d exceeds MaxPageSize %d", len(page.Items), tool.Bounds.MaxPageSize)
	}
	if _, err := c.Call(ctx, call("list_items", acct, map[string]any{"cursor": "garbage"})); err == nil {
		t.Error("bad cursor accepted")
	}
}

func TestFakeListItemsHonoursMaxResultBytes(t *testing.T) {
	c := fake.New(fake.Options{Bounds: connectors.Bounds{MaxPageSize: 50, MaxResultBytes: 200}})
	c.SeedAccount(alice, connectors.Account{ID: acct, Label: connectors.LabelCompany})
	ctx := context.Background()
	for i := range 10 {
		if _, err := c.Call(ctx, call("create_item", acct, map[string]any{"id": fmt.Sprintf("it-%02d", i), "name": strings.Repeat("x", 40)})); err != nil {
			t.Fatal(err)
		}
	}
	res, err := c.Call(ctx, call("list_items", acct, nil))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(res.Content)
	if len(raw) > 200 {
		t.Errorf("result is %d bytes, bound 200", len(raw))
	}
	var page itemsPage
	decode(t, res, &page)
	if len(page.Items) == 0 || len(page.Items) >= 10 || page.NextCursor == "" {
		t.Errorf("page = %d items, next=%q; want a shortened page with a cursor", len(page.Items), page.NextCursor)
	}
}

func TestFakePostNoteAndFlakyWriteRecordState(t *testing.T) {
	c := newFake(t)
	ctx := context.Background()
	if _, err := c.Call(ctx, call("post_note", acct, map[string]any{"text": "LGTM"})); err != nil {
		t.Fatal(err)
	}
	if notes := c.State().Notes(acct); len(notes) != 1 || notes[0].Text != "LGTM" {
		t.Errorf("notes = %+v", notes)
	}
	if tool := toolNamed(t, c, "post_note"); tool.Reconcile.Kind != connectors.ReconcileNone {
		t.Errorf("post_note reconcile = %q", tool.Reconcile.Kind)
	}
	if _, err := c.Call(ctx, call("flaky_write", acct, map[string]any{"marker": "m-1"})); err != nil {
		t.Fatal(err)
	}
	if writes := c.State().Writes(acct); len(writes) != 1 || writes[0].Marker != "m-1" {
		t.Errorf("writes = %+v", writes)
	}
}

func TestFakeCreateItemReconcilesByStableID(t *testing.T) {
	c := newFake(t)
	ctx := context.Background()
	tool := toolNamed(t, c, "create_item")
	if tool.Reconcile.Kind != connectors.ReconcileStableID || tool.Reconcile.Check == nil {
		t.Fatalf("create_item reconcile = %+v", tool.Reconcile)
	}

	// Client-chosen id: not found before the write, found after.
	in := connectors.ReconcileInput{Call: call("create_item", acct, map[string]any{"id": "it-9", "name": "n"}), OperationID: "op-1"}
	r, err := tool.Reconcile.Check(ctx, in)
	if err != nil || r.Outcome != connectors.ReconcileNotFound {
		t.Errorf("before: %+v %v", r, err)
	}
	if _, err := c.Call(ctx, in.Call); err != nil {
		t.Fatal(err)
	}
	r, err = tool.Reconcile.Check(ctx, in)
	if err != nil || r.Outcome != connectors.ReconcileFound || r.ResourceID != "it-9" {
		t.Errorf("after: %+v %v", r, err)
	}

	// No id in the arguments: the id derives from the operation, so the
	// same operation reconciles even though the harness chose nothing.
	opCall := call("create_item", acct, map[string]any{"name": "derived"})
	opCall.OperationID = "op-2"
	res, err := c.Call(ctx, opCall)
	if err != nil {
		t.Fatal(err)
	}
	var created fake.Item
	decode(t, res, &created)
	r, err = tool.Reconcile.Check(ctx, connectors.ReconcileInput{Call: opCall, OperationID: "op-2"})
	if err != nil || r.Outcome != connectors.ReconcileFound || r.ResourceID != created.ID {
		t.Errorf("derived: created=%q check=%+v %v", created.ID, r, err)
	}
	// Neither id nor operation: nothing to look for.
	if _, err := tool.Reconcile.Check(ctx, connectors.ReconcileInput{Call: call("create_item", acct, nil)}); err == nil {
		t.Error("check without id or operation must fail")
	}
}

func TestFakeFlakyWriteReconcilesByMarker(t *testing.T) {
	c := newFake(t)
	ctx := context.Background()
	tool := toolNamed(t, c, "flaky_write")
	if tool.Reconcile.Kind != connectors.ReconcileMarker || tool.Reconcile.Check == nil {
		t.Fatalf("flaky_write reconcile = %+v", tool.Reconcile)
	}
	wc := call("flaky_write", acct, nil)
	wc.OperationID = "op-7"
	in := connectors.ReconcileInput{Call: wc, OperationID: "op-7"}
	if r, err := tool.Reconcile.Check(ctx, in); err != nil || r.Outcome != connectors.ReconcileNotFound {
		t.Errorf("before: %+v %v", r, err)
	}
	if _, err := c.Call(ctx, wc); err != nil {
		t.Fatal(err)
	}
	if r, err := tool.Reconcile.Check(ctx, in); err != nil || r.Outcome != connectors.ReconcileFound {
		t.Errorf("after: %+v %v", r, err)
	}
}

func TestFakeFaultFail(t *testing.T) {
	c := newFake(t)
	c.InjectFault("flaky_write", fake.Fault{Mode: fake.FaultFail, Message: "vendor exploded"})
	_, err := c.Call(context.Background(), call("flaky_write", acct, map[string]any{"marker": "m"}))
	if err == nil || !strings.Contains(err.Error(), "vendor exploded") {
		t.Errorf("err = %v", err)
	}
	if len(c.State().Writes(acct)) != 0 {
		t.Error("a failed write changed state")
	}
}

func TestFakeFaultUnknownOutcome(t *testing.T) {
	c := newFake(t)
	ctx := context.Background()
	// Not applied: the error says unknown and nothing changed.
	c.InjectFault("create_item", fake.Fault{Mode: fake.FaultUnknown})
	_, err := c.Call(ctx, call("create_item", acct, map[string]any{"id": "u-1", "name": "n"}))
	if !errors.Is(err, connectors.ErrOutcomeUnknown) {
		t.Fatalf("err = %v, want ErrOutcomeUnknown", err)
	}
	if len(c.State().Items(acct)) != 0 {
		t.Error("unapplied unknown write changed state")
	}
	// Applied: the write happened but the caller still cannot tell, so
	// reconciliation finds it.
	c.InjectFault("create_item", fake.Fault{Mode: fake.FaultUnknown, Applied: true})
	_, err = c.Call(ctx, call("create_item", acct, map[string]any{"id": "u-2", "name": "n"}))
	if !errors.Is(err, connectors.ErrOutcomeUnknown) {
		t.Fatalf("err = %v, want ErrOutcomeUnknown", err)
	}
	tool := toolNamed(t, c, "create_item")
	r, err := tool.Reconcile.Check(ctx, connectors.ReconcileInput{Call: call("create_item", acct, map[string]any{"id": "u-2"})})
	if err != nil || r.Outcome != connectors.ReconcileFound {
		t.Errorf("applied unknown write not found: %+v %v", r, err)
	}
}

func TestFakeFaultHangUntilContextTimeout(t *testing.T) {
	c := newFake(t)
	c.InjectFault("flaky_write", fake.Fault{Mode: fake.FaultHang})
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.Call(ctx, call("flaky_write", acct, map[string]any{"marker": "m"}))
	if !errors.Is(err, connectors.ErrOutcomeUnknown) || !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want ErrOutcomeUnknown wrapping DeadlineExceeded", err)
	}
	if time.Since(start) < 40*time.Millisecond {
		t.Error("returned before the context expired")
	}
}

func TestFakeFaultLatency(t *testing.T) {
	c := newFake(t)
	c.InjectFault("get_item", fake.Fault{Latency: 30 * time.Millisecond})
	start := time.Now()
	_, _ = c.Call(context.Background(), call("get_item", acct, map[string]any{"id": "x"}))
	if time.Since(start) < 30*time.Millisecond {
		t.Error("latency fault did not delay the call")
	}
	// Latency respects the context.
	c.InjectFault("get_item", fake.Fault{Latency: time.Minute})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := c.Call(ctx, call("get_item", acct, map[string]any{"id": "x"})); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want DeadlineExceeded", err)
	}
}

func TestFakeFaultRateLimited(t *testing.T) {
	c := newFake(t)
	c.InjectFault("list_items", fake.Fault{Mode: fake.FaultRateLimited, RetryAfter: 17 * time.Second})
	_, err := c.Call(context.Background(), call("list_items", acct, nil))
	var rl *connectors.RateLimited
	if !errors.As(err, &rl) || rl.RetryAfter != 17*time.Second || rl.App != "fake" {
		t.Errorf("err = %v, want RateLimited{fake, 17s}", err)
	}
}

func TestFakeFaultPartialAndUnavailableReads(t *testing.T) {
	c := newFake(t)
	ctx := context.Background()
	if _, err := c.Call(ctx, call("create_item", acct, map[string]any{"id": "p-1", "name": "n"})); err != nil {
		t.Fatal(err)
	}
	c.InjectFault("list_items", fake.Fault{Mode: fake.FaultPartial})
	res, err := c.Call(ctx, call("list_items", acct, nil))
	if err != nil || !res.Partial || res.Unavailable {
		t.Errorf("partial: res=%+v err=%v", res, err)
	}
	var page itemsPage
	decode(t, res, &page)
	if len(page.Items) != 1 {
		t.Errorf("partial read lost its items: %+v", page)
	}
	c.InjectFault("list_items", fake.Fault{Mode: fake.FaultUnavailable})
	res, err = c.Call(ctx, call("list_items", acct, nil))
	if err != nil || !res.Unavailable {
		t.Errorf("unavailable: res=%+v err=%v", res, err)
	}
}

func TestFakeFaultRemainingAndClear(t *testing.T) {
	c := newFake(t)
	ctx := context.Background()
	c.InjectFault("get_item", fake.Fault{Mode: fake.FaultFail, Message: "once", Remaining: 1})
	if _, err := c.Call(ctx, call("get_item", acct, map[string]any{"id": "x"})); err == nil || !strings.Contains(err.Error(), "once") {
		t.Errorf("first call err = %v", err)
	}
	if _, err := c.Call(ctx, call("get_item", acct, map[string]any{"id": "x"})); err == nil || strings.Contains(err.Error(), "once") {
		t.Errorf("second call err = %v (fault should be spent)", err)
	}
	// Full tool names are accepted too, and faults can be cleared.
	c.InjectFault("fake.get_item", fake.Fault{Mode: fake.FaultFail, Message: "again"})
	if _, err := c.Call(ctx, call("get_item", acct, map[string]any{"id": "x"})); err == nil || !strings.Contains(err.Error(), "again") {
		t.Errorf("full-name fault err = %v", err)
	}
	c.Faults().Clear("get_item")
	if _, err := c.Call(ctx, call("get_item", acct, map[string]any{"id": "x"})); err == nil || strings.Contains(err.Error(), "again") {
		t.Errorf("cleared fault err = %v", err)
	}
}

func TestFakeFaultsUsableStandalone(t *testing.T) {
	f := fake.NewFaults()
	f.Inject("x", fake.Fault{Mode: fake.FaultFail})
	if _, ok := f.Take("x"); !ok {
		t.Error("Take after Inject = false")
	}
	f.ClearAll()
	if _, ok := f.Take("x"); ok {
		t.Error("Take after ClearAll = true")
	}
}

func toolNamed(t *testing.T, c *fake.Connector, name string) connectors.Tool {
	t.Helper()
	for _, tool := range c.Tools() {
		if tool.Name == name {
			return tool
		}
	}
	t.Fatalf("tool %q not declared", name)
	return connectors.Tool{}
}
