// Package fake is the in-process connector every safety-core test runs
// against (decision bt8ukyrd): reads with pagination and bounds, a write
// that reconciles by stable ID, one that cannot be reconciled, one that
// reconciles by marker, and injectable faults (failure, unknown outcome,
// hang, latency, vendor rate limit, partial and unavailable reads). State
// is in memory, per account. It is registered on the gateway only when
// GATEWAY_ENABLE_FAKE_CONNECTOR=true.
package fake

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// App is the connector's name; every tool is "fake.<name>".
const App = "fake"

// Tool names.
const (
	ToolListItems  = "list_items"
	ToolGetItem    = "get_item"
	ToolCreateItem = "create_item"
	ToolPostNote   = "post_note"
	ToolFlakyWrite = "flaky_write"
)

// Options configures New. Every field is optional.
type Options struct {
	// Accounts is the account source the fake seeds; New creates one when
	// nil. Pass it when the same source is shared with other connectors.
	Accounts *connectors.StaticAccountSource
	// AutoAccount seeds one company account for every user the first time
	// their fake accounts are listed, so a local gateway works without
	// anyone connecting anything. Development only.
	AutoAccount bool
	// Bounds overrides the default page and result bounds of every tool.
	Bounds connectors.Bounds
}

// Item is a stored item.
type Item struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Body        string    `json:"body,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	OperationID string    `json:"operation_id,omitempty"`
}

// Note is a posted note; it has no client-visible key, which is why
// post_note cannot be reconciled.
type Note struct {
	ID        string    `json:"id"`
	Text      string    `json:"text"`
	CreatedAt time.Time `json:"created_at"`
}

// Write is one flaky_write that took effect, found again by its marker.
type Write struct {
	Marker      string    `json:"marker"`
	Payload     string    `json:"payload,omitempty"`
	OperationID string    `json:"operation_id,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// Connector is the fake connector. Safe for concurrent use.
type Connector struct {
	accounts *accountSource
	faults   *Faults
	bounds   connectors.Bounds

	mu    sync.Mutex
	state map[string]*accountState // by account ID
}

type accountState struct {
	items  map[string]Item
	notes  []Note
	writes []Write
}

// New builds a fake connector.
func New(opts Options) *Connector {
	src := opts.Accounts
	if src == nil {
		src = connectors.NewStaticAccountSource()
	}
	bounds := opts.Bounds
	if bounds.MaxPageSize <= 0 {
		bounds.MaxPageSize = connectors.DefaultMaxPageSize
	}
	if bounds.MaxResultBytes <= 0 {
		bounds.MaxResultBytes = connectors.DefaultMaxResultBytes
	}
	return &Connector{
		accounts: &accountSource{static: src, auto: opts.AutoAccount},
		faults:   NewFaults(),
		bounds:   bounds,
		state:    map[string]*accountState{},
	}
}

// App implements connectors.Connector.
func (c *Connector) App() string { return App }

// Accounts returns the account source (pass it to RegisterConnector and
// the account stage).
func (c *Connector) Accounts() connectors.AccountSource { return c.accounts }

// SeedAccount gives userID the account; App is set to "fake" when empty
// and ID to a fresh UUID when empty (IDs must be UUIDs to be audited; see
// connectors.Account). The account is returned as stored.
func (c *Connector) SeedAccount(userID string, acct connectors.Account) connectors.Account {
	if acct.App == "" {
		acct.App = App
	}
	if acct.ID == "" {
		acct.ID = connectors.NewAccountID()
	}
	c.accounts.static.Add(userID, acct)
	return acct
}

// SeedItems stores items on account without going through a tool call.
func (c *Connector) SeedItems(account string, items ...Item) {
	c.mu.Lock()
	defer c.mu.Unlock()
	st := c.account(account)
	for _, it := range items {
		if it.CreatedAt.IsZero() {
			it.CreatedAt = time.Now()
		}
		st.items[it.ID] = it
	}
}

// InjectFault sets the fault for tool (short or full name).
func (c *Connector) InjectFault(tool string, f Fault) { c.faults.Inject(tool, f) }

// ClearFaults removes every fault.
func (c *Connector) ClearFaults() { c.faults.ClearAll() }

// Faults exposes the fault table for tests in other packages.
func (c *Connector) Faults() *Faults { return c.faults }

// State is a snapshot of every account's items, notes and writes.
type State struct {
	items  map[string][]Item
	notes  map[string][]Note
	writes map[string][]Write
}

// Items returns account's items ordered by ID.
func (s *State) Items(account string) []Item { return s.items[account] }

// Notes returns account's notes in posting order.
func (s *State) Notes(account string) []Note { return s.notes[account] }

// Writes returns account's flaky writes in order.
func (s *State) Writes(account string) []Write { return s.writes[account] }

// State returns a snapshot; later calls do not change it.
func (c *Connector) State() *State {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := &State{items: map[string][]Item{}, notes: map[string][]Note{}, writes: map[string][]Write{}}
	for id, st := range c.state {
		s.items[id] = st.sortedItems()
		s.notes[id] = append([]Note(nil), st.notes...)
		s.writes[id] = append([]Write(nil), st.writes...)
	}
	return s
}

// Tools implements connectors.Connector. Handlers are nil: Call
// dispatches by name (see connectors.Connector).
func (c *Connector) Tools() []connectors.Tool {
	obj := func(props string, required ...string) json.RawMessage {
		req := ""
		if len(required) > 0 {
			b, _ := json.Marshal(required)
			req = `,"required":` + string(b)
		}
		return json.RawMessage(`{"type":"object","properties":{` + props + `}` + req + `,"additionalProperties":false}`)
	}
	str := func(name, desc string) string {
		return fmt.Sprintf(`%q:{"type":"string","description":%q}`, name, desc)
	}
	identity := func(keys ...string) func(map[string]any) map[string]string {
		return func(args map[string]any) map[string]string {
			out := map[string]string{}
			for _, k := range keys {
				if v, ok := args[k].(string); ok && v != "" {
					out[k] = v
				}
			}
			return out
		}
	}
	return []connectors.Tool{
		{
			App: App, Name: ToolListItems, Kind: connectors.KindRead,
			Description: "List items in the fake app, newest id last. Paginated: pass next_cursor from a previous page as cursor.",
			InputSchema: obj(strings.Join([]string{
				`"page_size":{"type":"integer","minimum":1,"description":"Items per page; clamped to the tool's maximum."}`,
				str("cursor", "Opaque cursor from a previous page."),
				str("prefix", "Only items whose id starts with this."),
			}, ",")),
			ResourceIdentity: identity("prefix"),
			Bounds:           c.bounds,
		},
		{
			App: App, Name: ToolGetItem, Kind: connectors.KindRead,
			Description:      "Get one item by id.",
			InputSchema:      obj(str("id", "Item id."), "id"),
			ResourceIdentity: identity("id"),
			Bounds:           connectors.Bounds{MaxResultBytes: c.bounds.MaxResultBytes},
		},
		{
			App: App, Name: ToolCreateItem, Kind: connectors.KindWrite,
			Description: "Create an item. Choose an id or let the app assign one.",
			InputSchema: obj(strings.Join([]string{
				str("id", "Optional client-chosen id; must be new."),
				str("name", "Item name."),
				str("body", "Optional body."),
			}, ","), "name"),
			ResourceIdentity: identity("id"),
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: c.checkItem},
			Bounds:           connectors.Bounds{MaxResultBytes: c.bounds.MaxResultBytes},
		},
		{
			App: App, Name: ToolPostNote, Kind: connectors.KindWrite,
			Description:      "Post a note. Notes have no client-visible key, so this write cannot be verified after an unknown outcome.",
			InputSchema:      obj(str("text", "Note text."), "text"),
			ResourceIdentity: identity(),
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileNone},
			Bounds:           connectors.Bounds{MaxResultBytes: c.bounds.MaxResultBytes},
		},
		{
			App: App, Name: ToolFlakyWrite, Kind: connectors.KindWrite,
			Description: "A write used to exercise failures: inject faults on it in tests. Records a marker that reconciliation searches for.",
			InputSchema: obj(strings.Join([]string{
				str("marker", "Optional marker; defaults to the operation id."),
				str("payload", "Anything."),
			}, ",")),
			ResourceIdentity: identity("marker"),
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileMarker, Check: c.checkWrite},
			Bounds:           connectors.Bounds{MaxResultBytes: c.bounds.MaxResultBytes},
		},
	}
}

// Call implements connectors.Connector: applies any injected fault for the
// tool, then dispatches by name.
func (c *Connector) Call(ctx context.Context, call connectors.Call) (connectors.Result, error) {
	name := shortName(call.Tool)
	var run func(connectors.Call) (connectors.Result, error)
	write := false
	switch name {
	case ToolListItems:
		run = c.listItems
	case ToolGetItem:
		run = c.getItem
	case ToolCreateItem:
		run, write = c.createItem, true
	case ToolPostNote:
		run, write = c.postNote, true
	case ToolFlakyWrite:
		run, write = c.flakyWrite, true
	default:
		return connectors.Result{}, fmt.Errorf("%w: %q", connectors.ErrUnknownTool, call.Tool)
	}
	if call.Account == "" {
		return connectors.Result{}, errors.New("fake: account is required")
	}
	if call.Args == nil {
		call.Args = map[string]any{}
	}

	fault, ok := c.faults.Take(name)
	if !ok {
		return run(call)
	}
	if fault.Latency > 0 {
		if err := sleep(ctx, fault.Latency); err != nil {
			return connectors.Result{}, err
		}
	}
	switch fault.Mode {
	case FaultFail:
		msg := fault.Message
		if msg == "" {
			msg = "injected fault"
		}
		return connectors.Result{}, errors.New("fake: " + msg)
	case FaultRateLimited:
		return connectors.Result{}, &connectors.RateLimited{App: App, RetryAfter: fault.RetryAfter}
	case FaultUnknown, FaultHang:
		if write && fault.Applied {
			if _, err := run(call); err != nil {
				return connectors.Result{}, err
			}
		}
		if fault.Mode == FaultHang {
			<-ctx.Done()
			return connectors.Result{}, fmt.Errorf("%w: %w", connectors.ErrOutcomeUnknown, ctx.Err())
		}
		return connectors.Result{}, fmt.Errorf("%w: injected", connectors.ErrOutcomeUnknown)
	case FaultPartial:
		res, err := run(call)
		if err == nil && !write {
			res.Partial = true
		}
		return res, err
	case FaultUnavailable:
		if !write {
			return connectors.Result{Unavailable: true}, nil
		}
		return run(call)
	default:
		return run(call)
	}
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// account returns the state for an account, creating it. Callers hold mu.
func (c *Connector) account(id string) *accountState {
	st, ok := c.state[id]
	if !ok {
		st = &accountState{items: map[string]Item{}}
		c.state[id] = st
	}
	return st
}

func (st *accountState) sortedItems() []Item {
	out := make([]Item, 0, len(st.items))
	for _, it := range st.items {
		out = append(out, it)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// listPage is the wire shape of list_items.
type listPage struct {
	Items      []Item `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"`
}

func (c *Connector) listItems(call connectors.Call) (connectors.Result, error) {
	pageSize := c.bounds.MaxPageSize
	if v, ok := call.Args["page_size"]; ok {
		n, err := toInt(v)
		if err != nil || n < 1 {
			return connectors.Result{}, errors.New("fake: page_size must be a positive integer")
		}
		if n < pageSize {
			pageSize = n
		}
	}
	offset := 0
	if v, ok := call.Args["cursor"]; ok {
		s, _ := v.(string)
		if s != "" {
			n, err := strconv.Atoi(s)
			if err != nil || n < 0 {
				return connectors.Result{}, errors.New("fake: invalid cursor")
			}
			offset = n
		}
	}
	prefix, _ := call.Args["prefix"].(string)

	c.mu.Lock()
	all := c.account(call.Account).sortedItems()
	c.mu.Unlock()
	if prefix != "" {
		filtered := all[:0:0]
		for _, it := range all {
			if strings.HasPrefix(it.ID, prefix) {
				filtered = append(filtered, it)
			}
		}
		all = filtered
	}
	if len(all) == 0 {
		return connectors.Result{Content: listPage{Items: []Item{}}, Empty: true}, nil
	}
	if offset > len(all) {
		offset = len(all)
	}
	// Shrink the page until it fits MaxResultBytes (never below one item);
	// the cursor moves with it so nothing is skipped.
	end := min(offset+pageSize, len(all))
	var page listPage
	for {
		page = listPage{Items: all[offset:end]}
		if end < len(all) {
			page.NextCursor = strconv.Itoa(end)
		}
		if b, _ := json.Marshal(page); len(b) <= c.bounds.MaxResultBytes || end-offset <= 1 {
			break
		}
		end--
	}
	return connectors.Result{Content: page}, nil
}

func (c *Connector) getItem(call connectors.Call) (connectors.Result, error) {
	id, _ := call.Args["id"].(string)
	if id == "" {
		return connectors.Result{}, errors.New("fake: id is required")
	}
	c.mu.Lock()
	it, ok := c.account(call.Account).items[id]
	c.mu.Unlock()
	if !ok {
		return connectors.Result{}, fmt.Errorf("fake: item %q not found", id)
	}
	return connectors.Result{Content: it}, nil
}

// itemID is the stable id of a create_item call: the client-chosen id,
// else one derived from the operation, else "" (nothing to reconcile by).
func itemID(call connectors.Call) string {
	if id, _ := call.Args["id"].(string); id != "" {
		return id
	}
	if call.OperationID != "" {
		return "item-op-" + call.OperationID
	}
	return ""
}

func (c *Connector) createItem(call connectors.Call) (connectors.Result, error) {
	name, _ := call.Args["name"].(string)
	if name == "" {
		return connectors.Result{}, errors.New("fake: name is required")
	}
	id := itemID(call)
	if id == "" {
		id = "item-" + randomID()
	}
	body, _ := call.Args["body"].(string)
	c.mu.Lock()
	defer c.mu.Unlock()
	st := c.account(call.Account)
	if _, exists := st.items[id]; exists {
		return connectors.Result{}, fmt.Errorf("fake: item %q already exists", id)
	}
	it := Item{ID: id, Name: name, Body: body, CreatedAt: time.Now(), OperationID: call.OperationID}
	st.items[id] = it
	return connectors.Result{Content: it}, nil
}

// checkItem is create_item's reconciliation: look the stable id up.
func (c *Connector) checkItem(_ context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	call := in.Call
	if call.OperationID == "" {
		call.OperationID = in.OperationID
	}
	id := itemID(call)
	if id == "" {
		return connectors.ReconcileResult{}, errors.New("fake: no id or operation to reconcile by")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.account(call.Account).items[id]; ok {
		return connectors.ReconcileResult{Outcome: connectors.ReconcileFound, ResourceID: id}, nil
	}
	return connectors.ReconcileResult{Outcome: connectors.ReconcileNotFound}, nil
}

func (c *Connector) postNote(call connectors.Call) (connectors.Result, error) {
	text, _ := call.Args["text"].(string)
	if text == "" {
		return connectors.Result{}, errors.New("fake: text is required")
	}
	n := Note{ID: "note-" + randomID(), Text: text, CreatedAt: time.Now()}
	c.mu.Lock()
	st := c.account(call.Account)
	st.notes = append(st.notes, n)
	c.mu.Unlock()
	return connectors.Result{Content: n}, nil
}

// marker is flaky_write's reconciliation key: the argument, else the
// operation id.
func marker(call connectors.Call) string {
	if m, _ := call.Args["marker"].(string); m != "" {
		return m
	}
	return call.OperationID
}

func (c *Connector) flakyWrite(call connectors.Call) (connectors.Result, error) {
	m := marker(call)
	if m == "" {
		m = "write-" + randomID()
	}
	payload, _ := call.Args["payload"].(string)
	w := Write{Marker: m, Payload: payload, OperationID: call.OperationID, CreatedAt: time.Now()}
	c.mu.Lock()
	st := c.account(call.Account)
	st.writes = append(st.writes, w)
	c.mu.Unlock()
	return connectors.Result{Content: w}, nil
}

// checkWrite is flaky_write's reconciliation: search by marker.
func (c *Connector) checkWrite(_ context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	call := in.Call
	if call.OperationID == "" {
		call.OperationID = in.OperationID
	}
	m := marker(call)
	if m == "" {
		return connectors.ReconcileResult{}, errors.New("fake: no marker or operation to reconcile by")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, w := range c.account(call.Account).writes {
		if w.Marker == m {
			return connectors.ReconcileResult{Outcome: connectors.ReconcileFound, ResourceID: m}, nil
		}
	}
	return connectors.ReconcileResult{Outcome: connectors.ReconcileNotFound}, nil
}

func toInt(v any) (int, error) {
	switch n := v.(type) {
	case int:
		return n, nil
	case int64:
		return int(n), nil
	case float64:
		if n != float64(int(n)) {
			return 0, errors.New("not an integer")
		}
		return int(n), nil
	case json.Number:
		i, err := n.Int64()
		return int(i), err
	case string:
		return strconv.Atoi(n)
	}
	return 0, fmt.Errorf("not an integer: %T", v)
}

func randomID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b[:]))
}

// accountSource wraps the static source with the optional auto-account
// behaviour.
type accountSource struct {
	static *connectors.StaticAccountSource
	auto   bool
	mu     sync.Mutex
}

// ListAccounts implements connectors.AccountSource.
func (s *accountSource) ListAccounts(ctx context.Context, userID, app string) ([]connectors.Account, error) {
	list, err := s.static.ListAccounts(ctx, userID, app)
	if err != nil || app != App || !s.auto || userID == "" {
		return list, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	list, _ = s.static.ListAccounts(ctx, userID, app)
	if len(list) > 0 {
		return list, nil
	}
	s.static.Add(userID, connectors.Account{
		ID:          connectors.NewAccountID(),
		App:         App,
		Label:       connectors.LabelCompany,
		DisplayName: "Fake company account",
	})
	return s.static.ListAccounts(ctx, userID, app)
}
