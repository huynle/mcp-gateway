package connectors

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Connector is one app integration (github, slack, fake, ...). Tools lists
// its tool metadata; Call runs one of them.
//
// Dispatch convention: a connector dispatches by Call.Tool inside Call, and
// the tools it returns from Tools leave Handler nil. RegisterConnector binds
// every nil Handler to the connector's Call before registering, so the
// registry (which requires a Handler) never sees a nil one. A tool that
// sets its own Handler keeps it; that is the escape hatch for tools whose
// logic does not fit the connector's dispatcher (none so far). Call must
// return ErrUnknownTool for a name it does not serve.
type Connector interface {
	// App is the lower-case identifier every tool is registered under.
	App() string
	// Tools returns the connector's tools; each must carry App() as its App.
	Tools() []Tool
	// Call runs the tool named by call.Tool against call.Account.
	Call(ctx context.Context, call Call) (Result, error)
}

// ListAccountsName is the name of the read tool RegisterConnector adds to
// every app ("<app>.list_accounts"): it lists the caller's connected
// accounts (ID, label, display name; never tokens or scopes) so a harness
// can fill the gateway-injected "account" argument when the user has
// several (decision dovthftx). Connectors must not define a tool of this
// name themselves.
const ListAccountsName = "list_accounts"

// Errors from the connector contract.
var (
	// ErrUnknownTool is what Connector.Call returns for a tool name it does
	// not serve; it means a registration bug, never a harness mistake.
	ErrUnknownTool = errors.New("connectors: unknown tool")
	// ErrOutcomeUnknown says a write may or may not have happened: the
	// vendor did not answer in time, the connection dropped mid-call, or
	// the reply could not be interpreted. The ledger task marks such
	// operations unknown and hands reconcilable ones to the reconciler
	// (decision dovthftx); connectors wrap it so errors.Is matches.
	ErrOutcomeUnknown = errors.New("connectors: outcome unknown")
)

// AccountLabel says whose account a connection is: the company's or the
// user's own (decision mh7c6z3v). Policy and audit treat them differently.
type AccountLabel string

// The two labels.
const (
	LabelCompany  AccountLabel = "company"
	LabelPersonal AccountLabel = "personal"
)

// Account is one connected app account of one user, as the pipeline and
// list_accounts see it. It never carries tokens; those stay in the
// connections package.
type Account struct {
	// ID is the connection's identifier the harness passes as "account".
	ID string
	// Label is company or personal.
	Label AccountLabel
	// DisplayName is what the user recognises ("alice@acme.com",
	// "acme-inc", "Alice's workspace").
	DisplayName string
	// App is the connector the account belongs to.
	App string
	// Scopes are the vendor scopes the account granted; tools whose
	// RequiredScopes are not covered hide (connections task).
	Scopes []string
}

// AccountSource lists a user's connected accounts for one app. The
// connections task implements it over the connections table;
// StaticAccountSource is the in-memory implementation the fake connector
// and tests use. Implementations return only the accounts userID owns.
type AccountSource interface {
	ListAccounts(ctx context.Context, userID, app string) ([]Account, error)
}

// StaticAccountSource is an in-memory AccountSource: accounts are added
// per user and listed per user and app. Safe for concurrent use.
type StaticAccountSource struct {
	mu       sync.RWMutex
	accounts map[string][]Account // by user ID
}

// NewStaticAccountSource returns an empty source.
func NewStaticAccountSource() *StaticAccountSource {
	return &StaticAccountSource{accounts: map[string][]Account{}}
}

// Add gives userID the account; an existing account with the same App and
// ID is replaced.
func (s *StaticAccountSource) Add(userID string, acct Account) {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := s.accounts[userID]
	for i, a := range list {
		if a.App == acct.App && a.ID == acct.ID {
			list[i] = acct
			s.accounts[userID] = list
			return
		}
	}
	s.accounts[userID] = append(list, acct)
}

// ListAccounts implements AccountSource. It returns copies.
func (s *StaticAccountSource) ListAccounts(_ context.Context, userID, app string) ([]Account, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Account
	for _, a := range s.accounts[userID] {
		if a.App == app {
			a.Scopes = append([]string(nil), a.Scopes...)
			out = append(out, a)
		}
	}
	return out, nil
}

// ReconcileKind says how a write can be checked after an unknown outcome
// (decision dovthftx). It must be set explicitly on every write tool: the
// zero value is invalid so a connector cannot forget to decide.
type ReconcileKind string

// The four kinds.
const (
	// ReconcileNone: the write cannot be verified afterwards (a chat
	// message without a client-side key). An unknown outcome goes straight
	// to unresolved and the user is asked to check the app.
	ReconcileNone ReconcileKind = "none"
	// ReconcileStableID: the resource the write targets or creates has an
	// identifier known before the call (from the arguments, or derived
	// from the operation ID), so Check can look it up.
	ReconcileStableID ReconcileKind = "stable_id"
	// ReconcileClientID: the vendor accepts a client-chosen idempotency or
	// request ID that the connector derives from the operation and Check
	// can query by.
	ReconcileClientID ReconcileKind = "client_id"
	// ReconcileMarker: the connector embeds a marker (the operation ID in a
	// body or comment) and Check searches for it.
	ReconcileMarker ReconcileKind = "marker"
)

// Valid reports whether k is one of the four kinds.
func (k ReconcileKind) Valid() bool {
	switch k {
	case ReconcileNone, ReconcileStableID, ReconcileClientID, ReconcileMarker:
		return true
	}
	return false
}

// ReconcileInput is what the reconciler gives Check: the original call
// (principal, account, tool, arguments) and the ledger operation ID the
// write ran under (also in Call.OperationID). Connectors derive the stable
// ID, client ID or marker from these exactly as they did when the write
// was attempted.
type ReconcileInput struct {
	Call        Call
	OperationID string
}

// ReconcileOutcome is what Check found.
type ReconcileOutcome string

// The two definite outcomes. "Cannot tell yet" is an error from Check; the
// reconciler retries with backoff.
const (
	// ReconcileFound: the write took effect; ResourceID names the result.
	ReconcileFound ReconcileOutcome = "found"
	// ReconcileNotFound: the write did not take effect.
	ReconcileNotFound ReconcileOutcome = "not_found"
)

// ReconcileResult is Check's answer.
type ReconcileResult struct {
	Outcome ReconcileOutcome
	// ResourceID is the created or changed resource when found.
	ResourceID string
}

// Reconciliation is a write tool's declaration of how it can be checked
// after an unknown outcome. Check is required for every kind except
// ReconcileNone and must be read-only.
type Reconciliation struct {
	Kind  ReconcileKind
	Check func(ctx context.Context, in ReconcileInput) (ReconcileResult, error)
}

// Bounds caps what one call may return (decision mh7c6z3v). MaxPageSize is
// the largest page a paginated read returns (requests above it are
// clamped, not rejected); MaxResultBytes bounds the serialised content of
// any result. Zero MaxPageSize means the tool does not paginate.
type Bounds struct {
	MaxPageSize    int
	MaxResultBytes int
}

// Default bounds connectors can start from.
const (
	DefaultMaxPageSize    = 50
	DefaultMaxResultBytes = 256 << 10
)

// DefaultBounds returns Bounds with the package defaults.
func DefaultBounds() Bounds {
	return Bounds{MaxPageSize: DefaultMaxPageSize, MaxResultBytes: DefaultMaxResultBytes}
}

// RateLimited is the error a connector returns when the vendor answered
// 429 (or an equivalent quota error) for App. RetryAfter is the vendor's
// Retry-After, or the connector's best guess when the vendor gave none.
// The ratelimit stage surfaces it to the harness with the wait and pauses
// the app's bucket until then (decision dovthftx).
type RateLimited struct {
	App        string
	RetryAfter time.Duration
}

// Error implements error.
func (e *RateLimited) Error() string {
	return fmt.Sprintf("%s: rate limited by vendor; retry after %s", e.App, e.RetryAfter)
}

// RegisterConnector registers every tool of c under c.App() plus the
// generated "<app>.list_accounts" read tool backed by accounts. Tools with
// a nil Handler are bound to c.Call (see Connector). Every tool's App must
// equal c.App(), and c must not define list_accounts itself. On error
// nothing is registered.
func RegisterConnector(reg *Registry, c Connector, accounts AccountSource) error {
	switch {
	case reg == nil:
		return errors.New("connectors: registry is nil")
	case c == nil:
		return errors.New("connectors: connector is nil")
	case accounts == nil:
		return errors.New("connectors: account source is nil")
	}
	app := c.App()
	tools := append([]Tool(nil), c.Tools()...)
	for i := range tools {
		t := &tools[i]
		if t.App != app {
			return fmt.Errorf("%w: %s.%s: app %q does not match connector %q", ErrInvalidTool, t.App, t.Name, t.App, app)
		}
		if t.Name == ListAccountsName {
			return fmt.Errorf("%w: %s.%s is generated by the gateway; connectors must not define it", ErrInvalidTool, app, t.Name)
		}
		if t.Handler == nil {
			t.Handler = c.Call
		}
		if err := t.validateContract(); err != nil {
			return err
		}
	}
	tools = append(tools, ListAccountsTool(app, accounts))
	for _, t := range tools {
		if err := t.validate(); err != nil {
			return err
		}
	}
	return reg.registerAll(tools)
}

// validateContract applies the connector contract on top of Registry's
// checks: writes declare how they reconcile (connectortest.ContractTest
// asserts the same, plus descriptions and resource identity). Registry
// itself stays lenient so hand-assembled tools in tests need not declare
// it.
func (t Tool) validateContract() error {
	switch {
	case t.Kind == KindWrite && !t.Reconcile.Kind.Valid():
		return fmt.Errorf("%w: %s: write tools must declare a reconciliation kind (none, stable_id, client_id or marker), got %q", ErrInvalidTool, t.FullName(), t.Reconcile.Kind)
	case t.Kind == KindWrite && t.Reconcile.Kind != ReconcileNone && t.Reconcile.Check == nil:
		return fmt.Errorf("%w: %s: reconciliation %s needs a Check", ErrInvalidTool, t.FullName(), t.Reconcile.Kind)
	}
	return nil
}

// ListAccountsTool builds the "<app>.list_accounts" read tool over
// accounts. RegisterConnector calls it; it is exported so a registry
// assembled by hand (tests) can add it too.
func ListAccountsTool(app string, accounts AccountSource) Tool {
	return Tool{
		App:  app,
		Name: ListAccountsName,
		Description: "List your connected " + app + " accounts: id, label (company or personal) and display name. " +
			"Pass an id as the \"account\" argument of other " + app + " tools when you have more than one.",
		InputSchema:      json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`),
		Kind:             KindRead,
		NoAccount:        true,
		ResourceIdentity: func(map[string]any) map[string]string { return map[string]string{"app": app} },
		Bounds:           Bounds{MaxResultBytes: DefaultMaxResultBytes},
		Handler: func(ctx context.Context, call Call) (Result, error) {
			list, err := accounts.ListAccounts(ctx, call.Principal.UserID, app)
			if err != nil {
				return Result{}, fmt.Errorf("list accounts: %w", err)
			}
			sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
			out := make([]accountView, 0, len(list))
			for _, a := range list {
				out = append(out, accountView{ID: a.ID, Label: string(a.Label), DisplayName: a.DisplayName})
			}
			return Result{Content: map[string]any{"accounts": out}, Empty: len(out) == 0}, nil
		},
	}
}

// accountView is the wire shape of one account in list_accounts: nothing
// a token or scope could hide in.
type accountView struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	DisplayName string `json:"display_name"`
}
