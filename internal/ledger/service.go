package ledger

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/store"
)

// States mirror the ledger_state enum (decision dovthftx).
const (
	StateInProgress = store.LedgerInProgress
	StateSucceeded  = store.LedgerSucceeded
	StateFailed     = store.LedgerFailed
	StateUnknown    = store.LedgerUnknown
	StateUnresolved = store.LedgerUnresolved
)

// Errors.
var (
	// ErrInvalid reports an intent or outcome missing a required field.
	ErrInvalid = errors.New("ledger: invalid request")
	// ErrNotFound: no such operation is visible to the user.
	ErrNotFound = errors.New("ledger: operation not found")
	// ErrNotOpen: Finish on an operation that is no longer in_progress or
	// unknown (already finished, or resolved by the reconciler).
	ErrNotOpen = errors.New("ledger: operation is not open")
	// ErrApprovalsUnavailable: the intent names an approval but no
	// approvals service was configured to consume it.
	ErrApprovalsUnavailable = errors.New("ledger: approvals are not available")
)

// Intent is one write about to run: who, through which token, against
// which account, which tool, the canonical argument digest, the policy
// version in force, the approval the harness is retrying with (optional)
// and the connector's resource identity for the arguments (keys and short
// values; stored so the reconciler can re-derive the write's stable id or
// marker without the arguments, which are never stored).
type Intent struct {
	UserID           string
	TokenID          string
	AccountID        string
	Tool             string
	Digest           []byte
	PolicyVersionID  string
	ApprovalID       string
	ResourceIdentity map[string]string
}

// Operation is a ledger row as the rest of the gateway sees it: metadata
// and result IDs only. ApprovalArgs is transient: Begin fills it with the
// stored arguments of the approval it consumed, for the caller to execute
// instead of whatever the retry carried; it is never persisted here.
type Operation struct {
	ID                string
	UserID            string
	TokenID           string
	AccountID         string
	Tool              string
	State             string
	Key               string
	ApprovalID        string
	PolicyVersionID   string
	ResultIDs         map[string]string
	ErrorClass        string
	ReconcileAttempts int
	ResourceIdentity  map[string]string
	CreatedAt         time.Time
	UpdatedAt         time.Time
	FinishedAt        *time.Time
	ApprovalArgs      map[string]any
}

// Open reports whether the operation still awaits an outcome.
func (o *Operation) Open() bool { return o.State == StateInProgress || o.State == StateUnknown }

// PriorKind says what Begin found under the intent's idempotency key.
type PriorKind string

// The three answers.
const (
	// PriorNone: no operation blocks the key; Begin inserted a new one.
	PriorNone PriorKind = ""
	// PriorReplay: an operation with the key succeeded inside the window;
	// the caller returns its stored result IDs instead of running again.
	PriorReplay PriorKind = "replay"
	// PriorPending: an operation with the key is still in_progress or
	// unknown; the caller answers "pending verification".
	PriorPending PriorKind = "pending"
)

// Prior is what Begin found under the key (Operation is nil for PriorNone).
type Prior struct {
	Kind      PriorKind
	Operation *Operation
}

// Outcome is what Finish records.
type Outcome struct {
	// State is StateSucceeded, StateFailed or StateUnknown.
	State string
	// ResultIDs are the identifiers the write produced (succeeded only);
	// SanitizeResultIDs applies.
	ResultIDs map[string]string
	// ErrorClass is the short audit error class (failed and unknown).
	ErrorClass string
}

// Succeeded builds a succeeded outcome.
func Succeeded(ids map[string]string) Outcome { return Outcome{State: StateSucceeded, ResultIDs: ids} }

// Failed builds a failed outcome.
func Failed(class string) Outcome { return Outcome{State: StateFailed, ErrorClass: class} }

// Unknown builds an unknown outcome.
func Unknown(class string) Outcome { return Outcome{State: StateUnknown, ErrorClass: class} }

// ApprovalBinding is what the approvals service must match when the
// ledger consumes an approval inside Begin's transaction: the approval was
// granted for exactly this user, account, tool and policy version.
type ApprovalBinding struct {
	UserID          string
	AccountID       string
	Tool            string
	PolicyVersionID string
	ApprovalID      string
}

// ConsumedApproval is a successful consume: the approval, its stored
// arguments and the resource identity recorded with it (which the ledger
// stores on the operation in place of the intent's, since the stored
// arguments are what runs).
type ConsumedApproval struct {
	ID               string
	Args             map[string]any
	ResourceIdentity map[string]string
}

// ApprovalConsumer consumes an approval inside the ledger's transaction
// (decision s0p05diu: "consumed in the same transaction as the ledger
// insert"). The approvals service implements it over Tx.StoreTx; errors
// it returns pass through Begin unchanged so the caller can tell the
// harness why (mismatch, denied, used, expired).
type ApprovalConsumer interface {
	Consume(ctx context.Context, tx Tx, b ApprovalBinding) (*ConsumedApproval, error)
}

// ToolResolver resolves a tool by full name; *connectors.Registry
// implements it. The reconciler needs it to find a write's Reconciliation.
type ToolResolver interface {
	Get(name string) (connectors.Tool, bool)
}

// Options configures New. Everything is optional.
type Options struct {
	// Approvals consumes approvals inside Begin's transaction; nil means
	// intents with an ApprovalID fail with ErrApprovalsUnavailable.
	Approvals ApprovalConsumer
	// Registry resolves tools for the reconciler; nil means every unknown
	// operation is non-reconcilable.
	Registry ToolResolver
	// Notifier is told about unresolved operations; nil means LogNotifier.
	Notifier Notifier
	// Audit records reconciler outcomes as events.
	Audit audit.Recorder
	// Metrics counts transitions (ledger_operations_total{state}).
	Metrics metricsCounter
	Log     *slog.Logger
}

// metricsCounter is the slice of observability.Metrics the service uses.
type metricsCounter interface {
	LedgerOperation(state string)
}

// Service owns the write ledger: the in_progress row before every write,
// idempotency within the right scope, outcomes, the bounded reconciler and
// the stale sweep (decision dovthftx).
type Service struct {
	cfg       Config
	st        Store
	approvals ApprovalConsumer
	tools     ToolResolver
	notifier  Notifier
	audit     audit.Recorder
	metrics   metricsCounter
	log       *slog.Logger
	now       func() time.Time

	mu       sync.Mutex
	inFlight map[string]string // operation id -> user id
	// afterConsume runs between the approval consume and the insert
	// (tests inject a failure to prove the two commit or roll back
	// together).
	afterConsume func() error
}

// New builds the service.
func New(cfg Config, st Store, opts Options) (*Service, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if st == nil {
		return nil, errors.New("ledger: store is required")
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.Notifier == nil {
		opts.Notifier = LogNotifier{Log: opts.Log}
	}
	if opts.Audit == nil {
		opts.Audit = audit.NopRecorder{}
	}
	return &Service{
		cfg: cfg, st: st, approvals: opts.Approvals, tools: opts.Registry, notifier: opts.Notifier,
		audit: opts.Audit, metrics: opts.Metrics, log: opts.Log,
		now:      func() time.Time { return time.Now().UTC() },
		inFlight: map[string]string{},
	}, nil
}

// SetClock replaces the time source (tests).
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// Config returns the configuration in force.
func (s *Service) Config() Config { return s.cfg }

// Begin records the intent before the write runs, in one transaction:
//
//   - with an ApprovalID the approval is consumed first (the approvals
//     service, through Options.Approvals) and the key is ApprovalKey; the
//     returned operation carries the approval's stored arguments in
//     ApprovalArgs;
//   - otherwise the key is DigestKey and the newest operation with that
//     key inside Config.IdempotencyWindow decides: succeeded means
//     PriorReplay, in_progress or unknown means PriorPending, failed or
//     unresolved (or none) means a new operation;
//   - the new operation is inserted as in_progress and returned.
//
// Concurrent Begins for the same key serialise on the key (Tx.LockKey),
// so exactly one inserts and the others see it. Errors from the approval
// consume are returned unchanged.
func (s *Service) Begin(ctx context.Context, in Intent) (*Operation, Prior, error) {
	if err := in.validate(); err != nil {
		return nil, Prior{}, err
	}
	if in.ApprovalID != "" && s.approvals == nil {
		return nil, Prior{}, ErrApprovalsUnavailable
	}
	now := s.now()
	key := DigestKey(in.UserID, in.AccountID, in.Tool, in.Digest)
	if in.ApprovalID != "" {
		key = ApprovalKey(in.ApprovalID)
	}
	var (
		op    *Operation
		prior Prior
	)
	err := s.st.AsUser(ctx, in.UserID, func(tx Tx) error {
		if err := tx.LockKey(ctx, key); err != nil {
			return err
		}
		var consumed *ConsumedApproval
		if in.ApprovalID != "" {
			var err error
			consumed, err = s.approvals.Consume(ctx, tx, ApprovalBinding{
				UserID: in.UserID, AccountID: in.AccountID, Tool: in.Tool, PolicyVersionID: in.PolicyVersionID, ApprovalID: in.ApprovalID,
			})
			if err != nil {
				return err
			}
			if s.afterConsume != nil {
				if err := s.afterConsume(); err != nil {
					return err
				}
			}
		} else {
			found, err := tx.LatestByKey(ctx, key, now.Add(-s.cfg.IdempotencyWindow))
			switch {
			case errors.Is(err, store.ErrNotFound):
			case err != nil:
				return err
			case found.State == StateSucceeded:
				prior = Prior{Kind: PriorReplay, Operation: fromRow(found)}
				return nil
			case found.State == StateInProgress || found.State == StateUnknown:
				prior = Prior{Kind: PriorPending, Operation: fromRow(found)}
				return nil
			}
		}
		resource := in.ResourceIdentity
		if consumed != nil && consumed.ResourceIdentity != nil {
			resource = consumed.ResourceIdentity
		}
		row := &store.LedgerOperation{
			UserID: in.UserID, ConnectionID: in.AccountID, Tool: in.Tool, State: StateInProgress,
			IdempotencyKey: key, WindowStart: now, WindowEnd: now.Add(s.cfg.IdempotencyWindow),
			Digest: in.Digest, PolicyVersionID: in.PolicyVersionID,
			Resource: encodeResource(resource), TokenID: optional(in.TokenID),
			CreatedAt: now, UpdatedAt: now,
		}
		if consumed != nil {
			row.ApprovalID = &consumed.ID
		}
		if err := tx.Create(ctx, row); err != nil {
			if errors.Is(err, store.ErrLedgerKeyOpen) {
				// Lost the race to another replica despite the key lock
				// (it may be using a different store): report pending.
				if found, gerr := tx.LatestByKey(ctx, key, time.Time{}); gerr == nil {
					prior = Prior{Kind: PriorPending, Operation: fromRow(found)}
					return nil
				}
			}
			return err
		}
		op = fromRow(row)
		if consumed != nil {
			op.ApprovalArgs = consumed.Args
			if op.ApprovalArgs == nil {
				op.ApprovalArgs = map[string]any{}
			}
		}
		return nil
	})
	if err != nil {
		return nil, Prior{}, err
	}
	if prior.Kind != PriorNone {
		s.log.Info("ledger: prior operation found", "event", "ledger.prior", "kind", prior.Kind, "operation_id", prior.Operation.ID,
			"state", prior.Operation.State, "tool", in.Tool, "user_id", in.UserID, observability.RequestIDAttr(ctx))
		return nil, prior, nil
	}
	s.track(op.ID, op.UserID)
	s.count(StateInProgress)
	s.log.Info("ledger: operation started", "event", "ledger.begin", "operation_id", op.ID, "tool", op.Tool, "user_id", op.UserID,
		"approval_id", op.ApprovalID, observability.RequestIDAttr(ctx))
	return op, Prior{}, nil
}

// Finish records the write's outcome and its call attempt. The operation
// must be open (in_progress, or unknown when the stale sweep got there
// first); ErrNotOpen otherwise, ErrNotFound when the user cannot see it.
func (s *Service) Finish(ctx context.Context, userID, opID string, out Outcome) (*Operation, error) {
	if userID == "" || opID == "" {
		return nil, fmt.Errorf("%w: user and operation are required", ErrInvalid)
	}
	switch out.State {
	case StateSucceeded, StateFailed, StateUnknown:
	default:
		return nil, fmt.Errorf("%w: outcome state %q", ErrInvalid, out.State)
	}
	defer s.untrack(opID)
	now := s.now()
	var op *Operation
	err := s.st.AsUser(ctx, userID, func(tx Tx) error {
		row, err := tx.Get(ctx, opID)
		if err != nil {
			return mapNotFound(err)
		}
		if row.State != StateInProgress && row.State != StateUnknown {
			return ErrNotOpen
		}
		t := store.LedgerTransition{State: out.State, At: now, Finished: out.State != StateUnknown}
		if out.State == StateSucceeded {
			t.ResultIDs = encodeIDs(SanitizeResultIDs(out.ResultIDs))
		}
		if out.ErrorClass != "" {
			t.ErrorCode = &out.ErrorClass
		}
		ok, err := tx.Transition(ctx, opID, []string{StateInProgress, StateUnknown}, t)
		if err != nil {
			return err
		}
		if !ok {
			return ErrNotOpen
		}
		att := &store.LedgerAttempt{
			OperationID: opID, UserID: userID, AttemptNo: 1, Kind: store.AttemptCall,
			Outcome: out.State, ErrorCode: t.ErrorCode, StartedAt: row.CreatedAt, FinishedAt: &now,
		}
		if err := tx.CreateAttempt(ctx, att); err != nil {
			return err
		}
		row, err = tx.Get(ctx, opID)
		if err != nil {
			return mapNotFound(err)
		}
		op = fromRow(row)
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.count(out.State)
	s.log.Info("ledger: operation finished", "event", "ledger.finish", "operation_id", opID, "tool", op.Tool, "user_id", userID,
		"state", out.State, "error_class", out.ErrorClass, observability.RequestIDAttr(ctx))
	return op, nil
}

// Get returns one of the user's operations.
func (s *Service) Get(ctx context.Context, userID, opID string) (*Operation, error) {
	var op *Operation
	err := s.st.AsUser(ctx, userID, func(tx Tx) error {
		row, err := tx.Get(ctx, opID)
		if err != nil {
			return mapNotFound(err)
		}
		op = fromRow(row)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return op, nil
}

// Operations lists the user's most recent operations, newest first.
func (s *Service) Operations(ctx context.Context, userID string, limit int) ([]Operation, error) {
	var rows []store.LedgerOperation
	err := s.st.AsUser(ctx, userID, func(tx Tx) error {
		var err error
		rows, err = tx.List(ctx, store.LedgerFilter{UserID: userID, Limit: limit})
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("ledger: list operations: %w", err)
	}
	out := make([]Operation, 0, len(rows))
	for i := range rows {
		out = append(out, *fromRow(&rows[i]))
	}
	return out, nil
}

// --- internals ---------------------------------------------------------------

func (in Intent) validate() error {
	switch {
	case in.UserID == "":
		return fmt.Errorf("%w: user is required", ErrInvalid)
	case in.AccountID == "":
		return fmt.Errorf("%w: account is required", ErrInvalid)
	case in.Tool == "":
		return fmt.Errorf("%w: tool is required", ErrInvalid)
	case in.PolicyVersionID == "":
		return fmt.Errorf("%w: policy version is required", ErrInvalid)
	case len(in.Digest) == 0:
		return fmt.Errorf("%w: digest is required", ErrInvalid)
	}
	return nil
}

func (s *Service) count(state string) {
	if s.metrics != nil {
		s.metrics.LedgerOperation(state)
	}
}

func (s *Service) track(opID, userID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inFlight[opID] = userID
}

func (s *Service) untrack(opID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.inFlight, opID)
}

func fromRow(row *store.LedgerOperation) *Operation {
	op := &Operation{
		ID: row.ID, UserID: row.UserID, AccountID: row.ConnectionID, Tool: row.Tool, State: row.State, Key: row.IdempotencyKey,
		PolicyVersionID: row.PolicyVersionID, ReconcileAttempts: row.ReconcileAttempts,
		CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt, FinishedAt: row.FinishedAt,
		ResultIDs: decodeIDs(row.ResultIDs), ResourceIdentity: decodeIDs(row.Resource),
	}
	if row.ApprovalID != nil {
		op.ApprovalID = *row.ApprovalID
	}
	if row.TokenID != nil {
		op.TokenID = *row.TokenID
	}
	if row.ErrorCode != nil {
		op.ErrorClass = *row.ErrorCode
	}
	return op
}

func encodeIDs(m map[string]string) json.RawMessage {
	if m == nil {
		m = map[string]string{}
	}
	b, _ := json.Marshal(m)
	return b
}

func encodeResource(m map[string]string) json.RawMessage {
	ev := audit.Event{ResourceIdentity: m}
	ev.Normalize()
	return encodeIDs(ev.ResourceIdentity)
}

func decodeIDs(raw json.RawMessage) map[string]string {
	if len(raw) == 0 {
		return map[string]string{}
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return map[string]string{}
	}
	return m
}

func mapNotFound(err error) error {
	if errors.Is(err, store.ErrNotFound) {
		return ErrNotFound
	}
	return err
}

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
