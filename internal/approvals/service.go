package approvals

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/caps"
	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/store"
)

// Statuses mirror the approval_status enum.
const (
	StatusPending  = store.ApprovalPending
	StatusApproved = store.ApprovalApproved
	StatusDenied   = store.ApprovalDenied
	StatusConsumed = store.ApprovalConsumed
	StatusExpired  = store.ApprovalExpired
)

// Metric states for observability.Metrics.Approval.
const (
	MetricCreated       = "created"
	MetricApproved      = "approved"
	MetricDenied        = "denied"
	MetricConsumed      = "consumed"
	MetricExpired       = "expired"
	MetricWaitedThrough = "waited_through"
)

// Errors. Consume reports exactly one of ErrNotFound, ErrMismatch,
// ErrPending, ErrDenied, ErrConsumed or ErrExpired so the caller can
// answer the harness precisely.
var (
	// ErrInvalid reports a request missing a binding field.
	ErrInvalid = errors.New("approvals: invalid request")
	// ErrNotFound: no such approval is visible to the user (it does not
	// exist or belongs to someone else), or no approved one matches the
	// digest.
	ErrNotFound = errors.New("approvals: not found")
	// ErrMismatch: the approval exists but was granted for another
	// account, tool or policy version.
	ErrMismatch = errors.New("approvals: approval does not match this call")
	// ErrPending: the user has not decided yet.
	ErrPending = errors.New("approvals: approval is still pending")
	// ErrDenied: the user denied it.
	ErrDenied = errors.New("approvals: approval was denied")
	// ErrConsumed: it was already used once.
	ErrConsumed = errors.New("approvals: approval already used")
	// ErrExpired: its lifetime passed before it was consumed.
	ErrExpired = errors.New("approvals: approval expired")
	// ErrNotPending: Approve/Deny on an approval that is no longer
	// pending (decided, consumed or expired).
	ErrNotPending = errors.New("approvals: approval is not pending")
)

// payloadKind is the AAD kind for approval payloads.
const payloadKind = "approval"

// pollInterval is how often Wait re-reads the row (a decision on another
// replica is seen within this; one on this replica wakes the waiter at
// once).
const pollInterval = 500 * time.Millisecond

// Approval is an approval as the rest of the gateway sees it: metadata
// only, never the arguments. HasPayload says whether the encrypted
// arguments are still stored (pending and approved rows only).
type Approval struct {
	ID               string
	UserID           string
	TokenID          string
	AccountID        string
	AccountLabel     string
	AccountName      string
	Tool             string
	ResourceIdentity map[string]string
	Digest           []byte
	Status           string
	PolicyVersionID  string
	CreatedAt        time.Time
	ExpiresAt        time.Time
	DecidedAt        *time.Time
	ConsumedAt       *time.Time
	HasPayload       bool
}

// App is the tool's app (the part before the dot).
func (a Approval) App() string { return appOf(a.Tool) }

// Request creates an approval for one confirmed call.
type Request struct {
	UserID           string
	TokenID          string
	AccountID        string
	AccountLabel     string
	Tool             string
	Args             map[string]any
	ResourceIdentity map[string]string
	PolicyVersionID  string
	// Digest is Digest(Args); computed when empty.
	Digest []byte
}

// Binding is what a consume must match. ApprovalID selects the approval;
// when it is empty, Digest selects the newest approved one with the same
// canonical arguments (the retry-without-approval_id path).
type Binding struct {
	UserID          string
	AccountID       string
	Tool            string
	PolicyVersionID string
	ApprovalID      string
	Digest          []byte
}

func (b Binding) store() store.ApprovalBinding {
	return store.ApprovalBinding{UserID: b.UserID, ConnectionID: b.AccountID, Tool: b.Tool, PolicyVersionID: b.PolicyVersionID}
}

// Consumed is a successful consume: the approval and its stored
// arguments, which the caller executes instead of whatever the retry
// carried.
type Consumed struct {
	ID   string
	Args map[string]any
}

// Pending is an approval awaiting a decision as the portal shows it: the
// metadata plus a summary of the decrypted arguments.
type Pending struct {
	Approval
	Args    map[string]any
	Summary []Field
}

// Field is one argument in a Pending summary: strings truncated, nested
// values as compact JSON.
type Field struct {
	Key   string
	Value string
	// Truncated says Value was cut short.
	Truncated bool
}

// MaxSummaryLen bounds a Field value.
const MaxSummaryLen = 200

// Options configures New. Everything is optional.
type Options struct {
	// Audit records approve/deny as user events.
	Audit audit.Recorder
	// Metrics counts transitions (approvals_total{state}).
	Metrics *observability.Metrics
	// Notifier is told about every new approval; nil means PortalNotifier.
	Notifier Notifier
	Log      *slog.Logger
}

// Service owns approvals: creation with the encrypted argument payload,
// the bounded wait, the user's decision, single-use consumption and
// expiry (decision s0p05diu).
type Service struct {
	cfg      Config
	st       Store
	keys     crypto.KeyProvider
	audit    audit.Recorder
	metrics  *observability.Metrics
	notifier Notifier
	log      *slog.Logger
	now      func() time.Time

	mu      sync.Mutex
	waiters map[string][]chan struct{}
	// caps limits each user's pending approvals (SetCaps; nil: unlimited).
	caps atomic.Pointer[capsHolder]
}

// New builds the service. keys encrypts the stored arguments.
func New(cfg Config, st Store, keys crypto.KeyProvider, opts Options) (*Service, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if st == nil {
		return nil, errors.New("approvals: store is required")
	}
	if keys == nil {
		return nil, errors.New("approvals: key provider is required")
	}
	if opts.Audit == nil {
		opts.Audit = audit.NopRecorder{}
	}
	if opts.Notifier == nil {
		opts.Notifier = PortalNotifier{}
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	return &Service{
		cfg: cfg, st: st, keys: keys, audit: opts.Audit, metrics: opts.Metrics, notifier: opts.Notifier, log: opts.Log,
		now:     func() time.Time { return time.Now().UTC() },
		waiters: map[string][]chan struct{}{},
	}, nil
}

// SetClock replaces the time source (tests).
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// Config returns the configuration in force.
func (s *Service) Config() Config { return s.cfg }

// PortalURL is where the user decides: BaseURL + "/approvals".
func (s *Service) PortalURL() string { return strings.TrimRight(s.cfg.BaseURL, "/") + "/approvals" }

// Create stores a pending approval with the canonical digest, the
// encrypted arguments and the expiry, then notifies.
func (s *Service) Create(ctx context.Context, req Request) (*Approval, error) {
	switch {
	case req.UserID == "":
		return nil, fmt.Errorf("%w: user is required", ErrInvalid)
	case req.AccountID == "":
		return nil, fmt.Errorf("%w: account is required", ErrInvalid)
	case req.Tool == "":
		return nil, fmt.Errorf("%w: tool is required", ErrInvalid)
	case req.PolicyVersionID == "":
		return nil, fmt.Errorf("%w: policy version is required", ErrInvalid)
	}
	args := req.Args
	if args == nil {
		args = map[string]any{}
	}
	digest := req.Digest
	if len(digest) == 0 {
		digest = Digest(args)
	}
	plaintext, err := json.Marshal(payload{Args: args})
	if err != nil {
		return nil, fmt.Errorf("approvals: encode arguments: %w", err)
	}
	id := newID()
	env, err := crypto.Encrypt(ctx, s.keys, s.aad(req.UserID, id, req.Tool), plaintext)
	if err != nil {
		return nil, fmt.Errorf("approvals: encrypt arguments: %w", err)
	}
	resource, _ := json.Marshal(nonNil(req.ResourceIdentity))
	now := s.now()
	rec := &store.ApprovalRecord{
		Approval: store.Approval{
			ID: id, UserID: req.UserID, ConnectionID: req.AccountID, Tool: req.Tool, Digest: digest,
			Payload:         &store.Encrypted{KeyID: env.KeyID, WrappedDataKey: env.WrappedDataKey, Nonce: env.Nonce, Ciphertext: env.Ciphertext},
			Status:          StatusPending,
			PolicyVersionID: req.PolicyVersionID,
			CreatedAt:       now,
			ExpiresAt:       now.Add(s.cfg.TTL),
		},
		TokenID:      optional(req.TokenID),
		Resource:     resource,
		AccountLabel: req.AccountLabel,
	}
	err = s.st.AsUser(ctx, req.UserID, func(tx Tx) error {
		if err := tx.ReservePendingApproval(ctx, s.limiter(), req.UserID, now); err != nil {
			return err
		}
		return tx.CreateApproval(ctx, rec)
	})
	var ce *caps.ExceededError
	if errors.As(err, &ce) {
		return nil, ce
	}
	if err != nil {
		return nil, fmt.Errorf("approvals: create: %w", err)
	}
	a := fromRecord(rec)
	s.count(MetricCreated)
	s.log.Info("approval created", "event", "approvals.created", "approval_id", a.ID, "user_id", a.UserID, "tool", a.Tool,
		"expires_at", a.ExpiresAt, observability.RequestIDAttr(ctx))
	if err := s.notifier.Notify(ctx, a); err != nil {
		s.log.Warn("approval notification failed", "event", "approvals.notify_failed", "approval_id", a.ID,
			"error", observability.RedactError(err), observability.RequestIDAttr(ctx))
	}
	return &a, nil
}

// Get returns one of the user's approvals (metadata only).
func (s *Service) Get(ctx context.Context, userID, id string) (*Approval, error) {
	var rec *store.ApprovalRecord
	err := s.st.AsUser(ctx, userID, func(tx Tx) error {
		var err error
		rec, err = tx.GetApproval(ctx, id)
		return err
	})
	if err != nil {
		return nil, mapNotFound(err)
	}
	a := fromRecord(rec)
	return &a, nil
}

// Wait blocks until the approval is no longer pending, for at most d, and
// returns its status (StatusPending on timeout). A decision on this
// replica wakes it at once; one made elsewhere is seen within
// pollInterval. ctx cancellation is returned as the context's error.
func (s *Service) Wait(ctx context.Context, userID, id string, d time.Duration) (string, error) {
	wake := s.subscribe(id)
	defer s.unsubscribe(id, wake)
	deadline := time.NewTimer(d)
	defer deadline.Stop()
	poll := time.NewTicker(pollInterval)
	defer poll.Stop()
	for {
		a, err := s.Get(ctx, userID, id)
		if err != nil {
			return "", err
		}
		if a.Status != StatusPending || !a.ExpiresAt.After(s.now()) {
			if a.Status == StatusPending {
				return StatusExpired, nil
			}
			return a.Status, nil
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-deadline.C:
			return StatusPending, nil
		case <-wake:
		case <-poll.C:
		}
	}
}

// Approve records the user's yes. The payload stays until the consume.
func (s *Service) Approve(ctx context.Context, userID, id string) (*Approval, error) {
	return s.decide(ctx, userID, id, StatusApproved)
}

// Deny records the user's no and drops the payload.
func (s *Service) Deny(ctx context.Context, userID, id string) (*Approval, error) {
	return s.decide(ctx, userID, id, StatusDenied)
}

func (s *Service) decide(ctx context.Context, userID, id, status string) (*Approval, error) {
	now := s.now()
	var rec *store.ApprovalRecord
	err := s.st.AsUser(ctx, userID, func(tx Tx) error {
		// Tell "not yours / unknown" from "yours but no longer pending".
		existing, err := tx.GetApproval(ctx, id)
		if err != nil {
			return err
		}
		if existing.Status != StatusPending || !existing.ExpiresAt.After(now) {
			return ErrNotPending
		}
		rec, err = tx.DecideApproval(ctx, id, userID, status, now)
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotPending // decided concurrently
		}
		return err
	})
	if err != nil {
		return nil, mapNotFound(err)
	}
	a := fromRecord(rec)
	s.count(status)
	s.wake(id)
	action := "approval_" + status
	s.log.Info("approval decided", "event", "approvals."+status, "approval_id", id, "user_id", userID, "tool", a.Tool, observability.RequestIDAttr(ctx))
	ev := audit.Event{
		Time:             now,
		UserID:           userID,
		ResourceIdentity: map[string]string{"action": action, "tool": a.Tool},
		Decision:         "allow",
		PolicyVersion:    a.PolicyVersionID,
		ApprovalID:       id,
		Outcome:          "succeeded",
		RequestID:        observability.RequestIDFromContext(ctx),
	}
	if err := s.audit.Record(ctx, ev); err != nil {
		s.log.Error("approval decision not audited", "event", "approvals.audit_failed", "approval_id", id,
			"error", observability.RedactError(err), observability.RequestIDAttr(ctx))
	}
	return &a, nil
}

// Consume uses an approval exactly once inside the caller's transaction
// (tx must be scoped to b.UserID) and returns the stored arguments. The
// row must be approved, unconsumed, unexpired and bound to b; otherwise
// one of ErrNotFound, ErrMismatch, ErrPending, ErrDenied, ErrConsumed or
// ErrExpired is returned and nothing changes. Concurrent consumes of the
// same approval yield exactly one winner (the conditional UPDATE in
// store.ConsumeApproval).
func (s *Service) Consume(ctx context.Context, tx Tx, b Binding) (*Consumed, error) {
	switch {
	case b.UserID == "" || b.AccountID == "" || b.Tool == "" || b.PolicyVersionID == "":
		return nil, fmt.Errorf("%w: binding is incomplete", ErrInvalid)
	case b.ApprovalID == "" && len(b.Digest) == 0:
		return nil, fmt.Errorf("%w: approval id or digest is required", ErrInvalid)
	}
	now := s.now()
	id := b.ApprovalID
	if id == "" {
		var err error
		id, err = tx.FindApprovedApproval(ctx, b.store(), b.Digest, now)
		if err != nil {
			return nil, mapNotFound(err)
		}
	}
	rec, err := tx.GetApproval(ctx, id)
	if err != nil {
		return nil, mapNotFound(err)
	}
	if rec.UserID != b.UserID || rec.ConnectionID != b.AccountID || rec.Tool != b.Tool || rec.PolicyVersionID != b.PolicyVersionID {
		return nil, ErrMismatch
	}
	if err := s.stateError(rec, now); err != nil {
		return nil, err
	}
	if rec.Payload == nil {
		return nil, ErrConsumed
	}
	// Decrypt before the UPDATE: the payload is immutable until consumed,
	// so what we read is what the winner executes.
	args, err := s.decrypt(ctx, rec)
	if err != nil {
		return nil, err
	}
	if err := tx.ConsumeApproval(ctx, id, b.store(), now); err != nil {
		if errors.Is(err, store.ErrApprovalNotConsumable) {
			// Lost a race, or the row changed under us: re-read to say why.
			if again, rerr := tx.GetApproval(ctx, id); rerr == nil {
				if serr := s.stateError(again, now); serr != nil {
					return nil, serr
				}
			}
			return nil, ErrConsumed
		}
		return nil, fmt.Errorf("approvals: consume: %w", err)
	}
	s.count(MetricConsumed)
	s.log.Info("approval consumed", "event", "approvals.consumed", "approval_id", id, "user_id", b.UserID, "tool", b.Tool, observability.RequestIDAttr(ctx))
	return &Consumed{ID: id, Args: args}, nil
}

// ConsumeNow runs Consume in its own user-scoped transaction. The confirm
// handler uses it until the ledger wraps the consume in its own
// transaction (decision dovthftx).
func (s *Service) ConsumeNow(ctx context.Context, b Binding) (*Consumed, error) {
	if b.UserID == "" {
		return nil, fmt.Errorf("%w: user is required", ErrInvalid)
	}
	var out *Consumed
	err := s.st.AsUser(ctx, b.UserID, func(tx Tx) error {
		var err error
		out, err = s.Consume(ctx, tx, b)
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// stateError maps a row that is not consumable to the error naming why.
func (s *Service) stateError(rec *store.ApprovalRecord, now time.Time) error {
	switch rec.Status {
	case StatusConsumed:
		return ErrConsumed
	case StatusDenied:
		return ErrDenied
	case StatusExpired:
		return ErrExpired
	}
	if !rec.ExpiresAt.After(now) {
		return ErrExpired
	}
	if rec.Status == StatusPending {
		return ErrPending
	}
	return nil
}

// Pending lists the user's pending approvals, newest first, with the
// decrypted arguments and a display summary. An approval whose payload
// cannot be decrypted is listed without arguments and logged.
func (s *Service) Pending(ctx context.Context, userID string) ([]Pending, error) {
	var rows []store.ApprovalRecord
	err := s.st.AsUser(ctx, userID, func(tx Tx) error {
		var err error
		rows, err = tx.ListApprovals(ctx, userID, true, 0)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("approvals: pending: %w", err)
	}
	now := s.now()
	out := make([]Pending, 0, len(rows))
	for i := range rows {
		rec := &rows[i]
		if !rec.ExpiresAt.After(now) {
			continue // the expiry job has not swept it yet
		}
		p := Pending{Approval: fromRecord(rec)}
		if rec.Payload != nil {
			args, err := s.decrypt(ctx, rec)
			if err != nil {
				s.log.Error("approval payload unreadable", "event", "approvals.payload_unreadable", "approval_id", rec.ID, "error", observability.RedactError(err))
			} else {
				p.Args = args
				p.Summary = Summarize(args)
			}
		}
		out = append(out, p)
	}
	return out, nil
}

// History lists the user's most recent approvals (metadata only).
func (s *Service) History(ctx context.Context, userID string, limit int) ([]Approval, error) {
	var rows []store.ApprovalRecord
	err := s.st.AsUser(ctx, userID, func(tx Tx) error {
		var err error
		rows, err = tx.ListApprovals(ctx, userID, false, limit)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("approvals: history: %w", err)
	}
	out := make([]Approval, 0, len(rows))
	for i := range rows {
		out = append(out, fromRecord(&rows[i]))
	}
	return out, nil
}

// Expire marks every approval past its expiry as expired and drops the
// payloads, across all users. It returns how many rows changed.
func (s *Service) Expire(ctx context.Context) (int64, error) {
	now := s.now()
	var n int64
	err := s.st.Bypass(ctx, func(tx Tx) error {
		var err error
		n, err = tx.ExpireApprovals(ctx, now)
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("approvals: expire: %w", err)
	}
	for range n {
		s.count(MetricExpired)
	}
	if n > 0 {
		s.log.Info("approvals expired", "event", "approvals.expired", "count", n)
	}
	return n, nil
}

// Summarize renders arguments for the approval page: keys sorted,
// strings as they are, numbers and booleans formatted, nested values as
// compact JSON, everything cut at MaxSummaryLen.
func Summarize(args map[string]any) []Field {
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]Field, 0, len(keys))
	for _, k := range keys {
		var v string
		switch x := args[k].(type) {
		case string:
			v = x
		case nil:
			v = "null"
		case bool, float64, int, int64, json.Number:
			v = fmt.Sprint(x)
		default:
			b, err := Canonical(map[string]any{"v": x})
			if err != nil {
				v = fmt.Sprint(x)
			} else {
				v = strings.TrimSuffix(strings.TrimPrefix(string(b), `{"v":`), "}")
			}
		}
		f := Field{Key: k, Value: v}
		if len(v) > MaxSummaryLen {
			f.Value, f.Truncated = v[:MaxSummaryLen]+"…", true
		}
		out = append(out, f)
	}
	return out
}

// --- internals ---------------------------------------------------------------

// payload is the plaintext stored under the envelope. Only the arguments:
// everything else is a column.
type payload struct {
	Args map[string]any `json:"args"`
}

func (s *Service) aad(userID, id, tool string) crypto.AAD {
	return crypto.AAD{UserID: userID, Kind: payloadKind, RecordID: id, App: appOf(tool)}
}

func (s *Service) decrypt(ctx context.Context, rec *store.ApprovalRecord) (map[string]any, error) {
	env := crypto.Envelope{KeyID: rec.Payload.KeyID, WrappedDataKey: rec.Payload.WrappedDataKey, Nonce: rec.Payload.Nonce, Ciphertext: rec.Payload.Ciphertext}
	plaintext, err := crypto.Decrypt(ctx, s.keys, s.aad(rec.UserID, rec.ID, rec.Tool), env)
	if err != nil {
		return nil, fmt.Errorf("approvals: decrypt arguments: %w", err)
	}
	var p payload
	if err := json.Unmarshal(plaintext, &p); err != nil {
		return nil, fmt.Errorf("approvals: decode arguments: %w", err)
	}
	if p.Args == nil {
		p.Args = map[string]any{}
	}
	return p.Args, nil
}

func (s *Service) count(state string) {
	if s.metrics != nil {
		s.metrics.Approval(state)
	}
}

func (s *Service) subscribe(id string) chan struct{} {
	ch := make(chan struct{}, 1)
	s.mu.Lock()
	s.waiters[id] = append(s.waiters[id], ch)
	s.mu.Unlock()
	return ch
}

func (s *Service) unsubscribe(id string, ch chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := s.waiters[id]
	for i, c := range list {
		if c == ch {
			list = append(list[:i], list[i+1:]...)
			break
		}
	}
	if len(list) == 0 {
		delete(s.waiters, id)
	} else {
		s.waiters[id] = list
	}
}

func (s *Service) wake(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ch := range s.waiters[id] {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func fromRecord(rec *store.ApprovalRecord) Approval {
	a := Approval{
		ID: rec.ID, UserID: rec.UserID, AccountID: rec.ConnectionID, AccountLabel: rec.AccountLabel, AccountName: rec.AccountDisplayName,
		Tool: rec.Tool, Digest: rec.Digest, Status: rec.Status, PolicyVersionID: rec.PolicyVersionID,
		CreatedAt: rec.CreatedAt, ExpiresAt: rec.ExpiresAt, DecidedAt: rec.DecidedAt, ConsumedAt: rec.ConsumedAt,
		HasPayload: rec.Payload != nil,
	}
	if rec.TokenID != nil {
		a.TokenID = *rec.TokenID
	}
	if len(rec.Resource) > 0 {
		_ = json.Unmarshal(rec.Resource, &a.ResourceIdentity)
	}
	return a
}

func mapNotFound(err error) error {
	if errors.Is(err, store.ErrNotFound) {
		return ErrNotFound
	}
	return err
}

func appOf(tool string) string {
	if i := strings.IndexByte(tool, '.'); i > 0 {
		return tool[:i]
	}
	return tool
}

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func nonNil(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

// newID mints a random UUID v4 in canonical form.
func newID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
