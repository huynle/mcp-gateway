package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/store"
)

// Event types derived from the event's shape (the Event struct carries no
// type field by design): a tool call names a tool; a user event has a user
// but no tool (token created, connection revoked); a system event has
// neither (failed authentication, job runs).
const (
	EventTypeToolCall = "tool_call"
	EventTypeUser     = "user"
	EventTypeSystem   = "system"
)

// MaxErrorClassLen bounds ErrorClass as stored. Error classes are short
// labels (token_expired, vendor_rate_limited, timeout); anything longer is
// vendor text that has no place in the audit table.
const MaxErrorClassLen = 64

// Page sizes for ListForUser / AdminSearch.
const (
	DefaultPageSize = 50
	MaxPageSize     = 200
)

// Recorder appends audit events. Implementations never store arguments or
// content because Event cannot carry them.
type Recorder interface {
	Record(ctx context.Context, ev Event) error
}

// Reader pages audit events for the portal.
type Reader interface {
	// ListForUser returns the user's own events, newest first.
	ListForUser(ctx context.Context, userID string, f Filter, p Page) ([]Record, error)
	// AdminSearch returns every user's events (metadata only), newest first.
	AdminSearch(ctx context.Context, f Filter, p Page) ([]Record, error)
}

// Filter narrows a listing. Zero values mean "any". UserID applies to
// AdminSearch only; ListForUser always pins the caller's user.
type Filter struct {
	UserID   string
	Tool     string
	Decision string
	Outcome  string
	Since    time.Time
	Until    time.Time
}

// Page is offset pagination; Limit is clamped to [1, MaxPageSize] with
// DefaultPageSize for zero.
type Page struct {
	Limit  int
	Offset int
}

func (p Page) normalize() Page {
	if p.Limit <= 0 {
		p.Limit = DefaultPageSize
	}
	if p.Limit > MaxPageSize {
		p.Limit = MaxPageSize
	}
	if p.Offset < 0 {
		p.Offset = 0
	}
	return p
}

// Record is a stored event: the row ID and derived type plus the Event.
type Record struct {
	ID        string
	EventType string
	Event
}

// Scopes is the part of *store.Store the recorder uses.
type Scopes interface {
	WithUser(ctx context.Context, userID string, fn func(store.Tx) error) error
	WithJobs(ctx context.Context, fn func(store.Tx) error) error
}

// StoreRecorder writes to and reads from audit_events. Events with a
// UserID are inserted through WithUser so row-level security guarantees the
// row belongs to that user; system events (no user) go through WithJobs.
// ListForUser reads through WithUser; AdminSearch through WithJobs and the
// admin_audit_events metadata view (decision 9z5sdzsm).
type StoreRecorder struct {
	st Scopes
}

// NewStoreRecorder wraps st (normally *store.Store).
func NewStoreRecorder(st Scopes) *StoreRecorder {
	return &StoreRecorder{st: st}
}

// Record normalizes and inserts ev.
func (r *StoreRecorder) Record(ctx context.Context, ev Event) error {
	ev.Normalize()
	se := toStoreEvent(ev)
	insert := func(tx store.Tx) error { return tx.Audit().Create(ctx, se) }
	var err error
	if ev.UserID == "" {
		err = r.st.WithJobs(ctx, insert)
	} else {
		err = r.st.WithUser(ctx, ev.UserID, insert)
	}
	if err != nil {
		return fmt.Errorf("audit: record: %w", err)
	}
	return nil
}

// ListForUser implements Reader.
func (r *StoreRecorder) ListForUser(ctx context.Context, userID string, f Filter, p Page) ([]Record, error) {
	f.UserID = "" // the scope pins the user; never let a caller widen it
	var out []Record
	err := r.st.WithUser(ctx, userID, func(tx store.Tx) error {
		rows, err := store.ListAuditEvents(ctx, tx, false, toStoreFilter(f), store.AuditPage(p.normalize()))
		if err != nil {
			return err
		}
		out = fromStoreEvents(rows)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("audit: list for user: %w", err)
	}
	return out, nil
}

// AdminSearch implements Reader.
func (r *StoreRecorder) AdminSearch(ctx context.Context, f Filter, p Page) ([]Record, error) {
	var out []Record
	err := r.st.WithJobs(ctx, func(tx store.Tx) error {
		rows, err := store.ListAuditEvents(ctx, tx, true, toStoreFilter(f), store.AuditPage(p.normalize()))
		if err != nil {
			return err
		}
		out = fromStoreEvents(rows)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("audit: admin search: %w", err)
	}
	return out, nil
}

// NopRecorder discards events. For foundation-only mode (no database) and
// tests; it must never be used where the design requires an audit trail.
type NopRecorder struct{}

// Record implements Recorder.
func (NopRecorder) Record(context.Context, Event) error { return nil }

// details is the shape of the details jsonb column: the two Event fields
// without a dedicated column. Nothing else is ever written there.
type details struct {
	RequestID  string `json:"request_id,omitempty"`
	ErrorClass string `json:"error_class,omitempty"`
}

func toStoreEvent(ev Event) *store.AuditEvent {
	ev.Normalize()
	se := &store.AuditEvent{
		EventType:       eventType(ev),
		UserID:          optional(ev.UserID),
		TokenID:         optional(ev.TokenID),
		Tool:            optional(ev.Tool),
		ConnectionID:    optional(ev.AccountID),
		AccountLabel:    optional(ev.AccountLabel),
		Decision:        ev.Decision,
		PolicyVersionID: optional(ev.PolicyVersion),
		ApprovalID:      optional(ev.ApprovalID),
		OperationID:     optional(ev.OperationID),
		Outcome:         optional(ev.Outcome),
	}
	if ev.Latency > 0 {
		ms := int(ev.Latency / time.Millisecond)
		se.LatencyMS = &ms
	}
	res := ev.ResourceIdentity
	if res == nil {
		res = map[string]string{}
	}
	se.Resource, _ = json.Marshal(res)
	ec := observability.Redact(ev.ErrorClass)
	if len(ec) > MaxErrorClassLen {
		ec = ec[:MaxErrorClassLen]
	}
	se.Details, _ = json.Marshal(details{RequestID: ev.RequestID, ErrorClass: ec})
	return se
}

func eventType(ev Event) string {
	switch {
	case ev.Tool != "":
		return EventTypeToolCall
	case ev.UserID != "":
		return EventTypeUser
	default:
		return EventTypeSystem
	}
}

func fromStoreEvent(se *store.AuditEvent) Record {
	rec := Record{ID: se.ID, EventType: se.EventType}
	rec.Time = se.CreatedAt
	rec.UserID = deref(se.UserID)
	rec.TokenID = deref(se.TokenID)
	rec.Tool = deref(se.Tool)
	rec.AccountID = deref(se.ConnectionID)
	rec.AccountLabel = deref(se.AccountLabel)
	rec.Decision = se.Decision
	rec.PolicyVersion = deref(se.PolicyVersionID)
	rec.ApprovalID = deref(se.ApprovalID)
	rec.OperationID = deref(se.OperationID)
	rec.Outcome = deref(se.Outcome)
	if se.LatencyMS != nil {
		rec.Latency = time.Duration(*se.LatencyMS) * time.Millisecond
	}
	if len(se.Resource) > 0 {
		_ = json.Unmarshal(se.Resource, &rec.ResourceIdentity)
	}
	if len(se.Details) > 0 {
		var d details
		_ = json.Unmarshal(se.Details, &d)
		rec.RequestID, rec.ErrorClass = d.RequestID, d.ErrorClass
	}
	rec.Normalize()
	return rec
}

func fromStoreEvents(rows []store.AuditEvent) []Record {
	out := make([]Record, 0, len(rows))
	for i := range rows {
		out = append(out, fromStoreEvent(&rows[i]))
	}
	return out
}

func toStoreFilter(f Filter) store.AuditFilter {
	return store.AuditFilter{UserID: f.UserID, Tool: f.Tool, Decision: f.Decision, Outcome: f.Outcome, Since: f.Since, Until: f.Until}
}

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
