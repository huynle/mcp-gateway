package store

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// AuditFilter narrows ListAuditEvents. Zero values mean "any". UserID is
// honoured only through the bypass scope: under WithUser row-level
// security already pins the user and the filter is redundant.
type AuditFilter struct {
	UserID    string
	EventType string
	Tool      string
	Decision  string
	Outcome   string
	Since     time.Time
	Until     time.Time
}

// AuditPage is offset pagination for ListAuditEvents. Callers clamp Limit;
// the query refuses a non-positive one.
type AuditPage struct {
	Limit  int
	Offset int
}

// ListAuditEvents returns audit events newest first. It is a package-level
// function over the Querier of a WithUser or WithJobs transaction so the
// audit module can page without widening the AuditRepository interface:
// under WithUser the policy restricts rows to the scoped user; under
// WithJobs the admin_audit_events view (metadata projection) is read.
//
// Query via the view is chosen when the transaction bypasses RLS, which the
// function cannot detect; callers pass admin=true from WithJobs.
func ListAuditEvents(ctx context.Context, q Querier, admin bool, f AuditFilter, p AuditPage) ([]AuditEvent, error) {
	if p.Limit <= 0 {
		return nil, fmt.Errorf("store: list audit events: limit must be positive")
	}
	if p.Offset < 0 {
		p.Offset = 0
	}
	table := "audit_events"
	if admin {
		table = "admin_audit_events"
	}
	var (
		where []string
		args  []any
	)
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, fmt.Sprintf(cond, len(args)))
	}
	if f.UserID != "" {
		add("user_id = $%d", f.UserID)
	}
	if f.EventType != "" {
		add("event_type = $%d", f.EventType)
	}
	if f.Tool != "" {
		add("tool = $%d", f.Tool)
	}
	if f.Decision != "" {
		add("decision = $%d", f.Decision)
	}
	if f.Outcome != "" {
		add("outcome = $%d", f.Outcome)
	}
	if !f.Since.IsZero() {
		add("created_at >= $%d", f.Since)
	}
	if !f.Until.IsZero() {
		add("created_at < $%d", f.Until)
	}
	sql := `SELECT id, event_type, user_id, actor_user_id, token_id, tool, connection_id, account_label,
			resource, decision, policy_version_id, approval_id, operation_id, outcome, latency_ms, details, created_at
		FROM ` + table
	if len(where) > 0 {
		sql += " WHERE " + strings.Join(where, " AND ")
	}
	args = append(args, p.Limit, p.Offset)
	sql += fmt.Sprintf(" ORDER BY created_at DESC, id DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args))

	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list audit events: %w", err)
	}
	defer rows.Close()
	out := []AuditEvent{}
	for rows.Next() {
		var e AuditEvent
		if err := rows.Scan(&e.ID, &e.EventType, &e.UserID, &e.ActorUserID, &e.TokenID, &e.Tool, &e.ConnectionID, &e.AccountLabel,
			&e.Resource, &e.Decision, &e.PolicyVersionID, &e.ApprovalID, &e.OperationID, &e.Outcome, &e.LatencyMS, &e.Details, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("store: list audit events: %w", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list audit events: %w", err)
	}
	return out, nil
}
