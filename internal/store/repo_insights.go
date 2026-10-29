package store

import (
	"context"
	"fmt"
	"time"
)

// The insights aggregates (decision 3yq9s5ev) feed the charts on
// /activity, /operations and /admin/insights. They are package-level
// functions over the Querier of a WithUser or WithJobs transaction, like
// ListAuditEvents: under WithUser row-level security pins the rows to the
// scoped user and admin=false reads the base tables; under WithJobs
// admin=true reads the metadata-only admin_* views (decision 9z5sdzsm).
// Every query is bounded by an InsightsWindow on created_at, which the
// (user_id, created_at) and created_at indexes serve.

// InsightsWindow is the half-open range [Since, Until) an aggregate covers
// and the width of its time buckets. Buckets are aligned to
// insightsOrigin (UTC midnight), so hour, six-hour and day buckets start
// on UTC boundaries.
type InsightsWindow struct {
	Since  time.Time
	Until  time.Time
	Bucket time.Duration
}

func (w InsightsWindow) validate() error {
	if w.Since.IsZero() || w.Until.IsZero() || !w.Until.After(w.Since) {
		return fmt.Errorf("store: insights: window must have since < until")
	}
	if w.Bucket <= 0 {
		return fmt.Errorf("store: insights: bucket must be positive")
	}
	return nil
}

// insightsBin is the bucket expression; $1 is the bucket width in seconds.
const insightsBin = `date_bin(make_interval(secs => $1), created_at, timestamptz '2001-01-01 00:00:00+00')`

// InsightsCount is one category and its row count.
type InsightsCount struct {
	Key   string
	Count int64
}

// InsightsBucketCount is a row count for one category in one time bucket.
// Key is empty for single-series counts.
type InsightsBucketCount struct {
	Bucket time.Time
	Key    string
	Count  int64
}

// InsightsPercentiles are latency or duration percentiles (milliseconds)
// over the N rows of one time bucket that carry a value.
type InsightsPercentiles struct {
	Bucket        time.Time
	N             int64
	P50, P95, P99 float64
}

// InsightsCallSummary summarises the tool calls of a window.
type InsightsCallSummary struct {
	Calls, Succeeded, Failed, Denied int64
	Tools, Users                     int64
	P50, P95                         float64
}

// InsightsToolStats are one tool's calls in a window.
type InsightsToolStats struct {
	Tool                  string
	Calls, Failed, Denied int64
	P95                   float64
}

// InsightsUserStats are one user's calls in a window (admin only).
type InsightsUserStats struct {
	UserID, DisplayName          string
	Calls, Failed, Denied, Tools int64
	LastSeen                     time.Time
}

// InsightsUserToolCount is the number of calls one user made to one tool.
type InsightsUserToolCount struct {
	UserID, DisplayName, Tool string
	Count                     int64
}

// InsightsWriteSummary summarises the ledger operations of a window.
// P50 and P95 are the duration (finished_at - created_at) of finished
// writes in milliseconds.
type InsightsWriteSummary struct {
	Writes, Succeeded, Failed, Unknown, Unresolved, InProgress int64
	P50, P95                                                   float64
}

// InsightsWriteToolStats are one tool's writes in a window.
type InsightsWriteToolStats struct {
	Tool                       string
	Writes, Failed, Unresolved int64
	P95                        float64
}

// InsightsApprovalSummary summarises the approvals of a window (admin
// only). P50 and P95 are the time to a decision (decided_at - created_at)
// in seconds.
type InsightsApprovalSummary struct {
	Total, Pending, Approved, Denied, Consumed, Expired int64
	P50, P95                                            float64
}

func auditTable(admin bool) string {
	if admin {
		return "admin_audit_events"
	}
	return "audit_events"
}

func ledgerTable(admin bool) string {
	if admin {
		return "admin_ledger_operations"
	}
	return "ledger_operations"
}

const toolCall = `event_type = 'tool_call'`

// InsightsCalls returns the window's tool-call totals.
func InsightsCalls(ctx context.Context, q Querier, admin bool, w InsightsWindow) (InsightsCallSummary, error) {
	var s InsightsCallSummary
	if err := w.validate(); err != nil {
		return s, err
	}
	err := q.QueryRow(ctx, `SELECT count(*),
			count(*) FILTER (WHERE outcome = 'succeeded'),
			count(*) FILTER (WHERE outcome = 'failed'),
			count(*) FILTER (WHERE outcome = 'denied' OR decision = 'deny'),
			count(DISTINCT tool), count(DISTINCT user_id),
			coalesce(percentile_cont(0.5) WITHIN GROUP (ORDER BY latency_ms), 0),
			coalesce(percentile_cont(0.95) WITHIN GROUP (ORDER BY latency_ms), 0)
		FROM `+auditTable(admin)+` WHERE `+toolCall+` AND created_at >= $1 AND created_at < $2`,
		w.Since, w.Until).Scan(&s.Calls, &s.Succeeded, &s.Failed, &s.Denied, &s.Tools, &s.Users, &s.P50, &s.P95)
	if err != nil {
		return s, fmt.Errorf("store: insights calls: %w", err)
	}
	return s, nil
}

// InsightsCallsByOutcome counts tool calls per bucket and outcome
// (succeeded, failed, denied; "none" when the row has no outcome).
func InsightsCallsByOutcome(ctx context.Context, q Querier, admin bool, w InsightsWindow) ([]InsightsBucketCount, error) {
	return bucketCounts(ctx, q, w, "calls by outcome", `SELECT `+insightsBin+`, coalesce(outcome, 'none'), count(*)
		FROM `+auditTable(admin)+` WHERE `+toolCall+` AND created_at >= $2 AND created_at < $3
		GROUP BY 1, 2 ORDER BY 1, 2`)
}

// InsightsCallsPerBucket counts tool calls per bucket (Key empty).
func InsightsCallsPerBucket(ctx context.Context, q Querier, admin bool, w InsightsWindow) ([]InsightsBucketCount, error) {
	return bucketCounts(ctx, q, w, "calls per bucket", `SELECT `+insightsBin+`, '', count(*)
		FROM `+auditTable(admin)+` WHERE `+toolCall+` AND created_at >= $2 AND created_at < $3
		GROUP BY 1 ORDER BY 1`)
}

// InsightsActiveUsers counts distinct calling users per bucket (admin
// only; Key empty).
func InsightsActiveUsers(ctx context.Context, q Querier, w InsightsWindow) ([]InsightsBucketCount, error) {
	return bucketCounts(ctx, q, w, "active users", `SELECT `+insightsBin+`, '', count(DISTINCT user_id)
		FROM admin_audit_events WHERE `+toolCall+` AND user_id IS NOT NULL AND created_at >= $2 AND created_at < $3
		GROUP BY 1 ORDER BY 1`)
}

// InsightsLatency returns tool-call latency percentiles per bucket.
func InsightsLatency(ctx context.Context, q Querier, admin bool, w InsightsWindow) ([]InsightsPercentiles, error) {
	return bucketPercentiles(ctx, q, w, "latency", `SELECT `+insightsBin+`, count(latency_ms),
			percentile_cont(0.5) WITHIN GROUP (ORDER BY latency_ms),
			percentile_cont(0.95) WITHIN GROUP (ORDER BY latency_ms),
			percentile_cont(0.99) WITHIN GROUP (ORDER BY latency_ms)
		FROM `+auditTable(admin)+` WHERE `+toolCall+` AND latency_ms IS NOT NULL AND created_at >= $2 AND created_at < $3
		GROUP BY 1 ORDER BY 1`)
}

// InsightsLatencyHistogram counts tool calls by latency against the
// ascending millisecond bounds: element 0 is below bounds[0], element i
// is in [bounds[i-1], bounds[i]), the last is at or above the last bound.
func InsightsLatencyHistogram(ctx context.Context, q Querier, admin bool, w InsightsWindow, bounds []int32) ([]int64, error) {
	if err := w.validate(); err != nil {
		return nil, err
	}
	if len(bounds) == 0 {
		return nil, fmt.Errorf("store: insights latency histogram: no bounds")
	}
	rows, err := q.Query(ctx, `SELECT width_bucket(latency_ms, $3::int[]), count(*)
		FROM `+auditTable(admin)+` WHERE `+toolCall+` AND latency_ms IS NOT NULL AND created_at >= $1 AND created_at < $2
		GROUP BY 1`, w.Since, w.Until, bounds)
	if err != nil {
		return nil, fmt.Errorf("store: insights latency histogram: %w", err)
	}
	defer rows.Close()
	out := make([]int64, len(bounds)+1)
	for rows.Next() {
		var (
			i int
			n int64
		)
		if err := rows.Scan(&i, &n); err != nil {
			return nil, fmt.Errorf("store: insights latency histogram: %w", err)
		}
		if i >= 0 && i < len(out) {
			out[i] += n
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: insights latency histogram: %w", err)
	}
	return out, nil
}

// Dimensions InsightsCallsBy can group by.
const (
	InsightsByDecision     = "decision"
	InsightsByAccountLabel = "account_label"
	InsightsByErrorClass   = "error_class"
	InsightsByEventType    = "event_type"
)

// insightsDims maps a dimension to its column expression and the extra
// condition rows must meet. Only these are ever interpolated into SQL.
var insightsDims = map[string]struct{ expr, cond string }{
	InsightsByDecision:     {"decision", toolCall},
	InsightsByAccountLabel: {"coalesce(account_label::text, 'none')", toolCall},
	InsightsByErrorClass:   {"details->>'error_class'", toolCall + ` AND coalesce(details->>'error_class', '') <> ''`},
	InsightsByEventType:    {"event_type", "true"},
}

// InsightsCallsBy counts the window's events by dim (one of the
// InsightsBy* constants), largest first, at most limit categories. Every
// dimension but InsightsByEventType counts tool calls only.
func InsightsCallsBy(ctx context.Context, q Querier, admin bool, w InsightsWindow, dim string, limit int) ([]InsightsCount, error) {
	d, ok := insightsDims[dim]
	if !ok {
		return nil, fmt.Errorf("store: insights: unknown dimension %q", dim)
	}
	if err := w.validate(); err != nil {
		return nil, err
	}
	rows, err := q.Query(ctx, `SELECT `+d.expr+`, count(*)
		FROM `+auditTable(admin)+` WHERE `+d.cond+` AND created_at >= $1 AND created_at < $2
		GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT $3`, w.Since, w.Until, limit)
	if err != nil {
		return nil, fmt.Errorf("store: insights by %s: %w", dim, err)
	}
	defer rows.Close()
	out := []InsightsCount{}
	for rows.Next() {
		var c InsightsCount
		if err := rows.Scan(&c.Key, &c.Count); err != nil {
			return nil, fmt.Errorf("store: insights by %s: %w", dim, err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: insights by %s: %w", dim, err)
	}
	return out, nil
}

// InsightsTopTools returns the most-called tools of the window.
func InsightsTopTools(ctx context.Context, q Querier, admin bool, w InsightsWindow, limit int) ([]InsightsToolStats, error) {
	if err := w.validate(); err != nil {
		return nil, err
	}
	rows, err := q.Query(ctx, `SELECT tool, count(*),
			count(*) FILTER (WHERE outcome = 'failed'),
			count(*) FILTER (WHERE outcome = 'denied' OR decision = 'deny'),
			coalesce(percentile_cont(0.95) WITHIN GROUP (ORDER BY latency_ms), 0)
		FROM `+auditTable(admin)+` WHERE `+toolCall+` AND tool IS NOT NULL AND created_at >= $1 AND created_at < $2
		GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT $3`, w.Since, w.Until, limit)
	if err != nil {
		return nil, fmt.Errorf("store: insights top tools: %w", err)
	}
	defer rows.Close()
	out := []InsightsToolStats{}
	for rows.Next() {
		var s InsightsToolStats
		if err := rows.Scan(&s.Tool, &s.Calls, &s.Failed, &s.Denied, &s.P95); err != nil {
			return nil, fmt.Errorf("store: insights top tools: %w", err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: insights top tools: %w", err)
	}
	return out, nil
}

// InsightsTopUsers returns the users with the most tool calls in the
// window, with their display names (admin only: reads the admin views).
func InsightsTopUsers(ctx context.Context, q Querier, w InsightsWindow, limit int) ([]InsightsUserStats, error) {
	if err := w.validate(); err != nil {
		return nil, err
	}
	rows, err := q.Query(ctx, `SELECT a.user_id::text, coalesce(u.display_name, ''), count(*),
			count(*) FILTER (WHERE a.outcome = 'failed'),
			count(*) FILTER (WHERE a.outcome = 'denied' OR a.decision = 'deny'),
			count(DISTINCT a.tool), max(a.created_at)
		FROM admin_audit_events a LEFT JOIN admin_users u ON u.id = a.user_id
		WHERE a.event_type = 'tool_call' AND a.user_id IS NOT NULL AND a.created_at >= $1 AND a.created_at < $2
		GROUP BY 1, 2 ORDER BY 3 DESC, 1 LIMIT $3`, w.Since, w.Until, limit)
	if err != nil {
		return nil, fmt.Errorf("store: insights top users: %w", err)
	}
	defer rows.Close()
	out := []InsightsUserStats{}
	for rows.Next() {
		var s InsightsUserStats
		if err := rows.Scan(&s.UserID, &s.DisplayName, &s.Calls, &s.Failed, &s.Denied, &s.Tools, &s.LastSeen); err != nil {
			return nil, fmt.Errorf("store: insights top users: %w", err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: insights top users: %w", err)
	}
	return out, nil
}

// InsightsUserTools returns the call counts of the window's top users
// (at most users) on its top tools (at most tools), for the user × tool
// matrix (admin only).
func InsightsUserTools(ctx context.Context, q Querier, w InsightsWindow, users, tools int) ([]InsightsUserToolCount, error) {
	if err := w.validate(); err != nil {
		return nil, err
	}
	rows, err := q.Query(ctx, `WITH base AS (
			SELECT user_id, tool FROM admin_audit_events
			WHERE event_type = 'tool_call' AND user_id IS NOT NULL AND tool IS NOT NULL AND created_at >= $1 AND created_at < $2
		), tu AS (
			SELECT user_id FROM base GROUP BY 1 ORDER BY count(*) DESC, 1 LIMIT $3
		), tt AS (
			SELECT tool FROM base GROUP BY 1 ORDER BY count(*) DESC, 1 LIMIT $4
		)
		SELECT b.user_id::text, coalesce(u.display_name, ''), b.tool, count(*)
		FROM base b JOIN tu USING (user_id) JOIN tt USING (tool) LEFT JOIN admin_users u ON u.id = b.user_id
		GROUP BY 1, 2, 3 ORDER BY 4 DESC, 1, 3`, w.Since, w.Until, users, tools)
	if err != nil {
		return nil, fmt.Errorf("store: insights user tools: %w", err)
	}
	defer rows.Close()
	out := []InsightsUserToolCount{}
	for rows.Next() {
		var c InsightsUserToolCount
		if err := rows.Scan(&c.UserID, &c.DisplayName, &c.Tool, &c.Count); err != nil {
			return nil, fmt.Errorf("store: insights user tools: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: insights user tools: %w", err)
	}
	return out, nil
}

// insightsDuration is a finished write's duration in milliseconds.
const insightsDuration = `extract(epoch FROM finished_at - created_at) * 1000`

// InsightsWrites returns the window's ledger totals.
func InsightsWrites(ctx context.Context, q Querier, admin bool, w InsightsWindow) (InsightsWriteSummary, error) {
	var s InsightsWriteSummary
	if err := w.validate(); err != nil {
		return s, err
	}
	err := q.QueryRow(ctx, `SELECT count(*),
			count(*) FILTER (WHERE state = 'succeeded'),
			count(*) FILTER (WHERE state = 'failed'),
			count(*) FILTER (WHERE state = 'unknown'),
			count(*) FILTER (WHERE state = 'unresolved'),
			count(*) FILTER (WHERE state = 'in_progress'),
			coalesce(percentile_cont(0.5) WITHIN GROUP (ORDER BY `+insightsDuration+`), 0),
			coalesce(percentile_cont(0.95) WITHIN GROUP (ORDER BY `+insightsDuration+`), 0)
		FROM `+ledgerTable(admin)+` WHERE created_at >= $1 AND created_at < $2`,
		w.Since, w.Until).Scan(&s.Writes, &s.Succeeded, &s.Failed, &s.Unknown, &s.Unresolved, &s.InProgress, &s.P50, &s.P95)
	if err != nil {
		return s, fmt.Errorf("store: insights writes: %w", err)
	}
	return s, nil
}

// InsightsWritesByState counts ledger operations per bucket and state.
func InsightsWritesByState(ctx context.Context, q Querier, admin bool, w InsightsWindow) ([]InsightsBucketCount, error) {
	return bucketCounts(ctx, q, w, "writes by state", `SELECT `+insightsBin+`, state::text, count(*)
		FROM `+ledgerTable(admin)+` WHERE created_at >= $2 AND created_at < $3
		GROUP BY 1, 2 ORDER BY 1, 2`)
}

// InsightsWriteDuration returns finished-write duration percentiles per
// bucket.
func InsightsWriteDuration(ctx context.Context, q Querier, admin bool, w InsightsWindow) ([]InsightsPercentiles, error) {
	return bucketPercentiles(ctx, q, w, "write duration", `SELECT `+insightsBin+`, count(*),
			percentile_cont(0.5) WITHIN GROUP (ORDER BY `+insightsDuration+`),
			percentile_cont(0.95) WITHIN GROUP (ORDER BY `+insightsDuration+`),
			percentile_cont(0.99) WITHIN GROUP (ORDER BY `+insightsDuration+`)
		FROM `+ledgerTable(admin)+` WHERE finished_at IS NOT NULL AND created_at >= $2 AND created_at < $3
		GROUP BY 1 ORDER BY 1`)
}

// InsightsWriteTools returns the tools with the most writes in the window.
func InsightsWriteTools(ctx context.Context, q Querier, admin bool, w InsightsWindow, limit int) ([]InsightsWriteToolStats, error) {
	if err := w.validate(); err != nil {
		return nil, err
	}
	rows, err := q.Query(ctx, `SELECT tool, count(*),
			count(*) FILTER (WHERE state = 'failed'),
			count(*) FILTER (WHERE state IN ('unknown', 'unresolved')),
			coalesce(percentile_cont(0.95) WITHIN GROUP (ORDER BY `+insightsDuration+`), 0)
		FROM `+ledgerTable(admin)+` WHERE created_at >= $1 AND created_at < $2
		GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT $3`, w.Since, w.Until, limit)
	if err != nil {
		return nil, fmt.Errorf("store: insights write tools: %w", err)
	}
	defer rows.Close()
	out := []InsightsWriteToolStats{}
	for rows.Next() {
		var s InsightsWriteToolStats
		if err := rows.Scan(&s.Tool, &s.Writes, &s.Failed, &s.Unresolved, &s.P95); err != nil {
			return nil, fmt.Errorf("store: insights write tools: %w", err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: insights write tools: %w", err)
	}
	return out, nil
}

// InsightsWriteErrors counts failed and unresolved writes by error code,
// largest first.
func InsightsWriteErrors(ctx context.Context, q Querier, admin bool, w InsightsWindow, limit int) ([]InsightsCount, error) {
	if err := w.validate(); err != nil {
		return nil, err
	}
	rows, err := q.Query(ctx, `SELECT error_code, count(*)
		FROM `+ledgerTable(admin)+` WHERE coalesce(error_code, '') <> '' AND created_at >= $1 AND created_at < $2
		GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT $3`, w.Since, w.Until, limit)
	if err != nil {
		return nil, fmt.Errorf("store: insights write errors: %w", err)
	}
	defer rows.Close()
	out := []InsightsCount{}
	for rows.Next() {
		var c InsightsCount
		if err := rows.Scan(&c.Key, &c.Count); err != nil {
			return nil, fmt.Errorf("store: insights write errors: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: insights write errors: %w", err)
	}
	return out, nil
}

// InsightsApprovals returns the window's approval totals (admin only).
func InsightsApprovals(ctx context.Context, q Querier, w InsightsWindow) (InsightsApprovalSummary, error) {
	var s InsightsApprovalSummary
	if err := w.validate(); err != nil {
		return s, err
	}
	const decide = `extract(epoch FROM decided_at - created_at)`
	err := q.QueryRow(ctx, `SELECT count(*),
			count(*) FILTER (WHERE status = 'pending'),
			count(*) FILTER (WHERE status = 'approved'),
			count(*) FILTER (WHERE status = 'denied'),
			count(*) FILTER (WHERE status = 'consumed'),
			count(*) FILTER (WHERE status = 'expired'),
			coalesce(percentile_cont(0.5) WITHIN GROUP (ORDER BY `+decide+`), 0),
			coalesce(percentile_cont(0.95) WITHIN GROUP (ORDER BY `+decide+`), 0)
		FROM admin_approvals WHERE created_at >= $1 AND created_at < $2`,
		w.Since, w.Until).Scan(&s.Total, &s.Pending, &s.Approved, &s.Denied, &s.Consumed, &s.Expired, &s.P50, &s.P95)
	if err != nil {
		return s, fmt.Errorf("store: insights approvals: %w", err)
	}
	return s, nil
}

// InsightsApprovalsByStatus counts approvals per bucket and status (admin
// only).
func InsightsApprovalsByStatus(ctx context.Context, q Querier, w InsightsWindow) ([]InsightsBucketCount, error) {
	return bucketCounts(ctx, q, w, "approvals by status", `SELECT `+insightsBin+`, status::text, count(*)
		FROM admin_approvals WHERE created_at >= $2 AND created_at < $3
		GROUP BY 1, 2 ORDER BY 1, 2`)
}

// bucketCounts runs sql with $1 = bucket seconds, $2 = since, $3 = until;
// it selects (bucket, key, count).
func bucketCounts(ctx context.Context, q Querier, w InsightsWindow, what, sql string) ([]InsightsBucketCount, error) {
	if err := w.validate(); err != nil {
		return nil, err
	}
	rows, err := q.Query(ctx, sql, w.Bucket.Seconds(), w.Since, w.Until)
	if err != nil {
		return nil, fmt.Errorf("store: insights %s: %w", what, err)
	}
	defer rows.Close()
	out := []InsightsBucketCount{}
	for rows.Next() {
		var c InsightsBucketCount
		if err := rows.Scan(&c.Bucket, &c.Key, &c.Count); err != nil {
			return nil, fmt.Errorf("store: insights %s: %w", what, err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: insights %s: %w", what, err)
	}
	return out, nil
}

// bucketPercentiles runs sql with the bucketCounts parameters; it selects
// (bucket, n, p50, p95, p99).
func bucketPercentiles(ctx context.Context, q Querier, w InsightsWindow, what, sql string) ([]InsightsPercentiles, error) {
	if err := w.validate(); err != nil {
		return nil, err
	}
	rows, err := q.Query(ctx, sql, w.Bucket.Seconds(), w.Since, w.Until)
	if err != nil {
		return nil, fmt.Errorf("store: insights %s: %w", what, err)
	}
	defer rows.Close()
	out := []InsightsPercentiles{}
	for rows.Next() {
		var p InsightsPercentiles
		if err := rows.Scan(&p.Bucket, &p.N, &p.P50, &p.P95, &p.P99); err != nil {
			return nil, fmt.Errorf("store: insights %s: %w", what, err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: insights %s: %w", what, err)
	}
	return out, nil
}
