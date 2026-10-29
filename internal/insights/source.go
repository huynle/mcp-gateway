package insights

import (
	"context"
	"fmt"
	"math"
	"net/url"
	"strings"
	"time"

	"github.com/huynle/mcp-gateway/internal/store"
)

// Scopes is the part of *store.Store the source uses.
type Scopes interface {
	WithUser(ctx context.Context, userID string, fn func(store.Tx) error) error
	WithJobs(ctx context.Context, fn func(store.Tx) error) error
}

// Source builds dashboards from the store.
type Source struct {
	st  Scopes
	now func() time.Time
}

// NewSource wraps st (normally *store.Store).
func NewSource(st Scopes) *Source {
	return &Source{st: st, now: time.Now}
}

// Limits on the categories a chart shows.
const (
	topTools    = 10
	topUsers    = 10
	matrixUsers = 8
	matrixTools = 8
	topClasses  = 8
)

// latencyBounds are the latency histogram's bucket edges in milliseconds.
var latencyBounds = []int32{50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000}

// window is the range ending now: its start is aligned to the bucket so
// the buckets line up with the database's (UTC boundaries).
func (s *Source) window(r Range) store.InsightsWindow {
	now := s.now().UTC()
	return store.InsightsWindow{Since: now.Add(-r.Span).Truncate(r.Bucket), Until: now, Bucket: r.Bucket}
}

// hourly is w re-bucketed by the hour, for the weekday × hour punch card.
func hourly(w store.InsightsWindow) store.InsightsWindow {
	return store.InsightsWindow{Since: w.Since.Truncate(time.Hour), Until: w.Until, Bucket: time.Hour}
}

// Activity is the signed-in user's own tool calls (WithUser, RLS).
// u is the page URL: drill links keep its range.
func (s *Source) Activity(ctx context.Context, userID string, r Range, u *url.URL) (*Dashboard, error) {
	w := s.window(r)
	var c calls
	err := s.st.WithUser(ctx, userID, func(tx store.Tx) error { return c.load(ctx, tx, false, w) })
	if err != nil {
		return nil, fmt.Errorf("insights: activity: %w", err)
	}
	d := &Dashboard{Title: "Insights", Range: r, RangeLinks: RangeLinksFor(u, r), Empty: c.sum.Calls == 0}
	drill := DrillHref("/activity", u, RangeParam)
	d.Stats = c.stats(false)
	d.Groups = c.groups(w, drill)
	return d, nil
}

// Operations is the signed-in user's own writes (WithUser, RLS).
func (s *Source) Operations(ctx context.Context, userID string, r Range, u *url.URL) (*Dashboard, error) {
	w := s.window(r)
	var o writes
	err := s.st.WithUser(ctx, userID, func(tx store.Tx) error { return o.load(ctx, tx, false, w) })
	if err != nil {
		return nil, fmt.Errorf("insights: operations: %w", err)
	}
	d := &Dashboard{Title: "Insights", Range: r, RangeLinks: RangeLinksFor(u, r), Empty: o.sum.Writes == 0}
	d.Stats = o.stats()
	d.Groups = []Group{{Title: "Writes", Charts: o.charts(w, DrillHref("/activity", u, RangeParam))}}
	return d, nil
}

// Admin is every user's activity (WithJobs, admin views). Callers must
// have checked that the caller is an admin.
func (s *Source) Admin(ctx context.Context, r Range, u *url.URL) (*Dashboard, error) {
	w := s.window(r)
	var (
		c      calls
		o      writes
		users  []store.InsightsUserStats
		matrix []store.InsightsUserToolCount
		active []store.InsightsBucketCount
		types  []store.InsightsCount
		appr   store.InsightsApprovalSummary
		apprBy []store.InsightsBucketCount
	)
	err := s.st.WithJobs(ctx, func(tx store.Tx) error {
		if err := c.load(ctx, tx, true, w); err != nil {
			return err
		}
		if err := o.load(ctx, tx, true, w); err != nil {
			return err
		}
		var err error
		if users, err = store.InsightsTopUsers(ctx, tx, w, topUsers); err != nil {
			return err
		}
		if matrix, err = store.InsightsUserTools(ctx, tx, w, matrixUsers, matrixTools); err != nil {
			return err
		}
		if active, err = store.InsightsActiveUsers(ctx, tx, w); err != nil {
			return err
		}
		if types, err = store.InsightsCallsBy(ctx, tx, true, w, store.InsightsByEventType, 10); err != nil {
			return err
		}
		if appr, err = store.InsightsApprovals(ctx, tx, w); err != nil {
			return err
		}
		apprBy, err = store.InsightsApprovalsByStatus(ctx, tx, w)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("insights: admin: %w", err)
	}
	audit := DrillHref("/admin/audit", u)
	d := &Dashboard{Title: "Overview", Range: r, RangeLinks: RangeLinksFor(u, r),
		Empty: c.sum.Calls == 0 && o.sum.Writes == 0 && appr.Total == 0}

	d.Stats = append(c.stats(true),
		Stat{Label: "Writes", Value: fmtCount(o.sum.Writes)},
		Stat{Label: "Unresolved writes", Value: fmtCount(o.sum.Unresolved + o.sum.Unknown), Tone: toneIf(o.sum.Unresolved+o.sum.Unknown > 0, "danger")},
		Stat{Label: "Approvals", Value: fmtCount(appr.Total), Hint: "median decision " + fmtSeconds(appr.P50)},
		Stat{Label: "Pending approvals", Value: fmtCount(appr.Pending), Tone: toneIf(appr.Pending > 0, "warn")},
	)

	times := timeline(w)
	people := Group{Title: "Users"}
	people.Charts = append(people.Charts,
		Chart{ID: "active-users", Title: "Active users", Desc: "Distinct users calling tools per bucket", Kind: KindLine, Unit: "users",
			Times: millis(times), Bucket: w.Bucket.Milliseconds(),
			Series: []Series{{Key: "users", Name: "active users", Tone: "accent", Data: single(active, times)}}},
		topUsersChart(users, audit),
	)
	if m := matrixChart(matrix, audit); m != nil {
		people.Charts = append(people.Charts, *m)
	}
	for _, us := range users {
		d.Users = append(d.Users, UserRow{UserID: us.UserID, Name: userName(us.UserID, us.DisplayName), Calls: us.Calls,
			Failed: us.Failed, Denied: us.Denied, Tools: us.Tools, LastSeen: us.LastSeen,
			Href: "/admin/audit?" + url.Values{"user_id": {us.UserID}}.Encode()})
	}

	groups := c.groups(w, audit)
	groups[0].Charts = append(groups[0].Charts, doughnut("event-types", "Event types", "Tool calls, user actions and system events", types, map[string]string{
		"tool_call": "accent", "user": "c2", "system": "muted"}, nil))
	d.Groups = append([]Group{groups[0], people}, groups[1:]...)
	d.Groups = append(d.Groups, Group{Title: "Writes and approvals", Charts: append(o.charts(w, audit),
		Chart{ID: "approvals", Title: "Approvals by status", Desc: "Confirmed calls waiting for, or given, a decision", Kind: KindStacked, Unit: "approvals",
			Times: millis(times), Bucket: w.Bucket.Milliseconds(),
			Series: stacked(apprBy, times, []tone{{"consumed", "consumed", "ok"}, {"approved", "approved", "c2"}, {"pending", "pending", "accent"}, {"denied", "denied", "danger"}, {"expired", "expired", "warn"}})},
	)})
	return d, nil
}

// --- tool calls -------------------------------------------------------------------

// calls are the tool-call aggregates shared by /activity and the admin page.
type calls struct {
	sum       store.InsightsCallSummary
	byOutcome []store.InsightsBucketCount
	latency   []store.InsightsPercentiles
	hist      []int64
	tools     []store.InsightsToolStats
	decisions []store.InsightsCount
	classes   []store.InsightsCount
	accounts  []store.InsightsCount
	hourly    []store.InsightsBucketCount
	hourlyW   store.InsightsWindow
}

func (c *calls) load(ctx context.Context, tx store.Tx, admin bool, w store.InsightsWindow) error {
	var err error
	if c.sum, err = store.InsightsCalls(ctx, tx, admin, w); err != nil {
		return err
	}
	if c.byOutcome, err = store.InsightsCallsByOutcome(ctx, tx, admin, w); err != nil {
		return err
	}
	if c.latency, err = store.InsightsLatency(ctx, tx, admin, w); err != nil {
		return err
	}
	if c.hist, err = store.InsightsLatencyHistogram(ctx, tx, admin, w, latencyBounds); err != nil {
		return err
	}
	if c.tools, err = store.InsightsTopTools(ctx, tx, admin, w, topTools); err != nil {
		return err
	}
	if c.decisions, err = store.InsightsCallsBy(ctx, tx, admin, w, store.InsightsByDecision, 5); err != nil {
		return err
	}
	if c.classes, err = store.InsightsCallsBy(ctx, tx, admin, w, store.InsightsByErrorClass, topClasses); err != nil {
		return err
	}
	if c.accounts, err = store.InsightsCallsBy(ctx, tx, admin, w, store.InsightsByAccountLabel, 5); err != nil {
		return err
	}
	c.hourlyW = hourly(w)
	c.hourly, err = store.InsightsCallsPerBucket(ctx, tx, admin, c.hourlyW)
	return err
}

func (c *calls) stats(admin bool) []Stat {
	s := c.sum
	out := []Stat{{Label: "Tool calls", Value: fmtCount(s.Calls)}}
	if admin {
		out = append(out, Stat{Label: "Active users", Value: fmtCount(s.Users)})
	}
	return append(out,
		Stat{Label: "Success rate", Value: fmtPct(s.Succeeded, s.Calls), Tone: toneIf(s.Calls > 0 && s.Succeeded == s.Calls, "ok")},
		Stat{Label: "Failed", Value: fmtCount(s.Failed), Tone: toneIf(s.Failed > 0, "danger")},
		Stat{Label: "Denied", Value: fmtCount(s.Denied), Tone: toneIf(s.Denied > 0, "warn")},
		Stat{Label: "Latency p50", Value: fmtMS(s.P50)},
		Stat{Label: "Latency p95", Value: fmtMS(s.P95)},
		Stat{Label: "Tools used", Value: fmtCount(s.Tools)},
	)
}

// outcomeTones orders and colours the outcome series; "" is a call with
// no outcome (not a filterable value, so it has no drill key).
var outcomeTones = []tone{{"succeeded", "succeeded", "ok"}, {"failed", "failed", "danger"}, {"denied", "denied", "warn"},
	{"unresolved", "unresolved", "c3"}, {"unknown", "unknown", "c4"}, {"none", "no outcome", "muted"}}

// groups are the tool-call charts: volume and occurrence, tools and
// errors, latency. drill is the filtered table the clicks open.
func (c *calls) groups(w store.InsightsWindow, drill string) []Group {
	times := timeline(w)
	volume := Group{Title: "Calls", Charts: []Chart{
		{ID: "calls", Title: "Calls over time", Desc: "By outcome; click a bar to see those calls", Kind: KindStacked, Wide: true, Unit: "calls",
			Times: millis(times), Bucket: w.Bucket.Milliseconds(), Series: stacked(c.byOutcome, times, outcomeTones),
			Drill: &Drill{Href: drill, SeriesParam: "outcome", Time: true}},
		{ID: "punchcard", Title: "When calls happen", Desc: "Weekday × hour, your local time", Kind: KindPunchcard, Wide: true, Unit: "calls",
			Times: millis(timeline(c.hourlyW)), Bucket: time.Hour.Milliseconds(),
			Series: []Series{{Key: "calls", Name: "calls", Tone: "accent", Data: single(c.hourly, timeline(c.hourlyW))}}},
		doughnut("decisions", "Policy decisions", "Click to see those calls", c.decisions, map[string]string{"allow": "ok", "confirm": "accent", "deny": "danger"},
			&Drill{Href: drill, Param: "decision"}),
		doughnut("accounts", "Accounts", "Company and personal connected accounts", c.accounts, map[string]string{"company": "accent", "personal": "c2", "none": "muted"}, nil),
	}}
	tools := Group{Title: "Tools and errors", Charts: []Chart{
		toolsChart(c.tools, drill),
		countsChart("errors", "Error classes", "Why calls failed or were denied", c.classes, "danger", nil),
	}}
	latency := Group{Title: "Latency", Charts: []Chart{
		{ID: "latency", Title: "Latency percentiles", Desc: "p50, p95 and p99 of tool-call latency", Kind: KindLine, Wide: true, Unit: "ms",
			Times: millis(times), Bucket: w.Bucket.Milliseconds(), Series: percentiles(c.latency, times)},
		histogramChart(c.hist),
		latencyByTool(c.tools, drill),
	}}
	return []Group{volume, tools, latency}
}

func toolsChart(tools []store.InsightsToolStats, drill string) Chart {
	ch := Chart{ID: "tools", Title: "Top tools", Desc: "Calls by outcome; click a tool to see its calls", Kind: KindHBar, Unit: "calls",
		Drill: &Drill{Href: drill, Param: "tool"}}
	ok, failed, denied := Series{Key: "succeeded", Name: "other", Tone: "ok"}, Series{Key: "failed", Name: "failed", Tone: "danger"}, Series{Key: "denied", Name: "denied", Tone: "warn"}
	for _, t := range tools {
		ch.Labels = append(ch.Labels, t.Tool)
		ok.Data = append(ok.Data, Num(max(t.Calls-t.Failed-t.Denied, 0)))
		failed.Data = append(failed.Data, Num(t.Failed))
		denied.Data = append(denied.Data, Num(t.Denied))
	}
	ch.Series = []Series{ok, failed, denied}
	return ch
}

func latencyByTool(tools []store.InsightsToolStats, drill string) Chart {
	ch := Chart{ID: "tool-latency", Title: "p95 latency by tool", Desc: "The busiest tools; click to see their calls", Kind: KindHBar, Unit: "ms",
		Drill: &Drill{Href: drill, Param: "tool"}}
	s := Series{Key: "p95", Name: "p95", Tone: "warn"}
	for _, t := range tools {
		ch.Labels = append(ch.Labels, t.Tool)
		s.Data = append(s.Data, Num(t.P95))
	}
	ch.Series = []Series{s}
	return ch
}

func histogramChart(hist []int64) Chart {
	ch := Chart{ID: "latency-histogram", Title: "Latency distribution", Desc: "How many calls took how long", Kind: KindBar, Unit: "calls"}
	s := Series{Key: "calls", Name: "calls", Tone: "accent"}
	for i, n := range hist {
		// Upper bounds keep the axis labels short: "≤ 50 ms" … "> 30 s".
		label := "> " + fmtMS(float64(latencyBounds[len(latencyBounds)-1]))
		if i < len(latencyBounds) {
			label = "≤ " + fmtMS(float64(latencyBounds[i]))
		}
		ch.Labels = append(ch.Labels, label)
		s.Data = append(s.Data, Num(n))
	}
	ch.Series = []Series{s}
	return ch
}

func topUsersChart(users []store.InsightsUserStats, drill string) Chart {
	ch := Chart{ID: "users", Title: "Top users", Desc: "Calls by outcome; click a user to see their audit trail", Kind: KindHBar, Unit: "calls",
		Drill: &Drill{Href: drill, Param: "user_id"}}
	ok, failed, denied := Series{Key: "succeeded", Name: "other", Tone: "ok"}, Series{Key: "failed", Name: "failed", Tone: "danger"}, Series{Key: "denied", Name: "denied", Tone: "warn"}
	for _, u := range users {
		ch.Labels = append(ch.Labels, userName(u.UserID, u.DisplayName))
		ch.Keys = append(ch.Keys, u.UserID)
		ok.Data = append(ok.Data, Num(max(u.Calls-u.Failed-u.Denied, 0)))
		failed.Data = append(failed.Data, Num(u.Failed))
		denied.Data = append(denied.Data, Num(u.Denied))
	}
	ch.Series = []Series{ok, failed, denied}
	return ch
}

// matrixChart is the user × tool bubble chart, nil when there is no data.
func matrixChart(cells []store.InsightsUserToolCount, drill string) *Chart {
	if len(cells) == 0 {
		return nil
	}
	ch := Chart{ID: "user-tools", Title: "Who uses which tool", Desc: "Calls per user and tool; click a user to see their audit trail", Kind: KindMatrix, Wide: true, Unit: "calls",
		Drill: &Drill{Href: drill, Param: "user_id"}}
	rows, cols := map[string]int{}, map[string]int{}
	for _, c := range cells {
		if _, ok := rows[c.UserID]; !ok {
			rows[c.UserID] = len(ch.Labels)
			ch.Labels = append(ch.Labels, userName(c.UserID, c.DisplayName))
			ch.Keys = append(ch.Keys, c.UserID)
		}
		if _, ok := cols[c.Tool]; !ok {
			cols[c.Tool] = len(ch.XLabels)
			ch.XLabels = append(ch.XLabels, c.Tool)
		}
		ch.Points = append(ch.Points, Point{X: cols[c.Tool], Y: rows[c.UserID], V: float64(c.Count)})
	}
	ch.Series = []Series{{Key: "calls", Name: "calls", Tone: "accent"}}
	return &ch
}

// --- writes -------------------------------------------------------------------------

type writes struct {
	sum      store.InsightsWriteSummary
	byState  []store.InsightsBucketCount
	duration []store.InsightsPercentiles
	tools    []store.InsightsWriteToolStats
	errors   []store.InsightsCount
}

func (o *writes) load(ctx context.Context, tx store.Tx, admin bool, w store.InsightsWindow) error {
	var err error
	if o.sum, err = store.InsightsWrites(ctx, tx, admin, w); err != nil {
		return err
	}
	if o.byState, err = store.InsightsWritesByState(ctx, tx, admin, w); err != nil {
		return err
	}
	if o.duration, err = store.InsightsWriteDuration(ctx, tx, admin, w); err != nil {
		return err
	}
	if o.tools, err = store.InsightsWriteTools(ctx, tx, admin, w, topTools); err != nil {
		return err
	}
	o.errors, err = store.InsightsWriteErrors(ctx, tx, admin, w, topClasses)
	return err
}

func (o *writes) stats() []Stat {
	s := o.sum
	open := s.Unresolved + s.Unknown
	return []Stat{
		{Label: "Writes", Value: fmtCount(s.Writes)},
		{Label: "Succeeded", Value: fmtPct(s.Succeeded, s.Writes), Tone: toneIf(s.Writes > 0 && s.Succeeded == s.Writes, "ok")},
		{Label: "Failed", Value: fmtCount(s.Failed), Tone: toneIf(s.Failed > 0, "danger")},
		{Label: "Unresolved", Value: fmtCount(open), Hint: "verify these in the app", Tone: toneIf(open > 0, "danger")},
		{Label: "In progress", Value: fmtCount(s.InProgress)},
		{Label: "Duration p50", Value: fmtMS(s.P50)},
		{Label: "Duration p95", Value: fmtMS(s.P95)},
	}
}

var stateTones = []tone{{"succeeded", "succeeded", "ok"}, {"failed", "failed", "danger"}, {"unresolved", "unresolved", "warn"}, {"unknown", "unknown", "c4"}, {"in_progress", "in progress", "accent"}}

// charts are the write charts; tool clicks open drill (a tool-filtered
// activity or audit table: the ledger page itself has no filters).
func (o *writes) charts(w store.InsightsWindow, drill string) []Chart {
	times := timeline(w)
	tools := Chart{ID: "write-tools", Title: "Writes by tool", Desc: "Click a tool to see its calls", Kind: KindHBar, Unit: "writes",
		Drill: &Drill{Href: drill, Param: "tool"}}
	ok, failed, open := Series{Key: "succeeded", Name: "other", Tone: "ok"}, Series{Key: "failed", Name: "failed", Tone: "danger"}, Series{Key: "unresolved", Name: "unknown or unresolved", Tone: "warn"}
	for _, t := range o.tools {
		tools.Labels = append(tools.Labels, t.Tool)
		ok.Data = append(ok.Data, Num(max(t.Writes-t.Failed-t.Unresolved, 0)))
		failed.Data = append(failed.Data, Num(t.Failed))
		open.Data = append(open.Data, Num(t.Unresolved))
	}
	tools.Series = []Series{ok, failed, open}
	return []Chart{
		{ID: "writes", Title: "Writes over time", Desc: "By ledger state", Kind: KindStacked, Wide: true, Unit: "writes",
			Times: millis(times), Bucket: w.Bucket.Milliseconds(), Series: stacked(o.byState, times, stateTones)},
		{ID: "write-duration", Title: "Write duration", Desc: "p50, p95 and p99 from start to success or failure", Kind: KindLine, Wide: true, Unit: "ms",
			Times: millis(times), Bucket: w.Bucket.Milliseconds(), Series: percentiles(o.duration, times)},
		tools,
		countsChart("write-errors", "Write errors", "Error codes of failed and unresolved writes", o.errors, "danger", nil),
	}
}

// --- series helpers ---------------------------------------------------------------

// tone is a known series: its key in the data, display name and colour.
type tone struct{ key, name, tone string }

// timeline is the bucket starts of w.
func timeline(w store.InsightsWindow) []time.Time {
	var out []time.Time
	for t := w.Since; t.Before(w.Until); t = t.Add(w.Bucket) {
		out = append(out, t)
	}
	return out
}

func millis(ts []time.Time) []int64 {
	out := make([]int64, len(ts))
	for i, t := range ts {
		out[i] = t.UnixMilli()
	}
	return out
}

func index(ts []time.Time) map[int64]int {
	m := make(map[int64]int, len(ts))
	for i, t := range ts {
		m[t.Unix()] = i
	}
	return m
}

// stacked spreads rows over times, one series per key: the known ones in
// order (only those with data), then any others in muted grey. A key
// shown as "none" carries no drill key.
func stacked(rows []store.InsightsBucketCount, times []time.Time, known []tone) []Series {
	idx := index(times)
	byKey := map[string][]Num{}
	var order []string
	for _, r := range rows {
		i, ok := idx[r.Bucket.Unix()]
		if !ok {
			continue
		}
		if _, ok := byKey[r.Key]; !ok {
			byKey[r.Key] = make([]Num, len(times))
			order = append(order, r.Key)
		}
		byKey[r.Key][i] += Num(r.Count)
	}
	var out []Series
	seen := map[string]bool{}
	for _, k := range known {
		if data, ok := byKey[k.key]; ok {
			key := k.key
			if key == "none" {
				key = ""
			}
			out = append(out, Series{Key: key, Name: k.name, Tone: k.tone, Data: data})
			seen[k.key] = true
		}
	}
	for _, k := range order {
		if !seen[k] {
			out = append(out, Series{Key: k, Name: k, Tone: "muted", Data: byKey[k]})
		}
	}
	return out
}

// single spreads one series over times (zeros where empty).
func single(rows []store.InsightsBucketCount, times []time.Time) []Num {
	idx := index(times)
	out := make([]Num, len(times))
	for _, r := range rows {
		if i, ok := idx[r.Bucket.Unix()]; ok {
			out[i] += Num(r.Count)
		}
	}
	return out
}

// percentiles are the p50/p95/p99 lines; buckets without data are gaps.
func percentiles(rows []store.InsightsPercentiles, times []time.Time) []Series {
	idx := index(times)
	p50, p95, p99 := gaps(len(times)), gaps(len(times)), gaps(len(times))
	for _, r := range rows {
		if i, ok := idx[r.Bucket.Unix()]; ok {
			p50[i], p95[i], p99[i] = Num(r.P50), Num(r.P95), Num(r.P99)
		}
	}
	return []Series{{Key: "p50", Name: "p50", Tone: "accent", Data: p50}, {Key: "p95", Name: "p95", Tone: "warn", Data: p95}, {Key: "p99", Name: "p99", Tone: "danger", Data: p99}}
}

func gaps(n int) []Num {
	out := make([]Num, n)
	for i := range out {
		out[i] = Num(math.NaN())
	}
	return out
}

// doughnut is a share chart; tones maps keys to colours (others cycle
// c1…c6).
// The browser splits Series.Tone ("ok,danger,…") into one colour per
// slice.
func doughnut(id, title, desc string, rows []store.InsightsCount, tones map[string]string, drill *Drill) Chart {
	ch := Chart{ID: id, Title: title, Desc: desc, Kind: KindDoughnut, Unit: "calls", Drill: drill}
	s := Series{Key: id, Name: title}
	var colours []string
	for i, r := range rows {
		ch.Labels = append(ch.Labels, r.Key)
		s.Data = append(s.Data, Num(r.Count))
		t, ok := tones[r.Key]
		if !ok {
			t = fmt.Sprintf("c%d", i%6+1)
		}
		colours = append(colours, t)
	}
	s.Tone = strings.Join(colours, ",")
	ch.Series = []Series{s}
	return ch
}

// countsChart is a horizontal bar per category.
func countsChart(id, title, desc string, rows []store.InsightsCount, tn string, drill *Drill) Chart {
	ch := Chart{ID: id, Title: title, Desc: desc, Kind: KindHBar, Unit: "count", Drill: drill}
	s := Series{Key: id, Name: "count", Tone: tn}
	for _, r := range rows {
		ch.Labels = append(ch.Labels, r.Key)
		s.Data = append(s.Data, Num(r.Count))
	}
	ch.Series = []Series{s}
	return ch
}

func toneIf(cond bool, t string) string {
	if cond {
		return t
	}
	return ""
}
