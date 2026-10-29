//go:build integration

package store_test

import (
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/insights"
	"github.com/huynle/mcp-gateway/internal/store"
)

// The insights aggregates (repo_insights.go, decision 3yq9s5ev): bucketing
// on UTC boundaries, row-level security pinning a user's own aggregates,
// the admin views seeing everyone with display names, and the window
// excluding rows outside it.
func TestIntegrationInsightsAggregates(t *testing.T) {
	env := setup(t)
	env.reset(t)
	ctx := t.Context()
	st := env.open(t)
	alice := newUser(t, st, "Alice")
	bob := newUser(t, st, "Bob")
	appID := newVendorApp(t, st)
	connA := newConnection(t, st, alice, appID, "acct-a")
	connB := newConnection(t, st, bob, appID, "acct-b")
	var pvID string
	if err := env.super.QueryRow(ctx, `INSERT INTO policy_versions (version_hash, cedar, source) VALUES ('sha256:ins', 'permit(principal, action, resource);', '{}') RETURNING id`).Scan(&pvID); err != nil {
		t.Fatal(err)
	}

	day := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	at := func(h, m int) time.Time { return day.Add(time.Duration(h)*time.Hour + time.Duration(m)*time.Minute) }
	audit := func(user, tool, decision, outcome string, latency int, class string, ts time.Time) {
		t.Helper()
		var lat any
		if latency >= 0 {
			lat = latency
		}
		details := `{}`
		if class != "" {
			details = `{"error_class":"` + class + `"}`
		}
		if _, err := env.super.Exec(ctx, `INSERT INTO audit_events (event_type, user_id, tool, account_label, decision, outcome, latency_ms, details, created_at)
			VALUES ('tool_call', $1, $2, 'company', $3, $4, $5, $6::jsonb, $7)`, user, tool, decision, outcome, lat, details, ts); err != nil {
			t.Fatal(err)
		}
	}
	// Alice: three calls in hour 1, one in hour 2.
	audit(alice, "github.get_issue", "allow", "succeeded", 100, "", at(1, 5))
	audit(alice, "github.get_issue", "allow", "succeeded", 300, "", at(1, 10))
	audit(alice, "github.create_issue", "allow", "failed", 900, "timeout", at(1, 20))
	audit(alice, "github.create_issue", "deny", "denied", -1, "policy_denied", at(2, 0))
	// Bob: two calls in hour 2.
	audit(bob, "slack.post_message", "allow", "succeeded", 50, "", at(2, 30))
	audit(bob, "github.get_issue", "allow", "succeeded", 70, "", at(2, 45))
	// Outside the window, and a user event (not a tool call).
	audit(alice, "github.get_issue", "allow", "succeeded", 10, "", at(-1, 0))
	if _, err := env.super.Exec(ctx, `INSERT INTO audit_events (event_type, user_id, decision, outcome, created_at) VALUES ('user', $1, 'allow', 'succeeded', $2)`, alice, at(1, 0)); err != nil {
		t.Fatal(err)
	}

	ledger := func(user, conn, tool, state, key string, created time.Time, took time.Duration, code string) {
		t.Helper()
		var finished any
		if took > 0 {
			finished = created.Add(took)
		}
		var ec any
		if code != "" {
			ec = code
		}
		if _, err := env.super.Exec(ctx, `INSERT INTO ledger_operations (user_id, connection_id, tool, state, idempotency_key, window_start, window_end, policy_version_id, error_code, created_at, updated_at, finished_at)
			VALUES ($1, $2, $3, $4::ledger_state, $5, $6, $6::timestamptz + interval '1 day', $7, $8, $6, $6, $9)`, user, conn, tool, state, key, created, pvID, ec, finished); err != nil {
			t.Fatal(err)
		}
	}
	ledger(alice, connA, "github.create_issue", "succeeded", "k1", at(1, 0), 200*time.Millisecond, "")
	ledger(alice, connA, "github.create_issue", "failed", "k2", at(1, 30), 400*time.Millisecond, "vendor_error")
	ledger(alice, connA, "github.create_issue", "unresolved", "k3", at(2, 0), 0, "outcome_unknown")
	ledger(bob, connB, "slack.post_message", "succeeded", "k4", at(2, 10), 100*time.Millisecond, "")

	approval := func(user, conn, status string, created time.Time, decide time.Duration) {
		t.Helper()
		var decided any
		if decide > 0 {
			decided = created.Add(decide)
		}
		if _, err := env.super.Exec(ctx, `INSERT INTO approvals (user_id, connection_id, tool, digest, status, policy_version_id, created_at, expires_at, decided_at)
			VALUES ($1, $2, 'github.create_issue', 'd', $3::approval_status, $4, $5, $5::timestamptz + interval '1 hour', $6)`, user, conn, status, pvID, created, decided); err != nil {
			t.Fatal(err)
		}
	}
	approval(alice, connA, "consumed", at(1, 0), 10*time.Second)
	approval(alice, connA, "denied", at(1, 40), 30*time.Second)
	approval(bob, connB, "expired", at(2, 0), 0)

	w := store.InsightsWindow{Since: day, Until: day.Add(24 * time.Hour), Bucket: time.Hour}

	// --- a user's own aggregates (WithUser, base tables, RLS) ---
	err := st.WithUser(ctx, alice, func(tx store.Tx) error {
		s, err := store.InsightsCalls(ctx, tx, false, w)
		if err != nil {
			return err
		}
		if s.Calls != 4 || s.Succeeded != 2 || s.Failed != 1 || s.Denied != 1 || s.Tools != 2 || s.Users != 1 {
			t.Errorf("alice summary = %+v, want 4 calls (2 ok, 1 failed, 1 denied), 2 tools, 1 user", s)
		}
		if s.P50 != 300 {
			t.Errorf("alice p50 = %v, want 300 (median of 100, 300, 900; null latency ignored)", s.P50)
		}
		byOutcome, err := store.InsightsCallsByOutcome(ctx, tx, false, w)
		if err != nil {
			return err
		}
		want := []store.InsightsBucketCount{
			{Bucket: at(1, 0), Key: "failed", Count: 1},
			{Bucket: at(1, 0), Key: "succeeded", Count: 2},
			{Bucket: at(2, 0), Key: "denied", Count: 1},
		}
		if !equalBucketCounts(byOutcome, want) {
			t.Errorf("alice by outcome = %+v, want %+v", byOutcome, want)
		}
		per, err := store.InsightsCallsPerBucket(ctx, tx, false, store.InsightsWindow{Since: w.Since, Until: w.Until, Bucket: 6 * time.Hour})
		if err != nil {
			return err
		}
		if len(per) != 1 || !per[0].Bucket.Equal(day) || per[0].Count != 4 {
			t.Errorf("alice 6h buckets = %+v, want one bucket at midnight UTC with 4", per)
		}
		lat, err := store.InsightsLatency(ctx, tx, false, w)
		if err != nil {
			return err
		}
		if len(lat) != 1 || lat[0].N != 3 || lat[0].P50 != 300 {
			t.Errorf("alice latency = %+v, want one bucket (hour 1) with n=3 p50=300", lat)
		}
		hist, err := store.InsightsLatencyHistogram(ctx, tx, false, w, []int32{100, 500})
		if err != nil {
			return err
		}
		if !slices.Equal(hist, []int64{0, 2, 1}) {
			t.Errorf("alice histogram = %v, want [0 2 1] (<100, 100-500, >=500)", hist)
		}
		classes, err := store.InsightsCallsBy(ctx, tx, false, w, store.InsightsByErrorClass, 10)
		if err != nil {
			return err
		}
		if len(classes) != 2 {
			t.Errorf("alice error classes = %+v, want timeout and policy_denied", classes)
		}
		types, err := store.InsightsCallsBy(ctx, tx, false, w, store.InsightsByEventType, 10)
		if err != nil {
			return err
		}
		if len(types) != 2 || types[0] != (store.InsightsCount{Key: "tool_call", Count: 4}) || types[1] != (store.InsightsCount{Key: "user", Count: 1}) {
			t.Errorf("alice event types = %+v", types)
		}
		tools, err := store.InsightsTopTools(ctx, tx, false, w, 10)
		if err != nil {
			return err
		}
		if len(tools) != 2 || tools[0].Calls != 2 || tools[1].Calls != 2 {
			t.Errorf("alice top tools = %+v", tools)
		}
		ws, err := store.InsightsWrites(ctx, tx, false, w)
		if err != nil {
			return err
		}
		if ws.Writes != 3 || ws.Succeeded != 1 || ws.Failed != 1 || ws.Unresolved != 1 || ws.P50 != 300 {
			t.Errorf("alice writes = %+v, want 3 (1 ok, 1 failed, 1 unresolved), p50 300ms", ws)
		}
		errs, err := store.InsightsWriteErrors(ctx, tx, false, w, 10)
		if err != nil {
			return err
		}
		if len(errs) != 2 {
			t.Errorf("alice write errors = %+v", errs)
		}
		wt, err := store.InsightsWriteTools(ctx, tx, false, w, 10)
		if err != nil {
			return err
		}
		if len(wt) != 1 || wt[0].Writes != 3 || wt[0].Failed != 1 || wt[0].Unresolved != 1 {
			t.Errorf("alice write tools = %+v", wt)
		}
		dur, err := store.InsightsWriteDuration(ctx, tx, false, w)
		if err != nil {
			return err
		}
		if len(dur) != 1 || dur[0].N != 2 {
			t.Errorf("alice write duration = %+v, want one bucket with the two finished writes", dur)
		}
		states, err := store.InsightsWritesByState(ctx, tx, false, w)
		if err != nil {
			return err
		}
		if len(states) != 3 {
			t.Errorf("alice writes by state = %+v", states)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// --- admin aggregates (WithJobs, admin views) ---
	err = st.WithJobs(ctx, func(tx store.Tx) error {
		s, err := store.InsightsCalls(ctx, tx, true, w)
		if err != nil {
			return err
		}
		if s.Calls != 6 || s.Users != 2 || s.Tools != 3 {
			t.Errorf("admin summary = %+v, want 6 calls, 2 users, 3 tools", s)
		}
		users, err := store.InsightsTopUsers(ctx, tx, w, 10)
		if err != nil {
			return err
		}
		if len(users) != 2 || users[0].DisplayName != "Alice" || users[0].Calls != 4 || users[0].Denied != 1 || users[1].DisplayName != "Bob" || !users[0].LastSeen.Equal(at(2, 0)) {
			t.Errorf("admin top users = %+v", users)
		}
		active, err := store.InsightsActiveUsers(ctx, tx, w)
		if err != nil {
			return err
		}
		if len(active) != 2 || active[0].Count != 1 || active[1].Count != 2 {
			t.Errorf("admin active users = %+v, want 1 in hour 1, 2 in hour 2", active)
		}
		matrix, err := store.InsightsUserTools(ctx, tx, w, 1, 10)
		if err != nil {
			return err
		}
		if len(matrix) != 2 || matrix[0].DisplayName != "Alice" {
			t.Errorf("admin user tools (top 1 user) = %+v, want Alice's two tools", matrix)
		}
		ws, err := store.InsightsWrites(ctx, tx, true, w)
		if err != nil {
			return err
		}
		if ws.Writes != 4 {
			t.Errorf("admin writes = %+v, want 4", ws)
		}
		ap, err := store.InsightsApprovals(ctx, tx, w)
		if err != nil {
			return err
		}
		if ap.Total != 3 || ap.Consumed != 1 || ap.Denied != 1 || ap.Expired != 1 || ap.P50 != 20 {
			t.Errorf("admin approvals = %+v, want 3 (consumed, denied, expired), p50 20s", ap)
		}
		byStatus, err := store.InsightsApprovalsByStatus(ctx, tx, w)
		if err != nil {
			return err
		}
		if len(byStatus) != 3 {
			t.Errorf("admin approvals by status = %+v", byStatus)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// --- bad input ---
	err = st.WithJobs(ctx, func(tx store.Tx) error {
		if _, err := store.InsightsCallsBy(ctx, tx, true, w, "user_id; DROP TABLE users", 10); err == nil {
			t.Error("unknown dimension accepted")
		}
		if _, err := store.InsightsCalls(ctx, tx, true, store.InsightsWindow{Since: day, Until: day, Bucket: time.Hour}); err == nil {
			t.Error("empty window accepted")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func equalBucketCounts(got, want []store.InsightsBucketCount) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if !got[i].Bucket.Equal(want[i].Bucket) || got[i].Key != want[i].Key || got[i].Count != want[i].Count {
			return false
		}
	}
	return true
}

// The insights source end to end over a migrated database: a user's
// dashboards see only their own rows, the admin dashboard sees everyone
// with names, and every chart's series lines up with its timeline.
func TestIntegrationInsightsSource(t *testing.T) {
	env := setup(t)
	env.reset(t)
	ctx := t.Context()
	st := env.open(t)
	alice := newUser(t, st, "Alice")
	bob := newUser(t, st, "Bob")
	appID := newVendorApp(t, st)
	connA := newConnection(t, st, alice, appID, "acct-a")
	var pvID string
	if err := env.super.QueryRow(ctx, `INSERT INTO policy_versions (version_hash, cedar, source) VALUES ('sha256:src', 'permit(principal, action, resource);', '{}') RETURNING id`).Scan(&pvID); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for i, c := range []struct {
		user, tool, decision, outcome string
		ago                           time.Duration
	}{
		{alice, "github.get_issue", "allow", "succeeded", 2 * time.Hour},
		{alice, "github.create_issue", "allow", "failed", 3 * time.Hour},
		{bob, "slack.post_message", "deny", "denied", 30 * time.Minute},
		{bob, "slack.post_message", "allow", "succeeded", 40 * 24 * time.Hour}, // outside every range
	} {
		if _, err := env.super.Exec(ctx, `INSERT INTO audit_events (event_type, user_id, tool, decision, outcome, latency_ms, created_at)
			VALUES ('tool_call', $1, $2, $3, $4, $5, $6)`, c.user, c.tool, c.decision, c.outcome, 100*(i+1), now.Add(-c.ago)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := env.super.Exec(ctx, `INSERT INTO ledger_operations (user_id, connection_id, tool, state, idempotency_key, window_start, window_end, policy_version_id, created_at, updated_at, finished_at)
		VALUES ($1, $2, 'github.create_issue', 'succeeded', 'k', $3, $3::timestamptz + interval '1 day', $4, $3, $3, $3::timestamptz + interval '2 seconds')`, alice, connA, now.Add(-time.Hour), pvID); err != nil {
		t.Fatal(err)
	}

	src := insights.NewSource(st)
	u, _ := url.Parse("/activity?range=24h")
	day, _ := insights.ParseRange("24h")

	act, err := src.Activity(ctx, alice, day, u)
	if err != nil {
		t.Fatal(err)
	}
	if act.Empty || stat(act, "Tool calls") != "2" || stat(act, "Failed") != "1" || stat(act, "Denied") != "0" {
		t.Errorf("alice activity stats = %+v", act.Stats)
	}
	checkCharts(t, "activity", act)
	if c := chart(act, "tools"); c == nil || len(c.Labels) != 2 || c.Drill == nil || c.Drill.Href != "/activity?range=24h" {
		t.Errorf("alice tools chart = %+v", c)
	}

	ops, err := src.Operations(ctx, alice, day, u)
	if err != nil {
		t.Fatal(err)
	}
	if stat(ops, "Writes") != "1" || stat(ops, "Duration p50") != "2.0 s" {
		t.Errorf("alice operations stats = %+v", ops.Stats)
	}
	checkCharts(t, "operations", ops)

	bobOps, err := src.Operations(ctx, bob, day, u)
	if err != nil {
		t.Fatal(err)
	}
	if !bobOps.Empty {
		t.Errorf("bob sees writes: %+v", bobOps.Stats)
	}

	month, _ := insights.ParseRange("30d")
	adm, err := src.Admin(ctx, month, u)
	if err != nil {
		t.Fatal(err)
	}
	if stat(adm, "Tool calls") != "3" || stat(adm, "Active users") != "2" || stat(adm, "Writes") != "1" {
		t.Errorf("admin stats = %+v", adm.Stats)
	}
	if len(adm.Users) != 2 || adm.Users[0].Name != "Alice" || adm.Users[0].Href != "/admin/audit?user_id="+alice {
		t.Errorf("admin users = %+v", adm.Users)
	}
	checkCharts(t, "admin", adm)
	if c := chart(adm, "user-tools"); c == nil || len(c.Points) != 3 {
		t.Errorf("admin user × tool = %+v", c)
	}
}

func stat(d *insights.Dashboard, label string) string {
	for _, s := range d.Stats {
		if s.Label == label {
			return s.Value
		}
	}
	return "<missing>"
}

func chart(d *insights.Dashboard, id string) *insights.Chart {
	for _, c := range d.Charts() {
		if c.ID == id {
			return &c
		}
	}
	return nil
}

// checkCharts: ids are unique, every time series has one value per
// bucket, every category series one per label.
func checkCharts(t *testing.T, what string, d *insights.Dashboard) {
	t.Helper()
	seen := map[string]bool{}
	for _, c := range d.Charts() {
		if seen[c.ID] {
			t.Errorf("%s: duplicate chart id %q", what, c.ID)
		}
		seen[c.ID] = true
		n := len(c.Labels)
		if len(c.Times) > 0 {
			n = len(c.Times)
		}
		if c.Kind == insights.KindMatrix {
			continue
		}
		for _, s := range c.Series {
			if len(s.Data) != n {
				t.Errorf("%s: chart %s series %s has %d values for %d buckets/labels", what, c.ID, s.Key, len(s.Data), n)
			}
		}
	}
}
