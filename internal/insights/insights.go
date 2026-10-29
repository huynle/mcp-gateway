// Package insights builds the charts of the portal's activity pages
// (decision 3yq9s5ev): /activity (a user's own tool calls), /operations
// (a user's own writes) and /admin/insights (every user, admins only).
//
// The data are SQL aggregates (store/repo_insights.go) over the audit
// events, the write ledger and the approvals, bounded by a Range. A
// user's dashboards read through WithUser, so row-level security pins
// them to that user's rows; the admin dashboard reads the metadata-only
// admin views through WithJobs (decision 9z5sdzsm). Nothing here touches
// arguments or content, which those tables never hold.
//
// A Dashboard renders through the "insights.charts" template (Setup adds
// it to a module's template set): server-rendered summary numbers and
// range links, one <canvas> per Chart, and the charts as a JSON data
// block that the vendored Chart.js and static/charts.js draw. There is
// no JSON endpoint (decision 7datr7x4). Without JavaScript the summary
// numbers and the page's own tables still work.
package insights

import (
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Range is a time window the charts can show.
type Range struct {
	Key    string        // query value: 24h, 7d, 30d
	Label  string        // shown on the range links
	Span   time.Duration // how far back from now
	Bucket time.Duration // width of one time bucket
}

// Ranges are the windows offered, in display order.
var Ranges = []Range{
	{Key: "24h", Label: "24 hours", Span: 24 * time.Hour, Bucket: time.Hour},
	{Key: "7d", Label: "7 days", Span: 7 * 24 * time.Hour, Bucket: 6 * time.Hour},
	{Key: "30d", Label: "30 days", Span: 30 * 24 * time.Hour, Bucket: 24 * time.Hour},
}

// DefaultRange is used when the query names none.
var DefaultRange = Ranges[1]

// RangeParam is the query parameter that selects a Range.
const RangeParam = "range"

// ParseRange returns the Range named by key; "" is DefaultRange.
func ParseRange(key string) (Range, error) {
	if key == "" {
		return DefaultRange, nil
	}
	for _, r := range Ranges {
		if r.Key == key {
			return r, nil
		}
	}
	return Range{}, fmt.Errorf("range must be one of 24h, 7d, 30d")
}

// RangeLink is one entry of the range switcher.
type RangeLink struct {
	Label   string
	Href    string
	Current bool
}

// Dashboard is what "insights.charts" renders.
type Dashboard struct {
	Title      string
	Range      Range
	RangeLinks []RangeLink
	Stats      []Stat
	Groups     []Group
	// Users is the admin dashboard's top-users table (nil elsewhere).
	Users []UserRow
	// Empty is set when the window holds nothing to chart.
	Empty bool
	// Failed is set when the aggregates could not be loaded; the page
	// renders a notice instead of the charts and RequestID to quote.
	Failed    bool
	RequestID string
}

// Group is a titled set of charts.
type Group struct {
	Title  string
	Charts []Chart
}

// Charts returns every chart of every group, for the JSON data block.
func (d *Dashboard) Charts() []Chart {
	var out []Chart
	for _, g := range d.Groups {
		out = append(out, g.Charts...)
	}
	return out
}

// Stat is one summary number.
type Stat struct {
	Label string
	Value string
	Hint  string
	Tone  string // "", ok, warn, danger
}

// UserRow is one row of the admin top-users table.
type UserRow struct {
	UserID, Name                 string
	Calls, Failed, Denied, Tools int64
	LastSeen                     time.Time
	Href                         string
}

// Chart kinds the browser script knows.
const (
	KindStacked   = "stacked"   // stacked bars over time
	KindLine      = "line"      // lines over time
	KindBar       = "bar"       // vertical bars over categories
	KindHBar      = "hbar"      // horizontal (stacked) bars over categories
	KindDoughnut  = "doughnut"  // shares of a whole
	KindPunchcard = "punchcard" // hourly totals folded into weekday × hour (local time)
	KindMatrix    = "matrix"    // user × tool bubbles
)

// Chart is one chart. Exactly one of Times (bucket starts, Unix
// milliseconds, for time charts) or Labels (categories) is set.
type Chart struct {
	ID     string   `json:"id"`
	Title  string   `json:"title"`
	Desc   string   `json:"-"`
	Kind   string   `json:"kind"`
	Wide   bool     `json:"-"`
	Unit   string   `json:"unit,omitempty"`
	Times  []int64  `json:"times,omitempty"`
	Bucket int64    `json:"bucketMs,omitempty"`
	Labels []string `json:"labels,omitempty"`
	// Keys are the values Drill sends for each label when they differ
	// from the label (user IDs behind display names).
	Keys    []string `json:"keys,omitempty"`
	XLabels []string `json:"xLabels,omitempty"` // matrix columns
	Series  []Series `json:"series"`
	Points  []Point  `json:"points,omitempty"` // matrix cells
	Drill   *Drill   `json:"drill,omitempty"`
}

// Series is one data series. Tone picks its colour from the portal
// palette (ok, danger, warn, accent, muted, or c1…c6).
type Series struct {
	Key  string `json:"key"`
	Name string `json:"name"`
	Tone string `json:"tone"`
	Data []Num  `json:"data"`
}

// Num is a data value; NaN (no data in the bucket) encodes as null so a
// line shows a gap instead of a false zero.
type Num float64

// MarshalJSON implements json.Marshaler.
func (n Num) MarshalJSON() ([]byte, error) {
	if math.IsNaN(float64(n)) || math.IsInf(float64(n), 0) {
		return []byte("null"), nil
	}
	return strconv.AppendFloat(nil, math.Round(float64(n)*100)/100, 'f', -1, 64), nil
}

// Point is one matrix cell: column X, row Y, value V.
type Point struct {
	X int     `json:"x"`
	Y int     `json:"y"`
	V float64 `json:"v"`
}

// Drill makes a chart clickable: the browser opens Href (a same-origin
// path with its query) plus, when set, Param = the clicked label's key,
// SeriesParam = the clicked series' key, and for time charts since/until
// spanning the clicked bucket.
type Drill struct {
	Href        string `json:"href"`
	Param       string `json:"param,omitempty"`
	SeriesParam string `json:"seriesParam,omitempty"`
	Time        bool   `json:"time,omitempty"`
}

// RangeLinksFor returns the switcher for u: each link is u with
// RangeParam set and the table's page reset.
func RangeLinksFor(u *url.URL, cur Range) []RangeLink {
	out := make([]RangeLink, 0, len(Ranges))
	for _, r := range Ranges {
		q := u.Query()
		q.Set(RangeParam, r.Key)
		q.Del("page")
		out = append(out, RangeLink{Label: r.Label, Href: u.Path + "?" + q.Encode(), Current: r.Key == cur.Key})
	}
	return out
}

// DrillHref is path with the query values of keep that are set in u
// (so a click keeps the range) and a trailing separator for the
// browser to append to.
func DrillHref(path string, u *url.URL, keep ...string) string {
	q := url.Values{}
	src := u.Query()
	for _, k := range keep {
		if v := src.Get(k); v != "" {
			q.Set(k, v)
		}
	}
	return path + "?" + q.Encode()
}

// --- formatting ---------------------------------------------------------------

func fmtCount(n int64) string {
	s := strconv.FormatInt(n, 10)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}

func fmtMS(ms float64) string {
	switch {
	case ms <= 0:
		return "–"
	case ms < 1000:
		return strconv.FormatFloat(math.Round(ms), 'f', -1, 64) + " ms"
	case ms < 60_000:
		return strconv.FormatFloat(ms/1000, 'f', 1, 64) + " s"
	default:
		return strconv.FormatFloat(ms/60_000, 'f', 1, 64) + " min"
	}
}

func fmtSeconds(s float64) string {
	if s <= 0 {
		return "–"
	}
	return fmtMS(s * 1000)
}

// fmtPct is part/whole as a percentage, "–" for an empty whole.
func fmtPct(part, whole int64) string {
	if whole == 0 {
		return "–"
	}
	p := float64(part) * 100 / float64(whole)
	if p == 100 || p == 0 {
		return strconv.FormatFloat(p, 'f', 0, 64) + "%"
	}
	return strconv.FormatFloat(p, 'f', 1, 64) + "%"
}

// shortID is the first 8 characters of an ID, for users without a name.
func shortID(id string) string { return id[:min(8, len(id))] }

// userName is the display name, or the short ID when the user has none.
func userName(id, name string) string {
	if strings.TrimSpace(name) != "" {
		return name
	}
	return "user " + shortID(id)
}
