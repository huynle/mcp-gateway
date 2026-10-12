package portal

import (
	"net/url"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/store"
)

func TestApproveAllEnablesEveryToolIncludingWrites(t *testing.T) {
	e := newEnv(t)
	s := e.st.add(store.MCPServer{Name: "brain", URL: "https://brain.example/mcp", OwnerUserID: alice, AuthKind: store.MCPAuthNone})
	e.snap.pending(s.ID, snapOf(readTool("search", "s"), writeTool("delete", "d"), writeTool("attachment_add", "a")))
	// No enable fields at all: approve_all alone enables every tool. A
	// kind override posted with it still applies.
	r := e.post("/servers/"+s.ID+"/review", alice, url.Values{"version": {"1"}, "action": {"approve_all"}, "kind_1": {"read"}})
	if r.code != 303 || r.hdr.Get("Location") != "/servers/"+s.ID+"?approved=1" {
		t.Fatalf("approve all: %d %q %s", r.code, r.hdr.Get("Location"), r.body)
	}
	d := e.snap.approvals[0].d
	for _, name := range []string{"search", "delete", "attachment_add"} {
		if dec := d.Tools[name]; dec.Enabled == nil || !*dec.Enabled {
			t.Errorf("%s not enabled by approve_all: %+v", name, dec)
		}
	}
	if k := d.Tools["delete"].Kind; k == nil || *k != snapshot.KindRead {
		t.Errorf("kind override lost with approve_all: %+v", d.Tools["delete"])
	}
	if d.EnableReads {
		t.Error("approve_all set EnableReads")
	}
	if len(e.hook.changed) != 1 {
		t.Errorf("hook %v", e.hook.changed)
	}
}

func TestPlainApproveStillHonoursTheCheckboxes(t *testing.T) {
	e := newEnv(t)
	s := e.st.add(store.MCPServer{Name: "brain", URL: "https://brain.example/mcp", OwnerUserID: alice, AuthKind: store.MCPAuthNone})
	e.snap.pending(s.ID, snapOf(writeTool("save", "s"), writeTool("delete", "d")))
	r := e.post("/servers/"+s.ID+"/review", alice, url.Values{"version": {"1"}, "action": {"approve"}, "enable": {"0"}})
	if r.code != 303 {
		t.Fatalf("approve: %d %s", r.code, r.body)
	}
	d := e.snap.approvals[0].d
	if dec := d.Tools["save"]; dec.Enabled == nil || !*dec.Enabled {
		t.Errorf("save %+v", dec)
	}
	if dec := d.Tools["delete"]; dec.Enabled == nil || *dec.Enabled {
		t.Errorf("delete %+v", dec)
	}
}

func TestApproveAllNeedsCSRFFreshVersionAndOwnership(t *testing.T) {
	e := newEnv(t)
	s := e.st.add(store.MCPServer{Name: "brain", URL: "https://brain.example/mcp", OwnerUserID: alice, AuthKind: store.MCPAuthNone})
	e.snap.pending(s.ID, snapOf(writeTool("save", "s")))
	for _, tok := range []string{"", "csrf-" + bob} {
		r := e.post("/servers/"+s.ID+"/review", alice, url.Values{"_csrf": {tok}, "version": {"1"}, "action": {"approve_all"}})
		if r.code != 403 {
			t.Errorf("csrf %q: %d, want 403", tok, r.code)
		}
	}
	r := e.post("/servers/"+s.ID+"/review", alice, url.Values{"version": {"7"}, "action": {"approve_all"}})
	if r.code != 409 {
		t.Errorf("stale approve_all: %d, want 409", r.code)
	}
	mustContain(t, r.body, "changed since")

	pub := e.st.add(store.MCPServer{Name: "wiki", URL: "https://wiki.example/mcp", OwnerUserID: alice, AuthKind: store.MCPAuthNone,
		Audience: store.MCPAudiencePublished})
	e.snap.pending(pub.ID, snapOf(writeTool("save", "s")))
	r = e.post("/servers/"+pub.ID+"/review", alice, url.Values{"version": {"1"}, "action": {"approve_all"}})
	if r.code != 403 {
		t.Errorf("approve_all on a published server: %d, want 403", r.code)
	}
	mustContain(t, r.body, "an admin must review")
	if len(e.snap.approvals) != 0 {
		t.Errorf("approvals %+v", e.snap.approvals)
	}
}

func TestReviewPageHasGroupsSelectControlsAndSummary(t *testing.T) {
	e := newEnv(t)
	s := e.st.add(store.MCPServer{Name: "brain", URL: "https://brain.example/mcp", OwnerUserID: alice, AuthKind: store.MCPAuthNone})
	e.snap.pending(s.ID, snapOf(writeTool("attachment_get", "g"), writeTool("attachment_add", "a"), writeTool("attention_list", "l"), writeTool("search", "s")))
	r := e.get("/servers/"+s.ID+"/review", alice)
	if r.code != 200 {
		t.Fatalf("review %d", r.code)
	}
	mustContain(t, r.body,
		`data-review`, `src="/static/review.js"`, `href="/static/review.css"`,
		`class="review-bar"`, `data-select="all"`, `data-select="none"`, `data-review-filter`,
		`0 of 4 selected`, `name="action" value="approve"`, `name="action" value="approve_all"`, "Approve with all tools enabled",
		`data-group="attachment"`, `data-group="attention"`, `data-group="search"`, `data-group-check`, `0/2`,
		`<b>4</b> total`, `<b>0</b> enabled`, `<b>4</b> new`, `<b>0</b> changed`, `<b>0</b> removed`,
		`class="chip status-added">new<`, `class="chip kind-write">write<`)
	// Only writes: no "Select read-only", no read bulk option, no
	// per-row kind select outside the details.
	mustNotContain(t, r.body, `data-select="read"`, `name="enable_reads"`, "may be destructive")
	// Groups are in name order; attachment's tools are listed by name.
	if a, b, c := strings.Index(r.body, `data-group="attachment"`), strings.Index(r.body, `data-group="attention"`), strings.Index(r.body, `data-group="search"`); a >= b || b >= c {
		t.Errorf("group order %d %d %d", a, b, c)
	}
	if add, get := strings.Index(r.body, `aria-label="Enable attachment_add"`), strings.Index(r.body, `aria-label="Enable attachment_get"`); add < 0 || get < 0 || add > get {
		t.Errorf("tool order in group %d %d", add, get)
	}

	// With a read tool, "Select read-only" appears.
	e.snap.pending(s.ID, snapOf(readTool("search", "s"), writeTool("save", "w")))
	r = e.get("/servers/"+s.ID+"/review", alice)
	mustContain(t, r.body, `data-select="read"`, `class="chip kind-read">read<`)
}

func TestReviewRowTruncatesDescriptionAndHidesKindInDetails(t *testing.T) {
	e := newEnv(t)
	s := e.st.add(store.MCPServer{Name: "brain", URL: "https://brain.example/mcp", OwnerUserID: alice, AuthKind: store.MCPAuthNone})
	desc := "Find notes by keyword. Supports filters and paging.\n\nSecond paragraph with details."
	e.snap.pending(s.ID, snapOf(writeTool("search", desc)))
	r := e.get("/servers/"+s.ID+"/review", alice)
	mustContain(t, r.body, `<span class="tool-summary">Find notes by keyword.</span>`, "Advanced")
	more := strings.Index(r.body, `<details class="tool-more">`)
	if more < 0 {
		t.Fatalf("no details:\n%s", r.body)
	}
	for _, inside := range []string{"Supports filters and paging.", "Second paragraph with details.", `name="kind_0"`} {
		if i := strings.Index(r.body, inside); i < more {
			t.Errorf("%q at %d, want inside the details (from %d)", inside, i, more)
		}
	}
	if strings.Count(r.body, `name="kind_0"`) != 1 {
		t.Error("kind select rendered more than once")
	}
}

func TestReviewPrechecksUnchangedEnabledToolsIncludingWrites(t *testing.T) {
	e := newEnv(t)
	s := e.st.add(store.MCPServer{Name: "notes", URL: "https://notes.example/mcp", OwnerUserID: alice, AuthKind: store.MCPAuthNone})
	e.snap.approved(s.ID, snapOf(readTool("list", "List"), readTool("search", "Search"), writeTool("delete", "Delete"), writeTool("off", "x"), readTool("gone", "x")),
		snapshot.Review{"list": {Enabled: true, Kind: snapshot.KindRead}, "search": {Enabled: true, Kind: snapshot.KindRead},
			"delete": {Enabled: true, Kind: snapshot.KindWrite}, "off": {Enabled: false, Kind: snapshot.KindWrite}, "gone": {Enabled: true, Kind: snapshot.KindRead}})
	e.snap.pending(s.ID, snapOf(readTool("list", "List"), readTool("search", "Search, now also deletes"), writeTool("delete", "Delete"), writeTool("off", "x"), readTool("new", "n")))
	r := e.get("/servers/"+s.ID+"/review", alice)
	if r.code != 200 {
		t.Fatalf("review %d", r.code)
	}
	// list (0) and delete (2) are unchanged and enabled; search changed,
	// off disabled, new added.
	if n := strings.Count(r.body, " checked"); n != 2 || !strings.Contains(r.body, `value="0" checked`) || !strings.Contains(r.body, `value="2" checked`) {
		t.Errorf("%d pre-checked boxes:\n%s", n, r.body)
	}
	mustContain(t, r.body, "2 of 5 selected", `<b>5</b> total`, `<b>3</b> enabled`, `<b>1</b> new`, `<b>1</b> changed`, `<b>1</b> removed`,
		`class="chip status-changed">changed<`, "Changed: description", "gone")
}

func TestBuildReviewViewGroupsAndCounts(t *testing.T) {
	latest := &snapshot.Record{Version: 1, Snapshot: snapOf(writeTool("b_two", ""), readTool("a_one", ""), writeTool("b_one", ""), writeTool("solo", ""), writeTool("_x", ""))}
	v := BuildReviewView(latest, nil)
	var got []string
	for _, g := range v.Groups {
		var names []string
		for _, tl := range g.Tools {
			names = append(names, tl.Name)
		}
		got = append(got, g.Name+":"+strings.Join(names, ","))
	}
	want := "_x:_x a:a_one b:b_one,b_two solo:solo"
	if strings.Join(got, " ") != want {
		t.Errorf("groups = %q, want %q", strings.Join(got, " "), want)
	}
	if v.Counts != (ReviewCounts{Total: 5, New: 5}) || !v.HasReads || v.Selected != 0 {
		t.Errorf("counts %+v hasReads %v selected %d", v.Counts, v.HasReads, v.Selected)
	}
}

func TestDescriptionSummary(t *testing.T) {
	long := strings.Repeat("word ", 100)
	for _, c := range []struct{ in, want string }{
		{"", ""},
		{"One line", "One line"},
		{"First sentence. Second sentence.", "First sentence."},
		{"Line one\nLine two", "Line one"},
		{"Use e.g. this. Then that.", "Use e.g. this."},
		{"Really? Yes!", "Really?"},
	} {
		if got := DescriptionSummary(c.in); got != c.want {
			t.Errorf("DescriptionSummary(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	got := DescriptionSummary(long)
	if n := utf8.RuneCountInString(got); n > MaxSummary || !strings.HasSuffix(got, "…") {
		t.Errorf("long summary %d runes %q", n, got)
	}
}
