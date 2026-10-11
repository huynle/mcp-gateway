package portal

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"

	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/store"
)

// ReviewTool is one tool of the snapshot under review (shared with the
// admin pages). Upstream text is passed through the snapshot Display
// helpers here and HTML-escaped by the template. Index (position in the
// snapshot) names the form fields, so upstream names never become field
// names.
type ReviewTool struct {
	Index       int
	Name        string
	Title       string
	Description string
	HintKind    snapshot.Kind
	Override    snapshot.Kind // current reviewer override, if any
	Destructive bool
	Status      string // added | changed | unchanged
	Fields      []string
	Enabled     bool // enabled in the approved review
	Checked     bool // pre-checked: an unchanged read tool that is enabled
}

// ReviewView is the latest snapshot compared with the approved one, as
// the review pages show it (BuildReviewView).
type ReviewView struct {
	Version   int // latest version (0: no snapshot)
	From      int // approved version (0: none)
	UpToDate  bool
	Tools     []ReviewTool
	Removed   []string
	Resources KeyDiffView
	Templates KeyDiffView
	Prompts   KeyDiffView
}

type reviewData struct {
	ReviewView
	Title      string
	Caller     caller
	Server     serverView
	CanApprove bool
	NeedsAdmin bool
	Error      string
}

// KeyDiffView is a KeyDiff with display-safe keys.
type KeyDiffView struct{ Added, Removed, Changed []string }

// Empty: nothing added, removed or changed.
func (k KeyDiffView) Empty() bool { return len(k.Added)+len(k.Removed)+len(k.Changed) == 0 }

func displayKeys(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = snapshot.DisplayTitle(s)
	}
	return out
}

func keyView(k snapshot.KeyDiff) KeyDiffView {
	return KeyDiffView{Added: displayKeys(k.Added), Removed: displayKeys(k.Removed), Changed: displayKeys(k.Changed)}
}

// canApprove: the owner reviews a private server; a published server is
// reviewed by an admin (decision 17iv8p3b), not on this page.
func canApprove(c caller, s *store.MCPServer) bool {
	return s.OwnerUserID == c.UserID && s.Audience == store.MCPAudiencePrivate
}

// BuildReviewView compares latest with current (the approved record, nil
// when none) for the review pages. Writes are never pre-checked; neither
// is anything new or changed.
func BuildReviewView(latest, current *snapshot.Record) ReviewView {
	var v ReviewView
	if latest == nil {
		return v
	}
	var diff snapshot.Diff
	if current == nil || current.Version != latest.Version {
		var from *snapshot.Snapshot
		if current != nil {
			from = current.Snapshot
			v.From = current.Version
		}
		diff = snapshot.Compare(from, latest.Snapshot)
	} else {
		v.UpToDate, v.From = true, current.Version
	}
	v.Version = latest.Version
	var review snapshot.Review
	if current != nil {
		review = current.Review
	}
	for i, t := range latest.Snapshot.Tools {
		tv := ReviewTool{
			Index: i, Name: snapshot.DisplayName(t.Name), Title: snapshot.DisplayTitle(t.Title),
			Description: snapshot.DisplayDescription(t.Description), HintKind: t.HintKind(), Status: "unchanged",
		}
		if t.Annotations != nil {
			if tv.Title == "" {
				tv.Title = snapshot.DisplayTitle(t.Annotations.Title)
			}
			tv.Destructive = t.Annotations.DestructiveHint == nil || *t.Annotations.DestructiveHint
		} else {
			tv.Destructive = true
		}
		if slices.Contains(diff.Added, t.Name) {
			tv.Status = "added"
		}
		if j := slices.IndexFunc(diff.Changed, func(c snapshot.ToolChange) bool { return c.Name == t.Name }); j >= 0 {
			tv.Status, tv.Fields = "changed", diff.Changed[j].Fields
		}
		if rv, ok := review[t.Name]; ok {
			tv.Enabled = rv.Enabled
			if rv.Override != nil {
				tv.Override = rv.Override.Kind
			}
		}
		eff := tv.HintKind
		if tv.Override != "" {
			eff = tv.Override
		}
		// Writes are never pre-checked; neither is anything new or changed.
		tv.Checked = tv.Enabled && tv.Status == "unchanged" && eff == snapshot.KindRead
		v.Tools = append(v.Tools, tv)
	}
	v.Removed = displayKeys(diff.Removed)
	v.Resources, v.Templates, v.Prompts = keyView(diff.Resources), keyView(diff.ResourceTemplates), keyView(diff.Prompts)
	return v
}

func (p *Portal) review(w http.ResponseWriter, r *http.Request, c caller, s *store.MCPServer) {
	p.renderReview(w, r, c, s, http.StatusOK, "")
}

func (p *Portal) renderReview(w http.ResponseWriter, r *http.Request, c caller, s *store.MCPServer, status int, msg string) {
	ctx := r.Context()
	data := reviewData{Title: "Review " + s.Name, Caller: c, Server: p.view(ctx, c, s), Error: msg,
		CanApprove: canApprove(c, s), NeedsAdmin: s.Audience == store.MCPAudiencePublished}
	latest, err := p.d.Snapshots.Latest(ctx, c.snapActor(), s.ID)
	switch {
	case errors.Is(err, snapshot.ErrNoSnapshot):
		data.CanApprove = false
		p.render(w, r, status, "review.html", data)
		return
	case err != nil:
		p.fail(w, r, "latest snapshot", err)
		return
	}
	var current *snapshot.Record
	if current, err = p.d.Snapshots.Current(ctx, c.snapActor(), s.ID); err != nil && !errors.Is(err, snapshot.ErrNoSnapshot) {
		p.fail(w, r, "current snapshot", err)
		return
	}
	data.ReviewView = BuildReviewView(latest, current)
	p.render(w, r, status, "review.html", data)
}

// approve turns the review form into decisions for the posted version:
// every checked tool enabled; every unchecked tool disabled, except read
// tools when "enable all read tools" is on (left to EnableReads, which
// never re-enables a tool a reviewer disabled before).
func (p *Portal) approve(w http.ResponseWriter, r *http.Request, c caller, s *store.MCPServer) {
	ctx := r.Context()
	if !canApprove(c, s) {
		p.renderReview(w, r, c, s, http.StatusForbidden, "This server is published: an admin must review its tools.")
		return
	}
	version, err := strconv.Atoi(r.PostForm.Get("version"))
	latest, lerr := p.d.Snapshots.Latest(ctx, c.snapActor(), s.ID)
	if err != nil || lerr != nil || latest.Version != version {
		if lerr != nil && !errors.Is(lerr, snapshot.ErrNoSnapshot) {
			p.fail(w, r, "latest snapshot", lerr)
			return
		}
		p.renderReview(w, r, c, s, http.StatusConflict, "The server's tools changed since this page was loaded. Review them again.")
		return
	}
	var current *snapshot.Record
	if cur, err := p.d.Snapshots.Current(ctx, c.snapActor(), s.ID); err == nil {
		current = cur
	}
	d := ReviewDecisionsFromForm(r.PostForm, latest, current)
	_, err = p.d.Snapshots.Approve(ctx, c.snapActor(), s.ID, version, d)
	switch {
	case errors.Is(err, snapshot.ErrReviewNotAllowed):
		p.renderReview(w, r, c, s, http.StatusForbidden, "This server is published: an admin must review its tools.")
		return
	case errors.Is(err, snapshot.ErrStaleVersion):
		p.renderReview(w, r, c, s, http.StatusConflict, "The server's tools changed since this page was loaded. Review them again.")
		return
	case err != nil:
		p.fail(w, r, "approve snapshot", err)
		return
	}
	p.log.Info("snapshot approved", "event", "federation.snapshot_approved", "user_id", c.UserID, "server_id", s.ID, "version", version)
	p.changed(ctx, s.ID)
	http.Redirect(w, r, "/servers/"+s.ID+"?approved=1", http.StatusSeeOther)
}

// ReviewDecisionsFromForm turns a posted review form (fields enable=<i>,
// kind_<i>, enable_reads) into decisions for latest; current is the
// approved record (nil when none). Every checked tool is enabled; every
// unchecked tool disabled, except read tools when "enable all read tools"
// is on (left to EnableReads, which never re-enables a tool a reviewer
// disabled before and never enables writes).
func ReviewDecisionsFromForm(form url.Values, latest, current *snapshot.Record) snapshot.ReviewDecisions {
	var review snapshot.Review
	if current != nil {
		review = current.Review
	}
	checked := map[int]bool{}
	for _, v := range form["enable"] {
		if i, err := strconv.Atoi(v); err == nil {
			checked[i] = true
		}
	}
	d := snapshot.ReviewDecisions{Tools: map[string]snapshot.Decision{}, EnableReads: form.Get("enable_reads") != ""}
	for i, t := range latest.Snapshot.Tools {
		var dec snapshot.Decision
		eff := t.HintKind()
		switch k := snapshot.Kind(form.Get("kind_" + strconv.Itoa(i))); k {
		case snapshot.KindRead, snapshot.KindWrite:
			dec.Kind, eff = &k, k
		default:
			if rv, ok := review[t.Name]; ok && rv.Override != nil {
				none := snapshot.Kind("")
				dec.Kind = &none
			}
		}
		switch {
		case checked[i]:
			dec.Enabled = enabled(true)
		case d.EnableReads && eff == snapshot.KindRead:
			// left to EnableReads
		default:
			dec.Enabled = enabled(false)
		}
		d.Tools[t.Name] = dec
	}
	return d
}

func enabled(b bool) *bool { return &b }
