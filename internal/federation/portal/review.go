package portal

import (
	"errors"
	"net/http"
	"slices"
	"strconv"

	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/store"
)

// toolView is one tool of the snapshot under review. Upstream text is
// passed through the snapshot Display helpers here and HTML-escaped by
// the template. Index (position in the snapshot) names the form fields,
// so upstream names never become field names.
type toolView struct {
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

type reviewData struct {
	Title      string
	Caller     caller
	Server     serverView
	Version    int
	From       int
	UpToDate   bool
	CanApprove bool
	NeedsAdmin bool
	Tools      []toolView
	Removed    []string
	Resources  keyDiffView
	Templates  keyDiffView
	Prompts    keyDiffView
	Error      string
}

type keyDiffView struct{ Added, Removed, Changed []string }

func (k keyDiffView) Empty() bool { return len(k.Added)+len(k.Removed)+len(k.Changed) == 0 }

func displayKeys(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = snapshot.DisplayTitle(s)
	}
	return out
}

func keyView(k snapshot.KeyDiff) keyDiffView {
	return keyDiffView{Added: displayKeys(k.Added), Removed: displayKeys(k.Removed), Changed: displayKeys(k.Changed)}
}

// canApprove: the owner reviews a private server; a published server is
// reviewed by an admin (decision 17iv8p3b), not on this page.
func canApprove(c caller, s *store.MCPServer) bool {
	return s.OwnerUserID == c.UserID && s.Audience == store.MCPAudiencePrivate
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
	var diff snapshot.Diff
	if current == nil || current.Version != latest.Version {
		var from *snapshot.Snapshot
		if current != nil {
			from = current.Snapshot
			data.From = current.Version
		}
		diff = snapshot.Compare(from, latest.Snapshot)
	} else {
		data.UpToDate, data.From = true, current.Version
	}
	data.Version = latest.Version
	var review snapshot.Review
	if current != nil {
		review = current.Review
	}
	for i, t := range latest.Snapshot.Tools {
		tv := toolView{
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
		data.Tools = append(data.Tools, tv)
	}
	data.Removed = displayKeys(diff.Removed)
	data.Resources, data.Templates, data.Prompts = keyView(diff.Resources), keyView(diff.ResourceTemplates), keyView(diff.Prompts)
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
	var review snapshot.Review
	if cur, err := p.d.Snapshots.Current(ctx, c.snapActor(), s.ID); err == nil {
		review = cur.Review
	}
	checked := map[int]bool{}
	for _, v := range r.PostForm["enable"] {
		if i, err := strconv.Atoi(v); err == nil {
			checked[i] = true
		}
	}
	d := snapshot.ReviewDecisions{Tools: map[string]snapshot.Decision{}, EnableReads: r.PostForm.Get("enable_reads") != ""}
	for i, t := range latest.Snapshot.Tools {
		var dec snapshot.Decision
		eff := t.HintKind()
		switch k := snapshot.Kind(r.PostForm.Get("kind_" + strconv.Itoa(i))); k {
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

func enabled(b bool) *bool { return &b }
