package portal

import (
	"embed"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

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
	Description string // full (display-safe) description
	Summary     string // its first line or sentence (DescriptionSummary)
	HintKind    snapshot.Kind
	Override    snapshot.Kind // current reviewer override, if any
	Kind        snapshot.Kind // effective kind: Override, else HintKind
	Destructive bool
	// DestructiveHint: the upstream explicitly annotates the tool
	// destructiveHint=true (the review warns when such a tool is set to
	// run without asking).
	DestructiveHint bool
	Status          string // added | changed | unchanged
	Fields          []string
	Enabled         bool // enabled in the approved review
	Checked         bool // pre-checked: an unchanged tool that is enabled
	// Approval is the tool's approval mode as the form pre-selects it:
	// auto for reads; for writes the approved mode of an unchanged tool,
	// ask for a new or changed one (snapshot.ToolReview.Mode).
	Approval snapshot.Approval
}

// ReviewGroup is the tools sharing a name prefix (the text before the
// first "_"), listed by name.
type ReviewGroup struct {
	Name    string
	Tools   []ReviewTool
	Checked int // pre-checked tools in the group
}

// Form fields of the item checkboxes (value: the item's index in the
// snapshot list, never its upstream key).
const (
	FieldEnableResource = "enable_resource"
	FieldEnableTemplate = "enable_template"
	FieldEnablePrompt   = "enable_prompt"
)

// ReviewItem is one resource, resource template or prompt of the snapshot
// under review (task bdb5zcud), shown like a tool row. Key is the
// display-safe URI, URI template or prompt name.
type ReviewItem struct {
	Index       int
	Field       string // FieldEnable*
	Key         string
	Name        string
	Title       string
	Description string
	Summary     string
	MIMEType    string
	Status      string // added | changed | unchanged
	Enabled     bool   // enabled in the approved review
	Checked     bool   // pre-checked: unchanged and enabled
}

// ReviewItemGroup is the resources, the resource templates or the
// prompts of a snapshot (ID: resources | resource-templates | prompts).
type ReviewItemGroup struct {
	ID      string
	Name    string
	Items   []ReviewItem
	Checked int
}

// ReviewCounts summarises a review: tools in the latest snapshot, those
// enabled in the approved review, new, changed and removed ones.
type ReviewCounts struct{ Total, Enabled, New, Changed, Removed int }

// ReviewView is the latest snapshot compared with the approved one, as
// the review pages show it (BuildReviewView).
type ReviewView struct {
	Version  int // latest version (0: no snapshot)
	From     int // approved version (0: none)
	UpToDate bool
	Tools    []ReviewTool  // snapshot order
	Groups   []ReviewGroup // by name prefix, in name order
	Counts   ReviewCounts
	Selected int  // pre-checked tools and items
	HasReads bool // any tool whose effective kind is read
	// Items are the resources, resource templates and prompts, one group
	// each (empty groups left out); Selectable counts tools and items.
	Items      []ReviewItemGroup
	Selectable int
	Removed    []string
	Resources  KeyDiffView
	Templates  KeyDiffView
	Prompts    KeyDiffView
}

// MaxSummary caps DescriptionSummary (runes, "…" included).
const MaxSummary = 160

// DescriptionSummary is the first line of a display-safe description, cut
// after its first sentence (a ".", "!" or "?" followed by a space and an
// upper-case letter or digit) and capped at MaxSummary runes.
func DescriptionSummary(desc string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(desc), "\n")
	line = strings.TrimSpace(line)
	rs := []rune(line)
	for i := 0; i+2 < len(rs); i++ {
		if (rs[i] == '.' || rs[i] == '!' || rs[i] == '?') && unicode.IsSpace(rs[i+1]) &&
			(unicode.IsUpper(rs[i+2]) || unicode.IsDigit(rs[i+2])) {
			line = string(rs[:i+1])
			break
		}
	}
	if utf8.RuneCountInString(line) > MaxSummary {
		line = strings.TrimSpace(string([]rune(line)[:MaxSummary-1])) + "…"
	}
	return line
}

// groupName is the text before the first "_" of a tool name, or the whole
// name when there is none (or it starts with "_").
func groupName(name string) string {
	if prefix, _, ok := strings.Cut(name, "_"); ok && prefix != "" {
		return prefix
	}
	return name
}

func groupTools(tools []ReviewTool) []ReviewGroup {
	sorted := slices.Clone(tools)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	var groups []ReviewGroup
	at := map[string]int{}
	for _, t := range sorted {
		g := groupName(t.Name)
		i, ok := at[g]
		if !ok {
			i = len(groups)
			at[g] = i
			groups = append(groups, ReviewGroup{Name: g})
		}
		groups[i].Tools = append(groups[i].Tools, t)
		if t.Checked {
			groups[i].Checked++
		}
	}
	sort.SliceStable(groups, func(i, j int) bool { return groups[i].Name < groups[j].Name })
	return groups
}

type reviewData struct {
	Page       ReviewPage
	Title      string
	Caller     caller
	Server     serverView
	CanApprove bool
	NeedsAdmin bool
	Error      string
	// Skipped is what the refresh that rendered this page left out.
	Skipped []snapshot.Skipped
}

// ReviewPage is the data of the shared "review-tools" template
// (ReviewTemplateFS): the view plus the form it posts. Action empty
// renders the tools read-only, without a form.
type ReviewPage struct {
	ReviewView
	ServerName string
	Action     string // form action (path); "" = no form
	CSRFToken  string
	Approve    string // label of the primary submit button
}

// ReviewTemplateFS holds the shared review template ("review-tools") and
// the approval-modes template ("approval-modes"), ReviewTemplate and
// ApprovalTemplate their paths, for the admin pages to parse into their set.
//
//go:embed templates/_review_tools.html templates/_approval_modes.html
var ReviewTemplateFS embed.FS

// ReviewTemplate is the path of the shared review template in ReviewTemplateFS.
const ReviewTemplate = "templates/_review_tools.html"

// ApprovalTemplate is the path of the shared approval-modes template
// ("approval-modes", data ApprovalView) in ReviewTemplateFS.
const ApprovalTemplate = "templates/_approval_modes.html"

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
// when none) for the review pages. Unchanged tools that are enabled are
// pre-checked, reads and writes alike; new and changed tools never are.
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
		tv.Summary = DescriptionSummary(tv.Description)
		if t.Annotations != nil {
			if tv.Title == "" {
				tv.Title = snapshot.DisplayTitle(t.Annotations.Title)
			}
			tv.Destructive = t.Annotations.DestructiveHint == nil || *t.Annotations.DestructiveHint
			tv.DestructiveHint = t.Annotations.DestructiveHint != nil && *t.Annotations.DestructiveHint
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
		tv.Kind = tv.HintKind
		if tv.Override != "" {
			tv.Kind = tv.Override
		}
		tv.Approval = snapshot.ApprovalAsk
		if rv, ok := review[t.Name]; tv.Kind == snapshot.KindRead || ok && tv.Status == "unchanged" && rv.Mode() == snapshot.ApprovalAuto {
			tv.Approval = snapshot.ApprovalAuto
		}
		// New and changed tools start unchecked (decision d6sitdqi);
		// everything already enabled stays so (the user's bulk-approve
		// decision overrides the earlier "writes never pre-checked").
		tv.Checked = tv.Enabled && tv.Status == "unchanged"
		v.count(tv)
		v.Tools = append(v.Tools, tv)
	}
	v.Groups = groupTools(v.Tools)
	v.Selectable = len(v.Tools)
	v.buildItems(latest, current, diff)
	v.Removed = displayKeys(diff.Removed)
	v.Counts.Removed = len(v.Removed)
	v.Resources, v.Templates, v.Prompts = keyView(diff.Resources), keyView(diff.ResourceTemplates), keyView(diff.Prompts)
	return v
}

// buildItems adds the resources, templates and prompts of latest. An item
// is enabled when the approved snapshot has it and its review enables it
// (an approved snapshot without content review counts as all enabled);
// unchanged enabled items are pre-checked, new and changed ones never are.
func (v *ReviewView) buildItems(latest, current *snapshot.Record, diff snapshot.Diff) {
	var cur *snapshot.Snapshot
	var content *snapshot.ContentReview
	if current != nil && current.Snapshot != nil {
		cur, content = current.Snapshot, current.Content
	}
	status := func(k snapshot.KeyDiff, key string) string {
		switch {
		case slices.Contains(k.Added, key):
			return "added"
		case slices.Contains(k.Changed, key):
			return "changed"
		}
		return "unchanged"
	}
	add := func(g *ReviewItemGroup, it ReviewItem) {
		it.Description = snapshot.DisplayDescription(it.Description)
		it.Summary = DescriptionSummary(it.Description)
		it.Checked = it.Enabled && it.Status == "unchanged"
		if it.Checked {
			g.Checked++
			v.Selected++
		}
		g.Items = append(g.Items, it)
	}
	res := ReviewItemGroup{ID: "resources", Name: "Resources"}
	for i, r := range latest.Snapshot.Resources {
		add(&res, ReviewItem{Index: i, Field: FieldEnableResource, Key: snapshot.DisplayTitle(r.URI), Name: snapshot.DisplayName(r.Name),
			Title: snapshot.DisplayTitle(r.Title), Description: r.Description, MIMEType: snapshot.DisplayName(r.MIMEType),
			Status: status(diff.Resources, r.URI), Enabled: hasResource(cur, r.URI) && content.ResourceEnabled(r.URI)})
	}
	tpl := ReviewItemGroup{ID: "resource-templates", Name: "Resource templates"}
	for i, t := range latest.Snapshot.ResourceTemplates {
		add(&tpl, ReviewItem{Index: i, Field: FieldEnableTemplate, Key: snapshot.DisplayTitle(t.URITemplate), Name: snapshot.DisplayName(t.Name),
			Title: snapshot.DisplayTitle(t.Title), Description: t.Description, MIMEType: snapshot.DisplayName(t.MIMEType),
			Status: status(diff.ResourceTemplates, t.URITemplate), Enabled: hasTemplate(cur, t.URITemplate) && content.TemplateEnabled(t.URITemplate)})
	}
	prm := ReviewItemGroup{ID: "prompts", Name: "Prompts"}
	for i, p := range latest.Snapshot.Prompts {
		add(&prm, ReviewItem{Index: i, Field: FieldEnablePrompt, Key: snapshot.DisplayName(p.Name), Name: snapshot.DisplayName(p.Name),
			Title: snapshot.DisplayTitle(p.Title), Description: p.Description,
			Status: status(diff.Prompts, p.Name), Enabled: hasPrompt(cur, p.Name) && content.PromptEnabled(p.Name)})
	}
	for _, g := range []ReviewItemGroup{res, tpl, prm} {
		if len(g.Items) > 0 {
			v.Items = append(v.Items, g)
			v.Selectable += len(g.Items)
		}
	}
}

func hasResource(s *snapshot.Snapshot, uri string) bool {
	return s != nil && slices.ContainsFunc(s.Resources, func(r snapshot.Resource) bool { return r.URI == uri })
}

func hasTemplate(s *snapshot.Snapshot, t string) bool {
	return s != nil && slices.ContainsFunc(s.ResourceTemplates, func(r snapshot.ResourceTemplate) bool { return r.URITemplate == t })
}

func hasPrompt(s *snapshot.Snapshot, name string) bool {
	return s != nil && slices.ContainsFunc(s.Prompts, func(p snapshot.Prompt) bool { return p.Name == name })
}

func (v *ReviewView) count(t ReviewTool) {
	v.Counts.Total++
	switch t.Status {
	case "added":
		v.Counts.New++
	case "changed":
		v.Counts.Changed++
	}
	if t.Enabled {
		v.Counts.Enabled++
	}
	if t.Checked {
		v.Selected++
	}
	if t.Kind == snapshot.KindRead {
		v.HasReads = true
	}
}

func (p *Portal) review(w http.ResponseWriter, r *http.Request, c caller, s *store.MCPServer) {
	p.renderReview(w, r, c, s, http.StatusOK, "")
}

func (p *Portal) renderReview(w http.ResponseWriter, r *http.Request, c caller, s *store.MCPServer, status int, msg string) {
	p.renderReviewSkipped(w, r, c, s, status, msg, nil)
}

// renderReviewSkipped is renderReview listing the items a refresh just
// skipped (snapshot.Skipped: display-safe names).
func (p *Portal) renderReviewSkipped(w http.ResponseWriter, r *http.Request, c caller, s *store.MCPServer, status int, msg string, skipped []snapshot.Skipped) {
	ctx := r.Context()
	data := reviewData{Title: "Review " + s.Name, Caller: c, Server: p.view(ctx, c, s), Error: msg,
		CanApprove: canApprove(c, s), NeedsAdmin: s.Audience == store.MCPAudiencePublished, Skipped: skipped}
	data.Page = ReviewPage{ServerName: data.Server.Name, Approve: "Approve"}
	if data.CanApprove {
		data.Page.Action, data.Page.CSRFToken = "/servers/"+s.ID+"/review", c.CSRFToken
	}
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
	data.Page.ReviewView = BuildReviewView(latest, current)
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
	if !ReviewFormHasSelection(r.PostForm) {
		p.renderReview(w, r, c, s, http.StatusUnprocessableEntity, "Nothing is selected. Select at least one tool, resource or prompt, use Approve with all tools enabled, or explicitly choose Approve with none enabled.")
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
// kind_<i>, approval_<i>, enable_reads, enable_resource / enable_template /
// enable_prompt=<i>, action) into decisions for latest; current is the
// approved record (nil when none). action=approve_all enables every tool,
// resource, template and prompt of latest, writes included (the "Approve with all tools enabled"
// button; writes still go through the policy's confirmation per call).
// Otherwise every checked tool is enabled; every unchecked tool disabled,
// except read tools when "enable all read tools" is on (left to
// EnableReads, which never re-enables a tool a reviewer disabled before
// and never enables writes).
//
// Approval modes: approval_<i> (ask | auto) sets a write tool's mode; the
// bulk actions approve_auto ("Run selected without asking") and
// approve_ask ("Ask for selected") approve like approve and set every
// checked write tool to auto or ask; approve_all keeps the posted modes.
// Read tools get no approval decision (they always run without one).
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
	all := form.Get("action") == ActionApproveAll
	d := snapshot.ReviewDecisions{Tools: map[string]snapshot.Decision{}, EnableReads: !all && form.Get("enable_reads") != ""}
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
		case all, checked[i]:
			dec.Enabled = enabled(true)
		case d.EnableReads && eff == snapshot.KindRead:
			// left to EnableReads
		default:
			dec.Enabled = enabled(false)
		}
		if eff == snapshot.KindWrite {
			dec.Approval = approvalFromForm(form, i, checked[i])
		}
		d.Tools[t.Name] = dec
	}
	// Resources, templates and prompts: checked (or approve_all) enables,
	// unchecked disables.
	picked := func(field string) map[int]bool {
		out := map[int]bool{}
		for _, v := range form[field] {
			if i, err := strconv.Atoi(v); err == nil {
				out[i] = true
			}
		}
		return out
	}
	res, tpl, prm := picked(FieldEnableResource), picked(FieldEnableTemplate), picked(FieldEnablePrompt)
	d.Resources = map[string]bool{}
	for i, r := range latest.Snapshot.Resources {
		d.Resources[r.URI] = all || res[i]
	}
	d.ResourceTemplates = map[string]bool{}
	for i, t := range latest.Snapshot.ResourceTemplates {
		d.ResourceTemplates[t.URITemplate] = all || tpl[i]
	}
	d.Prompts = map[string]bool{}
	for i, p := range latest.Snapshot.Prompts {
		d.Prompts[p.Name] = all || prm[i]
	}
	return d
}

// ReviewFormHasSelection reports whether a review POST can proceed without
// accidentally approving an empty snapshot. approve_all and approve_none are
// explicit choices; the ordinary and approval-mode actions require at least
// one checked capability (or the legacy enable_reads choice).
func ReviewFormHasSelection(form url.Values) bool {
	switch form.Get("action") {
	case ActionApproveAll, ActionApproveNone:
		return true
	}
	if form.Get("enable_reads") != "" {
		return true
	}
	for _, field := range []string{"enable", FieldEnableResource, FieldEnableTemplate, FieldEnablePrompt} {
		if len(form[field]) != 0 {
			return true
		}
	}
	return false
}

// Review form action values beyond the plain "approve".
const (
	// ActionApproveAll enables every tool of the posted version.
	ActionApproveAll = "approve_all"
	// ActionApproveNone explicitly approves the posted version while keeping
	// every capability disabled. Plain approve may not do this accidentally.
	ActionApproveNone = "approve_none"
	// ActionApproveAuto approves and sets the checked write tools to run
	// without asking.
	ActionApproveAuto = "approve_auto"
	// ActionApproveAsk approves and sets the checked write tools to ask.
	ActionApproveAsk = "approve_ask"
)

// approvalFromForm is the approval decision of write tool i: the bulk
// action for a checked tool, else the posted approval_<i>, else none.
func approvalFromForm(form url.Values, i int, checked bool) *snapshot.Approval {
	mode := snapshot.Approval(form.Get("approval_" + strconv.Itoa(i)))
	switch action := form.Get("action"); {
	case checked && action == ActionApproveAuto:
		mode = snapshot.ApprovalAuto
	case checked && action == ActionApproveAsk:
		mode = snapshot.ApprovalAsk
	}
	if !mode.Valid() {
		return nil
	}
	return &mode
}

func enabled(b bool) *bool { return &b }
