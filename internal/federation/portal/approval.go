package portal

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/store"
)

// ApprovalTool is one enabled write tool of the approved snapshot as the
// approval-modes block shows it. Index (position in the approved
// snapshot) names the form field mode_<i>.
type ApprovalTool struct {
	Index   int
	Name    string
	Summary string
	Mode    snapshot.Approval
	// DestructiveHint: annotated destructiveHint=true upstream (warned
	// about when the tool runs without asking).
	DestructiveHint bool
}

// ApprovalView is the data of the shared "approval-modes" template
// (ApprovalTemplate): the approved snapshot's modes as counts and the
// enabled write tools, plus the edit form when Action is set (a POST of
// mode_<i> = ask | auto per tool, or all = ask | auto for every write).
// Note explains who may change the modes when the caller may not.
type ApprovalView struct {
	Version   int
	Counts    snapshot.ApprovalCounts
	Writes    []ApprovalTool
	Action    string
	CSRFToken string
	Note      string
}

// BuildApprovalView summarises the approval modes of the approved record
// (nil when nothing is approved).
func BuildApprovalView(current *snapshot.Record) *ApprovalView {
	if current == nil || current.Snapshot == nil {
		return nil
	}
	v := &ApprovalView{Version: current.Version, Counts: current.Review.ApprovalCounts()}
	for i, t := range current.Snapshot.Tools {
		rv, ok := current.Review[t.Name]
		if !ok || !rv.Enabled || rv.Kind != snapshot.KindWrite {
			continue
		}
		at := ApprovalTool{Index: i, Name: snapshot.DisplayName(t.Name), Mode: rv.Mode(),
			Summary: DescriptionSummary(snapshot.DisplayDescription(t.Description))}
		if a := t.Annotations; a != nil && a.DestructiveHint != nil && *a.DestructiveHint {
			at.DestructiveHint = true
		}
		v.Writes = append(v.Writes, at)
	}
	return v
}

// ApprovalModesFromForm turns a posted approval-modes form into modes for
// the approved record: all = ask | auto sets every enabled write tool;
// otherwise mode_<i> sets write tool i (reads, disabled tools and unknown
// indexes are skipped). A value other than ask or auto returns
// snapshot.ErrInvalidApproval.
func ApprovalModesFromForm(form url.Values, current *snapshot.Record) (map[string]snapshot.Approval, error) {
	modes := map[string]snapshot.Approval{}
	all := snapshot.Approval(form.Get("all"))
	if all != "" && !all.Valid() {
		return nil, snapshot.ErrInvalidApproval
	}
	for i, t := range current.Snapshot.Tools {
		rv, ok := current.Review[t.Name]
		if !ok || !rv.Enabled || rv.Kind != snapshot.KindWrite {
			continue
		}
		if all != "" {
			modes[t.Name] = all
			continue
		}
		raw, posted := form["mode_"+strconv.Itoa(i)]
		if !posted || len(raw) == 0 {
			continue
		}
		mode := snapshot.Approval(raw[0])
		if !mode.Valid() {
			return nil, snapshot.ErrInvalidApproval
		}
		modes[t.Name] = mode
	}
	return modes, nil
}

// ApprovalModesChangedEvent is the audit action of an approval-mode edit.
const ApprovalModesChangedEvent = "mcp_server.approval_modes_changed"

// ApprovalAuditResource is the audit resource of an approval-mode edit:
// the server, how many tools changed and how many writes now run without
// asking (names and counts only).
func ApprovalAuditResource(s *store.MCPServer, rec *snapshot.Record, changed int) map[string]string {
	return map[string]string{
		"action": ApprovalModesChangedEvent, "server_id": s.ID, "server": s.Name, "owner_user_id": s.OwnerUserID,
		"version": strconv.Itoa(rec.Version), "changed": strconv.Itoa(changed),
		"auto_run": strconv.Itoa(len(rec.Review.AutoRunWrites())),
	}
}

const (
	publishedModesMessage = "This server is published: an admin sets its approval modes."
	staleModesMessage     = "The server's approved tools changed since this page was loaded. Try again."
	invalidModesMessage   = "Choose Ask or Auto for each tool."
)

// setApprovalModes changes the approval modes of the approved snapshot
// without a new review (owner of a private server only; an admin changes
// a published one on the admin pages), audits it and reloads.
func (p *Portal) setApprovalModes(w http.ResponseWriter, r *http.Request, c caller, s *store.MCPServer) {
	ctx := r.Context()
	if s.OwnerUserID != c.UserID {
		p.notFound(w, r)
		return
	}
	if !canApprove(c, s) {
		p.renderDetailError(w, r, c, s, http.StatusForbidden, publishedModesMessage)
		return
	}
	current, err := p.d.Snapshots.Current(ctx, c.snapActor(), s.ID)
	if err != nil && !errors.Is(err, snapshot.ErrNoSnapshot) {
		p.fail(w, r, "current snapshot", err)
		return
	}
	version, verr := strconv.Atoi(r.PostForm.Get("version"))
	if current == nil || verr != nil || version != current.Version {
		p.renderDetailError(w, r, c, s, http.StatusConflict, staleModesMessage)
		return
	}
	modes, err := ApprovalModesFromForm(r.PostForm, current)
	if err != nil {
		p.renderDetailError(w, r, c, s, http.StatusUnprocessableEntity, invalidModesMessage)
		return
	}
	rec, changed, err := p.d.Snapshots.SetApprovalModes(ctx, c.snapActor(), s.ID, modes)
	switch {
	case errors.Is(err, snapshot.ErrReviewNotAllowed):
		p.renderDetailError(w, r, c, s, http.StatusForbidden, publishedModesMessage)
		return
	case errors.Is(err, snapshot.ErrNoSnapshot):
		p.renderDetailError(w, r, c, s, http.StatusConflict, staleModesMessage)
		return
	case err != nil:
		p.fail(w, r, "set approval modes", err)
		return
	}
	p.audit(r, c, ApprovalAuditResource(s, rec, changed))
	p.log.Info("approval modes changed", "event", ApprovalModesChangedEvent, "user_id", c.UserID, "server_id", s.ID, "changed", changed)
	p.changed(ctx, s.ID)
	http.Redirect(w, r, "/servers/"+s.ID+"?modes=1", http.StatusSeeOther)
}

// audit records a change made on the servers pages. A failure is logged,
// never returned: the change is already committed.
func (p *Portal) audit(r *http.Request, c caller, resource map[string]string) {
	ctx := r.Context()
	ev := audit.Event{
		Time: time.Now(), UserID: c.UserID, ResourceIdentity: resource, Decision: "allow", Outcome: "succeeded",
		RequestID: observability.RequestIDFromContext(ctx),
	}
	if err := p.d.Audit.Record(ctx, ev); err != nil {
		p.log.Error("audit event not recorded", "event", "federation.portal_audit_failed", "action", resource["action"],
			"error", observability.RedactError(err))
	}
}
