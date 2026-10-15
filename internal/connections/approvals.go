package connections

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"

	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/policy"
	"github.com/huynle/mcp-gateway/internal/store"
)

// ToolApprovals is the policy service's org-wide approval modes of vendor
// app write tools (*policy.Service).
type ToolApprovals interface {
	AppApprovalModes(ctx context.Context, app string) ([]policy.AppToolMode, error)
	SetAppApprovalModes(ctx context.Context, actorID, app string, modes map[string]snapshot.Approval) (policy.AppApprovalChange, error)
}

// SetToolApprovals wires the "Tool approvals" section of the vendor app
// pages (nil: no section, and POST .../approvals is not found).
func (p *Portal) SetToolApprovals(ta ToolApprovals) { p.approvals = ta }

// AppsFor returns the connector apps that use vendor's accounts (MapApp;
// an unmapped vendor's one app is named after it).
func (s *Service) AppsFor(vendor string) []string { return s.appsFor(vendor) }

// VendorFor returns the vendor whose accounts app uses (the app's own name
// when it is not mapped).
func (s *Service) VendorFor(app string) string { return s.vendorFor(app) }

// invalidModesMessage is the shared wording of the servers pages.
const invalidModesMessage = "Choose Ask or Auto for each tool."

// approvalSection is one app of the vendor in the Tool approvals section:
// its write tools with their modes, one form per app.
type approvalSection struct {
	App       string
	Writes    []policy.AppToolMode
	Ask, Auto int
}

// approvalSections lists the vendor's apps that have write tools, in the
// order they were mapped.
func (p *Portal) approvalSections(ctx context.Context, vendor string) ([]approvalSection, error) {
	if p.approvals == nil {
		return nil, nil
	}
	var out []approvalSection
	for _, app := range p.svc.AppsFor(vendor) {
		modes, err := p.approvals.AppApprovalModes(ctx, app)
		if errors.Is(err, policy.ErrApprovalApp) {
			continue
		}
		if err != nil {
			return nil, err
		}
		sec := approvalSection{App: app, Writes: modes}
		for _, m := range modes {
			if m.Mode == snapshot.ApprovalAsk {
				sec.Ask++
			} else {
				sec.Auto++
			}
		}
		out = append(out, sec)
	}
	return out, nil
}

// approvalsPath is where the vendor's approval forms post.
func approvalsPath(vendor string) string { return "/admin/vendor-apps/" + vendor + "/approvals" }

// modesFromForm reads one app's posted form: all = ask | auto sets every
// write tool; otherwise mode_<tool> sets that tool (tools not posted keep
// their mode). Any other value is snapshot.ErrInvalidApproval.
func modesFromForm(form url.Values, writes []policy.AppToolMode) (map[string]snapshot.Approval, error) {
	modes := map[string]snapshot.Approval{}
	all := snapshot.Approval(form.Get("all"))
	if all != "" && !all.Valid() {
		return nil, snapshot.ErrInvalidApproval
	}
	for _, m := range writes {
		if all != "" {
			modes[m.Tool] = all
			continue
		}
		raw, posted := form["mode_"+m.Tool]
		if !posted || len(raw) == 0 {
			continue
		}
		mode := snapshot.Approval(raw[0])
		if !mode.Valid() {
			return nil, snapshot.ErrInvalidApproval
		}
		modes[m.Tool] = mode
	}
	return modes, nil
}

// adminApprovals saves one app's approval modes (POST
// /admin/vendor-apps/{vendor}/approvals, app = the connector app).
func (p *Portal) adminApprovals(w http.ResponseWriter, r *http.Request, c caller) {
	vendor, _ := normalizeKey(r.PathValue("vendor"), "")
	if p.approvals == nil || !KnownVendor(vendor) {
		http.NotFound(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "the form could not be read", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	app := r.PostForm.Get("app")
	if !slices.Contains(p.svc.AppsFor(vendor), app) {
		http.NotFound(w, r)
		return
	}
	current, err := p.approvals.AppApprovalModes(ctx, app)
	switch {
	case errors.Is(err, policy.ErrApprovalApp):
		http.NotFound(w, r)
		return
	case err != nil:
		p.fail(w, r, "load approval modes", err)
		return
	}
	modes, err := modesFromForm(r.PostForm, current)
	if err == nil {
		_, err = p.approvals.SetAppApprovalModes(ctx, c.UserID, app, modes)
	}
	switch {
	case errors.Is(err, snapshot.ErrInvalidApproval), errors.Is(err, policy.ErrApprovalMode), errors.Is(err, policy.ErrApprovalTool):
		p.renderEdit(w, r, c, vendor, Variants(vendor)[0], http.StatusUnprocessableEntity, invalidModesMessage)
		return
	case err != nil:
		p.fail(w, r, "set approval modes", err)
		return
	}
	http.Redirect(w, r, adminPath(vendor, Variants(vendor)[0])+"?approvals=1#approvals", http.StatusSeeOther)
}

// renderEdit renders the vendor app editor with the approvals section;
// approvalsErr is shown in that section.
func (p *Portal) renderEdit(w http.ResponseWriter, r *http.Request, c caller, vendor, variant string, status int, approvalsErr string) {
	app, err := p.svc.VendorApp(r.Context(), vendor, variant)
	switch {
	case errors.Is(err, store.ErrNotFound):
		app = Defaults(vendor, variant)
	case err != nil:
		p.fail(w, r, "load vendor app", err)
		return
	}
	data := p.formData(c, app, r.URL.Query().Get("saved") == "1", "")
	if err := p.withApprovals(r, &data, approvalsErr); err != nil {
		p.fail(w, r, "load approval modes", err)
		return
	}
	p.render(w, r, status, "admin_vendor_app.html", data)
}

// withApprovals fills the editor's Tool approvals section.
func (p *Portal) withApprovals(r *http.Request, data *adminFormData, approvalsErr string) error {
	sections, err := p.approvalSections(r.Context(), data.App.Vendor)
	if err != nil {
		return err
	}
	data.Approvals, data.ApprovalsAction = sections, approvalsPath(data.App.Vendor)
	data.ApprovalsSaved, data.ApprovalsError = r.URL.Query().Get("approvals") == "1", approvalsErr
	return nil
}
