package admin

import (
	"errors"
	"net/http"
	"strconv"

	fedportal "github.com/huynle/mcp-gateway/internal/federation/portal"
	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
)

// approvalView is the shared approval-modes block for the admin server
// page: an admin edits the modes of any server, private or published (for
// a published server they are the default for the roles that allow its
// tools). Nil when nothing is approved.
func (a *Admin) approvalView(r *http.Request, c caller, s *Server) (*fedportal.ApprovalView, error) {
	cur, err := a.d.Snapshots.Current(r.Context(), c.snapActor(), s.ID)
	if errors.Is(err, snapshot.ErrNoSnapshot) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	v := fedportal.BuildApprovalView(cur)
	if v != nil {
		v.Action, v.CSRFToken = "/admin/servers/"+s.ID+"/approval", c.CSRFToken
	}
	return v, nil
}

// setApprovalModes changes the approval modes of the approved snapshot
// as an admin (no new review), audits it and tells the hook.
func (a *Admin) setApprovalModes(w http.ResponseWriter, r *http.Request, c caller, s *Server) {
	ctx := r.Context()
	current, err := a.d.Snapshots.Current(ctx, c.snapActor(), s.ID)
	if err != nil && !errors.Is(err, snapshot.ErrNoSnapshot) {
		a.fail(w, r, "current snapshot", err)
		return
	}
	version, verr := strconv.Atoi(r.PostForm.Get("version"))
	if current == nil || verr != nil || version != current.Version {
		a.renderDetail(w, r, c, s, http.StatusConflict, "", "The server's approved tools changed since this page was loaded. Try again.")
		return
	}
	modes, err := fedportal.ApprovalModesFromForm(r.PostForm, current)
	if err != nil {
		a.renderDetail(w, r, c, s, http.StatusUnprocessableEntity, "", "Choose Ask or Auto for each tool.")
		return
	}
	rec, changed, err := a.d.Snapshots.SetApprovalModes(ctx, c.snapActor(), s.ID, modes)
	switch {
	case errors.Is(err, snapshot.ErrNoSnapshot):
		a.renderDetail(w, r, c, s, http.StatusConflict, "", "The server's approved tools changed since this page was loaded. Try again.")
		return
	case err != nil:
		a.fail(w, r, "set approval modes", err)
		return
	}
	res := fedportal.ApprovalAuditResource(&s.MCPServer, rec, changed)
	delete(res, "action")
	a.record(ctx, c, fedportal.ApprovalModesChangedEvent, res)
	a.changed(ctx, s.ID)
	a.done(w, r, s, "modes")
}
