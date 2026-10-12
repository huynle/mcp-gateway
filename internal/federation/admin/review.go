package admin

import (
	"errors"
	"net/http"
	"strconv"

	fedportal "github.com/huynle/mcp-gateway/internal/federation/portal"
	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
)

type reviewData struct {
	Page   fedportal.ReviewPage // the shared "review-tools" view
	Title  string
	Caller caller
	Server serverRow
	Error  string
	// Skipped is what the refresh that rendered this page left out.
	Skipped []snapshot.Skipped
}

// review shows the latest snapshot against the approved one with the same
// diff and rules as the servers portal (fedportal.BuildReviewView). Admins
// review any server, private or published (Actor{Admin: true}).
func (a *Admin) review(w http.ResponseWriter, r *http.Request, c caller, s *Server) {
	a.renderReview(w, r, c, s, http.StatusOK, "")
}

func (a *Admin) renderReview(w http.ResponseWriter, r *http.Request, c caller, s *Server, status int, msg string) {
	a.renderReviewSkipped(w, r, c, s, status, msg, nil)
}

// renderReviewSkipped is renderReview listing the items a refresh just
// skipped (snapshot.Skipped: display-safe names).
func (a *Admin) renderReviewSkipped(w http.ResponseWriter, r *http.Request, c caller, s *Server, status int, msg string, skipped []snapshot.Skipped) {
	ctx := r.Context()
	byID, _, err := a.roleMap(r)
	if err != nil {
		a.fail(w, r, "list roles", err)
		return
	}
	data := reviewData{Title: "Review " + s.Name, Caller: c, Server: rowOf(s, byID), Error: msg, Skipped: skipped}
	data.Page = fedportal.ReviewPage{ServerName: data.Server.Name, Action: "/admin/servers/" + s.ID + "/review",
		CSRFToken: c.CSRFToken, Approve: "Approve as admin"}
	latest, err := a.d.Snapshots.Latest(ctx, c.snapActor(), s.ID)
	switch {
	case errors.Is(err, snapshot.ErrNoSnapshot):
		a.render(w, r, status, "review.html", data)
		return
	case err != nil:
		a.fail(w, r, "latest snapshot", err)
		return
	}
	current, err := a.d.Snapshots.Current(ctx, c.snapActor(), s.ID)
	if err != nil && !errors.Is(err, snapshot.ErrNoSnapshot) {
		a.fail(w, r, "current snapshot", err)
		return
	}
	data.Page.ReviewView = fedportal.BuildReviewView(latest, current)
	a.render(w, r, status, "review.html", data)
}

const staleMessage = "The server's tools changed since this page was loaded. Review them again."

// approve approves the posted version as an admin, then tells the hook.
func (a *Admin) approve(w http.ResponseWriter, r *http.Request, c caller, s *Server) {
	ctx := r.Context()
	version, err := strconv.Atoi(r.PostForm.Get("version"))
	latest, lerr := a.d.Snapshots.Latest(ctx, c.snapActor(), s.ID)
	if lerr != nil && !errors.Is(lerr, snapshot.ErrNoSnapshot) {
		a.fail(w, r, "latest snapshot", lerr)
		return
	}
	if err != nil || lerr != nil || latest.Version != version {
		a.renderReview(w, r, c, s, http.StatusConflict, staleMessage)
		return
	}
	var current *snapshot.Record
	if cur, err := a.d.Snapshots.Current(ctx, c.snapActor(), s.ID); err == nil {
		current = cur
	}
	d := fedportal.ReviewDecisionsFromForm(r.PostForm, latest, current)
	approved, err := a.d.Snapshots.Approve(ctx, c.snapActor(), s.ID, version, d)
	switch {
	case errors.Is(err, snapshot.ErrStaleVersion):
		a.renderReview(w, r, c, s, http.StatusConflict, staleMessage)
		return
	case err != nil:
		a.fail(w, r, "approve snapshot", err)
		return
	}
	enabled := 0
	for _, t := range d.Tools {
		if t.Enabled != nil && *t.Enabled {
			enabled++
		}
	}
	res := serverResource(s)
	res["version"] = strconv.Itoa(version)
	res["enabled_tools"] = strconv.Itoa(enabled)
	res["auto_run"] = strconv.Itoa(len(approved.Review.AutoRunWrites()))
	a.record(ctx, c, "mcp_server.reviewed", res)
	a.changed(ctx, s.ID)
	http.Redirect(w, r, "/admin/servers/"+s.ID+"?done=reviewed", http.StatusSeeOther)
}
