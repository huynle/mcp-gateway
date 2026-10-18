package portal

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/store"
)

// Public sign-up pages (identity/signup.go):
//
//	GET  /pending                          a pending account's only page
//	POST /admin/users/{id}/approve         admin: pending -> active + default role
//	POST /admin/users/{id}/reject          admin: pending -> disabled
//	POST /admin/users/invites              admin (invite mode): create, code shown once
//	POST /admin/users/invites/{id}/revoke  admin (invite mode)

// maxInviteDays bounds the invite lifetime the form accepts.
const maxInviteDays = 30

// maxInviteQuery bounds the invite code the sign-in page carries.
const maxInviteQuery = 128

type pendingData struct {
	DisplayName string
	CSRFToken   string
}

// pendingPage is the "waiting for approval" page. Anyone else is sent
// where they belong.
func (p *Portal) pendingPage(w http.ResponseWriter, r *http.Request) {
	if identity.PrincipalFrom(r.Context()) != nil {
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	pu := identity.PendingFrom(r.Context())
	if pu == nil {
		http.Redirect(w, r, "/signin", http.StatusSeeOther)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	p.render(w, r, http.StatusOK, "pending.html", pendingData{DisplayName: pu.DisplayName, CSRFToken: pu.CSRFToken})
}

// redirectPending sends a pending account to its page; it reports
// whether it did.
func redirectPending(w http.ResponseWriter, r *http.Request) bool {
	if identity.PrincipalFrom(r.Context()) == nil && identity.PendingFrom(r.Context()) != nil {
		http.Redirect(w, r, identity.PendingPath, http.StatusSeeOther)
		return true
	}
	return false
}

func (p *Portal) adminApprove(w http.ResponseWriter, r *http.Request) {
	actor := identity.PrincipalFrom(r.Context())
	id := r.PathValue("id")
	p.adminAction(w, r, id, p.svc.ApproveUser(r.Context(), actor.UserID, id))
}

func (p *Portal) adminReject(w http.ResponseWriter, r *http.Request) {
	actor := identity.PrincipalFrom(r.Context())
	id := r.PathValue("id")
	p.adminAction(w, r, id, p.svc.RejectUser(r.Context(), actor.UserID, id))
}

// inviteRow is one invite as the users page lists it (never the code).
type inviteRow struct {
	ID, Label, State string
	Created, Expires time.Time
}

func inviteRows(invites []store.SignupInvite, now time.Time) []inviteRow {
	out := make([]inviteRow, 0, len(invites))
	for _, inv := range invites {
		state := "unused"
		switch {
		case inv.UsedAt != nil:
			state = "used"
		case inv.RevokedAt != nil:
			state = "revoked"
		case !inv.ExpiresAt.After(now):
			state = "expired"
		}
		out = append(out, inviteRow{ID: inv.ID, Label: inv.Label, State: state, Created: inv.CreatedAt, Expires: inv.ExpiresAt})
	}
	return out
}

// newInvite is the invite just created, shown once.
type newInvite struct {
	Link, Label string
	Expires     time.Time
}

func (p *Portal) adminCreateInvite(w http.ResponseWriter, r *http.Request) {
	if p.svc.SignupMode() != config.SignupInvite {
		p.notFound(w, r)
		return
	}
	days, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue("days")))
	if err != nil || days < 1 || days > maxInviteDays {
		p.errorPage(w, r, http.StatusUnprocessableEntity, "Invalid invite", "The invite must be valid for 1 to 30 days.")
		return
	}
	label := strings.TrimSpace(r.PostFormValue("label"))
	if len(label) > identity.MaxInviteLabel {
		p.errorPage(w, r, http.StatusUnprocessableEntity, "Invalid invite", "The note must be at most 100 characters.")
		return
	}
	actor := identity.PrincipalFrom(r.Context())
	code, inv, err := p.svc.CreateInvite(r.Context(), actor.UserID, label, time.Duration(days)*24*time.Hour)
	if err != nil {
		p.serverError(w, r, err)
		return
	}
	data, err := p.loadAdminUsers(r)
	if err != nil {
		p.serverError(w, r, err)
		return
	}
	data.NewInvite = &newInvite{
		Link:    strings.TrimRight(p.svc.BaseURL(), "/") + "/signin?invite=" + url.QueryEscape(code),
		Label:   inv.Label,
		Expires: inv.ExpiresAt,
	}
	// The code is in this response only: never cache it.
	w.Header().Set("Cache-Control", "no-store")
	p.render(w, r, http.StatusOK, "admin_users.html", data)
}

func (p *Portal) adminRevokeInvite(w http.ResponseWriter, r *http.Request) {
	if p.svc.SignupMode() != config.SignupInvite {
		p.notFound(w, r)
		return
	}
	actor := identity.PrincipalFrom(r.Context())
	err := p.svc.RevokeInvite(r.Context(), actor.UserID, r.PathValue("id"))
	switch {
	case errors.Is(err, store.ErrNotFound):
		p.notFound(w, r)
	case err != nil:
		p.serverError(w, r, err)
	default:
		http.Redirect(w, r, "/admin/users#invites", http.StatusSeeOther)
	}
}

// inviteParam is the invite code the sign-in page forwards to /auth/.../start.
func inviteParam(r *http.Request) string {
	code := strings.TrimSpace(r.URL.Query().Get("invite"))
	if len(code) > maxInviteQuery {
		return ""
	}
	return code
}
