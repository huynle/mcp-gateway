package portal

import (
	"net/http"
	"sort"

	"github.com/huynle/mcp-gateway/internal/identity"
)

type adminSettingsData struct {
	Title       string
	Rates, Caps bool
}

type rateAppRow struct {
	App    string
	PerMin int
}
type rateUserRow struct {
	ID, Name    string
	Admin, Self *int
	Effective   int
}
type adminRateData struct {
	Title                   string
	UserDefault, AppDefault int
	Apps                    []rateAppRow
	Users                   []rateUserRow
}

func (p *Portal) adminSettings(w http.ResponseWriter, r *http.Request) {
	p.render(w, r, http.StatusOK, "admin_settings.html", adminSettingsData{Title: "Organization settings", Rates: p.rateSettings != nil, Caps: p.resourceCaps != nil})
}

func (p *Portal) adminRateLimits(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	snap := p.rateSettings.Snapshot(ctx)
	data := adminRateData{Title: "Rate limits", UserDefault: snap.UserDefault, AppDefault: snap.AppDefault}
	for app, n := range snap.Apps {
		data.Apps = append(data.Apps, rateAppRow{app, n})
	}
	sort.Slice(data.Apps, func(i, j int) bool { return data.Apps[i].App < data.Apps[j].App })
	users, err := p.svc.ListUsers(ctx)
	if err != nil {
		p.serverError(w, r, err)
		return
	}
	for _, u := range users {
		lim := snap.Users[u.ID]
		eff, _ := p.rateSettings.Limits(ctx, u.ID, "")
		data.Users = append(data.Users, rateUserRow{ID: u.ID, Name: u.DisplayName, Admin: lim.Admin, Self: lim.Self, Effective: eff})
	}
	p.render(w, r, http.StatusOK, "admin_rate_limits.html", data)
}

func (p *Portal) setOrgRateLimits(w http.ResponseWriter, r *http.Request) {
	u, eu := optionalPositiveInt(r.PostFormValue("user_per_min"))
	a, ea := optionalPositiveInt(r.PostFormValue("app_per_min"))
	if eu != nil || ea != nil || u == nil || a == nil {
		p.errorPage(w, r, http.StatusUnprocessableEntity, "Invalid rate limit", "Both limits must be positive numbers.")
		return
	}
	actor := identity.PrincipalFrom(r.Context()).UserID
	if err := p.rateSettings.SetOrg(r.Context(), actor, *u, *a); err != nil {
		p.serverError(w, r, err)
		return
	}
	http.Redirect(w, r, "/admin/settings/rate-limits?saved=org", http.StatusSeeOther)
}
func (p *Portal) setAppRateLimit(w http.ResponseWriter, r *http.Request) {
	n, err := optionalPositiveInt(r.PostFormValue("per_min"))
	if err == nil {
		err = p.rateSettings.SetApp(r.Context(), identity.PrincipalFrom(r.Context()).UserID, r.PostFormValue("app"), n)
	}
	if err != nil {
		p.errorPage(w, r, http.StatusUnprocessableEntity, "Invalid app rate limit", err.Error())
		return
	}
	http.Redirect(w, r, "/admin/settings/rate-limits?saved=app", http.StatusSeeOther)
}
func (p *Portal) setUserRateLimit(w http.ResponseWriter, r *http.Request) {
	n, err := optionalPositiveInt(r.PostFormValue("per_min"))
	if err == nil {
		err = p.rateSettings.SetUserAdmin(r.Context(), identity.PrincipalFrom(r.Context()).UserID, r.PostFormValue("user_id"), n)
	}
	if err != nil {
		p.errorPage(w, r, http.StatusUnprocessableEntity, "Invalid user rate limit", err.Error())
		return
	}
	http.Redirect(w, r, "/admin/settings/rate-limits?saved=user", http.StatusSeeOther)
}
