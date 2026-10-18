package portal

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/huynle/mcp-gateway/internal/caps"
	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/settings"
)

// ResourceCaps are the per-user resource caps (*settings.CapsService):
// My account shows the user's limits and usage; administrators change the
// organization values (/admin/settings/resource-caps) and one user's
// overrides (/admin/users/{id}/limits). Changes are audited by the
// implementation.
type ResourceCaps interface {
	Effective(ctx context.Context, userID string) caps.Values
	Usage(ctx context.Context, userID string) (caps.Values, error)
	Defaults() caps.Values
	CapsSnapshot(ctx context.Context) settings.CapsSnapshot
	SetOrg(ctx context.Context, actor string, p caps.Patch) error
	SetUser(ctx context.Context, actor, userID string, p caps.Patch) error
}

// SetResourceCaps adds the resource limits to My account and the admin
// pages. Call before Handler.
func (p *Portal) SetResourceCaps(c ResourceCaps) { p.resourceCaps = c }

// capRow is one resource on a page.
type capRow struct {
	Field, Noun string
	Limit       int  // effective (0 = unlimited)
	Used        *int // nil: unknown
	Org         *int // organization value; nil = ENV default
	Default     int
	Override    *int // the user's administrator override
}

type limitsView struct{ Rows []capRow }

func ptrOf(v caps.Values, r caps.Resource) *int {
	if n, ok := v[r]; ok {
		return &n
	}
	return nil
}

func (p *Portal) capRows(ctx context.Context, userID string, withUsage bool) []capRow {
	eff := p.resourceCaps.Effective(ctx, userID)
	snap := p.resourceCaps.CapsSnapshot(ctx)
	def := p.resourceCaps.Defaults()
	var use caps.Values
	if withUsage {
		if u, err := p.resourceCaps.Usage(ctx, userID); err == nil {
			use = u
		} else {
			p.log.Warn("resource usage unavailable", "event", "portal.caps_usage_failed", "error", err.Error())
		}
	}
	rows := make([]capRow, 0, len(caps.Resources))
	for _, r := range caps.Resources {
		row := capRow{Field: string(r), Noun: r.Noun(), Limit: eff[r], Org: ptrOf(snap.Org, r), Default: def[r], Override: ptrOf(snap.Users[userID], r)}
		if use != nil {
			row.Used = ptrOf(use, r)
		}
		rows = append(rows, row)
	}
	return rows
}

type capUserRow struct {
	ID, Name  string
	Overrides string
}

type adminCapsData struct {
	Title string
	Rows  []capRow
	Users []capUserRow
}

func (p *Portal) adminResourceCaps(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	data := adminCapsData{Title: "Resource limits", Rows: p.capRows(ctx, "", false)}
	users, err := p.svc.ListUsers(ctx)
	if err != nil {
		p.serverError(w, r, err)
		return
	}
	snap := p.resourceCaps.CapsSnapshot(ctx)
	for _, u := range users {
		var parts []string
		for _, res := range caps.Resources {
			if n, ok := snap.Users[u.ID][res]; ok {
				parts = append(parts, string(res)+"="+strconv.Itoa(n))
			}
		}
		data.Users = append(data.Users, capUserRow{ID: u.ID, Name: u.DisplayName, Overrides: strings.Join(parts, ", ")})
	}
	sort.SliceStable(data.Users, func(i, j int) bool { return data.Users[i].Name < data.Users[j].Name })
	p.render(w, r, http.StatusOK, "admin_resource_caps.html", data)
}

var errCapForm = errors.New("portal: invalid resource cap")

// capPatchForm reads the posted resource fields: blank clears (inherit),
// a number 0..caps.Max sets (0 = unlimited); fields not posted are kept.
func capPatchForm(r *http.Request) (caps.Patch, error) {
	if err := r.ParseForm(); err != nil {
		return nil, errCapForm
	}
	pt := caps.Patch{}
	for _, res := range caps.Resources {
		vals, ok := r.PostForm[string(res)]
		if !ok {
			continue
		}
		raw := strings.TrimSpace(vals[0])
		if raw == "" {
			pt[res] = nil
			continue
		}
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 || n > caps.Max {
			return nil, errCapForm
		}
		pt[res] = &n
	}
	if len(pt) == 0 {
		return nil, errCapForm
	}
	return pt, nil
}

const capFormMessage = "Limits are whole numbers between 0 (unlimited) and 100000; leave a field blank to use the default."

func (p *Portal) setOrgResourceCaps(w http.ResponseWriter, r *http.Request) {
	pt, err := capPatchForm(r)
	if err == nil {
		err = p.resourceCaps.SetOrg(r.Context(), identity.PrincipalFrom(r.Context()).UserID, pt)
	}
	switch {
	case errors.Is(err, errCapForm) || errors.Is(err, settings.ErrInvalidCap):
		p.errorPage(w, r, http.StatusUnprocessableEntity, "Invalid resource limit", capFormMessage)
		return
	case err != nil:
		p.serverError(w, r, err)
		return
	}
	http.Redirect(w, r, "/admin/settings/resource-caps?saved=org", http.StatusSeeOther)
}

type adminUserLimitsData struct {
	Title    string
	ID, Name string
	Rows     []capRow
}

// limitsUser returns the user named in the path, or false (404).
func (p *Portal) limitsUser(r *http.Request) (identity.UserSummary, bool, error) {
	id := r.PathValue("id")
	users, err := p.svc.ListUsers(r.Context())
	if err != nil {
		return identity.UserSummary{}, false, err
	}
	for _, u := range users {
		if u.ID == id {
			return u, true, nil
		}
	}
	return identity.UserSummary{}, false, nil
}

func (p *Portal) adminUserLimits(w http.ResponseWriter, r *http.Request) {
	u, ok, err := p.limitsUser(r)
	switch {
	case err != nil:
		p.serverError(w, r, err)
		return
	case !ok:
		p.notFound(w, r)
		return
	}
	p.render(w, r, http.StatusOK, "admin_user_limits.html", adminUserLimitsData{
		Title: "Limits: " + u.DisplayName, ID: u.ID, Name: u.DisplayName, Rows: p.capRows(r.Context(), u.ID, true),
	})
}

func (p *Portal) setUserResourceCaps(w http.ResponseWriter, r *http.Request) {
	u, ok, err := p.limitsUser(r)
	switch {
	case err != nil:
		p.serverError(w, r, err)
		return
	case !ok:
		p.notFound(w, r)
		return
	}
	pt, err := capPatchForm(r)
	if err == nil {
		err = p.resourceCaps.SetUser(r.Context(), identity.PrincipalFrom(r.Context()).UserID, u.ID, pt)
	}
	switch {
	case errors.Is(err, errCapForm) || errors.Is(err, settings.ErrInvalidCap):
		p.errorPage(w, r, http.StatusUnprocessableEntity, "Invalid resource limit", capFormMessage)
		return
	case err != nil:
		p.serverError(w, r, err)
		return
	}
	http.Redirect(w, r, "/admin/users/"+u.ID+"/limits?saved=1", http.StatusSeeOther)
}
