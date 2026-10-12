package admin

import (
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/huynle/mcp-gateway/internal/netguard"
	"github.com/huynle/mcp-gateway/internal/store"
)

// --- tunnels ------------------------------------------------------------------------------

type tunnelRow struct {
	Tunnel
	Online bool
}

type tunnelsData struct {
	Title   string
	Caller  caller
	Tunnels []tunnelRow
	Notice  string
}

// tunnels lists every tunnel; Online is this replica's view.
func (a *Admin) tunnels(w http.ResponseWriter, r *http.Request, c caller) {
	ts, err := a.d.Store.ListTunnels(r.Context())
	if err != nil {
		a.fail(w, r, "list tunnels", err)
		return
	}
	data := tunnelsData{Title: "Tunnels", Caller: c}
	if r.URL.Query().Get("done") == "revoked" {
		data.Notice = "Tunnel revoked: its token no longer works and its connection was closed."
	}
	for _, t := range ts {
		data.Tunnels = append(data.Tunnels, tunnelRow{Tunnel: t, Online: t.RevokedAt == nil && a.d.Tunnels.Online(t.ID)})
	}
	a.render(w, r, http.StatusOK, "tunnels.html", data)
}

// revokeTunnel revokes any user's tunnel (as its owner, which the tunnel
// service requires).
func (a *Admin) revokeTunnel(w http.ResponseWriter, r *http.Request, c caller) {
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		a.notFound(w, r)
		return
	}
	t, err := a.d.Store.GetTunnel(r.Context(), id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		a.notFound(w, r)
		return
	case err != nil:
		a.fail(w, r, "load tunnel", err)
		return
	}
	if t.RevokedAt == nil {
		if err := a.d.Tunnels.Revoke(r.Context(), t.OwnerUserID, t.ID); err != nil {
			a.fail(w, r, "revoke tunnel", err)
			return
		}
		a.record(r.Context(), c, "tunnel.revoked", map[string]string{"tunnel_id": t.ID, "tunnel": truncate(t.Name), "owner_user_id": t.OwnerUserID})
	}
	http.Redirect(w, r, "/admin/tunnels?done=revoked", http.StatusSeeOther)
}

// --- SSRF allow-list -------------------------------------------------------------------------

type allowHostsData struct {
	Title   string
	Caller  caller
	Hosts   []store.NetguardAllowHost
	Pattern string
	Note    string
	Notice  string
	Error   string
}

const (
	maxPattern = 253
	maxNote    = 256
)

func (a *Admin) allowHosts(w http.ResponseWriter, r *http.Request, c caller) {
	notice := ""
	switch r.URL.Query().Get("done") {
	case "added":
		notice = "Entry added. It applies at once on this replica and within 30 seconds on the others."
	case "removed":
		notice = "Entry removed."
	}
	a.renderAllowHosts(w, r, c, http.StatusOK, allowHostsData{Notice: notice})
}

func (a *Admin) renderAllowHosts(w http.ResponseWriter, r *http.Request, c caller, status int, data allowHostsData) {
	hosts, err := a.d.Store.ListAllowHosts(r.Context())
	if err != nil {
		a.fail(w, r, "list allow hosts", err)
		return
	}
	data.Title, data.Caller, data.Hosts = "Network allow-list", c, hosts
	a.render(w, r, status, "allow_hosts.html", data)
}

// validPattern accepts what netguard's allow list matches: an exact host
// name, an IP address or a CIDR prefix.
func validPattern(p string) bool {
	if p == "" || len(p) > maxPattern {
		return false
	}
	_, err := netguard.NewStaticAllowList(p)
	return err == nil
}

func printable(s string) bool {
	return !strings.ContainsFunc(s, func(r rune) bool { return unicode.IsControl(r) || r == unicode.ReplacementChar })
}

func (a *Admin) addAllowHost(w http.ResponseWriter, r *http.Request, c caller) {
	pattern := strings.TrimSpace(r.PostForm.Get("pattern"))
	note := strings.TrimSpace(r.PostForm.Get("note"))
	data := allowHostsData{Pattern: pattern, Note: note}
	switch {
	case !validPattern(pattern):
		data.Error = "Enter one host name (exact, no wildcard), IP address or CIDR prefix such as 10.20.0.0/16. No scheme, port or path."
	case len(note) > maxNote || !printable(note):
		data.Error = "The note must be at most 256 characters without control characters."
	}
	if data.Error != "" {
		a.renderAllowHosts(w, r, c, http.StatusUnprocessableEntity, data)
		return
	}
	createdBy := c.UserID
	h := &store.NetguardAllowHost{Pattern: pattern, Note: note, CreatedBy: &createdBy, CreatedAt: time.Now()}
	err := a.d.Store.AddAllowHost(r.Context(), h)
	switch {
	case errors.Is(err, ErrDuplicate):
		data.Error = "That entry is already on the list."
		a.renderAllowHosts(w, r, c, http.StatusUnprocessableEntity, data)
		return
	case err != nil:
		a.fail(w, r, "add allow host", err)
		return
	}
	a.d.AllowList.Invalidate()
	a.record(r.Context(), c, "netguard.allow_host_added", map[string]string{"allow_host_id": h.ID, "pattern": pattern})
	http.Redirect(w, r, "/admin/network/allow-hosts?done=added", http.StatusSeeOther)
}

func (a *Admin) deleteAllowHost(w http.ResponseWriter, r *http.Request, c caller) {
	id := r.PathValue("id")
	if !uuidRE.MatchString(id) {
		a.notFound(w, r)
		return
	}
	h, err := a.d.Store.DeleteAllowHost(r.Context(), id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		a.notFound(w, r)
		return
	case err != nil:
		a.fail(w, r, "delete allow host", err)
		return
	}
	a.d.AllowList.Invalidate()
	a.record(r.Context(), c, "netguard.allow_host_removed", map[string]string{"allow_host_id": h.ID, "pattern": h.Pattern})
	http.Redirect(w, r, "/admin/network/allow-hosts?done=removed", http.StatusSeeOther)
}
