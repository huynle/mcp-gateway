package portal

import (
	"context"
	"errors"
	"net/http"

	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/permissions"
)

// GatewayTools is the "Gateway management tools" setting shown on My
// account (*permissions.Service; Brain task ds5tjou2, decision bnneszc1):
// whether the user may add MCP servers, their stored setting, and the
// change (permissions.ErrNotPermitted when turning it on without the
// permission; audited by the implementation).
type GatewayTools interface {
	CanAddServers(ctx context.Context, userID string) bool
	GatewayToolsEnabled(ctx context.Context, userID string) (bool, error)
	SetGatewayToolsEnabled(ctx context.Context, userID string, on bool) error
}

// SetGatewayTools adds the "Gateway management tools" section to My
// account and its route, POST /account/gateway-tools. Call before
// Handler; without it (no database) neither exists.
func (p *Portal) SetGatewayTools(gt GatewayTools) { p.gatewayTools = gt }

// accountData is the My account page's data.
type accountData struct {
	// GatewayTools is nil when the setting is not wired.
	GatewayTools *gatewayToolsView
}

// gatewayToolsView: Enabled is the effective state (stored setting and
// permitted); without the permission the switch is shown off and disabled.
type gatewayToolsView struct {
	Permitted bool
	Enabled   bool
}

const askAdminForServers = "Gateway management tools need permission to add MCP servers. Ask an admin for a role that may add MCP servers."

func (p *Portal) account(w http.ResponseWriter, r *http.Request) {
	var data accountData
	if p.gatewayTools != nil {
		ctx := r.Context()
		userID := identity.PrincipalFrom(ctx).UserID
		v := &gatewayToolsView{Permitted: p.gatewayTools.CanAddServers(ctx, userID)}
		if v.Permitted {
			on, err := p.gatewayTools.GatewayToolsEnabled(ctx, userID)
			if err != nil {
				p.serverError(w, r, err)
				return
			}
			v.Enabled = on
		}
		data.GatewayTools = v
	}
	p.render(w, r, http.StatusOK, "account.html", data)
}

// setGatewayTools stores the switch: a checked box posts enabled=on, an
// unchecked one posts nothing (off). Behind requireUser and the CSRF check.
func (p *Portal) setGatewayTools(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := identity.PrincipalFrom(ctx).UserID
	on := r.PostFormValue("enabled") != ""
	err := p.gatewayTools.SetGatewayToolsEnabled(ctx, userID, on)
	switch {
	case errors.Is(err, permissions.ErrNotPermitted):
		p.errorPage(w, r, http.StatusForbidden, "Not permitted", askAdminForServers)
		return
	case err != nil:
		p.serverError(w, r, err)
		return
	}
	http.Redirect(w, r, "/account#gateway-tools", http.StatusSeeOther)
}
