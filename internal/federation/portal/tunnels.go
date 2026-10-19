package portal

import (
	"errors"
	"github.com/huynle/mcp-gateway/internal/clientinstall"
	"net/http"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/huynle/mcp-gateway/internal/caps"
	"github.com/huynle/mcp-gateway/internal/federation/tunnel"
	"github.com/huynle/mcp-gateway/internal/store"
)

// tunnelInstall is the client CLI install commands for the gateway at
// base (shared with the homepage, internal/clientinstall).
func tunnelInstall(base string) []clientinstall.Command { return clientinstall.Commands(base) }

const (
	tokenPlaceholder = "<token shown once>"
	stdioArgs        = `--stdio "<your server command>"`
	httpArgs         = "--http http://localhost:PORT/mcp"
)

// tunnelCommand is the `mcp-gateway tunnel` command line for a gateway, a
// token (or its placeholder) and the --stdio / --http arguments.
func tunnelCommand(base, token, target string) string {
	return "MCP_GATEWAY_TUNNEL_TOKEN=" + token + " mcp-gateway tunnel --gateway " + base + " " + target
}

// validTunnelName mirrors tunnel.Service: 1-100 printable characters.
func validTunnelName(name string) bool {
	n := utf8.RuneCountInString(name)
	return n >= 1 && n <= 100 && utf8.ValidString(name) && !strings.ContainsFunc(name, func(r rune) bool { return !unicode.IsPrint(r) })
}

// createTunnel creates a tunnel and shows its token on this response only
// (no redirect, no-store), with the command to run.
func (p *Portal) createTunnel(w http.ResponseWriter, r *http.Request, c caller) {
	ctx := r.Context()
	name := strings.TrimSpace(r.PostForm.Get("name"))
	var tun *store.MCPTunnel
	var token string
	err := errInvalidTunnelName
	if validTunnelName(name) {
		tun, token, err = p.d.Tunnels.CreateTunnel(ctx, c.UserID, name)
	}
	data, lerr := p.loadList(ctx, c)
	if lerr != nil {
		p.fail(w, r, "list servers", lerr)
		return
	}
	var ce *caps.ExceededError
	switch {
	case errors.Is(err, errInvalidTunnelName) || errors.Is(err, tunnel.ErrInvalidName):
		data.Error = "A tunnel name must be 1–100 printable characters."
		p.render(w, r, http.StatusUnprocessableEntity, "servers.html", data)
		return
	case errors.As(err, &ce):
		data.Error = ce.Error()
		p.render(w, r, http.StatusUnprocessableEntity, "servers.html", data)
		return
	case err != nil:
		p.fail(w, r, "create tunnel", err)
		return
	}
	stdio := ` --stdio "<your stdio server command>"`
	data.NewTunnel = &newTunnel{
		ID: tun.ID, Name: tun.Name, Token: token,
		Command:    "mcp-gateway-tunnel --gateway " + p.d.BaseURL + " --token " + token + stdio,
		EnvCommand: "MCP_GATEWAY_TUNNEL_TOKEN=" + token + " mcp-gateway-tunnel --gateway " + p.d.BaseURL + stdio,

		StdioCommand: tunnelCommand(p.d.BaseURL, token, stdioArgs),
		HTTPCommand:  tunnelCommand(p.d.BaseURL, token, httpArgs),
	}
	data.Install = tunnelInstall(p.d.BaseURL)
	p.log.Info("tunnel created", "event", "federation.tunnel_created", "user_id", c.UserID, "tunnel_id", tun.ID)
	p.render(w, r, http.StatusOK, "servers.html", data)
}

var errInvalidTunnelName = errors.New("portal: invalid tunnel name")

// revokeTunnel revokes one of the caller's live tunnels; anything else is
// the 404 page.
func (p *Portal) revokeTunnel(w http.ResponseWriter, r *http.Request, c caller) {
	ctx := r.Context()
	id := r.PostForm.Get("id")
	tunnels, err := p.d.Store.ListTunnels(ctx, c.UserID)
	if err != nil {
		p.fail(w, r, "list tunnels", err)
		return
	}
	if !slices.ContainsFunc(tunnels, func(t store.MCPTunnel) bool { return t.ID == id && t.RevokedAt == nil }) {
		p.notFound(w, r)
		return
	}
	if err := p.d.Tunnels.Revoke(ctx, c.UserID, id); err != nil {
		if errors.Is(err, tunnel.ErrForbidden) {
			p.notFound(w, r)
			return
		}
		p.fail(w, r, "revoke tunnel", err)
		return
	}
	p.log.Info("tunnel revoked", "event", "federation.tunnel_revoked", "user_id", c.UserID, "tunnel_id", id)
	http.Redirect(w, r, "/servers?revoked=1", http.StatusSeeOther)
}
