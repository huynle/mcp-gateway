package connector

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strings"
	"unicode/utf8"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/yosida95/uritemplate/v3"

	"github.com/huynle/mcp-gateway/internal/federation/auth"
	"github.com/huynle/mcp-gateway/internal/federation/client"
	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

// Tool-like access names (audit rows, the rate limiter, token
// allow-lists): "<server>.resources/read", "<server>.prompts/get".
const (
	opReadResource = "resources/read"
	opGetPrompt    = "prompts/get"
)

// maxKeyLen bounds an upstream resource URI, template or prompt name the
// gateway lists.
const maxKeyLen = 4096

// ResourceProvider serves the resources, resource templates and prompts of
// user-added MCP servers on the gateway's /mcp (mcp.Options.Resources).
//
// Lists are the union, over the servers the caller may use (the same
// visibility as their tools: owner of a private server, or a role it is
// published to; and a narrowed token must name the server), of each
// server's approved snapshot as of the last load, never a live listing.
// Resources keep their upstream URI behind the server's namespace
// (GatewayResourceURI), prompts are "<server>.<prompt>"; titles and
// descriptions carry "[<server>] " (provenance) and are cleaned like tool
// descriptions.
//
// resources/read and prompts/get check again (server active, visible,
// the URI listed in the approved snapshot or matching one of its
// templates, the prompt in it) and then go upstream live with the
// caller's credential, endpoint and tunnel exactly like a tool call. Policy
// is server-level only for now: no per-resource or per-prompt rules.
func (m *Manager) ResourceProvider() mcp.ResourceProvider { return resourceProvider{m: m} }

type resourceProvider struct{ m *Manager }

// usableEntries returns the loaded servers p may use for op, by name.
func (m *Manager) usableEntries(ctx context.Context, p *tokens.Principal, op string) []*entry {
	if p == nil || p.UserID == "" {
		return nil
	}
	m.mu.RLock()
	all := make([]*entry, 0, len(m.apps))
	for _, e := range m.apps {
		all = append(all, e)
	}
	m.mu.RUnlock()
	sort.Slice(all, func(i, j int) bool { return all[i].server.Name < all[j].server.Name })
	out := all[:0]
	for _, e := range all {
		if e.snap != nil && m.usable(ctx, p, e, op) {
			out = append(out, e)
		}
	}
	return out
}

// usable reports whether p may use e's server for op: the token's
// allow-list admits "<server>.<op>" (an allow-list naming the server
// does) and the user may see the server.
func (m *Manager) usable(ctx context.Context, p *tokens.Principal, e *entry, op string) bool {
	return p != nil && p.Scope.Allows(e.server.Name+"."+op) && m.canSee(ctx, p.UserID, e.server.ID)
}

// safeKey reports whether an upstream key (URI, template, prompt name)
// can be shown and echoed back as is: not empty, bounded, no control or
// format characters (bidi overrides, zero-width), no runs of whitespace.
func safeKey(s string) bool {
	return s != "" && len(s) <= maxKeyLen && snapshot.Display(s, utf8.RuneCountInString(s)+1) == s
}

// provenanceTitle is "[<server>] " + the title, or the name without one.
func provenanceTitle(server, title, name string) string {
	if title == "" {
		title = name
	}
	return "[" + server + "] " + snapshot.DisplayTitle(title)
}

// provenanceDescription is "[<server>] " + the cleaned description.
func provenanceDescription(server, desc string) string {
	return strings.TrimSpace("[" + server + "] " + snapshot.DisplayDescription(desc))
}

func (r resourceProvider) ListResources(ctx context.Context, p *tokens.Principal) ([]*sdk.Resource, error) {
	out := []*sdk.Resource{}
	for _, e := range r.m.usableEntries(ctx, p, opReadResource) {
		name := e.server.Name
		for _, res := range e.snap.Resources {
			if !safeKey(res.URI) {
				continue
			}
			out = append(out, &sdk.Resource{
				URI:         GatewayResourceURI(name, res.URI),
				Name:        name + "." + snapshot.DisplayName(res.Name),
				Title:       provenanceTitle(name, res.Title, res.Name),
				Description: provenanceDescription(name, res.Description),
				MIMEType:    snapshot.DisplayName(res.MIMEType),
			})
		}
	}
	return out, nil
}

func (r resourceProvider) ListResourceTemplates(ctx context.Context, p *tokens.Principal) ([]*sdk.ResourceTemplate, error) {
	out := []*sdk.ResourceTemplate{}
	for _, e := range r.m.usableEntries(ctx, p, opReadResource) {
		name := e.server.Name
		for _, t := range e.snap.ResourceTemplates {
			gw := GatewayResourceTemplate(name, t.URITemplate)
			if !safeKey(t.URITemplate) {
				continue
			}
			if _, err := uritemplate.New(gw); err != nil {
				continue
			}
			out = append(out, &sdk.ResourceTemplate{
				URITemplate: gw,
				Name:        name + "." + snapshot.DisplayName(t.Name),
				Title:       provenanceTitle(name, t.Title, t.Name),
				Description: provenanceDescription(name, t.Description),
				MIMEType:    snapshot.DisplayName(t.MIMEType),
			})
		}
	}
	return out, nil
}

func (r resourceProvider) ListPrompts(ctx context.Context, p *tokens.Principal) ([]*sdk.Prompt, error) {
	out := []*sdk.Prompt{}
	for _, e := range r.m.usableEntries(ctx, p, opGetPrompt) {
		name := e.server.Name
		for _, pr := range e.snap.Prompts {
			if !safeKey(pr.Name) {
				continue
			}
			args := make([]*sdk.PromptArgument, 0, len(pr.Arguments))
			for _, a := range pr.Arguments {
				args = append(args, &sdk.PromptArgument{
					Name: a.Name, Title: snapshot.DisplayTitle(a.Title), Description: snapshot.DisplayDescription(a.Description), Required: a.Required,
				})
			}
			out = append(out, &sdk.Prompt{
				Name:        GatewayPromptName(name, pr.Name),
				Title:       provenanceTitle(name, pr.Title, pr.Name),
				Description: provenanceDescription(name, pr.Description),
				Arguments:   args,
			})
		}
	}
	return out, nil
}

func (r resourceProvider) ReadResource(ctx context.Context, p *tokens.Principal, uri string, admit mcp.Admit) (*sdk.ReadResourceResult, error) {
	notFound := mcp.ErrResourceNotFound(uri)
	name, upstream, ok := ParseGatewayResourceURI(uri)
	if !ok || !safeKey(upstream) {
		return nil, notFound
	}
	server, snap, err := r.m.approvedFor(ctx, p, name, opReadResource, notFound)
	if err != nil {
		return nil, err
	}
	if !resourceApproved(snap, upstream) {
		return nil, notFound
	}
	label := name + "." + opReadResource
	if err := admit(ctx, mcp.Access{Name: label, ResourceIdentity: resourceIdentity(name, upstream)}); err != nil {
		return nil, err
	}
	var res *sdk.ReadResourceResult
	err = r.m.withSession(ctx, server, p.UserID, label, notFound, func(s *client.Session) error {
		var err error
		res, err = s.ReadResource(ctx, upstream)
		return err
	})
	if err != nil {
		return nil, err
	}
	if res == nil {
		res = &sdk.ReadResourceResult{}
	}
	// Contents name what they are in the gateway's namespace too.
	for _, c := range res.Contents {
		if c == nil {
			continue
		}
		if c.URI == "" {
			c.URI = uri
		} else {
			c.URI = GatewayResourceURI(name, c.URI)
		}
	}
	return res, nil
}

func (r resourceProvider) GetPrompt(ctx context.Context, p *tokens.Principal, gwName string, args map[string]string, admit mcp.Admit) (*sdk.GetPromptResult, error) {
	notFound := mcp.ErrPromptNotFound(gwName)
	name, prompt, ok := ParseGatewayPromptName(gwName)
	if !ok || !safeKey(prompt) {
		return nil, notFound
	}
	server, snap, err := r.m.approvedFor(ctx, p, name, opGetPrompt, notFound)
	if err != nil {
		return nil, err
	}
	if !promptApproved(snap, prompt) {
		return nil, notFound
	}
	label := name + "." + opGetPrompt
	if err := admit(ctx, mcp.Access{Name: label, ResourceIdentity: map[string]string{"server": name, "prompt": prompt}}); err != nil {
		return nil, err
	}
	var res *sdk.GetPromptResult
	err = r.m.withSession(ctx, server, p.UserID, label, notFound, func(s *client.Session) error {
		var err error
		res, err = s.GetPrompt(ctx, prompt, args)
		return err
	})
	if err != nil {
		return nil, err
	}
	if res == nil {
		res = &sdk.GetPromptResult{}
	}
	return res, nil
}

// approvedFor resolves a server by name for p and op: loaded, usable by
// p (visibility, token allow-list), still active under the same name, and
// its approved snapshot as read in p's own scope (row-level security
// again). Anything missing or hidden is notFound.
func (m *Manager) approvedFor(ctx context.Context, p *tokens.Principal, name, op string, notFound error) (*store.MCPServer, *snapshot.Snapshot, error) {
	e, ok := m.entry(name)
	if !ok || !m.usable(ctx, p, e, op) {
		return nil, nil, notFound
	}
	server, err := m.o.Store.GetServer(ctx, e.server.ID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, nil, notFound
	case err != nil:
		m.log.Error("federated server lookup failed", "event", "federation.server_lookup_failed", "server_id", e.server.ID,
			"error", observability.RedactError(err))
		return nil, nil, mcp.NewToolError(mcp.CodeInternal, "server_unavailable", "the server could not be looked up")
	case server.Status != store.MCPServerActive, server.Name != name:
		return nil, nil, notFound
	}
	rec, err := m.o.Snapshots.Current(ctx, snapshot.Actor{UserID: p.UserID}, server.ID)
	switch {
	case errors.Is(err, snapshot.ErrNoSnapshot):
		return nil, nil, notFound
	case err != nil:
		m.log.Error("snapshot check failed", "event", "federation.snapshot_failed", "server_id", server.ID, "error", observability.RedactError(err))
		return nil, nil, mcp.NewToolError(mcp.CodeInternal, "snapshot_unavailable", "the reviewed snapshot could not be checked")
	case rec == nil || rec.Snapshot == nil:
		return nil, nil, notFound
	}
	return server, rec.Snapshot, nil
}

// resourceApproved reports whether upstream is a resource of snap or an
// expansion of one of its templates.
func resourceApproved(snap *snapshot.Snapshot, upstream string) bool {
	for _, r := range snap.Resources {
		if r.URI == upstream {
			return true
		}
	}
	for _, t := range snap.ResourceTemplates {
		if safeKey(t.URITemplate) && templateMatches(t.URITemplate, upstream) {
			return true
		}
	}
	return false
}

// promptApproved reports whether snap has the prompt.
func promptApproved(snap *snapshot.Snapshot, prompt string) bool {
	for _, p := range snap.Prompts {
		if p.Name == prompt {
			return true
		}
	}
	return false
}

// withSession runs fn on a session with the server, as user, over the
// same path as a tool call: auth.ForUser (per_user: the caller's
// connection; shared: the server's secret; none), the endpoint (netguard,
// or the owner's tunnel), Connect under auth.Reauth. label names the
// request in credential messages. Failures are class-level: credential
// refusals are *mcp.ToolError (auth_required, needs_reconnect,
// server_not_configured, shared_credential_rejected), upstream failures
// ClassedError (tunnel_offline, upstream_*); a read is never an unknown
// outcome.
func (m *Manager) withSession(ctx context.Context, server *store.MCPServer, user, label string, notFound error, fn func(*client.Session) error) error {
	az, err := m.o.Credentials.ForUser(ctx, server, user)
	if err != nil {
		err = m.credentialError(label, server, err)
		var te *mcp.ToolError
		if errors.As(err, &te) && te.Class() == "tool_not_found" {
			return notFound
		}
		return err
	}
	hc, ep, err := m.endpoint(ctx, server)
	if err != nil {
		return err
	}
	c, err := client.New(client.Options{
		HTTPClient: hc, Authorizer: az, Timeout: m.o.Timeout,
		ClientVersion: m.o.Version, Log: m.log, OnCall: m.o.OnCall,
	})
	if err != nil {
		return mcp.NewToolError(mcp.CodeInternal, "client_unavailable", "the upstream client could not be built")
	}
	err = auth.Reauth(ctx, az, func() error {
		s, err := c.Connect(ctx, ep)
		if err != nil {
			return err
		}
		defer func() { _ = s.Close() }()
		return fn(s)
	})
	if err == nil {
		return nil
	}
	var ce *client.Error
	if errors.As(err, &ce) && ce.Class == client.ClassProtocol && (ce.RPCCode != 0 || ce.Status == http.StatusBadRequest) {
		// The server answered with a JSON-RPC error (no such resource,
		// bad arguments, ...; go-sdk servers send those as HTTP 400 in
		// stateless mode); the client calls that a protocol error
		// outside tools/call. Its text is never relayed.
		m.log.Warn("federated request refused upstream", "event", "federation.call_failed", "server", server.Name,
			"server_id", server.ID, "class", "upstream_refused", "rpc_code", ce.RPCCode)
		return &upstreamError{class: "upstream_refused", msg: server.Name + ": the server refused the request"}
	}
	return m.callError(server, snapshot.KindRead, err)
}
