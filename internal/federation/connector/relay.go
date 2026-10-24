package connector

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/huynle/mcp-gateway/internal/federation/auth"
	"github.com/huynle/mcp-gateway/internal/federation/client"
	"github.com/huynle/mcp-gateway/internal/federation/elicit"
	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/federation/tunnel"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/store"
)

// Upstream URL elicitation relay (GATEWAY_UPSTREAM_ELICITATION_ENABLED,
// plan 2 of docs/plans/2026-10-23-credential-links-and-elicitation-relay-design.md):
// an upstream that sends the user to its own page (MCP URL-mode
// elicitation: a -32042 answer, or elicitation/create {mode:"url"}
// mid-call) gets that page relayed through the gateway's /elicit
// interstitial:
//
//   - opt in: the per-call client declares elicitation {url} only for
//     calls that may relay (below), never through a tunnel (a stdio
//     process behind a tunnel is shared by every user, and the gateway
//     cannot tell stdio from a proxied HTTP server);
//   - who: a server with per-user credentials (needsUserCredential: the
//     upstream knows which user it talks to; a no-auth server never counts,
//     as auth.ForUser sends it no per-user headers) relays for anyone;
//     shared, no-auth and tunnel servers only for their owner, so user B can never
//     complete an elicitation the upstream meant for one shared identity.
//     Everyone else gets the answer the gateway gave before the relay;
//   - when: a -32042 answer always (checked before the unknown-outcome
//     logic); requests recorded mid-call only when the call then failed
//     with a known outcome (an isError result, or an upstream error that
//     is not an unknown outcome). A successful call or an unknown outcome
//     never relays;
//   - what: every URL must pass elicit.Rules (https, a DNS host in the
//     server's registrable domain or one of its elicitation origins);
//     each survivor is stored (Elicitations.Create, its normalised URL:
//     what the interstitial shows and redirects to) and the harness gets
//     a -32042 with the gateway's own links (<base>/elicit/<id>), its own
//     elicitationId (gwe_…) and a fixed message naming the server. The
//     upstream URL, elicitationId and message never reach the harness or
//     the logs: only the upstream_elicitations row and the interstitial
//     its signed-in owner opens.

// Classes of the relay's answers.
const (
	// ClassUpstreamElicitationRequired: the upstream asks the user to open
	// a page; the harness gets the gateway's /elicit links (-32042). A
	// known failure: the upstream received the call.
	ClassUpstreamElicitationRequired = "upstream_elicitation_required"
	// ClassUpstreamElicitationRefused: every page the upstream asked for is
	// outside its domain and allowed origins (a handler error, like other
	// upstream failures).
	ClassUpstreamElicitationRefused = "upstream_elicitation_refused"
	// ClassUpstreamElicitationsLimited: the caller has too many open
	// relayed links (elicit.ErrLimited), -32029.
	ClassUpstreamElicitationsLimited = "upstream_elicitations_limited"
)

// relayRetryAfter is the wait suggested when the caller has too many open
// links (they expire after elicit.LinkTTL).
const relayRetryAfter = time.Minute

// Elicitations stores relayed elicitations (*elicit.Service).
type Elicitations interface {
	Create(ctx context.Context, owner, harnessID, serverID, rawURL, upstreamID, message string) (string, elicit.Elicitation, error)
}

// mayRelay reports whether user's calls to server may relay upstream URL
// elicitations (see above).
func (m *Manager) mayRelay(server *store.MCPServer, user string) bool {
	if !m.o.UpstreamElicitation || m.o.Elicitations == nil || server == nil || user == "" {
		return false
	}
	if user == server.OwnerUserID {
		return true
	}
	// A no-auth server sends no per-user credential (auth.ForUser answers
	// before per-user headers), so it is never per-user for the relay.
	return !tunnel.IsTunnelURL(server.URL) && server.AuthKind != store.MCPAuthNone && needsUserCredential(server)
}

// optIn reports whether the per-call client declares URL elicitation for
// user's call to server: mayRelay, and never through a tunnel.
func (m *Manager) optIn(server *store.MCPServer, user string) bool {
	return m.mayRelay(server, user) && !tunnel.IsTunnelURL(server.URL)
}

// relayCall identifies the call a relay answers.
type relayCall struct {
	user, harness string
	server        *store.MCPServer
}

// relayError is the relay's answer to a failed call, if it has one: the
// upstream's -32042 entries (merged with any recorded mid-call), or the
// recorded mid-call entries when the failure's outcome is known (kind
// decides, as in callError). ok is false when the gateway answers as it
// did before the relay (callError).
func (m *Manager) relayError(ctx context.Context, rc relayCall, kind snapshot.Kind, err error, recorded []client.Elicitation) (error, bool) {
	if !m.mayRelay(rc.server, rc.user) {
		return nil, false
	}
	if entries, ok := client.URLElicitations(err); ok {
		return m.relay(ctx, rc, merge(entries, recorded)), true
	}
	var ce *client.Error
	if errors.As(err, &ce) && ce.IsURLElicitationRequired() {
		return nil, false // a -32042 without usable entries: as before
	}
	if len(recorded) == 0 || !relayableFailure(kind, err) {
		return nil, false
	}
	return m.relay(ctx, rc, merge(recorded)), true
}

// relayResult is the relay's answer to a call that returned a result: the
// recorded mid-call entries when the result is an error. A successful
// result is never relayed.
func (m *Manager) relayResult(ctx context.Context, rc relayCall, isError bool, recorded []client.Elicitation) (error, bool) {
	if !isError || len(recorded) == 0 || !m.mayRelay(rc.server, rc.user) {
		return nil, false
	}
	return m.relay(ctx, rc, merge(recorded)), true
}

// relayableFailure reports whether a failed call may relay what was
// recorded mid-call: an upstream failure (not a credential refusal, which
// has its own answer) whose outcome is known.
func relayableFailure(kind snapshot.Kind, err error) bool {
	var ce *client.Error
	switch {
	case errors.Is(err, auth.ErrNeedsReconnect), errors.Is(err, auth.ErrSharedCredentialRejected),
		errors.Is(err, auth.ErrNotConfigured), errors.Is(err, auth.ErrNotConnected):
		return false
	case errors.As(err, &ce) && ce.Class == client.ClassAuthRequired:
		return false
	}
	_, unknown := classify(kind, err)
	return !unknown
}

// merge de-duplicates elicitations by upstream id, first seen wins, and
// keeps at most client.MaxElicitations.
func merge(lists ...[]client.Elicitation) []client.Elicitation {
	var r client.Recorder
	for _, l := range lists {
		for _, e := range l {
			r.Add(e)
		}
	}
	return r.List()
}

// relay validates, stores and answers entries for rc (see above).
func (m *Manager) relay(ctx context.Context, rc relayCall, entries []client.Elicitation) error {
	s := rc.server
	rules := elicit.Rules{ServerURL: s.URL, AllowedOrigins: s.ElicitationOrigins}
	var out []mcp.URLElicitation
	var links, ids []string
	valid, limited := 0, false
	for _, e := range entries {
		checked, err := rules.Check(e.URL)
		if err != nil {
			m.log.Warn("upstream elicitation refused", "event", "federation.elicitation_refused", "server", s.Name,
				"server_id", s.ID, "reason", refusalReason(err))
			continue
		}
		valid++
		link, rec, err := m.o.Elicitations.Create(ctx, rc.user, rc.harness, s.ID, checked.Display, e.ElicitationID, e.Message)
		switch {
		case errors.Is(err, elicit.ErrLimited):
			limited = true
			continue
		case err != nil:
			m.log.Error("upstream elicitation not stored", "event", "federation.elicitation_failed", "server_id", s.ID,
				"error", observability.RedactError(err))
			continue
		}
		u := m.link("/elicit/" + link)
		links = append(links, u)
		ids = append(ids, rec.ID)
		out = append(out, mcp.URLElicitation{ElicitationID: elicit.ElicitationID(rec), URL: u, Message: s.Name + " asks you to open a page"})
	}
	switch {
	case len(out) > 0:
	case valid == 0:
		msg := s.Name + ": the server asked you to open a page that is not allowed (configure allowed origins)"
		if rc.user == s.OwnerUserID {
			msg += "; as the server's owner, add the page's origin to the server's allowed elicitation origins at " +
				EditLink(m.o.BaseURL, s.ID) + ", then retry"
		}
		return &upstreamError{class: ClassUpstreamElicitationRefused, msg: msg}
	case limited:
		te := mcp.NewToolError(mcp.CodeRateLimited, ClassUpstreamElicitationsLimited,
			s.Name+" asks you to open a page, but you have too many open pages from servers; finish them or wait for them to expire, then retry")
		te.RetryAfter = relayRetryAfter
		return te
	default:
		return mcp.NewToolError(mcp.CodeInternal, "elicitation_unavailable", s.Name+" asks you to open a page, but the link could not be created; retry")
	}
	m.log.Info("upstream elicitation relayed", "event", "federation.elicitation_relayed", "server", s.Name,
		"server_id", s.ID, "count", len(out), "elicitation_ids", ids)
	text := s.Name + " asks you to open a page: " + links[0]
	if len(links) > 1 {
		text = fmt.Sprintf("%s asks you to open %d pages: %s", s.Name, len(links), strings.Join(links, ", "))
	}
	return mcp.NewURLElicitationRequired(ClassUpstreamElicitationRequired, text+" — then retry", out,
		map[string]any{"server": s.Name})
}

// refusalReason names an elicit.Rules refusal for logs (never the URL).
func refusalReason(err error) string {
	switch {
	case errors.Is(err, elicit.ErrNotAllowed):
		return "not_allowed"
	case errors.Is(err, elicit.ErrNotHTTPS):
		return "not_https"
	case errors.Is(err, elicit.ErrUserinfo):
		return "userinfo"
	case errors.Is(err, elicit.ErrTooLong):
		return "too_long"
	case errors.Is(err, elicit.ErrIPHost):
		return "ip_host"
	}
	return "invalid"
}
