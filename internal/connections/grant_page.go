package connections

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/huynle/mcp-gateway/internal/observability"
)

// AccessAdvisor computes what a connection lacks for the tools its user
// may see (*Service.MissingAccess; tests substitute fakes).
type AccessAdvisor interface {
	MissingAccess(ctx context.Context, userID string, conn Info) (AccessGap, error)
}

// SetAccessAdvisor replaces the advisor behind the Grant more access
// links (nil restores the service).
func (p *Portal) SetAccessAdvisor(a AccessAdvisor) { p.advisor = a }

func (p *Portal) accessAdvisor() AccessAdvisor {
	if p.advisor != nil {
		return p.advisor
	}
	return p.svc
}

// connRow is one connection on the connections page: GrantURL is its
// Reconnect link (needs_reconnect) or its Grant more access link (active
// with something missing; empty otherwise); Unlocks and Extends say what
// granting adds.
type connRow struct {
	Info
	GrantURL string
	Unlocks  string
	Extends  string
}

// maxListedTools caps the function names a summary spells out.
const maxListedTools = 8

// connRows pairs the connections with their access gaps. A gap that
// cannot be computed is logged and treated as none: the page still
// renders, and Reconnect still works without extra scopes.
func (p *Portal) connRows(ctx context.Context, userID string, conns []Info) []connRow {
	rows := make([]connRow, 0, len(conns))
	for _, c := range conns {
		gap, err := p.accessAdvisor().MissingAccess(ctx, userID, c)
		if err != nil {
			p.log.Warn("missing scopes could not be computed", "event", "connections.access_gap_failed", "user_id", userID,
				"connection_id", c.ID, "vendor", c.Vendor, "request_id", observability.RequestIDFromContext(ctx), "error", observability.RedactError(err))
			gap = AccessGap{}
		}
		row := connRow{Info: c}
		if c.NeedsReconnect() || (c.Active() && !gap.Empty()) {
			row.GrantURL = grantURL(c, gap.Scopes)
			row.Unlocks = summarize("Unlocks", gap.Tools)
			row.Extends = summarize("Also extends", gap.Extended)
		}
		rows = append(rows, row)
	}
	return rows
}

// grantURL is the connect flow start for re-granting c with scopes.
func grantURL(c Info, scopes []string) string {
	q := url.Values{"variant": {c.Variant}, "connection": {c.ID}, "return_to": {"/connections"}}
	if len(scopes) > 0 {
		q.Set("scopes", strings.Join(scopes, " "))
	}
	return "/connect/" + url.PathEscape(c.Vendor) + "/start?" + q.Encode()
}

// summarize renders "Unlocks 11 functions: a, b, … and 3 more"
// ("Also extends a, b" for the extended tools); empty for no tools.
func summarize(verb string, tools []string) string {
	if len(tools) == 0 {
		return ""
	}
	listed := tools
	if len(listed) > maxListedTools {
		listed = listed[:maxListedTools]
	}
	names := strings.Join(listed, ", ")
	if rest := len(tools) - len(listed); rest > 0 {
		names += fmt.Sprintf(" and %d more", rest)
	}
	if verb != "Unlocks" {
		return verb + " " + names
	}
	noun := "functions"
	if len(tools) == 1 {
		noun = "function"
	}
	return fmt.Sprintf("%s %d %s: %s", verb, len(tools), noun, names)
}
