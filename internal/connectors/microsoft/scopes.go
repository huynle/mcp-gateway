package microsoft

import (
	"sort"
	"strings"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Graph delegated permissions the tools need (RequiredScopes), as the
// vendor app requests them and Graph reports them in the token
// response's scope field (docs/vendor-apps.md section 5.2).
const (
	ScopeUserRead               = "User.Read"
	ScopeMailRead               = "Mail.Read"
	ScopeMailSend               = "Mail.Send"
	ScopeCalendarsRead          = "Calendars.Read"
	ScopeCalendarsReadWrite     = "Calendars.ReadWrite"
	ScopeFilesReadAll           = "Files.Read.All"
	ScopeFilesReadWrite         = "Files.ReadWrite"
	ScopeTeamReadBasicAll       = "Team.ReadBasic.All"
	ScopeChannelReadBasicAll    = "Channel.ReadBasic.All"
	ScopeChannelMessageReadAll  = "ChannelMessage.Read.All"
	ScopeChannelMessageSend     = "ChannelMessage.Send"
	ScopeSitesReadAll           = "Sites.Read.All"
	ScopeSitesReadWriteAll      = "Sites.ReadWrite.All"
	graphScopePrefix            = "https://graph.microsoft.com/"
	personalAccountsLackMessage = "personal Microsoft accounts cannot grant Teams or SharePoint permissions"
)

// TeamsScope reports whether scope is one of the Teams or SharePoint
// permissions personal Microsoft accounts cannot grant (decision
// mh7c6z3v). The binder strips them from personal accounts.
func TeamsScope(scope string) bool {
	s := strings.ToLower(normalizeScope(scope))
	return strings.HasPrefix(s, "team.") || strings.HasPrefix(s, "channel.") || strings.HasPrefix(s, "channelmessage.") ||
		strings.HasPrefix(s, "chat.") || strings.HasPrefix(s, "sites.") || strings.HasPrefix(s, "teamsactivity.")
}

// normalizeScope strips the Graph resource prefix and surrounding space.
func normalizeScope(scope string) string {
	scope = strings.TrimSpace(scope)
	if strings.HasPrefix(strings.ToLower(scope), graphScopePrefix) {
		scope = scope[len(graphScopePrefix):]
	}
	return scope
}

// ScopeCovered reports whether one of the granted scopes covers
// required: the same permission (case-insensitive, with or without the
// Graph resource prefix) or a documented superset of it
// (<Resource>.ReadWrite covers <Resource>.Read; <Resource>.X.All covers
// <Resource>.X; so ReadWrite.All covers Read.All, ReadWrite and Read).
func ScopeCovered(granted []string, required string) bool {
	req := strings.ToLower(normalizeScope(required))
	if req == "" {
		return true
	}
	for _, g := range granted {
		if covers(strings.ToLower(normalizeScope(g)), req) {
			return true
		}
	}
	return false
}

// covers says whether the granted permission g implies req.
func covers(g, req string) bool {
	if g == "" {
		return false
	}
	if g == req {
		return true
	}
	gres, gaccess, gall := splitScope(g)
	rres, raccess, rall := splitScope(req)
	if gres == "" || gres != rres {
		return false
	}
	if rall && !gall {
		return false
	}
	switch {
	case gaccess == raccess:
		return true
	case gaccess == "readwrite" && (raccess == "read" || raccess == "readbasic"):
		return true
	case gaccess == "read" && raccess == "readbasic":
		return true
	}
	return false
}

// splitScope breaks "Resource.Access[.All]" into its parts (lower-case).
func splitScope(s string) (resource, access string, all bool) {
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return "", "", false
	}
	if parts[len(parts)-1] == "all" {
		all = true
		parts = parts[:len(parts)-1]
	}
	if len(parts) < 2 {
		return "", "", false
	}
	return strings.Join(parts[:len(parts)-1], "."), parts[len(parts)-1], all
}

// missingScopes returns the required scopes none of the granted ones
// cover, sorted.
func missingScopes(granted, required []string) []string {
	var out []string
	for _, r := range required {
		if !ScopeCovered(granted, r) {
			out = append(out, r)
		}
	}
	sort.Strings(out)
	return out
}

// stripTeamsScopes returns scopes without the Teams and SharePoint
// permissions (for personal accounts).
func stripTeamsScopes(scopes []string) []string {
	out := make([]string, 0, len(scopes))
	for _, s := range scopes {
		if !TeamsScope(s) {
			out = append(out, s)
		}
	}
	return out
}

// ScopeGrantable is the connectors.ScopeGrantable of the Microsoft app:
// personal accounts cannot grant the Teams and SharePoint permissions
// (TeamsScope); work accounts can grant everything.
func ScopeGrantable(label connectors.AccountLabel, scope string) bool {
	return label != connectors.LabelPersonal || !TeamsScope(scope)
}
