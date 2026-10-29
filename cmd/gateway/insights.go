package main

import (
	"log/slog"
	"net/http"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/insights"
)

// insightsReader is the audit reader together with the insights source
// (decision 3yq9s5ev): newPortalWithAccount charts the user's calls on
// /activity when its reader is one. Tests that pass a plain reader get
// the table only.
type insightsReader struct {
	audit.Reader
	src *insights.Source
}

func (r insightsReader) activityInsights() insights.Loader { return r.src.Activity }

// withInsightsPage mounts GET /admin/insights behind the portal's admin
// check (an /admin pattern, see portalMount).
func withInsightsPage(src *insights.Source) portalExtra {
	return func(_ *identity.Service, mount func(string, http.Handler), _ func(*http.Request) (string, string), log *slog.Logger, _ http.Handler) {
		if src == nil {
			return
		}
		who := func(r *http.Request) (string, bool) {
			pr := identity.PrincipalFrom(r.Context())
			if pr == nil {
				return "", false
			}
			return pr.UserID, pr.IsAdmin()
		}
		mount("GET /admin/insights", insights.AdminHandler(src.Admin, who, log))
	}
}
