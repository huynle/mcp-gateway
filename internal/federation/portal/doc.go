// Package portal is the users' Servers portal for user-added MCP servers
// (Brain plan 0omkv2e1, task 9dp13dgy): list my servers and those
// published to me, add a server (auth detection, credentials, static OAuth
// client, headers), connect my account or key, refresh and review its
// tools, browse resources and prompts, and manage tunnels.
//
// Pages are server-rendered from the package's own embedded templates
// through the shared nav (internal/portal/nav), with CSRF on every POST,
// Cache-Control: no-store, and upstream text passed through the snapshot
// Display helpers before html/template escapes it. A server the caller
// cannot see is the 404 page. See docs/plugins-portal.md.
package portal
