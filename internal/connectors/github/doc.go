// Package github is the GitHub connector (app "github"), the reference
// every other connector copies (decision bt8ukyrd): a connections.Binder
// for GitHub App user access tokens (binder.go) and read tools over the
// REST API through go-github (tools_read.go; writes land in
// tools_write.go). Tokens come from the connection's oauth2.TokenSource,
// obtained per call through the function injected at construction, so
// the connector never stores one. Results mark Empty (no items), Partial
// (clamped page size, result truncated to fit the bounds, or GitHub's
// incomplete_results) and Unavailable (5xx, network); GitHub rate limits
// (primary and secondary) are *connectors.RateLimited with the vendor's
// reset or Retry-After; other failures are *Error with a Class
// (reconnect_required, not_found, forbidden, invalid_argument,
// vendor_error).
//
// Tool descriptions, schemas and the minimal result shapes are adapted
// from github/github-mcp-server (MIT; see THIRD_PARTY_NOTICES.md).
//
// Design: Brain plan 36bakiw8 section 5; decisions bt8ukyrd, mh7c6z3v,
// dovthftx, wcp2fmbz, rrmfnkqu, 0sod196t.
package github

// App is the connector's name; every tool is "github.<name>".
const App = "github"

// userAgent identifies the gateway to GitHub.
const userAgent = "mcp-gateway"
