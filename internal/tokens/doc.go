// Package tokens owns generated harness tokens (mgw_<id>_<secret>): the
// format (format.go), creation / listing / revocation and the authenticator
// with its expiry, revocation, owner-status and sign-in-freshness rules
// (service.go), the per-IP failed-authentication limiter and the
// BearerMiddleware the /mcp endpoint wraps itself in (limiter.go,
// middleware.go), the self-service portal pages mounted through
// portal.MountUser (handlers.go, templates/), and the identity disable hook
// that revokes a user's tokens. It never logs or returns the secret after
// the one-time display; tokenstest/ is the in-memory Store for tests.
//
// Design: Brain plan 36bakiw8 sections 3 (step 1) and 4; decisions
// uamxx6ba (format and rules), bt8ukyrd (IP allow-list cut, custom
// secret-scanning pattern), 9z5sdzsm (pre-auth lookup through WithJobs).
package tokens
