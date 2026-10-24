# Credential links and the upstream URL elicitation relay

Two features, each behind its own flag (default off), both answer a tool call with MCP 2025-11-25's
`URLElicitationRequiredError`: JSON-RPC **`-32042`** with
`data.elicitations[] = {mode: "url", elicitationId, url, message}`. The agent shows the link, the user acts in the
browser, the agent retries. Design: [plans/2026-10-23-credential-links-and-elicitation-relay-design.md](plans/2026-10-23-credential-links-and-elicitation-relay-design.md).

| Flag | Helm | What it does |
|---|---|---|
| `GATEWAY_CREDENTIAL_LINKS_ENABLED` | `gateway.credentialLinks.enabled` | A credential problem the caller can fix answers `-32042` with a link to the gateway's own connection page (plan 1). |
| `GATEWAY_UPSTREAM_ELICITATION_ENABLED` | `gateway.upstreamElicitation.enabled` | An upstream server may send the user to **its own** page (URL-mode elicitation), relayed through the gateway's `/elicit/<id>` confirmation page (plan 2). |

Both are read at startup by `elicit.ConfigFromEnv` (`cmd/gateway/federation.go`); a value `strconv.ParseBool` does not
accept stops startup naming the variable. Both need user-added MCP servers (a key provider).

## Credential links (plan 1)

See [federation-connector.md](federation-connector.md#credential-links) for the class-by-class table. In short: no
connection, sign-in needed, an expired or rejected per-user credential or a missing per-user header value answer
`-32042` with `<base>/servers/<id>/connect` or `…#connection` (`elicitationId` `gwc_…`); problems only the owner can fix
(missing shared credential, invalid setup) answer the owner with `<base>/servers/<id>/edit` and everyone else with the
unchanged `-32031` text. The audit and ledger class never changes.

## Upstream URL elicitation relay (plan 2)

```
agent ──tools/call──▶ gateway ──tools/call──▶ upstream
                      gateway ◀── -32042 {elicitations:[{url:"https://mcp.example.com/connect?…"}]}
                         │  or: elicitation/create {mode:"url"} mid-call → answer {action:"cancel"}, record it,
                         │      relay only if the call then fails (error or isError result)
                         ▼ check the URL (rules below), store a row (10 min)
agent ◀── -32042 {elicitations:[{url:"<base>/elicit/<id>", elicitationId:"gwe_…", message:"<server> asks you to open a page"}]}
user ──<base>/elicit/<id> (signed in, owner only)──▶ confirmation page: server, harness, FULL url,
                         registrable domain highlighted, punycode warning, server's message as plain text
user ──Continue (POST, CSRF)──▶ 303 to the upstream URL ──▶ user finishes on the server's own page
agent ──retry──▶ the upstream now has what it asked for
```

### Who relays

| Server | Caller | Relay? |
|---|---|---|
| per-user credentials (`credential_mode = per_user` with an auth kind other than `none`, or declared per-user headers on a server with an auth kind) | anyone who may use it | yes: the upstream knows which user it talks to |
| shared credential, `auth_kind = none`, or a tunnel (`tunnel://`) | the server's owner | yes |
| shared credential, `auth_kind = none`, or a tunnel | anyone else | **no**: the upstream sees one identity for every gateway user, so user B could complete user A's elicitation (the spec's phishing case). The caller gets the answer the gateway gave before the relay (`upstream_tool_error`, …) |

The rule is `connector.NeedsUserCredential` (shared with credential links and the servers portal) plus "not `none`"
(`Manager.mayRelay`, `connector/relay.go`).

**Capability.** The connector's per-call client declares `elicitation: {"url": {}}` (never form) only when the call
may relay, and **never through a tunnel**: a stdio process behind a tunnel is shared by every user and the gateway
cannot tell it from a proxied HTTP server. The portal and discovery clients never declare it. Form-mode requests are
refused (`-32602`; an upstream SDK usually refuses them itself, since form was not declared).

**When.** A `-32042` answer from the upstream (HTTP 200, or HTTP 400 from servers that map JSON-RPC errors to 400) is
checked **before** the unknown-outcome logic. Requests recorded mid-call (`elicitation/create`, multi round-trip input
requests) are relayed only when the call then failed with a known outcome: an `isError` result, or an upstream error
that is not an unknown outcome. **A successful call never relays; an unknown outcome never relays** (the write may have
happened; the user must check first). A reauth retry starts a new session, so its record starts empty. Entries are
de-duplicated by upstream `elicitationId` and capped at 5. A `-32042` without usable entries is today's upstream error.

### URL rules

`elicit.Rules{ServerURL, AllowedOrigins}.Check` (`internal/federation/elicit/validate.go`):

- absolute `https`, at most 2048 bytes, no control, whitespace or format characters or backslashes, no userinfo;
- a DNS host: no IP literal in any form (`127.1`, `0x7f.1`, `[::1]`), not `localhost`, at least two labels; IDNs are
  normalised to punycode;
- the host's **registrable domain** (eTLD+1 from the public suffix list; private suffixes such as `github.io` count as
  suffixes) equals the server URL's, **or** its origin is exactly one of the server's **allowed elicitation origins**.

Servers without a registrable domain (tunnels, IP addresses) can only use the list. The owner edits it on the server's
edit form ("Allowed elicitation origins", one `https://host[:port]` per line, normalised by `elicit.ValidateOrigin`,
stored in `mcp_servers.elicitation_origins`). Changing it does not need a new review.

Entries that fail are dropped and logged by reason (`not_allowed`, `not_https`, `ip_host`, …), never by URL. When none
survive the caller gets `upstream_elicitation_refused` ("… asked you to open a page that is not allowed (configure
allowed origins)"); the owner's message adds the edit link. Nothing is stored.

### What is stored and shown

`upstream_elicitations` (migration 00032, forced row-level security): owner, server, harness (token id or OAuth family),
the normalised URL (what the page shows and redirects to), the upstream `elicitationId` and message (cleaned, at most
500 characters), `expires_at` (10 minutes), `opened_at`, `cancelled_at`; the link id is stored only as its SHA-256. The
expiry job (`elicit.expire`, every 10 minutes) deletes rows 24 h after expiry; deleting a user deletes theirs. At most
20 live links per user (`upstream_elicitations_limited`, `-32029`, `retry_after` 60 s).

**The harness never sees the upstream URL, `elicitationId` or message**, nor do logs, audit rows or ledger rows: they
could carry prompt injection or phishing text. The agent gets the gateway's link, its own `gwe_…` id and the fixed
message `<server> asks you to open a page`. Link ids are redacted from logs (`/elicit/…`).

### The confirmation page (`/elicit/<id>`)

`internal/federation/elicit` (`portal.go`), mounted behind the portal's sign-in and CSRF checks (`cmd/gateway/elicit.go`):

- only the signed-in owner of the row sees it; anyone else, and an unknown, cancelled or expired link, get the portal's
  ordinary 404 page, and failed lookups are limited per address like the secrets entry page;
- shows the server and harness names, the full URL, the host with its registrable domain highlighted, a warning for
  punycode hosts, and the server's message as escaped plain text;
- **Continue** (POST with the CSRF token) answers `303` to exactly the stored URL; **Cancel** ends the link. Continue can
  be pressed again until the link expires (the upstream decides whether its flow can run twice);
- `Cache-Control: no-store`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer` (the upstream never learns the link);
- the package has no HTTP client (the `rawhttpcheck` lint), so the gateway never fetches the upstream page;
- audit `elicit.opened` / `elicit.cancelled` with the record id and server id only.

The harness binding is shown, not verified: the browser has only the user's session.

### Errors

| Class | Code | Meaning | Ledger / secrets |
|---|---|---|---|
| `upstream_elicitation_required` | `-32042` | the server asks the user to open a page: open the `/elicit/` link, then retry | known failure; a secret use is **not** refunded (the upstream received the call) |
| `upstream_elicitation_refused` | tool error (`isError`) | the page is outside the server's domain and allowed origins | known failure; not refunded |
| `upstream_elicitations_limited` | `-32029` | 20 open links already; open them or wait for them to expire | known failure; not refunded |
| `elicitation_unavailable` | `-32603` | the link could not be stored | - |

A relayed `-32042` passes the secrets stage intact (`TestStageRelayedElicitationPassesIntact`).

### Limitations

- **Stateless towards the harness.** The gateway does not send `notifications/elicitation/complete` and ignores the
  upstream's; the agent retries when the user says they are done.
- **Mid-call requests are cancelled.** The gateway cannot ask the user during a call, so it answers `cancel` and relays
  only if the call fails. An upstream that carries on after `cancel` and succeeds is answered as is.
- **Stdio (tunnel) servers** never get the capability, so they cannot ask mid-call; a `-32042` answer from one relays
  for its owner only, through the allowed-origins list.
- **No-auth servers with per-user headers.** `auth.ForUser` returns no credential for `auth_kind = none` before it
  looks at per-user headers, so declared per-user headers are not sent to such a server (pre-existing, noted in C2).
  The relay therefore treats it as shared: owner only.

### Ingress

The pages are `/elicit/{id}`; the Helm chart's default `ingress.paths` routes `/elicit` (production routes the whole
host).

### Tests

- unit: `go test ./internal/federation/connector/ -run TestRelay` (`-32042` at 200 and 400, mid-call on failure, no relay
  on success or unknown outcome, refused domains, allowed origins, shared and no-auth non-owners, tunnels never opt in,
  dedup and cap, the rate limit, resources/read, nothing upstream-controlled in the marshalled error);
  `internal/secrets` `TestStageRelayedElicitationPassesIntact`; `cmd/gateway` `TestElicitDomain`; `internal/portal`
  `TestLoggedPathsKeepEntryLinkIDsOut` (`/elicit/<id>` kept out of CSRF rejection logs);
- integration: `TestIntegrationFederationUpstreamElicitationFlag`;
- e2e: `TestE2EUpstreamElicitationRelay` (relayed link, the page, CSRF, `303` to the exact URL, no pre-fetch, retry
  succeeds, leak scan);
- security: `TestSecurityFedElicitation*` (identical 404 for another user, CSRF, no pre-fetch, phishing refused and never
  stored, `<script>` inert, shared server non-owner gets no relay, form mode refused, leak sweep over harness answers,
  ledger rows, audit rows and logs).

The e2e and security upstreams listen on `127.0.0.1`, which has no registrable domain, so they list a test origin
(`https://connect.linked.example`) in `elicitation_origins` rather than resolving test host names.
