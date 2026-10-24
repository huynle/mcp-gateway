# Credential links and upstream URL elicitation relay

Status: design agreed 2026-10-23 (user, interactive), validated against feature/ephemeral-secrets @ bee0ece.
Follows [ephemeral secrets](2026-10-23-ephemeral-secrets-design.md). Both features are behind flags and use the
MCP 2025-11-25 `URLElicitationRequiredError` (`-32042`, `data.elicitations[] = {mode:"url", elicitationId, url,
message}`), the same shape `secrets.request` already returns.

## Why

Many MCP servers need more than sign-in: an OpenRouter key on top of OAuth, a PAT for another service. The standard
place for these is per-user server settings (`header_config.per_user`, per-user `api_key` / `bearer`). The gateway
already stores them, encrypted and sealed to the server URL. But a missing or rejected credential ends the call with an
error the agent cannot act on (`no_account`, `auth_required`, `needs_reconnect`, `server_not_configured`).
Separately, MCP 2025-11-25 lets a server send the user to its own page (URL-mode elicitation) to collect such
credentials; the gateway's federation client declares no elicitation capability, so those servers cannot ask.

## Plan 1: credential links (`GATEWAY_CREDENTIAL_LINKS_ENABLED`)

When the caller can fix the problem themselves, the error becomes `-32042` with a link to the existing connection
flow. **Classes do not change**, only the code and data, so audit, ledger and the secrets refund list behave exactly as
before. The message keeps the link in its text for harnesses that ignore `data`.

| Situation | Where it is decided today | Link |
|---|---|---|
| No connection for a per-user server (`no_account`) | account stage, `internal/mcp/account.go:54` via `connector` `ListAccounts` | `/servers/{id}/connect` (OAuth) or `/servers/{id}#connection` |
| OAuth not connected (`auth_required`) | `connector/call.go` `credentialError` | `/servers/{id}/connect` |
| Expired or rejected per-user credential (`needs_reconnect`) | `call.go` `credentialError` / `callError` | as above |
| **New:** a declared per-user header has no value | `auth/authorizer.go` `pick()` (new sentinel `ErrUserHeaderMissing`) | `/servers/{id}#connection` |
| Shared credential missing/rejected, mode invalid, tunnel URL invalid (`server_not_configured`, `shared_credential_rejected`) | `call.go` | **owner only**: `/servers/{id}/edit`; everyone else unchanged |
| `credentials_unavailable` | `call.go` | unchanged |

- User-fixable = `credential_mode = per_user` with an auth kind, or any `header_config.per_user` (same rule as
  `fedportal.needsUserCredential`).
- `auth.ErrNotConfigured` gets wrapping sub-sentinels (`ErrSharedMissing`, `ErrModeInvalid`, `ErrNowRequiresAuth`) so
  owner-only cases are distinguishable while `errors.Is(err, ErrNotConfigured)` keeps working. Fixes the existing
  misclassification of a no-auth server that starts answering 401 (today `upstream_error`).
- Missing per-user header values are now refused before the call (today they are silently dropped). This is a
  behaviour change, gated by the flag.
- The link helpers (`ServerPath`, `ConnectPath`, `ConnectionPath`, `EditPath`, `connectLinkOf`) move from `fedportal`
  / `gatewaytools` into `connector` (`links.go`) to avoid an import cycle; the old call sites delegate.
- The account stage gains an optional `AccountSource` hook (`MissingAccount(ctx, user, app) error`) so `internal/mcp`
  stays independent of `connector`.
- Applies to `tools/call` and to resources/prompts (`connector/resources.go` `withSession`).
- The OAuth connect state is already bound to the signed-in user, so a forwarded link cannot connect someone else.

## Plan 2: upstream URL elicitation relay (`GATEWAY_UPSTREAM_ELICITATION_ENABLED`)

```
agent ──tools/call──▶ gateway ──tools/call──▶ upstream (per-user server)
                      gateway ◀── -32042 {elicitations:[{url:"https://mcp.example.com/connect?…"}]}
                         │  or: elicitation/create {mode:"url"} mid-call → answer {action:"cancel"}, record it,
                         │      relay only if the call then fails (error or isError result)
                         ▼ validate URL, store row (10 min)
agent ◀── -32042 {elicitations:[{url:"<base>/elicit/<id>", elicitationId:"gwe_…", message:"<server> asks you to open a page"}]}
user ──<base>/elicit/<id> (signed in, owner only)──▶ interstitial: server name, FULL url, registrable domain
                         highlighted, punycode warning, server message as plain text, [Continue] [Cancel]
user ──Continue (POST, CSRF)──▶ 303 to upstream URL ──▶ user completes on the server's own page
agent ──retry──▶ upstream now has the user's credential
```

- **Capability:** the federation client declares `elicitation: {url: {}}` explicitly (never form), only for tool and
  resource calls made by the connector (not the portal/discovery client factory). Form-mode requests answer `-32602`.
  `notifications/elicitation/complete` is ignored (the gateway is stateless towards the harness; the agent retries).
- **Detection:** `-32042` arrives as `client.ClassToolError` (HTTP 200) or `ClassProtocol` (HTTP 400 from stateless
  go-sdk servers); `callError` checks `RPCCode == -32042` **before** the unknown-outcome logic. Mid-call requests are
  recorded per call (sessions are per call, not pooled), de-duplicated by `elicitationId`, capped at 5, reset on reauth.
  A call whose outcome is unknown is never relayed.
- **Who:** only servers with per-user credentials (the upstream knows which user it is talking to). For shared,
  no-auth and stdio-tunnel servers the upstream sees one identity for every gateway user, so a relay would let user B
  complete user A's elicitation (the spec's phishing case): relay only when the caller is the owner, otherwise
  answer the existing upstream error. Stdio tunnels never support mid-call requests (shared process).
- **URL rules:** https only; no userinfo; ≤ 2048 bytes; no control characters; no IP-literal hosts (netguard
  `parseHost` rules); host within the upstream server's registrable domain (eTLD+1 via `golang.org/x/net/publicsuffix`,
  private suffixes such as `github.io` count as suffixes) **or** listed in the server's owner-managed
  `elicitation_origins` (exact `https://host[:port]` origins). Tunnel servers have no origin and need the list.
- **Storage:** migration `00032`:
  - `mcp_servers.elicitation_origins text[] NOT NULL DEFAULT '{}'`, edited on the server edit form; the published
    lock function is replaced so changing it locks like other settings but does not supersede the approved snapshot;
    admin view and select lists updated.
  - `upstream_elicitations`: `id` uuid, `link_hash` bytea UNIQUE (SHA-256 of a 256-bit random link id),
    `owner_user_id` (FK, cascade), `server_id`, `harness_id`, `url`, `upstream_elicitation_id`, `message`
    (≤ 500 chars, shown as escaped text only on the interstitial), `expires_at` (10 min), `opened_at`; forced RLS,
    grants like `00031`; expiry job deletes old rows; `DeleteUserData` covers it. No envelope encryption: the URL must
    not contain secrets (spec), and storing it is required to show it.
- **Harness-facing data:** our own `elicitationId` (`gwe_…`), our URL and a fixed message naming the server; never the
  upstream message or URL (they could carry prompt injection or phishing text).
- **Interstitial:** `internal/federation/elicit` (no HTTP client, so the `rawhttpcheck` lint guarantees no pre-fetch).
  Pattern of `internal/secrets/portal.go`: signed-in owner only, identical 404 otherwise, CSRF on Continue,
  `no-store`, `X-Frame-Options: DENY`, `no-referrer`, per-address failure limiter. The harness binding is shown, not
  verified (the browser has only the user session).
- **Secrets stage:** a relayed `-32042` passes through `scrubError` intact (test). Its class
  `upstream_elicitation_required` is not refunded (the upstream received the call).

## Rollout

Ingress paths `/elicit` (repo chart; production routes the whole host). Flags default off. Production
(`huynle/infra` `apps/homelab/mcp-gateway/release.yaml`, `values.env`) turns on `GATEWAY_SECRETS_ENABLED`,
`GATEWAY_CREDENTIAL_LINKS_ENABLED` and `GATEWAY_UPSTREAM_ELICITATION_ENABLED`, after promoting the image built from
`main` (manual promotion runbook). Schema 32 makes old pods fail readiness during the rollout (brief).

## Tasks

| # | Task | Depends |
|---|---|---|
| C1 | Foundation: `mcp.NewURLElicitationRequired`, link helpers moved into `connector/links.go`, both flags | — |
| C2 | Plan 1: authorizer sentinels, call/resources mapping, account-stage hook, tests, docs | C1 |
| C3 | Plan 2 client: capability, recorder, `-32042` extraction; `internal/federation/elicit/validate.go` URL rules | C1 |
| C4 | Plan 2 storage + pages: migration 00032, store, edit-form origins, interstitial | C1 |
| C5 | Plan 2 relay + wiring + e2e/security + docs + `/elicit` ingress | C2, C3, C4 |
