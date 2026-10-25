# Connecting a harness

Every harness talks to one endpoint, `GATEWAY_BASE_URL` + `/mcp` (stateless Streamable HTTP), and authenticates each request with a bearer token. There are two ways to get one:

| | **MCP OAuth sign-in** | **Generated token** |
|---|---|---|
| Who | harnesses that implement the MCP authorization spec (Claude Code, Claude Desktop, the MCP inspector, most SDK clients), and any stdio harness through `mcp-gateway proxy` | anything that can set a header: OpenCode, scripts, `curl`, older harnesses |
| How | the harness discovers the gateway's authorization server, registers itself, opens the browser (or, on a remote host, shows a code you enter at `/activate`); you sign in with your company account and approve it | you create a token at `/tokens` and paste it into the harness config |
| Lifetime | 1-hour access tokens, renewed with a 30-day rotating refresh token for as long as you keep signing in to the portal | up to 90 days; stops working if you have not signed in to the portal for 30 days |
| Revoke | `/harnesses` → *Disconnect* (or disable the user) | `/tokens` → *Revoke* |

Both kinds of token go through the same policy, approvals, ledger and audit. OAuth access tokens carry a scope: `mcp` (everything your role allows) or `mcp:read` (read tools only), the equivalent of a read-only generated token.

## Claude Code

```bash
claude mcp add --transport http gateway https://gw.example.com/mcp
```

The first tool call answers `401`; Claude Code reads the `WWW-Authenticate` header, fetches the discovery documents, registers itself (`POST /oauth/register`) and opens your browser at `/oauth/authorize`. Sign in with your company account if you are not already, read what the harness asks for, press **Allow**, and the browser bounces back to `http://localhost:<port>/callback`; Claude Code exchanges the code and is connected. `/mcp` then shows the tools your role grants. To use a generated token instead:

```bash
claude mcp add --transport http gateway https://gw.example.com/mcp --header "Authorization: Bearer mgw_<id>_<secret>"
```

or in `.mcp.json`:

```jsonc
{ "mcpServers": { "gateway": { "type": "http", "url": "https://gw.example.com/mcp",
                               "headers": { "Authorization": "Bearer mgw_<id>_<secret>" } } } }
```

## Claude Desktop

*Settings → Connectors → Add custom connector*, name `gateway`, URL `https://gw.example.com/mcp`. Leave the OAuth client ID and secret empty: Claude Desktop registers itself dynamically. Press *Connect*, sign in and approve in the browser window that opens. Claude Desktop keeps the refresh token in its own keychain; *Disconnect* on `/harnesses` ends it from the gateway side.

## Any stdio harness: `mcp-gateway proxy`

`mcp-gateway proxy` (the client CLI, `brew install huynle/tap/mcp-gateway` or `curl -fsSL https://gateway.huynle.com/install | sh`) is a local stdio MCP server that forwards every message to `<base>/mcp`. Any harness that can start a local MCP command uses it, with no token to paste and no browser redirect: it signs in with the device flow below, so it works the same on your laptop and on a remote host over SSH.

```jsonc
// OpenCode: opencode.json (project or ~/.config/opencode/opencode.json)
{ "$schema": "https://opencode.ai/config.json",
  "mcp": { "mcp-gateway": { "type": "local", "enabled": true,
                            "command": ["mcp-gateway", "proxy", "--gateway", "https://gw.example.com"] } } }
```

```bash
# Claude Code (or any harness that takes a stdio command)
claude mcp add gateway -- mcp-gateway proxy --gateway https://gw.example.com
```

```jsonc
// .mcp.json / Claude Desktop / other mcpServers-style configs
{ "mcpServers": { "gateway": { "command": "mcp-gateway", "args": ["proxy", "--gateway", "https://gw.example.com"] } } }
```

Instead of `--gateway`, set `MCP_GATEWAY_URL` in the harness's environment or `gateway:` in `~/.config/mcp-gateway/config.yaml`; on a machine enrolled with `mcp-gateway login` the proxy also falls back to that machine's gateway. With just `"command": ["mcp-gateway", "proxy"]` the gateway comes from one of those.

**First run.** The proxy registers itself (`POST /oauth/register`, public client `mcp-gateway proxy (<hostname>)`, grants `device_code` + `refresh_token`) and prints to **stderr** (the harness's MCP log; stdout carries only MCP messages):

```
mcp-gateway proxy: sign in to https://gw.example.com to connect this harness.
To sign in, open https://gw.example.com/activate and enter BCDF-GHJK
  or open https://gw.example.com/activate?code=BCDF-GHJK
The page shows the client "mcp-gateway proxy (devbox)". Waiting for approval...
```

Open the link on **any** device signed in to the portal (your laptop's browser, your phone), check the client name and the address it came from, press **Allow**. The harness's first request waits until then; if the harness gives up first, restart it after allowing, or sign in ahead of time from a terminal on that host with `mcp-gateway proxy --login --gateway https://gw.example.com` (it signs in and exits). Deny or a code left for 10 minutes ends the proxy with an error.

**Afterwards** the access token (1 hour) lives in the proxy's memory only and is renewed a minute before it expires, or once after a `401` (the request is then retried once). The rotating refresh token is stored after every renewal, per user and host and per gateway, independent of machine enrollment: in the macOS keychain (service `mcp-gateway-proxy`, account = the gateway URL) or, with `--key-store file` and on Linux, in `~/.config/mcp-gateway/proxy/<id>.token` (0600), next to `<id>.json` (client id and scope, no secret) and `<id>.lock`, where `<id>` is the first 16 hex digits of SHA-256(gateway URL). Several harnesses on the same host share that sign-in; the lock makes their renewals take turns, so none presents a refresh token another already rotated (which would revoke the family). *Disconnect* on `/harnesses` (or a lapsed portal sign-in) ends it: the next renewal answers `invalid_grant` and the proxy shows a new code. Delete the files (or the keychain item) to forget the sign-in.

| Flag | |
|---|---|
| `--gateway URL` | gateway base URL (default `$MCP_GATEWAY_URL`, then `gateway` in `config.yaml`, then the enrolled machine's gateway) |
| `--scope mcp\|mcp:read` | `mcp:read` limits the harness to read tools; changing it signs in again |
| `--login` | sign in if needed and exit |
| `--key-store keychain\|file` | where the refresh token goes (keychain is the macOS default) |
| `--config PATH`, `--verbose` | as for the other commands; debug lines go to stderr and never contain tokens |

Messages are forwarded as they come, concurrently (a slow tool call does not hold up the others), and answers are written one per line; JSON and `text/event-stream` answers are both understood, and notifications (`202`) produce no output. The proxy keeps `MCP-Protocol-Version` from the `initialize` answer (and a `Mcp-Session-Id` if the gateway ever sends one). When stdin closes it writes the answers still in flight and exits. Not supported on Windows yet.

## OpenCode

Use `mcp-gateway proxy` as above (recommended: no token in the config, works over SSH). OpenCode (as of 1.x) sends only static headers for remote MCP servers, so the alternative is a generated token:

```jsonc
// opencode.json
{ "$schema": "https://opencode.ai/config.json",
  "mcp": { "gateway": { "type": "remote", "url": "https://gw.example.com/mcp", "enabled": true,
                        "headers": { "Authorization": "Bearer mgw_<id>_<secret>" } } } }
```

`/tokens/new` renders this snippet with the token filled in. When OpenCode gains OAuth support it will work like Claude Code: the discovery below is standard.

## Harnesses on a remote host (device flow)

A harness running over SSH on another machine cannot receive the browser's loopback redirect. Harnesses that implement the OAuth 2.0 Device Authorization Grant (RFC 8628) sign in with a code instead (`mcp-gateway proxy` does this for any stdio harness):

1. The harness registers for the grant (`grant_types: ["urn:ietf:params:oauth:grant-type:device_code", "refresh_token"]`, public client, no redirect URIs needed) and calls `POST /oauth/device_authorization`.
2. It prints a code like `BCDF-GHJK` and a link, `<base>/activate` (or `<base>/activate?code=BCDF-GHJK`).
3. Open the link in any browser **signed in** to the portal (or enter the code there; case and dash do not matter). The page shows the harness name, what it asks for, and the address and User-Agent the request came from. Check that they are the remote host you are working on, then press **Allow**. Opening the link never approves anything by itself; only the Allow button does. Never allow a code someone sent you.
4. Within a few seconds the harness finishes on its own. It now holds exactly what the browser sign-in gives (1-hour access token, 30-day rotating refresh token), lists on `/harnesses` and is disconnected there like any other.

The code is valid for `GATEWAY_OAUTH_CODE_TTL` (10 minutes). The same `/activate` page enrolls machines (`mcp-gateway login`, [machines.md](machines.md)); it tells you which kind of request a code belongs to.

### Browser sign-in with the harness on another machine

A harness that only does the browser sign-in (authorization code with a loopback redirect, e.g. Claude Code over SSH) opens or prints the authorize URL; you open it on your laptop, but the harness listens on `127.0.0.1:<port>` of the remote host, so the browser's redirect after **Allow** goes to your laptop and fails. For these redirect URIs the gateway answers **Allow** with a page instead of a bare redirect:

- It forwards the browser to the callback after one second (a `<meta http-equiv="refresh">`, no script) and has a **Continue** link to it, so a harness on the same computer finishes as before.
- Under *Is the harness on another machine (SSH)?* it shows `curl '<callback URL>'` (single-quoted for a POSIX shell) with a Copy button. Run it **on the machine where the harness runs**, once, within `GATEWAY_OAUTH_CODE_TTL` (10 minutes) and while the harness is still waiting; the harness then finishes on its own.
- On the consent page, tick **The harness runs on another machine** before pressing **Allow** and the page does not forward the browser at all, so the command stays on screen. Without the tick, if the browser already moved on to an error page, go back to the consent page and Allow again with the box ticked (the first code just expires).

The code on the page is the same code the redirect would carry: single use, bound to the PKCE challenge only the harness holds, so it is useless to anyone else. The page is `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, cannot be framed and loads nothing from another origin. For a remote host, `mcp-gateway proxy` (above) avoids the redirect altogether.

## What the harness does (the discovery flow)

This is the MCP authorization spec, which the gateway implements as both the resource server (`/mcp`) and the authorization server (decision `3ycafouv`):

1. `POST /mcp` without a token → `401` with `WWW-Authenticate: Bearer realm="mcp-gateway", resource_metadata="<base>/.well-known/oauth-protected-resource"`.
2. `GET /.well-known/oauth-protected-resource` (RFC 9728; also at `/.well-known/oauth-protected-resource/mcp` for path-aware clients) → `{"resource": "<base>/mcp", "authorization_servers": ["<base>"], "bearer_methods_supported": ["header"], "scopes_supported": ["mcp", "mcp:read"]}`.
3. `GET /.well-known/oauth-authorization-server` (RFC 8414) → the endpoints below (including `device_authorization_endpoint: <base>/oauth/device_authorization`), `code_challenge_methods_supported: ["S256"]`, `grant_types_supported: ["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"]`, `token_endpoint_auth_methods_supported: ["none", "client_secret_post", "client_secret_basic"]`.
4. `POST /oauth/register` (RFC 7591, no authentication) with `redirect_uris` (https, or http on exactly `localhost` / `127.0.0.1` / `[::1]` on any port; no fragment, no userinfo, no other scheme), `client_name`, `token_endpoint_auth_method: "none"` → `201` with a `client_id`. Public clients get no secret; a client that asks for `client_secret_basic` / `client_secret_post` gets one, shown once. Registrations are limited to `GATEWAY_OAUTH_REGISTER_PER_MIN` per address (`429` + `Retry-After` beyond it), at most `GATEWAY_OAUTH_MAX_UNUSED_CLIENTS` that never completed a sign-in are kept, and a client unused for `GATEWAY_OAUTH_CLIENT_IDLE` is pruned (its `client_id` then answers `invalid_client`; the harness registers again).
5. The browser opens `GET /oauth/authorize?client_id=…&redirect_uri=…&response_type=code&code_challenge=<S256>&code_challenge_method=S256&state=…&scope=mcp&resource=<base>/mcp`. Anonymous users are sent to `/signin?return_to=…` first. The client and the `redirect_uri` are checked before anything else (a mismatch is an error page, never a redirect). The match is exact, with one tolerance from OAuth 2.1 §8.4.2: an http loopback redirect URI (`localhost` / `127.0.0.1` / `[::1]`) may use a different **port** than the registered one, so a harness can bind an ephemeral port per run; scheme, host, path and query must still match, and the code is bound to the URI actually used (repeat it at the token endpoint). `response_type`, PKCE (S256 only), `state` (required), `scope` and the `resource` indicator (RFC 8707: must be exactly `<base>/mcp`) are reported back to the redirect URI as `error=…&state=…`; a repeated parameter is refused. Then the consent page (it cannot be framed: `X-Frame-Options: DENY`): client name, what it asks for, where the tokens go. **Deny** redirects with `error=access_denied`; **Allow** issues a single-use code bound to the user, client, redirect URI, resource and PKCE challenge, valid for `GATEWAY_OAUTH_CODE_TTL` (10 minutes), and sends the browser to the redirect URI with it: a plain `303` for an https redirect URI, and for an http loopback one (`localhost` / `127.0.0.1` / `[::1]`) a short page that forwards the browser after a second (no script needed) and shows the callback as a `curl` command for a harness on another machine (see [Browser sign-in with the harness on another machine](#browser-sign-in-with-the-harness-on-another-machine)). Errors (Deny included) are always a plain `303`. Every authorization response, success or error, carries `iss=<base>` (RFC 9207; the metadata advertises `authorization_response_iss_parameter_supported: true`) so the harness can detect a mix-up with another authorization server.
6. `POST /oauth/token` (form-encoded) with `grant_type=authorization_code&code=…&redirect_uri=…&client_id=…&code_verifier=…&resource=<base>/mcp` → `{"access_token": "<JWT>", "token_type": "Bearer", "expires_in": 3600, "refresh_token": "gwr_…", "scope": "mcp"}`. A replayed code answers `invalid_grant` **and revokes the tokens it produced**; a wrong verifier, client, redirect URI or expired code is `invalid_grant`; a wrong `resource` is `invalid_target`.
7. `POST /mcp` with `Authorization: Bearer <JWT>`. The access token is an ES256 JWT (`typ: at+jwt`, `kid` in the header) with `iss` = `<base>`, `aud` = `<base>/mcp`, `sub` = your user id, `client_id`, `scope`, `fid` (the harness's refresh-token family, which audit rows record as the token id) and a 1-hour `exp`. `/mcp` verifies the signature against `GET /oauth/jwks`, the issuer, the audience, the expiry and that you are not disabled. A token minted for another resource or issuer is `401 invalid_token`.
8. Before the hour is up: `POST /oauth/token` with `grant_type=refresh_token&refresh_token=…&client_id=…` → new access **and refresh** token; the old refresh token is dead. Presenting a dead one again is treated as theft and revokes the whole family (OAuth 2.1 §4.3.1): the harness has to sign in again. Refresh also stops when you are disabled or have not signed in to the portal for `GATEWAY_TOKEN_SIGNIN_MAX_AGE` (30 days). `scope=mcp:read` on a refresh narrows the new tokens; widening is `invalid_scope`.
9. `POST /oauth/revoke` with `token=<refresh token>&client_id=…` (RFC 7009) revokes the family; the answer is `200` whatever the token.

### The device authorization grant (RFC 8628)

Instead of steps 5 and 6, a harness that cannot receive a redirect:

- registers with `grant_types` including `urn:ietf:params:oauth:grant-type:device_code` and `token_endpoint_auth_method: "none"` (the grant is for public clients; a confidential client asking for it is `invalid_client_metadata`). Without `authorization_code` in `grant_types`, `redirect_uris` must be absent (`invalid_redirect_uri`) and `response_types` is `[]`. A client must register at least one of `authorization_code` and the device grant, and may only use the grants it registered: `/oauth/authorize` answers `unauthorized_client` (at the registered redirect URI) to a client without `authorization_code`, and the token endpoint answers `unauthorized_client` for any grant type the client did not register (`authorization_code`, `refresh_token` or the device grant). A client stored without `grant_types` keeps the default `authorization_code` + `refresh_token`.
- `POST /oauth/device_authorization` (form-encoded) with `client_id`, `scope` (`mcp`, `mcp:read`, or empty for `mcp`; within what the client registered) and `resource=<base>/mcp` (required, exactly one, as on `/oauth/authorize`) → `200` `{"device_code": "gwd_…", "user_code": "BCDF-GHJK", "verification_uri": "<base>/activate", "verification_uri_complete": "<base>/activate?code=BCDF-GHJK", "expires_in": 600, "interval": 5}` with `Cache-Control: no-store`. Errors: `invalid_client` (`401`, unknown client), `unauthorized_client` (not registered for the grant), `invalid_scope`, `invalid_target`, `invalid_request` (a repeated parameter, not a form). The device code (256 bits) and the user code (8 letters from `BCDFGHJKLMNPQRSTVWXZ`, about 2^34.6) are stored as SHA-256 only, with the requesting address and User-Agent (`oauth_device_grants`, migration 00034). Every request spends the address's `GATEWAY_OAUTH_DEVICE_PER_MIN` budget (default 10; `429` + `Retry-After`), and a client may hold at most 10 pending, unexpired grants (`429`). Expires after `GATEWAY_OAUTH_CODE_TTL`.
- polls `POST /oauth/token` with `grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=…&client_id=…` every `interval` seconds: `authorization_pending` until the user answers; `slow_down` when it polls sooner than the interval since its last poll, which also raises that grant's interval by 5 seconds (up to 60); `access_denied` after Deny; `expired_token` after expiry; `invalid_grant` for an unknown code; `invalid_client` (`401`) when another client presents the code; `unauthorized_client` for a client not registered for the grant. After **Allow** the next poll answers exactly what step 6 answers (same JWT, a new `gwr_` refresh-token family, the user who pressed Allow as `sub`). The device code is single use: presenting it again is `invalid_grant` **and revokes the family it produced**, as a replayed authorization code does.

The user's side is `/activate` (portal session, the page machine enrollment uses): a user code typed or prefilled from `verification_uri_complete` is looked up among pending machine requests and harness grants, and the confirmation names its kind. For a harness it shows the code, client name and id, the scopes, the resource, the requesting address and User-Agent, and **Allow** / **Deny**: a `POST` with the session's CSRF token whose `request_id` must belong to the code. A `GET`, prefilled or not, only displays. The page cannot be framed (`X-Frame-Options: DENY`, `frame-ancestors 'none'`). Wrong codes are limited to 10 a minute per user and 30 a minute per address; while limited even a right code is refused. The two kinds use the same code format and hash, and neither table accepts a user code the other holds (the inserts check, and `/activate` refuses a code found in both), so a code never resolves to the wrong kind.

Signing keys live in the `signing_keys` table, the private half envelope-encrypted (`docs/crypto.md`), so every replica signs with the same key and verifies with the same JWKS. The key is rotated after `GATEWAY_OAUTH_KEY_ROTATION` (30 days); the previous key keeps verifying for `GATEWAY_OAUTH_KEY_GRACE` (2 hours, longer than any access token) and is then deleted.

## Local walkthrough with curl

Run the gateway with a key provider (`GATEWAY_KEY_PROVIDER=file`, `GATEWAY_KEY_FILE=…`; `make compose-up` does) and `GATEWAY_BASE_URL=http://localhost:18080`. Everything below is what the acceptance test (`internal/authserver/e2e_test.go`) does; the outputs were captured against `bin/gateway`.

```bash
B=http://localhost:18080

# 1. The challenge
curl -s -D - -o /dev/null -X POST $B/mcp | grep -i www-authenticate
# Www-Authenticate: Bearer realm="mcp-gateway", resource_metadata="http://localhost:18080/.well-known/oauth-protected-resource"

# 2.+3. Discovery
curl -s $B/.well-known/oauth-protected-resource
# {"resource":"http://localhost:18080/mcp","authorization_servers":["http://localhost:18080"],"bearer_methods_supported":["header"],"scopes_supported":["mcp","mcp:read"],"resource_name":"MCP Gateway"}
curl -s $B/.well-known/oauth-authorization-server | python3 -m json.tool

# 4. Register a public client (loopback redirect, PKCE)
curl -s -X POST $B/oauth/register -H 'Content-Type: application/json' \
  -d '{"client_name":"curl","redirect_uris":["http://localhost:8765/callback"],"token_endpoint_auth_method":"none"}'
# {"client_id":"gwc_C6K2Kub-FgpDdAYlXxFKMQ","client_id_issued_at":1791510055,"client_name":"curl","redirect_uris":["http://localhost:8765/callback"],"token_endpoint_auth_method":"none","grant_types":["authorization_code","refresh_token"],"response_types":["code"],"scope":"mcp mcp:read"}
CID=gwc_C6K2Kub-FgpDdAYlXxFKMQ
curl -s -X POST $B/oauth/register -H 'Content-Type: application/json' -d '{"redirect_uris":["http://evil.test/cb"]}'
# {"error":"invalid_redirect_uri","error_description":"http://evil.test/cb: http is only allowed for localhost / 127.0.0.1 / [::1]"}

# 5. PKCE pair and the authorization URL (open it in the browser that is signed in to the portal)
V=$(openssl rand -base64 32 | tr -d '=+/' | cut -c1-43)
C=$(printf %s "$V" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')
open "$B/oauth/authorize?client_id=$CID&redirect_uri=http%3A%2F%2Flocalhost%3A8765%2Fcallback&response_type=code&code_challenge=$C&code_challenge_method=S256&state=xyz&scope=mcp&resource=http%3A%2F%2Flocalhost%3A18080%2Fmcp"
# anonymous → 303 /signin?return_to=/oauth/authorize?...; signed in → consent page → Allow →
# a page that forwards to http://localhost:8765/callback?code=<code>&iss=...&state=xyz
#   (nothing listens there; copy the code from the page's Continue link or curl command, or the address bar)
CODE=...

# 6. Exchange
curl -s -X POST $B/oauth/token -d "grant_type=authorization_code&code=$CODE&redirect_uri=http://localhost:8765/callback&client_id=$CID&code_verifier=$V&resource=http://localhost:18080/mcp"
# {"access_token":"eyJhbGciOiJFUzI1NiIs...","token_type":"Bearer","expires_in":3600,"refresh_token":"gwr_...","scope":"mcp"}
AT=eyJ... ; RT=gwr_...
curl -s -X POST $B/oauth/token -d "grant_type=authorization_code&code=$CODE&redirect_uri=http://localhost:8765/callback&client_id=$CID&code_verifier=$V"
# {"error":"invalid_grant","error_description":"the authorization code was already used"}   (and the family above is now revoked)

# 7. Use it
curl -s $B/mcp -H "Authorization: Bearer $AT" -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
curl -s $B/oauth/jwks
# {"keys":[{"use":"sig","kty":"EC","kid":"FsqeawPOHvcp9HH9","crv":"P-256","alg":"ES256","x":"...","y":"..."}]}

# 8. Refresh (rotates), 9. revoke
curl -s -X POST $B/oauth/token -d "grant_type=refresh_token&refresh_token=$RT&client_id=$CID"
curl -s -o /dev/null -w '%{http_code}\n' -X POST $B/oauth/revoke -d "token=$RT&client_id=$CID"
```

`/harnesses` in the portal lists the `curl` client with when it connected and was last used; *Disconnect* there does what step 9 does.

## Secrets the agent asks for (`-32042`)

When the gateway runs with ephemeral secrets ([secrets.md](secrets.md)), an agent asks the user for a password with `secrets.request` and gets JSON-RPC error **`-32042`** (URL elicitation required). The message holds the link (`<base>/s/<id>`) and four check words; `error.data` holds the same `url`, the `handle`, the `fingerprint` and `elicitations[]` in the MCP URL-elicitation shape. The gateway never sends `notifications/elicitation/complete`: the agent shows the link, the user enters the secret in the browser, and the agent retries the real call with `{"<arg>": {"$secret": "<handle>"}}`. Harnesses built on the official go-sdk client get `-32042` from `CallTool` as a plain error, without running an elicitation handler, so the harness (or the model reading the error) must show the link. Retrying while the user has not saved the secret yet answers the same `-32042`.

**Credential links.** With `GATEWAY_CREDENTIAL_LINKS_ENABLED`, a call to a user-added MCP server that fails on a credential the caller can fix (no connection yet, sign-in needed, an expired or rejected key, a missing per-user header value) also answers **`-32042`**: the message ends with "connect your account at `<base>/servers/<id>/connect`" (OAuth) or "`…#connection`", `then retry`, and `error.data` holds `url`, `server` and one `elicitations[]` entry (`elicitationId` `gwc_…`, stable for the same user, server and problem). The server's owner gets the same shape with `<base>/servers/<id>/edit` for problems only the owner can fix (missing shared credential, invalid setup); everyone else keeps the `-32031` text. Show the link, let the user fix it in the browser, then retry the same call. See [federation-connector.md](federation-connector.md#credential-links).

**Upstream page requests.** With `GATEWAY_UPSTREAM_ELICITATION_ENABLED`, a user-added server that wants the user on its own page answers **`-32042`** through the gateway: the message is "`<server>` asks you to open a page: `<base>/elicit/<id>` — then retry", `error.data` holds `url`, `server` and `elicitations[]` (`elicitationId` `gwe_…`, `message` "`<server>` asks you to open a page"). The link opens the gateway's confirmation page, never the server's page directly, and neither the message nor the data carry the server's own text or URL. Show the link; when the user says they are done, retry the same call. The gateway never sends `notifications/elicitation/complete`. See [elicitation.md](elicitation.md).

## Operating notes

- Both `/oauth/*` and `/.well-known/*` are served by the gateway itself; a reverse proxy only needs to forward `GATEWAY_BASE_URL` as-is (the issuer must match what harnesses see, and must be `https` outside local development). The documents, the `iss` parameter and the 401 challenge are built from `GATEWAY_BASE_URL`, never from the request's `Host` / `X-Forwarded-Host`. A wrong method on any of these routes is `405` with `Allow`; `OPTIONS` is the CORS preflight (`Access-Control-Allow-Origin: *`, no credentials, for browser-hosted harnesses).
- The OAuth attack suite (`make test-attack`, `test/oauthattack`, CI job *OAuth attack suite*) runs the whole gateway in-process and asserts the exact failure of every attack it knows: redirect URI tampering and loopback lookalikes, code replay and cross-client exchange, PKCE downgrade, resource / audience confusion against a decoy gateway, forged and mis-issued JWTs (`alg=none`, HS256 key confusion, unknown or rotated-out `kid`, missing `exp`), refresh reuse and revocation, registration flooding and hostile metadata, consent CSRF and tampering, the loopback callback page (escaping, no foreign assets or inline script, the code still single-use and PKCE-bound, errors still redirects), open redirects on `/signin?return_to=`, clickjacking, host-header injection, endpoint hygiene, and the device grant (device code reuse revoking the family, `slow_down`, user-code brute force on `/activate`, resource mismatch, wrong client, expiry, deny, approval without CSRF, a prefilled code never approving). Extend it when the server grows a new input.
- Harnesses that cannot register dynamically can be registered by `curl` as above and given the `client_id` by hand.
- Audit (`/activity`): `oauth_consent_granted` / `oauth_consent_denied`, `oauth_harness_revoked`, `oauth_harness_revoked_by_client`, the device grant's `oauth_device_authorization_requested` (no user yet; client, scope, requesting address), `oauth_device_approved`, `oauth_device_denied` and `oauth_device_redeemed` (with `device_grant_id`), and the three reuse events `oauth_code_replayed`, `oauth_device_code_replayed` and `oauth_refresh_reuse` (decision `deny`), all with the client id and name in the resource identity and the family id as the token id; every tool call made with an OAuth token carries that family id as its `token_id`.
- Metrics: OAuth rejections count in `auth_failures_total{reason}` like generated tokens (`malformed`, `unknown`, `expired`, `user_disabled`).
- Logs: `authserver.client_registered`, `authserver.consent_granted`, `authserver.tokens_issued`, `authserver.code_replayed`, `authserver.refresh_reuse`, `authserver.device_requested` / `device_approved` / `device_denied` / `device_code_replayed` / `device_code_wrong_client`, `authserver.key_created` / `key_rotated`, `authserver.pruned`.
