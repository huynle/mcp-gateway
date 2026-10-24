# Connecting a harness

Every harness talks to one endpoint, `GATEWAY_BASE_URL` + `/mcp` (stateless Streamable HTTP), and authenticates each request with a bearer token. There are two ways to get one:

| | **MCP OAuth sign-in** | **Generated token** |
|---|---|---|
| Who | harnesses that implement the MCP authorization spec (Claude Code, Claude Desktop, the MCP inspector, most SDK clients) | anything that can set a header: OpenCode, scripts, `curl`, older harnesses |
| How | the harness discovers the gateway's authorization server, registers itself, opens the browser; you sign in with your company account and approve it | you create a token at `/tokens` and paste it into the harness config |
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

## OpenCode

OpenCode (as of 1.x) sends static headers for remote MCP servers, so use a generated token:

```jsonc
// opencode.json
{ "$schema": "https://opencode.ai/config.json",
  "mcp": { "gateway": { "type": "remote", "url": "https://gw.example.com/mcp", "enabled": true,
                        "headers": { "Authorization": "Bearer mgw_<id>_<secret>" } } } }
```

`/tokens/new` renders this snippet with the token filled in. When OpenCode gains OAuth support it will work like Claude Code: the discovery below is standard.

## What the harness does (the discovery flow)

This is the MCP authorization spec, which the gateway implements as both the resource server (`/mcp`) and the authorization server (decision `3ycafouv`):

1. `POST /mcp` without a token → `401` with `WWW-Authenticate: Bearer realm="mcp-gateway", resource_metadata="<base>/.well-known/oauth-protected-resource"`.
2. `GET /.well-known/oauth-protected-resource` (RFC 9728; also at `/.well-known/oauth-protected-resource/mcp` for path-aware clients) → `{"resource": "<base>/mcp", "authorization_servers": ["<base>"], "bearer_methods_supported": ["header"], "scopes_supported": ["mcp", "mcp:read"]}`.
3. `GET /.well-known/oauth-authorization-server` (RFC 8414) → the endpoints below, `code_challenge_methods_supported: ["S256"]`, `grant_types_supported: ["authorization_code", "refresh_token"]`, `token_endpoint_auth_methods_supported: ["none", "client_secret_post", "client_secret_basic"]`.
4. `POST /oauth/register` (RFC 7591, no authentication) with `redirect_uris` (https, or http on exactly `localhost` / `127.0.0.1` / `[::1]` on any port; no fragment, no userinfo, no other scheme), `client_name`, `token_endpoint_auth_method: "none"` → `201` with a `client_id`. Public clients get no secret; a client that asks for `client_secret_basic` / `client_secret_post` gets one, shown once. Registrations are limited to `GATEWAY_OAUTH_REGISTER_PER_MIN` per address (`429` + `Retry-After` beyond it), at most `GATEWAY_OAUTH_MAX_UNUSED_CLIENTS` that never completed a sign-in are kept, and a client unused for `GATEWAY_OAUTH_CLIENT_IDLE` is pruned (its `client_id` then answers `invalid_client`; the harness registers again).
5. The browser opens `GET /oauth/authorize?client_id=…&redirect_uri=…&response_type=code&code_challenge=<S256>&code_challenge_method=S256&state=…&scope=mcp&resource=<base>/mcp`. Anonymous users are sent to `/signin?return_to=…` first. The client and the `redirect_uri` are checked before anything else (a mismatch is an error page, never a redirect). The match is exact, with one tolerance from OAuth 2.1 §8.4.2: an http loopback redirect URI (`localhost` / `127.0.0.1` / `[::1]`) may use a different **port** than the registered one, so a harness can bind an ephemeral port per run; scheme, host, path and query must still match, and the code is bound to the URI actually used (repeat it at the token endpoint). `response_type`, PKCE (S256 only), `state` (required), `scope` and the `resource` indicator (RFC 8707: must be exactly `<base>/mcp`) are reported back to the redirect URI as `error=…&state=…`; a repeated parameter is refused. Then the consent page (it cannot be framed: `X-Frame-Options: DENY`): client name, what it asks for, where the tokens go. **Deny** redirects with `error=access_denied`; **Allow** redirects with a single-use code bound to the user, client, redirect URI, resource and PKCE challenge, valid for `GATEWAY_OAUTH_CODE_TTL` (10 minutes). Every authorization response, success or error, carries `iss=<base>` (RFC 9207; the metadata advertises `authorization_response_iss_parameter_supported: true`) so the harness can detect a mix-up with another authorization server.
6. `POST /oauth/token` (form-encoded) with `grant_type=authorization_code&code=…&redirect_uri=…&client_id=…&code_verifier=…&resource=<base>/mcp` → `{"access_token": "<JWT>", "token_type": "Bearer", "expires_in": 3600, "refresh_token": "gwr_…", "scope": "mcp"}`. A replayed code answers `invalid_grant` **and revokes the tokens it produced**; a wrong verifier, client, redirect URI or expired code is `invalid_grant`; a wrong `resource` is `invalid_target`.
7. `POST /mcp` with `Authorization: Bearer <JWT>`. The access token is an ES256 JWT (`typ: at+jwt`, `kid` in the header) with `iss` = `<base>`, `aud` = `<base>/mcp`, `sub` = your user id, `client_id`, `scope`, `fid` (the harness's refresh-token family, which audit rows record as the token id) and a 1-hour `exp`. `/mcp` verifies the signature against `GET /oauth/jwks`, the issuer, the audience, the expiry and that you are not disabled. A token minted for another resource or issuer is `401 invalid_token`.
8. Before the hour is up: `POST /oauth/token` with `grant_type=refresh_token&refresh_token=…&client_id=…` → new access **and refresh** token; the old refresh token is dead. Presenting a dead one again is treated as theft and revokes the whole family (OAuth 2.1 §4.3.1): the harness has to sign in again. Refresh also stops when you are disabled or have not signed in to the portal for `GATEWAY_TOKEN_SIGNIN_MAX_AGE` (30 days). `scope=mcp:read` on a refresh narrows the new tokens; widening is `invalid_scope`.
9. `POST /oauth/revoke` with `token=<refresh token>&client_id=…` (RFC 7009) revokes the family; the answer is `200` whatever the token.

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
# http://localhost:8765/callback?code=<code>&state=xyz   (nothing listens there; copy the code from the address bar)
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
- The OAuth attack suite (`make test-attack`, `test/oauthattack`, CI job *OAuth attack suite*) runs the whole gateway in-process and asserts the exact failure of every attack it knows: redirect URI tampering and loopback lookalikes, code replay and cross-client exchange, PKCE downgrade, resource / audience confusion against a decoy gateway, forged and mis-issued JWTs (`alg=none`, HS256 key confusion, unknown or rotated-out `kid`, missing `exp`), refresh reuse and revocation, registration flooding and hostile metadata, consent CSRF and tampering, open redirects on `/signin?return_to=`, clickjacking, host-header injection and endpoint hygiene. Extend it when the server grows a new input.
- Harnesses that cannot register dynamically can be registered by `curl` as above and given the `client_id` by hand.
- Audit (`/activity`): `oauth_consent_granted` / `oauth_consent_denied`, `oauth_harness_revoked`, `oauth_harness_revoked_by_client`, and the two reuse events `oauth_code_replayed` and `oauth_refresh_reuse` (decision `deny`), all with the client id and name in the resource identity and the family id as the token id; every tool call made with an OAuth token carries that family id as its `token_id`.
- Metrics: OAuth rejections count in `auth_failures_total{reason}` like generated tokens (`malformed`, `unknown`, `expired`, `user_disabled`).
- Logs: `authserver.client_registered`, `authserver.consent_granted`, `authserver.tokens_issued`, `authserver.code_replayed`, `authserver.refresh_reuse`, `authserver.key_created` / `key_rotated`, `authserver.pruned`.
