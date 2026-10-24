# Upstream auth and credentials (`internal/federation/auth`)

How the gateway finds out how a **user-added MCP server** wants to be authenticated, and how it holds and uses the credentials: OAuth connections per user, shared or per-user API keys, bearer tokens and custom headers. The package supplies the [federation client](federation-client.md)'s `Authorizer`s. Everything outbound goes through [netguard](netguard.md). Design: Brain plan `0omkv2e1`, decisions `yhd5kcaz`, `yd6qrbqc`, `uvi2nzcw`, `17iv8p3b`, task `k3ff95ec`.

Wired by `connector.Wire` and mounted by `cmd/gateway/federation.go` (see [federation-connector.md](federation-connector.md)): `GET /servers/{id}/connect` and `GET /servers/oauth/callback` behind the portal session, the client metadata document public; the connector calls `ForUser` and `Reauth` for every federated tool call.

## Wiring (for the connector task)

```go
guard := netguard.New(netguard.Options{ /* allow list, metrics, log */ })
svc, err := auth.New(auth.Options{
    HTTPClient: guard.Client(),               // required: every request goes through it
    Store:      auth.NewPostgresStore(st),    // AsUser = WithUser, Bypass = WithJobs
    Keys:       keyProvider,                  // the gateway's crypto.KeyProvider
    BaseURL:    cfg.BaseURL,                  // GATEWAY_BASE_URL
    Log:        log,
    // optional: ClientName, Clock, StateTTL (10m), RefreshSkew (1m), Replay, Finish
})

user := func(r *http.Request) (string, bool) { /* portal session -> user ID */ }
mux.Handle("GET /servers/{id}/connect", svc.StartConnect(user))          // -> 302 to the AS
mux.Handle("GET "+auth.CallbackPath, svc.Callback(user))                  // /servers/oauth/callback
mux.Handle("GET "+auth.ClientMetadataPath, svc.ClientMetadataDocument())  // public, no session

// Per call:
az, err := svc.ForUser(ctx, server, userID) // auth.Authorizer (a client.Authorizer)
c, _ := client.New(client.Options{HTTPClient: guard.Client(), Authorizer: az})
err = auth.Reauth(ctx, az, func() error { /* connect + call */ })
```

`Options.Finish(w, r, serverID, err)` renders the end of the callback (default: a short plain-text page). The portal will want to redirect to its servers page instead.

## API

| Function | Purpose |
|---|---|
| `NewDiscoverer(DiscoveryOptions{HTTPClient, Log})`, `(*Discoverer).Detect(ctx, url)`, `(*Service).Detect` | auth detection (below) |
| `(*Service).ConnectURL(ctx, userID, serverID)` | start an OAuth connection; returns the AS authorization URL |
| `(*Service).CompleteConnect(ctx, CallbackRequest{UserID, State, Code, Iss, Error})` | finish it; returns the server ID |
| `(*Service).StartConnect(UserFunc)`, `Callback(UserFunc)`, `ClientMetadataDocument()` | the HTTP handlers |
| `(*Service).ForUser(ctx, server, userID) (Authorizer, error)` | credentials for one user's calls |
| `Reauth(ctx, az, call)` | run a call; on an upstream 401 refresh once and retry; give up (needs_reconnect) on the second |
| `(*Service).SetSharedCredential(ctx, Actor, serverID, Credential)` | shared API key / bearer / headers (owner, or `Actor{Admin: true}` through the bypass role) |
| `(*Service).SetUserCredential(ctx, userID, serverID, Credential)` | the user's own key / bearer / headers, or values of per-user headers |
| `(*Service).SetStaticClient(ctx, Actor, serverID, clientID, secret, issuer)` | a hand-registered OAuth client (owner or admin) |
| `(*Service).Disconnect(ctx, userID, serverID)` | delete the user's connection (no revocation at the AS) |
| `CanonicalResource(u)` | the RFC 8707 canonical URI of a server |

`Actor.Admin` switches to the bypass role: only set it after checking the user is an admin.

**Owner-only causes of `ErrNotConfigured`** (credential links, [federation-connector.md](federation-connector.md#credential-links)). Each wraps `ErrNotConfigured` and keeps its text (`errors.Is(err, ErrNotConfigured)` and every message stay as they were); `errors.Is` with the sub-sentinel tells them apart:

| Sentinel | Returned by |
|---|---|
| `ErrSharedMissing` | `ForUser`, shared mode: no shared credential, one sealed to another URL, or one without what the auth kind needs |
| `ErrModeInvalid` | `ForUser`: an unknown auth kind (e.g. `auto`) or credential mode. Shared OAuth stays `ErrUnsupported` |
| `ErrNowRequiresAuth` | the no-auth Authorizer's `Unauthorized` (`Reauth`): a server added without authentication answered 401 |

**Missing per-user header values.** By default `ForUser` leaves a declared per-user header (`header_config.per_user`) the user has no value for out of the request (as before). With `Options.RequireUserHeaders`, or on the view `(*Service).UserHeadersRequired(true)` (same store, keys and replay guard), it refuses with **`ErrUserHeaderMissing`** instead, in both modes; per-user mode still answers `ErrNotConnected` first when there is no connection. `connector.Wire` gives the Manager the strict view when `WireOptions.CredentialLinks` is set; `Federation.Auth` (the portal's refresh, the admin pages) stays lenient.

Errors are sentinels safe to show (`ErrNotConnected`, `ErrNeedsReconnect`, `ErrNotConfigured` and its owner-only causes `ErrSharedMissing` / `ErrModeInvalid` / `ErrNowRequiresAuth`, `ErrUserHeaderMissing`, `ErrUnsupported`, `ErrNoOAuth`, `ErrPKCEUnsupported`, `ErrNoClient`, `ErrFlowInvalid`, `ErrDenied`, `ErrSharedCredentialRejected`, `ErrInvalidCredential`, `ErrForbidden`, `ErrInvalidServerURL`), `store.ErrNotFound` for a server the user cannot see, or a `*client.Error` from discovery. The handlers answer with the sentinel's text only.

## Detection

`Detect(ctx, serverURL)` returns `DetectResult{AuthKinds, ResourceMetadata, ResourceMetadataURL, AuthServerMetadata, Resource, SupportsDCR, SupportsCIMD, SupportsS256, OfflineAccess, Scopes, Blocked}`:

1. Unauthenticated `initialize` through the federation client. Success: `AuthKinds = [none]`. A failure other than 401/403 is returned as the `*client.Error` (unreachable, blocked, ...).
2. On 401/403 the `WWW-Authenticate` challenge is parsed (defensively, never displayed). Protected resource metadata (RFC 9728) is tried at the challenge's `resource_metadata`, then the path-aware `/.well-known/oauth-protected-resource/<path>`, then the root. A document is accepted only if it names authorization servers and its `resource` is the server's origin with a path equal to, or a segment prefix of, the server's path (Brain names its origin).
3. Authorization server metadata for each advertised issuer (or, with no resource metadata, the server's origin, as in MCP 2025-03-26): RFC 8414 `/.well-known/oauth-authorization-server[/<path>]`, then OIDC `/.well-known/openid-configuration[/<path>]` and `<issuer>/.well-known/openid-configuration`. The document's `issuer` must equal the issuer (RFC 8414 §3.3) and it must name absolute authorization and token endpoints.
4. With AS metadata: `AuthKinds = [oauth, api_key, bearer, headers]`; otherwise `[api_key, bearer, headers]` for the owner to choose. `Scopes` = the challenge's `scope`, else the resource's `scopes_supported`. `Resource` = the resource metadata's `resource` when accepted, else the canonical server URL. `Blocked` lists netguard refusals (`host: reason`) met on the way.

Shapes covered by tests: Brain (`401 Bearer realm="brain-api"` without `resource_metadata`, PRM at both well-known URLs naming the origin, AS metadata at the root with `registration_endpoint` and S256), API-key-only (401 without metadata), no auth, OIDC fallback, mismatched issuer and resource, internal destinations.

## OAuth connections (credential mode `per_user`, auth kind `oauth`)

- **Client**: a static client set by the owner/admin wins (an explicit choice; if it names an issuer, it must match). Otherwise a stored CIMD or DCR client of the same issuer is reused. Otherwise the gateway's **client ID metadata document** URL (`<BASE_URL>/.well-known/mcp-gateway-client.json`) is the client ID when the AS advertises `client_id_metadata_document_supported`; else **dynamic client registration** (RFC 7591, public client `token_endpoint_auth_method: none` when the AS allows it). Clients are stored with `store.UpsertMCPOAuthClient` through the bypass role, because any user of a published server may be the first to connect; a client secret is enveloped (AAD: server, method; a static client also the server URL).
- **Authorization request**: code + PKCE S256 (refused with `ErrPKCEUnsupported` when the AS does not advertise S256), `resource` (RFC 8707), `scope` (configured `auth_config.scopes`, else discovered, plus `offline_access` when the AS advertises it), redirect URI `<BASE_URL>/servers/oauth/callback`.
- **State**: no table. The state value is `<server id>.<sealed envelope>`, sealed with the gateway's envelope crypto under AAD bound to the user and the server. It carries the PKCE verifier, issuer, token endpoint, client, resource and scopes, expires after `StateTTL`, and is one-use through `ReplayGuard` (in-process by default; plug a shared one in for several replicas). A replay on another replica would still need a fresh code issued for this state's PKCE challenge, which only the AS can mint.
- **Callback**: the state must open for the signed-in user. If the AS advertises RFC 9207, or sends `iss` anyway, `iss` must equal the issuer. An `error` from the AS becomes `ErrDenied`. The server must still have the URL it had when the flow started (the state carries it); otherwise the flow is refused, so a token minted for the old resource is never stored for (and sent to) a new address. The code is exchanged with the verifier and the resource, and the token bundle (tokens + issuer, token endpoint, client ID, auth method, resource, scopes, pinned at connect time) is stored with `store.UpsertMCPUserConnection`, AAD = (user, server, auth kind, server URL).
- **Refresh**: when the token is within `RefreshSkew` of expiry, or the upstream answered 401 with it, the refresh runs **under `SELECT ... FOR UPDATE`** on the connection (`store.LockMCPUserConnection`, added by this task): one refresh at a time per connection across replicas, and waiters read the new token. `resource` is sent again. A rotated refresh token is stored (the old one kept if none is returned). `invalid_grant`, a missing refresh token or an unreadable bundle mark the connection `needs_reconnect` (`ErrNeedsReconnect`). Other failures are transient errors.
- **401 from upstream**: `Reauth` calls `Authorizer.Unauthorized` once, which forces a refresh unless another request already refreshed, then retries. A second 401 marks the connection `needs_reconnect`.

x/oauth2 is used only for `GenerateVerifier` and `S256ChallengeFromVerifier`. Registration, token and refresh requests are made by this package with the netguard client, so nothing can fall back to `http.DefaultClient`.

Shared OAuth tokens (one token for all users) are **not supported** (`ErrUnsupported`).

## Static credentials

| Kind | Stored | Sent |
|---|---|---|
| `api_key` | `Credential.APIKey` | header `auth_config.api_key.header` (preferred), else query parameter `auth_config.api_key.query`, else header `X-API-Key` |
| `bearer` | `Credential.Bearer` | `Authorization: Bearer <token>` |
| `headers` | `Credential.Headers` | each header |
| `none` | - | nothing |

- **Shared** (`credential_mode = shared`): `SetSharedCredential` stores the credential once with `store.SetMCPServerSharedSecret` (AAD: server, kind, server URL; `SecretKeys` names only what it holds, e.g. `api_key`, `header:X-Foo`). It is read through the bypass role for every user. A 401 returns `ErrSharedCredentialRejected` and marks nothing.
- **Bound to the server URL** (security task rvrfpzzj): an owner may edit a server's URL even after it is published. Because user connections, the shared credential and a static client secret are sealed to the URL, a changed URL makes them unreadable: users must reconnect (`needs_reconnect`), and the shared credential and static client must be set again (`server_not_configured` / no client). Nobody's stored credential is ever sent to an address it was not entered for. Registered (DCR) clients are not URL-bound: they are only used with the issuer they were registered at.
- **Per user**: `SetUserCredential` stores the user's own key, token or headers (AAD: user, server, kind, server URL). A 401 marks the connection `needs_reconnect`. Setting the credential again revives it.
- **Per-user headers** (`header_config.per_user`, e.g. Brain's `X-Brain-Project`): the user's values live in their connection bundle (next to an OAuth token, if any) and are added for any kind and mode. Undeclared names are refused. Static non-secret headers (`header_config.static`) belong in `client.Endpoint.Headers` (connector).
- Validation: values without control characters, up to 8 KiB; header names must be RFC 9110 tokens, and not transport-owned (`Host`, `Content-*`, `Accept*`, hop-by-hop, `Cache-Control`, `Last-Event-Id`), `Mcp-*` or `Proxy-*`.

## Security notes

- Every request (MCP probe, metadata, registration, token, refresh) uses `Options.HTTPClient`. Metadata or endpoints that point at loopback, private or metadata addresses are refused unless an admin allow-lists them, and appear in `DetectResult.Blocked`.
- Secrets are never logged: logs carry event names, user and server IDs, OAuth error codes (validated `[A-Za-z0-9_.-]{1,64}`) and `observability.RedactError` of transport errors. Error descriptions and bodies from the AS are dropped. A test captures all logs of the flows and checks that no token, code, client secret or key appears.
- Authorization servers and protected-resource documents are upstream-controlled: they are size-capped (256 KiB metadata, 1 MiB token responses), validated, and never echoed to users.

## Tests

`go test -race ./internal/federation/auth/` runs everything in-process: a fake network maps public-looking names to `httptest` servers through the **real** netguard resolver and dial hooks, an in-process AS is shaped like Brain's (knobs: CIMD, iss, no S256, no registration, internal token endpoint, failing refresh), and an in-memory store with schema 14's visibility rules. `make test-integration` adds `TestIntegrationFederationAuthPostgres` (the flow over PostgreSQL row-level security with a published server and a non-owner connecting first) and `TestIntegrationMCPUserConnectionLock`.
