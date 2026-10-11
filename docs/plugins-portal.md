# Servers portal (`internal/federation/portal`)

The users' pages for **user-added MCP servers** ("plugins"): list my servers and the ones published to me, add a server, connect my account or key, refresh and review its tools, browse its resources and prompts, and manage tunnels. Design: Brain plan `0omkv2e1`, decisions `yhd5kcaz` (everyone may add; servers start private; frozen snapshots), `17iv8p3b` (owner writes, admin-only publish and published review), `7datr7x4` (server-rendered portal, CSRF), `u46t7kmq` (shared nav); task `9dp13dgy`. Admin pages (publish, review published servers, allow-list) are a separate task.

## Pages

| Route | Who | What |
|---|---|---|
| `GET /servers` | signed in | My servers and servers published to me: status, last error class, auth kind, my connection (**connected / needs connect / needs reconnect / shared credential / no connection needed**), **pending review** badge. Tunnels section: my live tunnels (online on this replica / offline, last seen), create, revoke. |
| `GET /servers/new`, `POST /servers/new` | signed in | Add form. `action=detect` re-renders with what detection found; anything else creates the server. |
| `POST /servers/tunnels` | signed in | Create a tunnel. The response shows the token **once** (no redirect, `no-store`) with `mcp-gateway-tunnel --gateway <BaseURL> --token … --stdio "…"` and the `MCP_GATEWAY_TUNNEL_TOKEN=…` variant. |
| `POST /servers/tunnels/revoke` | tunnel owner | Revoke (form field `id`); another user's tunnel is the 404 page. |
| `GET /servers/{id}` | can see the server | Settings (no secrets: "a secret is stored"), my connection with **Connect / Reconnect** (OAuth: link to `/servers/{id}/connect`) or a form for my API key / bearer / headers and per-user header values, **Disconnect**, approved-snapshot summary, links to review and resources. Owner: stored-credential summary, **Refresh**, Edit, Delete. |
| `POST /servers/{id}/credential` | can see | `auth.SetUserCredential` (fields `api_key`, `bearer`, `headers`, `header:<Name>`). |
| `POST /servers/{id}/disconnect` | can see | `auth.Disconnect`. |
| `POST /servers/{id}/refresh` | owner | Opens a session with the owner's credential (ClientFactory), `snapshot.Refresh`, redirects to the review. Failures are class-level messages. |
| `GET /servers/{id}/review` | can see | Latest snapshot vs the approved one: added / changed (with fields) / removed tools, resource, template and prompt changes; per tool the display name, title, sanitized description, annotated kind, enable checkbox and kind override. |
| `POST /servers/{id}/review` | owner of a **private** server | `snapshot.Approve` with `Actor{UserID, Admin: false}`, then `Hook.ServerChanged`. A published server shows "an admin must review" (403). |
| `GET /servers/{id}/resources` | can see | Resources, resource templates and prompts (with arguments) of the **approved** snapshot. No upstream call. |
| `POST /servers/{id}/resources/read` | can see | Reads one resource **listed in the approved snapshot** (others: 422, no upstream call) live with my credential; bounded preview. |
| `GET /servers/{id}/prompts/{name}`, `POST …` | can see | A prompt of the approved snapshot with its argument form; POST gets it live (required arguments checked) and previews the messages. |
| `GET/POST /servers/{id}/edit`, `POST /servers/{id}/delete` | owner | Edit (the name is fixed: it is the tool prefix) / delete. Both call the hook. |

Every route: 401 without a user; `Cache-Control: no-store`; POSTs need the CSRF token (`_csrf` field or `X-CSRF-Token`, else 403), checked here as well as by the portal's own middleware. A server the caller cannot see, a malformed ID and owner-only routes of someone else's server all render the same **404 page** ("Page not found"), so existence is not revealed.

The OAuth connect routes `GET /servers/{id}/connect` and `GET /servers/oauth/callback` belong to `internal/federation/auth` and are mounted by the gateway wiring; they coexist with these patterns on one mux (checked).

## Adding a server

- **Name**: `[a-z0-9_-]{1,63}` (the store's check), globally unique ("already taken"), and not a **reserved built-in name**: `github, slack, atlassian, jira, confluence, google, calendar, tasks, gmail, drive, docs, sheets, contacts, microsoft, fake` (`portal.ReservedNames`, `portal.ValidateName`). The store does not reserve them (decision `17iv8p3b`), so this is the place.
- **Address**: an `https` URL (no user info, no fragment, at most 2048 bytes), or one of **my live tunnels** plus an optional path, stored as `tunnel://<id>/<path>`.
- **Detect** (`action=detect`): `auth.Detect` runs server-side through netguard (https only; tunnels are not probed). The form comes back with the first offered kind pre-selected (a Brain-shaped server: OAuth), the OAuth facts (CIMD / DCR / static client needed, PKCE S256, refresh tokens), scopes, and the destinations netguard **blocked**. Errors are shown by class: "blocked by the gateway's network policy (SSRF protection)", "could not be reached", "did not answer in time", "did not answer like an MCP server", and so on, never upstream text.
- **Auth kind**: `oauth`, `api_key` (header, default `X-API-Key`, or query parameter name), `bearer`, `headers`, `none`. **Credential mode**: `per_user` or `shared`; `oauth` + `shared` is refused (the auth package does not support shared OAuth tokens); `none` is stored as `per_user`.
- **Shared secret** (shared mode): API key, bearer token or `Name: value` header lines, **write-only**: never rendered (not even on a validation error), stored with `auth.SetSharedCredential(Actor{UserID: owner})`. On edit, blank keeps the stored secret; changing the auth kind requires a new one (the secret is sealed to the kind).
- **Static OAuth client** (optional): client ID, write-only secret, issuer (https), stored with `auth.SetStaticClient`.
- **Headers**: static `Name: value` lines (not secret, stored in `header_config.static`; `Authorization`, `Cookie`, `X-Api-Key` are refused there) and per-user header names (`header_config.per_user`, e.g. `X-Brain-Project`). Names must be RFC 9110 tokens and not transport-owned.
- Create: `Store.CreateServer` (owner = me, **private**), then the shared secret and the static client; if either fails the server is deleted again and the form shows the message. Then `Hook.ServerChanged`.
- There is **no description field**: schema 14 has no column for one (Brain decision for task 9dp13dgy).

## Review

- Form fields use the tool's **index** in the pinned version (`enable=<i>`, `kind_<i>`), never upstream names; the posted `version` must still be the latest (else 409 "changed since this page was loaded").
- Pre-checked: only tools that are **unchanged, currently enabled and read** (effective kind). Writes are **never** pre-checked; neither are new or changed tools.
- Submit: checked means `Enabled: true`; unchecked means `Enabled: false`, except read tools when "also enable all read tools I have not decided on" is ticked: those are left to `ReviewDecisions.EnableReads`, which never re-enables a tool a reviewer disabled and never enables writes. Kind select: `read`/`write` sets an override; "as annotated" clears an existing one.
- Upstream text (names, titles, descriptions, URIs, MIME types, blocked hosts) goes through `snapshot.DisplayName/DisplayTitle/DisplayDescription` (control, bidi and zero-width characters dropped, length capped) and is then HTML-escaped by `html/template`. The server name is shown next to it as provenance.

## Browse

- Lists come from the approved snapshot only. Reading a resource is limited to URIs listed there; templates are shown but not expanded.
- Previews: text through `DisplayMultiline`, capped at **8192 runes per item** ("Preview truncated"), at most **20 items or messages**; blobs, images and audio show size and MIME type only. Upstream failures show the class-level message (502).

## API (for the gateway wiring)

```go
import fedportal "github.com/huynle/mcp-gateway/internal/federation/portal"

factory, err := fedportal.NewClientFactory(fedportal.FactoryOptions{
    Credentials: authSvc,        // *auth.Service (ForUser)
    Tunnels:     tunnelSvc,      // *tunnel.Service (Authorize, HTTPClient)
    HTTPClient:  guard.Client(), // netguard
    Log:         log,
})
fedportal.NewPortal(fedportal.Deps{
    Store:         fedportal.NewStore(st), // *store.Store, WithUser for everything
    Snapshots:     snapSvc,                // *snapshot.Service
    Auth:          authSvc,                // *auth.Service
    Tunnels:       tunnelSvc,              // *tunnel.Service (CreateTunnel, Revoke, Online)
    ClientFactory: factory,
    Hook:          registry,               // anything with ServerChanged(ctx, serverID); nil = no-op
    Identity:      identityFunc,           // func(r) (userID, csrfToken string, isAdmin bool)
    Log:           log,
    BaseURL:       cfg.BaseURL,
}).Mount(portalSrv.MountUser)
```

- `Deps.Hook` (`ToolsChanged`) is called after create, edit, delete and approve, with a context detached from the request's cancellation. The federation connector's registry should implement it.
- `NewClientFactory`: credentials from `auth.ForUser` (the user's connection or the shared credential), https servers through the given (netguard) client, `tunnel://` servers only after `tunnel.Authorize(server owner, tunnel)` and through the tunnel-only transport, `header_config.static` as endpoint headers, one refresh-and-retry on 401 (`auth.Reauth`). The connector may supply its own `ClientFactory` instead.
- `NewStore(st)`: every call `WithUser`, so row-level security decides visibility; duplicate names give `ErrNameTaken`; malformed IDs give `store.ErrNotFound`; `CredentialInfo` reads only whether the owner-only rows exist.
- `auth.Options.Finish` can redirect the OAuth callback to `/servers/{id}?connected=1` (the detail page shows "Credential saved.").

## Tests

`go test ./internal/federation/portal/` (fakes for store, auth, snapshots, tunnels, upstream sessions): list with connection states and badge; another user's private server is 404 on every route and POSTs reach no service; CSRF 403; nav shows Servers; detect pre-selects OAuth for a Brain-shaped result and shows errors by class; reserved and invalid names; bad URLs and combinations (secrets never echoed); create stores a private server, its config and the shared secret through the auth service; OAuth with a static client and a tunnel URL; edit and delete are owner-only; the shared secret is never rendered; connect / reconnect links; per-user key form; refresh, review, approve with only reads enabled; explicit decisions and kind override; a refresh review pre-checks only unchanged enabled reads; a hostile description (`<script>`, ANSI, bidi, zero-width, 20k characters) is escaped and capped; a published server needs an admin; refresh errors are class-level; resources list, bounded escaped read preview, unlisted URI refused; prompt preview with required arguments; the tunnel token is shown once with the command; revoke. The client factory is tested against a go-sdk server (credential and static headers, errors, tunnel authorization by the server owner).

`make test-integration` adds `TestIntegrationPortalStoreVisibility` (own database `gateway_portal_test`): owner vs published reader vs other user, duplicate names, owner-only writes, credential info, tunnels.
