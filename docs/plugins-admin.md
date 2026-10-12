# Servers admin pages (`internal/federation/admin`)

The admins' pages for **user-added MCP servers** ("plugins"): every server with its owner, audience, credentials and review state; publishing to roles and back to private; shared credentials and static OAuth clients (write-only); disable, enable, delete; refresh and admin review of snapshots; every tunnel with revoke; the netguard SSRF allow-list. The users' pages are in [plugins-portal.md](plugins-portal.md).

Design: Brain plan `0omkv2e1`, decisions `yhd5kcaz` (everyone may add; servers start private; frozen snapshots), `17iv8p3b` (owner writes; admin-only publish and published review; admin data access through `WithJobs`), `d6sitdqi` (snapshot review), `mrvsu07m` (connector, owner layer), `ocyf34pb` (servers portal); task `1d9i8b07`.

## Pages

| Route | What |
|---|---|
| `GET /admin/servers` | Every server: name, owner, host (`tunnel` for a tunnel URL), audience and roles, credential mode / auth kind, shared credential stored or not, user connections, status and last error class, **pending review** badge. Filters `?status=active\|disabled\|error` and `?pending=1`. |
| `GET /admin/servers/reviews` | The review queue: servers whose newest snapshot is not the approved one. |
| `GET /admin/servers/{id}` | Details and the admin forms below. A shared-credential server shows a notice that every user it is published to acts with the same upstream account. |
| `POST /admin/servers/{id}/publish` | Publish to the posted `roles` (IDs from the role list; the set **replaces** the previous one). Unknown role IDs or an empty set: 422. |
| `POST /admin/servers/{id}/unpublish` | Back to private (no roles). |
| `POST /admin/servers/{id}/shared-credential` | Set / replace the shared API key (`api_key`), bearer token (`bearer`) or `Name: value` header lines (`headers`) through `auth.SetSharedCredential(Actor{Admin: true})`. Only for `credential_mode = shared` servers of those kinds (else 422; the owner chooses the mode). **Write-only**: never rendered, not even on a validation error. |
| `POST /admin/servers/{id}/static-client` | Set / replace the static OAuth client (`client_id`, write-only `client_secret`, optional https `issuer`) through `auth.SetStaticClient`. OAuth servers only. |
| `POST /admin/servers/{id}/disable`, `…/enable` | Status `disabled` / `active`. A disabled server's tools are withdrawn for everyone. |
| `POST /admin/servers/{id}/delete` | Delete the server, its snapshots, credentials and every user's connection. `confirm` must be the server's name (else 422). |
| `POST /admin/servers/{id}/refresh` | Rediscover the server's tools through the servers portal's `ClientFactory` as the owner would: with the shared credential (shared mode) or **the owner's own connection** (per-user mode). Stores a pending snapshot and redirects to the review. With no usable credential the page says what is missing (ask the owner to connect, or set a shared credential); other failures are class-level (502). |
| `GET /admin/servers/{id}/review` | Latest snapshot vs the approved one, the same page as the servers portal's review (`BuildReviewView` and the shared `review-tools` template: summary, sticky action bar, groups, compact rows; same pre-check rule: unchanged enabled tools are checked, new and changed ones are not). See [plugins-portal.md](plugins-portal.md#review). |
| `POST /admin/servers/{id}/review` | `snapshot.Approve` with `Actor{UserID, Admin: true}` (any server, private or published); the posted `version` must still be the latest (else 409). `action=approve_all` ("Approve with all tools enabled") enables every tool, writes included. |
| `GET /admin/tunnels` | Every user's tunnel: owner, name, created, last seen, revoked, **online** (this replica's view). |
| `POST /admin/tunnels/{id}/revoke` | Revoke any tunnel (`tunnel.Service.Revoke` as the tunnel's owner, which the service requires): its token stops working and its live connection is closed. An already revoked tunnel is a no-op. |
| `GET /admin/network/allow-hosts` | The SSRF allow-list (`netguard_allow_hosts`) with the warning below. |
| `POST /admin/network/allow-hosts` | Add one entry: `pattern` (an exact host name, an IP address or a CIDR prefix, validated with `netguard.NewStaticAllowList`; no scheme, port, path or wildcard; at most 253 bytes) and `note` (at most 256 printable characters). A duplicate is 422. |
| `POST /admin/network/allow-hosts/{id}/delete` | Remove an entry. |

Every route is mounted with `portal.MountAdmin` (anonymous users are sent to sign in) and checks again itself: a caller who is not a signed-in admin gets the **404 page**, before any CSRF check, so the routes are not revealed. POSTs need the CSRF token (`_csrf` field or `X-CSRF-Token`, else 403). Every response is `Cache-Control: no-store`. A malformed or unknown server, tunnel or allow-list ID is the 404 page. Upstream text on the review page goes through the snapshot `Display*` helpers before `html/template` escapes it. The nav gains **Servers** in the admin links.

## SSRF allow-list warning

netguard refuses to connect user-added servers (and their OAuth endpoints) to loopback, private, link-local, CGNAT and cloud-metadata addresses. **Every allow-list entry lifts that protection for the host or network, for every user**: anyone who may add a server (everyone, decision `yhd5kcaz`) can then make the gateway reach it. Add only what must be reachable, as narrowly as possible (one host rather than a network, a `/32` rather than a `/16`), and say why in the note. The page shows this warning above the list.

Changes apply at once on the replica that served the request (`Invalidate`, below) and within `netguard.DefaultAllowListTTL` (30 s) on the others.

## Hooks: what each change calls

| Change | Store / service | Then |
|---|---|---|
| publish, unpublish | `SetPublishedRoles` | `Hook.ServerChanged` |
| shared credential, static client | `auth.Service` | `Hook.ServerChanged` |
| disable, enable | `SetStatus` | `Hook.ServerChanged` |
| delete | `DeleteServer` | `Hook.ServerChanged` |
| admin review | `snapshot.Approve` | `Hook.ServerChanged` |
| refresh | `snapshot.Refresh` | nothing: a pending snapshot changes no tools until approved |
| tunnel revoke | `tunnel.Service.Revoke` | the service drops the live connection |
| allow-list add / remove | `AddAllowHost` / `DeleteAllowHost` | `AllowList.Invalidate()` |

`Hook` is the connector's `*connector.Manager`: `ServerChanged` drops the visibility cache, reloads the server apps and runs `OnChange` (cmd/gateway: `policySvc.Invalidate`, which recompiles the owner layer). It is called with a context detached from the request's cancellation; a failure is logged (`federation.server_changed_failed`) and the Manager's periodic reload (every minute) catches up; other replicas pick changes up with that reload. `AllowList` is the connector's `*netguard.CachedAllowList`.

## Publishing and the owner's access

Publishing changes who may **see** a server and also who may **use its tools**:

- A **private** active server gets the implicit **owner layer** (`policy.OwnerGrant`, decision `mrvsu07m`): its owner may list and call every tool (reads allowed, writes confirmed) without any role grant.
- A **published** server has **no owner layer**: its tools are hidden for every user, **the owner included**, until a role allows them in the role editor (`<server>.*` or single tools). The owner still sees the server in `/servers` (they own it), but after publishing they lose its tools unless a role they hold is granted them.
- Unpublishing restores the owner layer.

So after publishing, grant the tools in the role editor (`/admin/roles`) to the published roles and, if the owner should keep using the server, to a role the owner holds. The detail page says so in its Publish section and in the "Published" notice. This task leaves the connector unchanged; a warning on the page that names the owner explicitly (or a one-click grant to the owner's role) is a recorded follow-up.

## Audit events

Every change is audited through `audit.Recorder` with the admin as `UserID`, decision `allow`, outcome `succeeded` and the request ID. `ResourceIdentity["action"]` names the event; no secrets are recorded (only names, IDs and counts). The same name is the `event` of an info log line.

| `action` | Other `ResourceIdentity` keys |
|---|---|
| `mcp_server.published` | `server_id`, `server`, `owner_user_id`, `roles` (role names, comma-separated, at most 128 bytes) |
| `mcp_server.unpublished` | `server_id`, `server`, `owner_user_id` |
| `mcp_server.shared_credential_set` | `server_id`, `server`, `owner_user_id`, `auth_kind` |
| `mcp_server.static_client_set` | `server_id`, `server`, `owner_user_id` |
| `mcp_server.disabled`, `mcp_server.enabled` | `server_id`, `server`, `owner_user_id` |
| `mcp_server.deleted` | `server_id`, `server`, `owner_user_id` |
| `mcp_server.refreshed` | `server_id`, `server`, `owner_user_id` |
| `mcp_server.reviewed` | `server_id`, `server`, `owner_user_id`, `version`, `enabled_tools` (count) |
| `tunnel.revoked` | `tunnel_id`, `tunnel` (name, at most 128 bytes), `owner_user_id` |
| `netguard.allow_host_added` | `allow_host_id`, `pattern` |
| `netguard.allow_host_removed` | `allow_host_id`, `pattern` |

A failed audit write is logged (`federation.admin_audit_failed`), never returned: the change is already committed. Page failures log `federation.admin_failed`; a failed refresh logs `federation.admin_refresh_failed`.

## API (for the gateway wiring)

```go
import fedadmin "github.com/huynle/mcp-gateway/internal/federation/admin"

as := fedadmin.NewStore(st) // *store.Store; every call WithJobs
fedadmin.NewAdmin(fedadmin.Deps{
    Store:         as,            // Store
    Roles:         as,            // Roles (ListRoles)
    Snapshots:     fed.Snapshots, // *snapshot.Service (Refresh, Latest, Current, Approve)
    Auth:          fed.Auth,      // *auth.Service (SetSharedCredential, SetStaticClient)
    Tunnels:       fed.Tunnels,   // *tunnel.Service (Revoke, Online)
    ClientFactory: factory,       // fedportal.NewClientFactory(...)
    Hook:          fed.Manager,   // ServerChanged(ctx, id) error; nil = no-op
    AllowList:     fed.AllowList, // Invalidate(); nil = no-op
    Identity:      identityFn,    // func(r) (userID, csrfToken string, isAdmin bool)
    Audit:         rec,           // audit.Recorder
    Log:           log,
}).Mount(portalSrv.MountAdmin)
```

`cmd/gateway/federation.go` (`withFederationAdmin`) does this when federation is configured; without it nothing is mounted. `NewAdmin` panics when a required dependency is missing. Exported: `Admin` (`NewAdmin`, `Mount`), `Deps`, `Store`, `Roles`, `Snapshots`, `Auth`, `Tunnels`, `Hook`, `Invalidator`, `Identity`, `Server` (`PendingReview()`), `Tunnel`, `Role`, `PGStore` (`NewStore`), `ErrDuplicate`. The store package adds `ListAdminMCPServers`, `GetAdminMCPServer`, `ListAdminMCPTunnels` and `GetAdminMCPTunnel` over the secret-free views `admin_mcp_servers` and `admin_mcp_tunnels` (migration 00014; run them under `WithJobs`).

## Tests

`go test ./internal/federation/admin/` (fakes): non-admins and anonymous callers get 404 on every route and reach no service; POSTs without the CSRF token are 403; list and filters; review queue; publish calls the store, the hook and the audit; unknown or no roles refused; unpublish; the shared credential and the static client secret are never rendered; shared credential needs shared mode; disable, enable, delete with name confirmation; malformed and unknown IDs are 404; refresh with the owner's connection or an explanation; admin review approves as admin and calls the hook; the admin page uses the shared review view and `approve_all` enables every tool of a published server (CSRF and stale version still refused); tunnels list and revoke; allow-list add, validation, duplicates, delete, and `Invalidate`; `NewAdmin` panics without required deps. `go test ./internal/policy/` checks the role editor grants a published server's tools (`TestRoleEditorGrantsServerAppTools`). `go test ./cmd/gateway/` checks the admin patterns go behind the admin check and nothing mounts without federation.

`make test-integration` adds `TestIntegrationAdminPublishMakesServerVisibleToRole` (the acceptance test: publish a member's server to a role and the role's users see it, other roles do not, unpublish hides it, replacing the role set drops a role) and `TestIntegrationAdminStore` (own database `gateway_fedadmin_test`), and `TestIntegrationAdminServersMounted` in `cmd/gateway` (real portal: anonymous users are sent to sign in, members get 404 on GET and POST, admins get the pages, POST without CSRF is 403, an added allow-list entry reaches netguard's allow list at once).
