# Servers admin pages (`internal/federation/admin`)

The admins' pages for **user-added MCP servers** ("plugins"): every server with its owner, audience, credentials and review state; publishing to roles and back to private; shared credentials and static OAuth clients (write-only); disable, enable, delete; refresh and admin review of snapshots; every tunnel with revoke; the netguard SSRF allow-list. The users' pages are in [plugins-portal.md](plugins-portal.md).

Design: Brain plan `0omkv2e1`, decisions `yhd5kcaz` (servers start private; frozen snapshots), `bnneszc1` (adding servers needs a role with "May add MCP servers"), `17iv8p3b` (owner writes; admin-only publish and published review; admin data access through `WithJobs`), `d6sitdqi` (snapshot review), `mrvsu07m` (connector, owner layer), `ocyf34pb` (servers portal); task `1d9i8b07`.

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
| `POST /admin/servers/{id}/review` | `snapshot.Approve` with `Actor{UserID, Admin: true}` (any server, private or published); the posted `version` must still be the latest (else 409). `action=approve_all` ("Approve with all tools enabled") enables every tool, writes included, and every resource, resource template and prompt. |
| `GET /admin/tunnels` | Every user's tunnel: owner, name, created, last seen, revoked, **online** (this replica's view). |
| `POST /admin/tunnels/{id}/revoke` | Revoke any tunnel (`tunnel.Service.Revoke` as the tunnel's owner, which the service requires): its token stops working and its live connection is closed. An already revoked tunnel is a no-op. |
| `GET /admin/network/allow-hosts` | The SSRF allow-list (`netguard_allow_hosts`) with the warning below. |
| `POST /admin/network/allow-hosts` | Add one entry: `pattern` (an exact host name, an IP address or a CIDR prefix, validated with `netguard.NewStaticAllowList`; no scheme, port, path or wildcard; at most 253 bytes) and `note` (at most 256 printable characters). A duplicate is 422. |
| `POST /admin/network/allow-hosts/{id}/delete` | Remove an entry. |

Every route is mounted with `portal.MountAdmin` (anonymous users are sent to sign in) and checks again itself: a caller who is not a signed-in admin gets the **404 page**, before any CSRF check, so the routes are not revealed. POSTs need the CSRF token (`_csrf` field or `X-CSRF-Token`, else 403). Every response is `Cache-Control: no-store`. A malformed or unknown server, tunnel or allow-list ID is the 404 page. Upstream text on the review page goes through the snapshot `Display*` helpers before `html/template` escapes it. The nav gains **Servers** in the admin links.

## Who may add servers

Users add servers only when they are an **admin** or hold a role with **May add MCP servers** (decision `bnneszc1`, schema 16, task `ds5tjou2`). Admins set it per role in the role editor (`/admin/roles/{name}` and `/admin/roles/new`: the checkbox under the description; the role list shows a "may add servers" pill). It is stored in `roles.may_add_servers` with the role and audited with the save (`role_saved` event, `ResourceIdentity["may_add_servers"] = "true" | "false"`). It grants no tools and is not part of the compiled Cedar policy.

New roles start without it, and existing roles were migrated without it: after upgrading to schema 16, **members who are not admins can no longer add servers** until an admin ticks the box on one of their roles (or gives them a role that has it). Servers they already own keep working. The same permission lets a user switch on **Gateway management tools** in My account (the `gateway.*` MCP tools); see [plugins-portal.md](plugins-portal.md#who-may-add-servers) and [gateway-management.md](gateway-management.md). Taking the role away hides a user's `gateway.*` tools within seconds. The role editor lists the `gateway.*` tools: they need no grant (an implicit policy layer allows them, `delete_server` always needs an approval), but a role can deny them.

Schema 16 also tightens privileges: the request path (`gateway_app`) can no longer write `roles` or `role_assignments` (only the admin path, through `gateway_jobs`, can), and may update only the `gateway_tools_enabled` column of the signed-in user's own `users` row.

## SSRF allow-list warning

netguard refuses to connect user-added servers (and their OAuth endpoints) to loopback, private, link-local, CGNAT and cloud-metadata addresses. **Every allow-list entry lifts that protection for the host or network, for every user**: anyone who may add a server (admins and holders of a role with "May add MCP servers", decision `bnneszc1`) can then make the gateway reach it. Add only what must be reachable, as narrowly as possible (one host rather than a network, a `/32` rather than a `/16`), and say why in the note. The page shows this warning above the list.

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

Publishing **shares** a server with the chosen roles (task `fekckdrt`, decision `q7vbxlyk` point 1):

- Every **active** server, private or published, gets the implicit **owner layer** (`policy.OwnerGrant`, decision `mrvsu07m`): its owner may list and call every tool (reads allowed, writes confirmed) and use its resources and prompts, without any role grant. The owner **keeps access** after publishing.
- Holders of the published roles see the server in `/servers`, but its tools, resources and prompts stay **hidden for them** until a role allows them in the role editor (`/admin/roles`): `<server>.*` (everything), single tools, `<server>.resources/read` (resources and resource templates) and `<server>.prompts/get` (prompts). A tool grant does not grant resources or prompts. Only *allow* grants the two per-server actions (no approval exists for reads of resources and prompts, so *confirm* refuses them).
- Role **denials still win** over the owner layer: an admin can take a server away from its owner with a deny rule on a role the owner holds (an unconditional deny hides the tools). The admin role gets nothing from the owner layer.

The detail page says so in its Publish section and in the "Published" notice ("… The owner keeps access.").

## Resources and prompts in the review

The admin review page is the servers portal's (`BuildReviewView`, shared `review-tools` template): resources, resource templates and prompts appear in their own groups next to the tool groups with the same compact rows and checkboxes (`enable_resource`, `enable_template`, `enable_prompt`, by index). Unchanged enabled items are pre-checked, new and changed ones are not. `approve_all` and "Select all" cover them; "Select read-only" picks among tools only. Only enabled items are listed and served on `/mcp` (task `bdb5zcud`). A snapshot approved before these toggles counts as all enabled until the next approval.

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

`go test ./internal/federation/admin/` (fakes): non-admins and anonymous callers get 404 on every route and reach no service; POSTs without the CSRF token are 403; list and filters; review queue; publish calls the store, the hook and the audit; unknown or no roles refused; unpublish; the shared credential and the static client secret are never rendered; shared credential needs shared mode; disable, enable, delete with name confirmation; malformed and unknown IDs are 404; refresh with the owner's connection or an explanation; admin review approves as admin and calls the hook; the admin page uses the shared review view and `approve_all` enables every tool of a published server (CSRF and stale version still refused); tunnels list and revoke; allow-list add, validation, duplicates, delete, and `Invalidate`; `NewAdmin` panics without required deps. `go test ./internal/policy/` checks the role editor grants a published server's tools (`TestRoleEditorGrantsServerAppTools`) and its `resources/read` / `prompts/get` actions (`TestRoleEditorGrantsServerResourcesAndPrompts`). `go test ./cmd/gateway/` checks the admin patterns go behind the admin check and nothing mounts without federation.

`make test-integration` adds `TestIntegrationAdminPublishMakesServerVisibleToRole` (the acceptance test: publish a member's server to a role and the role's users see it, other roles do not, unpublish hides it, replacing the role set drops a role) and `TestIntegrationAdminStore` (own database `gateway_fedadmin_test`), and `TestIntegrationAdminServersMounted` in `cmd/gateway` (real portal: anonymous users are sent to sign in, members get 404 on GET and POST, admins get the pages, POST without CSRF is 403, an added allow-list entry reaches netguard's allow list at once).
