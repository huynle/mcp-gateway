# Servers admin pages (`internal/federation/admin`)

The admins' pages for **user-added MCP servers** ("plugins"): every server with its owner, audience, credentials and review state; publishing to roles and back to private; shared credentials and static OAuth clients (write-only); disable, enable, delete; refresh and admin review of snapshots; every tunnel with revoke; the netguard SSRF allow-list. The users' pages are in [plugins-portal.md](plugins-portal.md).

Design: Brain plan `0omkv2e1`, decisions `yhd5kcaz` (servers start private; frozen snapshots), `bnneszc1` (adding servers needs a role with "May add MCP servers"), `17iv8p3b` (owner writes; admin-only publish and published review; admin data access through `WithJobs`), `d6sitdqi` (snapshot review), `mrvsu07m` (connector, owner layer), `ocyf34pb` (servers portal); task `1d9i8b07`.

## Pages

| Route | What |
|---|---|
| `GET /admin/servers` | Every server: name, owner, host (`tunnel` for a tunnel URL), audience and roles, credential mode / auth kind, shared credential stored or not, user connections, status and last error class, **pending review** badge (**re-review required** for a published server without an approved snapshot). Filters `?status=active\|disabled\|error` and `?pending=1`. |
| `GET /admin/servers/reviews` | The review queue: servers whose newest snapshot is not the approved one. |
| `GET /admin/servers/{id}` | Details and the admin forms below. A shared-credential server shows a notice that every user it is published to acts with the same upstream account. A published server without an approved snapshot shows **Re-review required** with a link to the review. |
| `POST /admin/servers/{id}/address` | Change the server's URL (`url`: https, no user info or fragment, at most 2048 bytes; not the current one; else 422). Tunnel addresses are the owner's to choose. On a **published** server this withdraws the approved snapshot (below). |
| `POST /admin/servers/{id}/publish` | Publish to the posted `roles` (IDs from the role list; the set **replaces** the previous one). Unknown role IDs or an empty set: 422. |
| `POST /admin/servers/{id}/unpublish` | Back to private (no roles). |
| `POST /admin/servers/{id}/shared-credential` | Set / replace the shared API key (`api_key`), bearer token (`bearer`) or `Name: value` header lines (`headers`) through `auth.SetSharedCredential(Actor{Admin: true})`. Only for `credential_mode = shared` servers of those kinds (else 422; the owner chooses the mode). **Write-only**: never rendered, not even on a validation error. |
| `POST /admin/servers/{id}/static-client` | Set / replace the static OAuth client (`client_id`, write-only `client_secret`, optional https `issuer`) through `auth.SetStaticClient`. OAuth servers only. |
| `POST /admin/servers/{id}/disable`, `…/enable` | Status `disabled` / `active`. A disabled server's tools are withdrawn for everyone. |
| `POST /admin/servers/{id}/delete` | Delete the server, its snapshots, credentials and every user's connection. `confirm` must be the server's name (else 422). |
| `POST /admin/servers/{id}/refresh` | Rediscover the server's tools through the servers portal's `ClientFactory` as the owner would: with the shared credential (shared mode) or **the owner's own connection** (per-user mode). Stores a pending snapshot and redirects to the review. With no usable credential the page says what is missing (ask the owner to connect, or set a shared credential); other failures are class-level (502). |
| `GET /admin/servers/{id}/review` | Latest snapshot vs the approved one, the same page as the servers portal's review (`BuildReviewView` and the shared `review-tools` template: summary, sticky action bar, groups, compact rows; same pre-check rule: unchanged enabled tools are checked, new and changed ones are not). See [plugins-portal.md](plugins-portal.md#review). |
| `POST /admin/servers/{id}/review` | `snapshot.Approve` with `Actor{UserID, Admin: true}` (any server, private or published); the posted `version` must still be the latest (else 409). `action=approve_all` ("Approve with all tools enabled") enables every tool, writes included, and every resource, resource template and prompt. The Ask / Auto controls and `approve_auto` / `approve_ask` work as on the servers portal; the `mcp_server.reviewed` audit row also carries `auto_run`. |
| `POST /admin/servers/{id}/approval` | Change the **approval modes** (Ask / Auto) of the approved snapshot of any server without a new review (`snapshot.SetApprovalModes` as admin): `all=auto\|ask` or `mode_<i>` per write tool; the posted `version` must be the approved one (409), a bad mode is 422. Audited `mcp_server.approval_modes_changed` (`changed`, `auto_run` counts), then `ServerChanged`. The detail page shows the modes ("N tools · A run without asking · K ask") with this form. |
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
| address | `UpdateAddress` (published: approved snapshot superseded in the same transaction) | `Hook.ServerChanged` |
| delete | `DeleteServer` | `Hook.ServerChanged` |
| admin review | `snapshot.Approve` | `Hook.ServerChanged` |
| refresh | `snapshot.Refresh` | nothing: a pending snapshot changes no tools until approved |
| tunnel revoke | `tunnel.Service.Revoke` | the service drops the live connection |
| allow-list add / remove | `AddAllowHost` / `DeleteAllowHost` | `AllowList.Invalidate()` |

`Hook` is the connector's `*connector.Manager`: `ServerChanged` drops the visibility cache, reloads the server apps and runs `OnChange` (cmd/gateway: `policySvc.Invalidate`, which recompiles the owner layer). It is called with a context detached from the request's cancellation; a failure is logged (`federation.server_changed_failed`) and the Manager's periodic reload (every minute) catches up; other replicas pick changes up with that reload. `AllowList` is the connector's `*netguard.CachedAllowList`.

## Publishing and the owner's access

Publishing **shares** a server with the chosen roles (task `fekckdrt`, decision `q7vbxlyk` point 1):

- Every **active** server, private or published, gets the implicit **owner layer** (`policy.OwnerGrant`, decision `mrvsu07m`): its owner may list and call every tool (reads allowed, writes as their **approval mode** says: Ask needs an approval, Auto runs without one) and use its resources and prompts, without any role grant. The owner **keeps access** after publishing.
- Holders of the published roles see the server in `/servers`, but its tools, resources and prompts stay **hidden for them** until a role allows them in the role editor (`/admin/roles`): `<server>.*` (everything), single tools, `<server>.resources/read` (resources and resource templates) and `<server>.prompts/get` (prompts). A tool grant does not grant resources or prompts. Only *allow* grants the two per-server actions (no approval exists for reads of resources and prompts, so *confirm* refuses them).
- Role **denials still win** over the owner layer: an admin can take a server away from its owner with a deny rule on a role the owner holds (an unconditional deny hides the tools). The admin role gets nothing from the owner layer.

- **Approval modes are the server-level default for granted roles** (task auto-approve). The admin sets them on the detail page or in the review; they are compiled into the Cedar set (`policy.ServerApproval`) for every active server:

  | Role rule for the tool | Tool mode Auto | Tool mode Ask |
  |---|---|---|
  | allow (or `<server>.*` allow) | **allow** (runs) | confirm (approval) |
  | confirm | confirm | confirm |
  | deny | deny (hidden when unconditional) | deny |
  | no rule (owner layer) | **allow** | confirm |

  User restrictions (deny / confirm) and token narrowing (read-only, allow-list) still win. Reviews stored before modes existed count as Ask for every write, so a role *allow* on a published server's write now asks for an approval until the admin sets the tool to Auto (before this change a role allow on a server write ran without one).

The detail page says so in its Publish section and in the "Published" notice ("… The owner keeps access.").

## Changing a published server's address

Published servers are **admin-governed** (Brain task `mpszh6h0`, decision `q7vbxlyk` point 3, schema 17). Their owner can no longer change the URL, transport, authentication kind, auth config (scopes, API key placement), extra headers or static OAuth client (portal 422, database trigger `mcp_servers_published_lock` on the request path). The owner may still switch the credential mode and rotate the shared secret.

An admin may change those columns (through `gateway_jobs`). For a published server the trigger then marks the **approved snapshot superseded** in the same transaction, so:

1. its tools, resources and prompts disappear for everyone at once (`Hook.ServerChanged`);
2. the list and detail pages show **re-review required**;
3. stored credentials were sealed to the old URL (decision `4l6dik46`): users reconnect, and a shared credential or static OAuth client must be set again;
4. **Refresh** discovers what the new address serves, then the review (all tools start disabled: there is no approved snapshot to carry decisions from) approves it, and the tools are back.

The detail page has the **Address** form for this; it accepts https URLs only. Other settings of a published server: unpublish it, let the owner edit it, review and republish. Publishing again is the admin's decision on the server as it now is (address and approved snapshot are on the detail page).

## Resources and prompts in the review

The admin review page is the servers portal's (`BuildReviewView`, shared `review-tools` template): resources, resource templates and prompts appear in their own groups next to the tool groups with the same compact rows and checkboxes (`enable_resource`, `enable_template`, `enable_prompt`, by index). Unchanged enabled items are pre-checked, new and changed ones are not. `approve_all` and "Select all" cover them; "Select read-only" picks among tools only. Only enabled items are listed and served on `/mcp` (task `bdb5zcud`). A snapshot approved before these toggles counts as all enabled until the next approval.

## Audit events

Every change is audited through `audit.Recorder` with the admin as `UserID`, decision `allow`, outcome `succeeded` and the request ID. `ResourceIdentity["action"]` names the event; no secrets are recorded (only names, IDs and counts). The same name is the `event` of an info log line.

| `action` | Other `ResourceIdentity` keys |
|---|---|
| `mcp_server.published` | `server_id`, `server`, `owner_user_id`, `roles` (role names, comma-separated, at most 128 bytes) |
| `mcp_server.unpublished` | `server_id`, `server`, `owner_user_id` |
| `mcp_server.shared_credential_set` | `server_id`, `server`, `owner_user_id`, `auth_kind` |
| `mcp_server.static_client_set` | `server_id`, `server`, `owner_user_id` |
| `mcp_server.address_changed` | `server_id`, `server`, `owner_user_id`, `old_host`, `new_host` (hosts only, at most 128 bytes), `audience` |
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

`cmd/gateway/federation.go` (`withFederationAdmin`) does this when federation is configured; without it nothing is mounted. `NewAdmin` panics when a required dependency is missing. `Store.UpdateAddress` is new in schema 17. Exported: `Admin` (`NewAdmin`, `Mount`), `Deps`, `Store`, `Roles`, `Snapshots`, `Auth`, `Tunnels`, `Hook`, `Invalidator`, `Identity`, `Server` (`PendingReview()`), `Tunnel`, `Role`, `PGStore` (`NewStore`), `ErrDuplicate`. The store package adds `ListAdminMCPServers`, `GetAdminMCPServer`, `ListAdminMCPTunnels` and `GetAdminMCPTunnel` over the secret-free views `admin_mcp_servers` and `admin_mcp_tunnels` (migration 00014; run them under `WithJobs`).

## Tests

`go test ./internal/federation/admin/` (fakes): non-admins and anonymous callers get 404 on every route and reach no service; POSTs without the CSRF token are 403; list and filters; review queue; publish calls the store, the hook and the audit; unknown or no roles refused; unpublish; the shared credential and the static client secret are never rendered; shared credential needs shared mode; disable, enable, delete with name confirmation; malformed and unknown IDs are 404; refresh with the owner's connection or an explanation; admin review approves as admin and calls the hook; the address form changes the URL, calls the hook, audits the hosts and flags the re-review (bad, tunnel and unchanged URLs are 422; `address_test.go`); the admin page uses the shared review view and `approve_all` enables every tool of a published server (CSRF and stale version still refused); tunnels list and revoke; allow-list add, validation, duplicates, delete, and `Invalidate`; `NewAdmin` panics without required deps. `go test ./internal/policy/` checks the role editor grants a published server's tools (`TestRoleEditorGrantsServerAppTools`) and its `resources/read` / `prompts/get` actions (`TestRoleEditorGrantsServerResourcesAndPrompts`). `go test ./cmd/gateway/` checks the admin patterns go behind the admin check and nothing mounts without federation; `NewAdmin` panics without required deps. `go test ./internal/policy/` checks the role editor grants a published server's tools (`TestRoleEditorGrantsServerAppTools`) and its `resources/read` / `prompts/get` actions (`TestRoleEditorGrantsServerResourcesAndPrompts`). `go test ./cmd/gateway/` checks the admin patterns go behind the admin check and nothing mounts without federation. Approval modes (`approval_test.go`): the detail page shows the modes and the form for a published server; `POST /admin/servers/{id}/approval` as admin (audited, hooked), member 404, CSRF 403, stale 409, bad mode 422; the admin review carries `approve_auto` into the decisions.

`make test-integration` adds `TestIntegrationAdminPublishMakesServerVisibleToRole` (the acceptance test: publish a member's server to a role and the role's users see it, other roles do not, unpublish hides it, replacing the role set drops a role) , `TestIntegrationAdminStore` and `TestIntegrationAdminAddressChangeWithdrawsApproval` (an admin's new address withdraws the approval; the owner's is refused; re-approval serves again) (own database `gateway_fedadmin_test`), and `TestIntegrationAdminServersMounted` in `cmd/gateway` (real portal: anonymous users are sent to sign in, members get 404 on GET and POST, admins get the pages, POST without CSRF is 403, an added allow-list entry reaches netguard's allow list at once).
