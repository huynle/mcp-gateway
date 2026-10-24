# Organization and user settings

One gateway deployment is one organization. Administrators manage durable
settings at `/admin/settings`; users manage their own preferences at
`/account`. Database values take precedence over environment configuration,
which is only the bootstrap/fallback when no persisted value exists.

## Sign-up and the default role

Sign-up modes (`GATEWAY_SIGNUP_MODE`), any-domain providers, the pending
approval queue and invites on `/admin/users`, the new-account rate limit and
the **Apply public member baseline** action on
`/admin/settings/default-role` are described in
[public-signup.md](public-signup.md). They are environment configuration and
explicit admin actions, not persisted settings.

## Rate limits

`/admin/settings/rate-limits` controls:

- organization default calls/minute per user (all apps together);
- organization default calls/minute per app (shared by users);
- per-app/server overrides;
- per-user administrator overrides.

My account shows the effective user limit and lets a user set a lower personal
ceiling or clear it. Effective user limit is `min(personal ceiling,
administrator override or organization default)`; effective app limit is the
app override or organization default. Limits are positive integers up to
100,000. Changes are audited and update the local replica immediately; other
replicas refresh within two seconds.

The token buckets remain in memory. This deployment runs one replica. Before
scaling, move buckets to a shared store (for example Redis); otherwise each
replica enforces its own copy of the budget.

The management MCP exposes `gateway.get_rate_limits` and
`gateway.set_my_rate_limit`; administrators additionally see
`gateway.set_org_rate_limits`, `gateway.set_app_rate_limit` and
`gateway.set_user_rate_limit`. Every setter requires normal gateway approval.

`GATEWAY_RATE_USER_PER_MIN` and `GATEWAY_RATE_APP_PER_MIN` are fallback
defaults only. They do not overwrite persisted settings on restart or deploy.

## Resource limits (per-user caps)

A public gateway limits what one user may hold. `/admin/settings/resource-caps`
sets the organization values; `/admin/users/<id>/limits` (the **Limits** button
on `/admin/users`) sets one user's overrides. My account shows the user's
limits and current usage (read only).

| Resource | ENV default | Counted |
|---|---|---|
| `servers` | `GATEWAY_CAP_SERVERS=10` | MCP servers the user owns |
| `tunnels` | `GATEWAY_CAP_TUNNELS=5` | the user's tunnels that are not revoked |
| `connections_per_app` | `GATEWAY_CAP_CONNECTIONS_PER_APP=5` | live (not revoked) app connections to one vendor app |
| `connections_total` | `GATEWAY_CAP_CONNECTIONS_TOTAL=20` | live app connections over all vendor apps |
| `pending_approvals` | `GATEWAY_CAP_PENDING_APPROVALS=50` | pending approvals that have not expired |
| `machines` | `GATEWAY_CAP_MACHINES=5` | the user's enrolled machines that are not revoked ([machines.md](machines.md)) |

Effective limit: per-user administrator override, else organization value,
else ENV default. **0 means unlimited** and can only be set by an
administrator (ENV values must be 1..100000; an invalid ENV value stops
startup). Values are 0..100000; a blank field clears the value so the parent
applies. Changes are audited (`organization.resource_caps_changed`,
`organization.user_resource_caps_changed`, with the changed values and, for a
user, `target_user`) and apply at once on the replica; others refresh within
two seconds. Lowering a limit never deletes anything: only new resources are
refused.

Enforcement is server side, inside the transaction that inserts the row
(`internal/caps.Reserve`): a transaction-scoped Postgres advisory lock per
(user, resource) serialises concurrent creates of that user, then the count
sees every committed row, so parallel requests cannot exceed the limit. It
applies to every creation path:

- servers: the servers portal (Add server) and `gateway.add_server` (one shared budget);
- tunnels: tunnel creation in the portal (`tunnel` store) and `PUT /machine/v1/servers/{name}` (a new machine tunnel);
- machines: device-flow approval and enrollment with a code (a replaced machine of the same name does not count);
- app connections: the connect callback, only before inserting a **new**
  connection or reviving a disconnected one. Reconnecting or granting more
  access to a live connection is never blocked. Internal anchor accounts of
  user-added servers and the gateway tools (vendor `mcp`) do not count. The
  development-only fake-vendor seed is not capped;
- pending approvals: every approval request (`approvals.Service.Create`); the
  tool call answers class `cap_exceeded`.

A refusal says "You have reached the limit of N …; … or ask an admin to raise
the limit", is logged (`event=caps.exceeded`, `class=cap_exceeded`, user,
resource, limit) and, for tool calls and connect refusals, audited with class
`cap_exceeded`.

The management MCP exposes `gateway.get_limits` (your limits and usage;
administrators also see organization values, ENV defaults, overrides and may
pass `user_id`) and, for administrators only, `gateway.set_org_limits` and
`gateway.set_user_limits` (`user_id`, any of the resource names with 0..100000,
and/or `clear: [resource, …]`). Both setters always require approval.

Storage: migration 00028 (`gateway_resource_caps`, singleton;
`gateway_user_resource_caps`, row-level security, `gateway_app` read only).

## Notifications (Web Push)

Not a persisted setting: `GATEWAY_WEBPUSH_ENABLED` (default `false`; Helm
`gateway.webpush.enabled`) turns the feature on, and each user then turns
notifications on per device under **My account → Notifications** (at most 10
devices per user, a constant). The VAPID key is created on first use and kept
in the database. See [push-notifications.md](push-notifications.md).
