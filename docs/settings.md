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
