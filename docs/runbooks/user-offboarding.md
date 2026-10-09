# User offboarding

Removing a coworker's access, immediately or as part of leaving. Background: README "Sign-in, users and the portal" and "Harness tokens", decision `uamxx6ba` (tokens, 30-day sign-in rule). Checked against `internal/identity/service.go` (`DisableUser`, `OnDisable`), `internal/tokens/service.go` (`DisableHook`, `Authenticate`), `internal/authserver/{harnesses.go,jwt.go}` (`DisableHook`, `RevokeUserRefreshTokens`), `internal/store/repo_oauth_lookup.go`, `internal/connections/tokens.go` (`DisableHook`, `disconnectAll`), `internal/portal/portal.go` (`/admin/users` routes), `cmd/gateway/{main.go,authserver.go}` (hook registration).

## When to use

- Someone leaves the company, changes role out of the team, or must lose access now (incident).
- You want to know what the **30-day rule** already did for an inactive account.

## What "disable" does (one transaction)

`POST /admin/users/{id}/disable` (admin only, CSRF; the *Disable* button on `/admin/users`) calls `identity.Service.DisableUser`, which in **one `WithJobs` transaction**:

1. sets `users.status = disabled` and `disabled_at`;
2. revokes every **portal session** (`RevokeUserSessions`): the browser is signed out on its next request;
3. runs the registered `OnDisable` hooks, in registration order (`cmd/gateway/main.go`, `cmd/gateway/authserver.go`):
   - **generated tokens** (`tokens.Service.DisableHook`): every `mgw_` token gets `revoked_at`; a harness presenting one gets `401` with reason `revoked` (and a re-enabled user's old tokens stay revoked);
   - **MCP OAuth harnesses** (`authserver.Service.DisableHook` → `store.RevokeUserOAuthRefreshTokens`): every refresh-token family is revoked and every unconsumed authorization code deleted; access tokens already issued keep verifying until their `exp` (1 h, `GATEWAY_OAUTH_ACCESS_TOKEN_TTL`) **except** that `authserver.JWTAuthenticator` also checks the user's status on every call, so a disabled user's access token is refused at once with reason `user_disabled`;
   - **app connections** (`connections.Service.DisableHook` → `disconnectAll`): for every non-revoked connection the vendor token is revoked at the vendor when the vendor app has a revoke URL (best effort, logged `connections.revoke_failed` on failure), the `connection_secrets` row is deleted and the connection is marked `revoked` (the row stays: approvals, ledger and audit reference it); one `user` audit event per connection with `action=disconnected_on_disable`.

If any hook fails the whole transaction rolls back and the page shows an error: the user stays enabled; read the gateway log around the request (`error` lines from `identity` / `connections`) and retry.

What disable does **not** do: it does not delete the user, their audit rows, ledger rows or approvals (pending approvals simply expire through `approvals.expire`, and nothing of theirs can run because the token is refused first); it does not touch the IdP (remove them there too); it does not revoke the Slack bot's ability to DM them (no DM is sent without a pending approval, and none can be created). *Enable* (`POST /admin/users/{id}/enable`) restores sign-in only; nothing revoked comes back — they create new tokens and reconnect accounts.

Disable is logged (`event=identity.user_disabled user=<hash> actor_user_id=<hash> sessions_revoked=N`, `tokens.revoked_on_disable revoked=N`, `authserver.revoked_on_disable revoked=N`, `connections.revoked_on_disable revoked=N`); there is **no audit row for the disable itself** in v1 (only the per-connection rows above), so note who disabled whom in the offboarding ticket.

## The 30-day rule (what happens with no action)

Generated tokens and OAuth refresh tokens stop working when the user's last company sign-in (`users.last_company_sign_in_at`) is older than `GATEWAY_TOKEN_SIGNIN_MAX_AGE` (`720h` = 30 days): `tokens.Service.Authenticate` answers `401` reason `signin_stale` ("sign in to the portal to reactivate your tokens"), and `POST /oauth/token` refresh is refused the same way. Removing the person from the IdP therefore cuts every harness within 30 days of their last portal sign-in even if nobody presses *Disable* — and their app connections' refresh tokens keep being refreshed by `connections.keepalive` (every 24 h, for connections idle 30 days) until the connection is revoked. For a leaver, always disable explicitly.

## Preconditions

- You are an admin (role `admin`) in the portal.
- You know the user's display name (and, for a leaver, that the IdP account is being removed by the identity team).

## Steps

```text
1. Portal → /admin/users → find the user → Disable (confirm dialog: "Their sessions end immediately").
   The row re-renders with status "disabled" (htmx) and the Enable button.
2. IdP: remove or suspend the account at the company identity provider (otherwise they can sign in again
   on a re-enable, and their IdP account can still reach other systems).
3. Vendors: nothing to do for GitHub/Google/Microsoft/Atlassian/Slack user tokens (revoked at the vendor
   by step 1 where the vendor supports it; the rest expire). If the leaver was the OWNER of a vendor app
   registration (docs/vendor-apps.md section 0.3), transfer ownership at the vendor now.
4. If the person was an admin: check /admin/roles and /admin/vendor-apps were not changed by them recently
   (/admin/audit?user_id=<their user id>&since=<date>: role_saved, default_role_set, vendor_app_saved events).
5. Incident variant (credentials suspected leaked): do step 1 first, then docs/runbooks/vendor-app-secret-rotation.md
   if they held vendor app secrets, and docs/runbooks/key-rotation.md "Vault token" if they had cluster access.
```

The user id for the audit filter is on `/admin/users` (the row's form action `/admin/users/<uuid>/...`) or `admin_users`:

```bash
psql "$JOBS_URL" -c "SELECT id, display_name, status, last_company_sign_in_at, disabled_at FROM admin_users WHERE display_name ILIKE '%<name>%';"
```

## Verification

```bash
U=<user uuid>
psql "$JOBS_URL" -c "SELECT status, disabled_at FROM admin_users WHERE id='$U';"                              # disabled, timestamp
psql "$JOBS_URL" -c "SELECT count(*) FROM admin_tokens WHERE user_id='$U' AND revoked_at IS NULL;"           # 0
psql "$JOBS_URL" -c "SELECT count(*) FROM admin_oauth_refresh_tokens WHERE user_id='$U' AND revoked_at IS NULL;"  # 0
psql "$JOBS_URL" -c "SELECT id, label, status, token_updated_at FROM admin_connections WHERE user_id='$U';"  # every row revoked, token_updated_at NULL (secret row gone)
psql "$JOBS_URL" -c "SELECT created_at, resource FROM admin_audit_events WHERE user_id='$U' AND resource->>'action'='disconnected_on_disable';"
kubectl -n $NS logs deploy/$RELEASE --since=10m | grep -E 'revoked_on_disable|user_disabled'
```

Ask the leaver's harness owner (or test with their token if you have an incident copy) that `/mcp` answers `401` with `error="invalid_token"` — do **not** paste a token into a ticket to prove it; the per-IP failure limiter also counts the attempt.

## Rollback

*Enable* on `/admin/users` (`POST /admin/users/{id}/enable`) lets the person sign in again; tokens, harness sign-ins and connections stay revoked and must be recreated by them (`/tokens`, harness OAuth sign-in, `/connections`). Audit, ledger and approval history is intact. If the disable was a mistake during an incident, tell the person which three things to redo.
