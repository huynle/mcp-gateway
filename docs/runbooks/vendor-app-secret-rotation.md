# Vendor app secret rotation

Replacing a vendor OAuth client secret, the Slack bot token or the Slack signing secret. Background: README "App connections" (vendor apps), [`docs/vendor-apps.md`](../vendor-apps.md) (where each secret comes from). Checked against `internal/connections/{handlers.go,secrets.go,tokens.go}` (`/admin/vendor-apps` routes, `VendorSecrets`, `clientSecret`), `internal/connections/templates/admin_vendor_app.html`, `internal/approvals/notify_slack.go`, `internal/slack/interactions.go`.

## When to use

- Scheduled expiry: Microsoft Entra client secrets expire (max 24 months; the date is in the `docs/vendor-apps.md` checklist). Google, GitHub, Atlassian and Slack secrets do not expire but rotate on policy or after exposure.
- Exposure: a secret travelled over a weak channel, a vendor console shows an unexpected regeneration, an offboarded person held it ([user-offboarding.md](user-offboarding.md) step 5).
- Alert `MCPGatewayConnectionRefreshFailures` for one app across many users: the vendor refuses our client credentials (`invalid_client`) — rotate at once.

## How the secrets are stored and used

- Admin page `/admin/vendor-apps/{vendor}` (Google: `/admin/vendor-apps/google/{internal|external}`), admins only, CSRF. Fields: client ID, **client secret** (write-only `password` input; "a secret is stored; leave blank to keep it"), for Slack also **Bot User OAuth token** and **signing secret** (`connections.ExtraSecretKeys("slack")` = `bot_token`, `signing_secret`, same write-only treatment), URLs, scopes, extra parameters, Enabled.
- On save all of an app's secrets are one envelope-encrypted JSON bundle in the row's four `secret_*` columns (`connections.encodeSecrets`); a blank field keeps the stored value, a filled one replaces it. Every save is a `user` audit event of the admin (`action=vendor_app_saved`, vendor, variant).
- They are **read per use**, not cached: the token refresh path (`clientSecret` in `Service.token`), the connect flow's code exchange, the vendor revoke on disconnect, the Slack approval DM (`VendorSecrets(ctx, "slack", "", "bot_token")`) and `/slack/interactions` (signing secret) all decrypt the current row on each call. A save takes effect on every replica with the next request; **no restart, no Helm change**.
- The secrets never appear in `admin_vendor_apps` (metadata view), in logs (the redactor denylists `client_secret`, `signing_secret`, `token` keys and the `xox*` value shape), or in the editor.

## Preconditions

- Admin in the portal and access to the vendor console with rights to create a new client secret (GitHub App settings, Slack app Basic Information / OAuth & Permissions, Atlassian developer console Settings, Google Cloud Clients page, Entra Certificates & secrets).
- The new secret is handed over through the password manager, never pasted in chat or a ticket (`docs/vendor-apps.md` 0.3).

## Steps: client secret (every vendor)

```text
1. At the vendor, create the NEW secret WITHOUT deleting the old one (GitHub, Entra and Google allow several;
   Atlassian and Slack regenerate in place — for those, do steps 1 and 2 back to back).
2. Portal → /admin/vendor-apps → <vendor> → paste the new secret into "Client secret" → Save ("Saved.").
   Leave every other field as it is; a blank secret field keeps the old value, so make sure you pasted.
3. Verify (below), then delete the OLD secret at the vendor.
```

Between 1 and 3 both secrets work at the vendor, so in-flight refreshes never fail. After 3, anything still using the old secret fails — there is nothing in the gateway that still does, because the row is read per use.

## Steps: Slack bot token

The bot token (`xoxb-…`) is what `approvals.SlackNotifier` posts approval DMs with (`conversations.open`, `chat.postMessage`, `chat.update`). It changes when the app is reinstalled into the workspace (new scopes) or when Slack rotates it after a revoke.

```text
1. Slack app → OAuth & Permissions → Reinstall to Workspace (or copy the current Bot User OAuth Token).
2. Portal → /admin/vendor-apps/slack → paste into "Bot User OAuth token" → Save.
3. Trigger one confirmed tool call as a user with a company Slack connection and check the DM arrives
   (or watch the log for approvals.notify_failed, which is what a dead token produces: a failed DM never
   fails the approval; the portal /approvals page still works).
```

## Steps: Slack signing secret

The signing secret verifies `X-Slack-Signature` on `POST /slack/interactions` (`slack.VerifySignature`, 5-minute timestamp window). Regenerating it at Slack (Basic Information → App Credentials → Regenerate) invalidates the old one at once, so every button press between regeneration and the save answers `401` (the user sees Slack's "something went wrong"; the approval is untouched and can be decided on `/approvals`).

```text
1. Slack app → Basic Information → Signing Secret → Regenerate; copy it.
2. Portal → /admin/vendor-apps/slack → paste into "Signing secret" → Save, immediately.
3. Press Approve on a fresh approval DM: the message updates to "Approved by you at …" and the call runs.
```

## Verification

```bash
# the save happened (admin audit event; the secret itself is not in the row)
psql "$JOBS_URL" -c "SELECT created_at, actor_user_id, resource FROM admin_audit_events WHERE resource->>'action'='vendor_app_saved' ORDER BY created_at DESC LIMIT 3;"
psql "$JOBS_URL" -c "SELECT vendor, name, enabled, updated_at FROM admin_vendor_apps;"
```

Then exercise each path that uses the secret:

1. **Refresh**: a user whose connection's access token is near expiry runs a read tool; or wait for `connections.keepalive`; the log shows `connections.refreshed` for that vendor and `connection_refresh_failures_total{app="<vendor>"}` stops rising.
2. **Connect**: a user connects a new account on `/connections` → *Connect* for the vendor; the callback succeeds (`connections.connected` log, the account appears).
3. **Disconnect**: *Disconnect* on a test account; the log shows `connections.revoked` (vendors with a revoke URL) rather than `connections.revoke_failed`.
4. Slack: a DM for a confirmed call and a working button press (above).

A wrong secret shows up as `connections.refresh_failed vendor=<vendor> vendor_error=invalid_client` within minutes for refreshes and as an error page on the connect callback.

## Rollback

Paste the previous secret back on the same page and Save (if it still exists at the vendor; for Atlassian/Slack regenerate-in-place there is no previous value — regenerate again and save that). The audit trail shows both saves.

## After an exposure

Rotating the client secret does **not** invalidate user tokens the vendor already issued to the gateway (they are bound to the app, not the secret, at most vendors); if the exposure included the database or Vault, follow [key-rotation.md](key-rotation.md) and ask users to reconnect (`/connections` → *Reconnect*) once the new secret is in. Record the rotation and the exposure window in the incident ticket; the audit event above is the gateway-side evidence.
