# Push notifications for approvals

When a tool call waits for an approval, the gateway can show a notification on the user's phone or computer. It uses the browser's standard Web Push: no app store app, no third-party push SDK. The portal is an installable app ([portal-ui.md](portal-ui.md#installable-app-pwa)); notifications are turned on per device on **My account → Notifications**. Design: Brain decision `0pzhidap`.

Off by default: an operator sets `GATEWAY_WEBPUSH_ENABLED=true` (Helm `gateway.webpush.enabled`).

## What the user sees

- **My account → Notifications** (only when the feature is on): "Get a notification on this device when an approval is waiting. On iPhone, add the app to your Home Screen first (Share → Add to Home Screen)."
- The device control: its state (*Not supported on this browser*, *Blocked in browser settings*, *Off*, *On for this device*), **Turn on for this device** / **Turn off for this device**, and **Send test notification** while it is on. Turning on asks the browser for permission (from the click, as iOS requires), subscribes the browser and stores the subscription. The control needs JavaScript; it is rendered hidden and revealed by `pwa.js`, and without JavaScript the panel says so.
- The device table (works without JavaScript): device (a label such as *Android Chrome* or *iPhone Safari*, derived from the browser's User-Agent family; never a version or model), push service host, added, last delivered, and **Remove** (a plain form). Removing the device you are using stops its notifications, but its browser still holds the subscription, so the control shows *On* until you turn it off or on again.
- The notification: **"Approval needed"**, body **`<tool> (<account label>)`** (e.g. `github.create_issue (company)`), one notification per approval (tag `approval-<id>`). Tapping it opens `/approvals`, where the arguments are shown and the decision is made. There are deliberately no Approve / Deny buttons on the notification: deciding without seeing the arguments is what the approvals page exists to prevent.
- At most **10 devices** per user; an 11th is refused ("You already have 10 devices…", 409). A test notification can be sent once every **30 seconds**.

Finding it: with the feature on, the sidebar has a **Notifications** link (right after My account) to that section, and the **Approvals** page (where the installed app opens) shows a "Get notified on this device" bar with **Turn on** and **Not now** while this browser can take notifications, has not blocked them and is not subscribed. "Not now" hides the bar on that browser for 30 days (localStorage).

## Privacy of the payload

Push services (Google FCM, Apple, Mozilla, Microsoft) relay the message and see its metadata (size, time, the subscription); the text sits on the device's lock screen. So the payload is exactly `{"title","body","url","tag"}` with the tool name and the account **label** (company / personal) only: **never** the call arguments, the resource identity (repo, channel, file), the connected account's name or any secret. The payload is encrypted end to end to the browser (RFC 8291, aes128gcm); the push service cannot read it.

Each message has a TTL until the approval expires (at least 1 minute, at most 1 hour), urgency `high`, and a `Topic` that is a short hash of the approval id (the push service replaces an undelivered duplicate without learning the id).

## Delivery

`internal/pushnotify` is one more `approvals.Notifier` next to the portal and the Slack DM ([user-guide.md](user-guide.md#4-approvals-when-a-tool-call-waits-for-you)). When an approval is created it sends to every device of the approval's user, and only that user's (the subscriptions are read under the user's row-level security scope):

- at most 4 sends at a time, the whole fan-out bounded by **5 seconds** (plus at most 1 second of bookkeeping), so a slow push service never holds the approval flow; a send that is not back by then counts as failed and is not waited for;
- a `404` / `410` from the push service (the browser unsubscribed, the app was removed) **deletes** the subscription;
- every result is recorded on the device row (last delivered, last failure, failure count; shown in the device table);
- failures are logged by the approvals service (`approvals.notify_failed`, redacted) and **never fail the approval**. There are no push metrics yet (the other notifiers have none either); the log line `pushnotify.sent` carries delivered / gone / failed counts.

## Security

- **SSRF**: the subscription's endpoint URL comes from the browser. It is accepted only as `https` on port 443 on a known push service (`fcm.googleapis.com`, `updates.push.services.mozilla.com`, `web.push.apple.com`, `*.push.apple.com`, `*.notify.windows.com`; `internal/webpush`), checked when stored and again before every send, and the request goes through the netguard client, which refuses internal addresses at dial time ([netguard.md](netguard.md)). Redirects are never followed.
- **The endpoint is a capability** (whoever knows it can push to that browser). It is stored only inside the envelope together with the browser's keys (`push_subscriptions.sub_*`, AAD `{user, "push_subscription", id}`), with only its SHA-256 in the clear. It is never logged, audited, exported or shown; errors name the push service host only.
- **One endpoint, one account**: the SHA-256 is unique across users. When another account turns notifications on in a browser that is subscribed for someone else, the subscription is handed over (the previous account's row is deleted through the jobs scope), so one account's approvals never show on a device another account is now signed in on.
- **Requests**: the routes are signed-in only and the POSTs pass the portal's CSRF check (`X-CSRF-Token` header, which `pwa.js` reads from `<body hx-headers>`, or the `_csrf` form field); JSON bodies are limited to 8 KiB.
- **Lifecycle**: disabling a user deletes their subscriptions (identity disable hook); deleting the account deletes them (`store.DeleteUserData`); the rows also cascade with the user row.
- **Audit** (user events, `/activity`): `push.subscribed` (with `renewed` when an existing device re-subscribed), `push.unsubscribed`, `push.test_sent`, with the subscription id, device label and push service host.
- **Data export** (`push_subscriptions` section): device label, push service host, added, last delivered. Never the endpoint or keys.

## Routes

| Route | What |
|---|---|
| `GET /account/push/key` | `{"publicKey": "<base64url>"}`: the VAPID public key, the browser's `applicationServerKey` (`no-store`) |
| `POST /account/push/subscribe` | JSON `PushSubscription.toJSON()` plus an optional `"label"` → `204`; `400` malformed or endpoint not on a known push service (one generic message); `409` at 10 devices; `413` over 8 KiB |
| `POST /account/push/unsubscribe` | JSON `{"endpoint"}` (turn off for this browser) → `204`; or the device table's form `id` → `303` to `/account#notifications` (`404` for an unknown device) |
| `POST /account/push/test` | sends "Test notification" to all the user's devices → `{"sent": n}`; `429` with `Retry-After` within 30 seconds of the last one (per replica) |

Anonymous requests get the sign-in redirect; POSTs without a valid CSRF token get `403`.

## Enabling it

1. A key provider is required (`GATEWAY_KEY_PROVIDER` / `GATEWAY_KEY_FILE`; [crypto.md](crypto.md)). Without one the feature stays off with a startup warning.
2. A **VAPID subject** (how a push service contacts the operator) is derived: the gateway's `GATEWAY_BASE_URL` when it is `https` (production), otherwise `mailto:<GATEWAY_LEGAL_CONTACT_EMAIL>` (a local or http deployment). With neither the feature stays off with a startup warning ("there is no VAPID subject"). Browsers only allow push on secure origins (https, or `localhost`).
3. Set `GATEWAY_WEBPUSH_ENABLED=true` (Helm `gateway.webpush.enabled: true`). An unparsable value fails startup.
4. **Egress**: the gateway pods need HTTPS (443) to the push services above. The chart's default vendor egress (public internet minus private ranges on 443) already covers them; they are listed in `networkPolicy.egress.vendorAPIs.hosts` (recorded on the NetworkPolicy annotation). With an FQDN-aware CNI or an egress proxy, allow those hosts there ([deploy.md](deploy.md#network-policy-assumptions)).

Startup logs `web push ready` with the subject and the routes. Nothing else needs configuring: the VAPID key pair is created on first use.

## The VAPID key

- One P-256 key pair for the whole gateway, in `webpush_keys` (migration 00033). The first replica that needs it creates it; concurrent replicas agree on one key (`INSERT … ON CONFLICT DO NOTHING` on a singleton column, then a re-read in the same transaction). Each process caches it for its lifetime.
- The public key is stored plain; the private key (PKCS#8) is envelope-encrypted with AAD `{kind "webpush_key", record id}`. Admins see metadata only in `admin_webpush_keys` (id, public key, created).
- It is **never rotated automatically**: a new key invalidates every browser subscription (each was made for the old public key). A stored key that does not decrypt is an error (logged, notifications fail), never silently replaced.
- **Root key rotation** re-wraps it with everything else: `webpush_keys.private` and `push_subscriptions.sub` are in `rewrap.Columns`, so `migrate rewrap` moves both ([crypto.md](crypto.md)).
- To rotate the VAPID key deliberately (suspected compromise): as the database owner `DELETE FROM push_subscriptions; DELETE FROM webpush_keys;`, then restart the gateway pods; users turn notifications on again.

## iPhone and iPad

iOS / iPadOS 16.4 or later deliver Web Push **only to an app added to the Home Screen** (Safari → Share → *Add to Home Screen*, then open it from the Home Screen icon and turn notifications on there). In a Safari tab the control says *Not supported on this browser*. Focus modes and the installed app's notification settings apply as for any app.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| no Notifications panel on My account | the feature is off | check the startup log for `web push ready`, or the warning saying why it stayed off |
| *Not supported on this browser* | no service worker / Push API (an iPhone Safari tab, an old browser, a non-secure origin, private mode) | iPhone: add to Home Screen and open the app; elsewhere use https and a current browser |
| *Blocked in browser settings* | the user denied permission once; browsers do not ask again | allow notifications for the site in the browser's site settings, then turn on |
| turning on says "This browser's push subscription was refused." | the endpoint is not on a known push service (some privacy browsers use their own) | use a mainstream browser; the allow-list is in `internal/webpush` |
| the test says "No device got it." | this browser's subscription is no longer stored (removed in the table, handed over, or deleted after a 410) | turn notifications off and on again on this device |
| a device shows failures | the push service refused or timed out | check the gateway log (`approvals.notify_failed`, `pushnotify.sent`); egress to the push hosts must be open |
| everything fails after a restore under another key provider | the VAPID key or subscriptions do not decrypt | `migrate rewrap verify` with the right provider ([crypto.md](crypto.md)) |

Code: `internal/webpush` (protocol), `internal/pushnotify` (key, subscriptions, notifier), `internal/portal/push.go` and `static/pwa.js` (UI), `cmd/gateway/push.go` (wiring), migration `00033_push_notifications.sql`. Tests: `internal/pushnotify/*_test.go` (payload, TTL, timeout and concurrency bounds, 410 deletes, cap, upsert, handover, AAD binding, test rate limit; integration: key created once across replicas, row-level security, cap), `internal/store/push_integration_test.go`, `internal/portal/push_test.go`, `internal/portal/pwa_test.go`, `cmd/gateway/push_test.go`, `internal/rewrap`.
