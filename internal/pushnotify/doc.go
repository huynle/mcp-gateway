// Package pushnotify sends approval notifications to the user's browsers
// and installed apps over Web Push (decision 0pzhidap,
// docs/push-notifications.md). It sits between internal/webpush (the
// protocol: message encryption, VAPID, the push-service allow-list) and
// the gateway: the VAPID key, the stored subscriptions, the approvals
// notifier and what the portal's "Notifications" panel needs.
//
//   - The VAPID key: one P-256 key pair for the whole gateway, created by
//     the first replica that needs it (INSERT ... ON CONFLICT DO NOTHING on
//     a singleton, then a re-read, so concurrent replicas agree), the
//     private half envelope-encrypted under AAD {kind KeyKind, record id}.
//     Each process caches it for its lifetime: it is never rotated
//     automatically, because a new key invalidates every subscription.
//   - Subscriptions (Subscribe, Unsubscribe, RemoveDevice, Devices): the
//     browser's PushSubscription, validated by webpush.ParseSubscription
//     (endpoint on a known push service only: the SSRF guard), stored with
//     endpoint, p256dh and auth sealed together under AAD {user,
//     SubscriptionKind, record id} and only the endpoint's SHA-256 in the
//     clear. Re-subscribing an endpoint updates the row; at most
//     MaxSubscriptionsPerUser per user (ErrLimit). An endpoint belongs to
//     one user: subscribing one another user holds hands it over (the
//     browser presenting it is now signed in as the new user).
//   - Notify (approvals.Notifier): for the approval's user only, a
//     minimal message {"title","body","url","tag"} with the tool and the
//     account label (never arguments, resource identity or account
//     names), TTL until the approval expires (MinTTL..MaxTTL), urgency
//     high and a topic derived from the approval id. Sends run at most
//     NotifyConcurrency at a time and the whole fan-out is bounded by the
//     timeout (DefaultNotifyTimeout), so a slow push service never holds
//     the approval flow longer; a 404/410 deletes the subscription; every
//     outcome is recorded on the row (last success, last failure, failure
//     count); failures are returned joined and the approvals service only
//     logs them.
//   - SendTest: the "Send test notification" button, once per
//     TestInterval per user (per process).
//   - OnDisableUser (identity.DisableHook): a disabled user's
//     subscriptions are deleted in the disabling transaction. Account
//     deletion deletes them in store.DeleteUserData.
//
// Subscribe, unsubscribe and test sends are audited as user events
// (push.subscribed, push.unsubscribed, push.test_sent) with the
// subscription id, device label and push-service host. The endpoint URL
// is a bearer capability: it is never logged, audited, exported or shown,
// and errors from this package never contain it.
//
// Files: config.go (GATEWAY_WEBPUSH_ENABLED, limits, the VAPID subject),
// store.go (the Store/Tx persistence interface and NewPostgresStore),
// service.go (keys, subscriptions, the disable hook), notifier.go
// (Notify, SendTest, the bounded fan-out), label.go (DeviceLabel from
// the User-Agent, label cleanup).
package pushnotify
