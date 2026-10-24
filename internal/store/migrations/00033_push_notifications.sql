-- Web Push approval notifications (decision 0pzhidap, docs/push-notifications.md).
--
-- A user turns notifications on for a browser or installed app on My
-- account; the browser hands the gateway a push subscription (an endpoint
-- URL at a push service plus two keys). When an approval waits, the
-- approvals notifier encrypts a minimal message ("Approval needed", tool,
-- account label; never arguments or resource identity) for every one of
-- the user's subscriptions and posts it to the push service, signed with
-- the gateway's VAPID key.
--
--   * webpush_keys: the gateway's single VAPID key pair (P-256), created by
--     the first replica that needs it and never rotated automatically:
--     a new key invalidates every browser subscription. The singleton
--     column (always true, UNIQUE) makes "create it once" an
--     INSERT ... ON CONFLICT (singleton) DO NOTHING followed by a re-read,
--     so two replicas starting together agree on one key. The public key
--     (base64url, the browser's applicationServerKey) is plain; the private
--     key (PKCS#8 DER) is envelope-encrypted with AAD
--     {kind "webpush_key", record id}. A system table like signing_keys
--     (00006): no row security; admins see metadata only
--     (admin_webpush_keys, like admin_signing_keys in 00007).
--   * push_subscriptions: one row per browser subscription, owned by the
--     user who turned notifications on. The endpoint URL is a bearer
--     capability (whoever knows it can push to that browser), so endpoint,
--     p256dh and auth are sealed together in one envelope (the sub_*
--     columns, AAD {user, "push_subscription", id}); only its SHA-256 is
--     stored in the clear, for uniqueness and for "turn off" lookups.
--     endpoint_host (the push service, e.g. fcm.googleapis.com) and
--     device_label ("Android Chrome") are for display only.
--     endpoint_sha256 is unique across all users, not per user: one
--     browser profile has one push channel, so when another account
--     subscribes the same browser the gateway hands the channel over
--     (deletes the previous owner's row through the jobs scope) instead
--     of showing one account's approvals on a device another account now
--     uses. The per-user cap (10) is enforced in code under an advisory
--     lock. Rows cascade with the user row; disabling or deleting a user
--     deletes them explicitly (deleted users are tombstoned, not
--     removed). Owner's rows under forced row security like secrets
--     (00031).

-- +goose Up
CREATE TABLE webpush_keys (
    id                  uuid        PRIMARY KEY,
    singleton           boolean     NOT NULL DEFAULT true UNIQUE CHECK (singleton),
    public_key          text        NOT NULL CHECK (public_key <> '' AND length(public_key) <= 200),
    private_key_id      text        NOT NULL,
    private_wrapped_key bytea       NOT NULL,
    private_nonce       bytea       NOT NULL,
    private_ciphertext  bytea       NOT NULL,
    created_at          timestamptz NOT NULL DEFAULT now()
);
-- UPDATE only for the re-wrap job (migrate rewrap as gateway_jobs); the
-- service itself never changes or deletes a key.
GRANT SELECT, INSERT ON webpush_keys TO gateway_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON webpush_keys TO gateway_jobs;

CREATE VIEW admin_webpush_keys WITH (security_invoker = true) AS
    SELECT id, public_key, created_at
    FROM webpush_keys;
GRANT SELECT ON admin_webpush_keys TO gateway_app, gateway_jobs;

CREATE TABLE push_subscriptions (
    id               uuid        PRIMARY KEY,
    user_id          uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    endpoint_sha256  bytea       NOT NULL UNIQUE CHECK (length(endpoint_sha256) = 32),
    sub_key_id       text        NOT NULL,
    sub_wrapped_key  bytea       NOT NULL,
    sub_nonce        bytea       NOT NULL,
    sub_ciphertext   bytea       NOT NULL,
    endpoint_host    text        NOT NULL CHECK (endpoint_host <> '' AND length(endpoint_host) <= 253),
    device_label     text        NOT NULL CHECK (device_label <> '' AND char_length(device_label) <= 100),
    failure_count    integer     NOT NULL DEFAULT 0 CHECK (failure_count >= 0),
    last_success_at  timestamptz,
    last_failure_at  timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX push_subscriptions_user_idx ON push_subscriptions (user_id, created_at);
ALTER TABLE push_subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE push_subscriptions FORCE ROW LEVEL SECURITY;
CREATE POLICY push_subscriptions_owner ON push_subscriptions
    USING (user_id = app_user_id()) WITH CHECK (user_id = app_user_id());
-- The owner subscribes, re-subscribes (new keys), records deliveries and
-- removes devices on the request path; the notifier deletes gone
-- subscriptions under the owner's scope too. The jobs scope hands an
-- endpoint over to another user and runs the disable hook.
GRANT SELECT, INSERT, UPDATE, DELETE ON push_subscriptions TO gateway_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON push_subscriptions TO gateway_jobs;

-- +goose Down
-- No other table's policy reads these tables (the quirk of 00014's Down
-- does not apply); the owner policy is dropped explicitly anyway, in
-- reverse order of the Up section.
DROP POLICY IF EXISTS push_subscriptions_owner ON push_subscriptions;
DROP TABLE IF EXISTS push_subscriptions;
DROP VIEW IF EXISTS admin_webpush_keys;
DROP TABLE IF EXISTS webpush_keys;
