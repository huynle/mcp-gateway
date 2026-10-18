-- Public sign-up (feature public-launch): sign-up modes, invites and the
-- new-account rate limit.
--
--   users.status 'pending'   approval mode: a new account waits for an
--                            admin. Pending users have no role, and every
--                            module that issues or accepts credentials
--                            (sessions as a principal, generated tokens,
--                            OAuth codes and refresh tokens) already refuses
--                            status <> 'active'.
--   signup_invites           invite mode: single-use codes created by admins
--                            on /admin/users. Only the SHA-256 of the code is
--                            stored; the code is shown once.
--   signup_events            one row per account created on sign-in, keyed by
--                            a SHA-256 of the client IP (the IP itself is
--                            never stored), for the per-IP and global
--                            new-account limits. Rows older than the window
--                            are pruned on insert.
--
-- Both tables are admin / sign-in metadata written before any user scope
-- exists, so only gateway_jobs (BYPASSRLS) may touch them. Row-level
-- security is enabled and forced without a policy: should gateway_app ever
-- be granted access, it still sees nothing (fail closed).

-- +goose Up
ALTER TABLE users DROP CONSTRAINT users_status_check;
ALTER TABLE users ADD CONSTRAINT users_status_check
    CHECK (status IN ('active', 'disabled', 'pending'));

CREATE TABLE signup_invites (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    code_hash   bytea       NOT NULL UNIQUE,
    label       text        NOT NULL DEFAULT '' CHECK (length(label) <= 100),
    created_by  uuid        REFERENCES users(id),
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    used_at     timestamptz,
    used_by     uuid        REFERENCES users(id),
    revoked_at  timestamptz,
    CHECK ((used_at IS NULL) = (used_by IS NULL))
);
CREATE INDEX signup_invites_created_idx ON signup_invites (created_at DESC);
ALTER TABLE signup_invites ENABLE ROW LEVEL SECURITY;
ALTER TABLE signup_invites FORCE ROW LEVEL SECURITY;
GRANT SELECT, INSERT, UPDATE, DELETE ON signup_invites TO gateway_jobs;

CREATE TABLE signup_events (
    id          bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    client_key  bytea       NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX signup_events_created_idx ON signup_events (created_at);
CREATE INDEX signup_events_client_idx ON signup_events (client_key, created_at);
ALTER TABLE signup_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE signup_events FORCE ROW LEVEL SECURITY;
GRANT SELECT, INSERT, DELETE ON signup_events TO gateway_jobs;

-- +goose Down
DROP TABLE IF EXISTS signup_events;
DROP TABLE IF EXISTS signup_invites;
-- A pending account cannot exist without this schema: going down rejects
-- it (disabled), the fail-closed reading of "not approved".
UPDATE users SET status = 'disabled', disabled_at = coalesce(disabled_at, now()) WHERE status = 'pending';
ALTER TABLE users DROP CONSTRAINT users_status_check;
ALTER TABLE users ADD CONSTRAINT users_status_check
    CHECK (status IN ('active', 'disabled'));
