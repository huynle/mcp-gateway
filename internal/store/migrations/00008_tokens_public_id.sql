-- Generated tokens carry a short public id in the token string itself
-- (mgw_<public_id>_<secret>, decision uamxx6ba): 8 base62 characters chosen
-- at creation, independent of the row's uuid, so a bearer token can be
-- resolved to its row (and owner) with one narrow lookup before the secret
-- is compared. Existing rows (none in any real deployment yet) receive a
-- placeholder derived from their uuid so the column can be NOT NULL UNIQUE.

-- +goose Up
ALTER TABLE tokens ADD COLUMN public_id text;
UPDATE tokens SET public_id = substr(md5(id::text), 1, 8) WHERE public_id IS NULL;
ALTER TABLE tokens ALTER COLUMN public_id SET NOT NULL;
ALTER TABLE tokens ADD CONSTRAINT tokens_public_id_key UNIQUE (public_id);
ALTER TABLE tokens ADD CONSTRAINT tokens_public_id_format CHECK (public_id ~ '^[A-Za-z0-9]{8}$');

-- The admin projection shows the prefix users see in the portal (never the hash).
DROP VIEW IF EXISTS admin_tokens;
CREATE VIEW admin_tokens WITH (security_invoker = true) AS
    SELECT id, user_id, public_id, name, read_only, scope, expires_at, revoked_at, last_used_at, created_at
    FROM tokens;
GRANT SELECT ON admin_tokens TO gateway_app, gateway_jobs;

-- +goose Down
DROP VIEW IF EXISTS admin_tokens;
CREATE VIEW admin_tokens WITH (security_invoker = true) AS
    SELECT id, user_id, name, read_only, scope, expires_at, revoked_at, last_used_at, created_at
    FROM tokens;
GRANT SELECT ON admin_tokens TO gateway_app, gateway_jobs;
ALTER TABLE tokens DROP CONSTRAINT IF EXISTS tokens_public_id_format;
ALTER TABLE tokens DROP CONSTRAINT IF EXISTS tokens_public_id_key;
ALTER TABLE tokens DROP COLUMN IF EXISTS public_id;
