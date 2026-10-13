-- Durable organization, app and user rate-limit settings (decision 7fzb71uv).
-- Environment values remain bootstrap defaults; non-null DB settings override
-- them. User ceilings are self-service and can only lower the effective admin
-- or organization limit.

-- +goose Up
CREATE TABLE gateway_rate_settings (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    user_per_min integer CHECK (user_per_min > 0),
    app_per_min integer CHECK (app_per_min > 0),
    version bigint NOT NULL DEFAULT 1,
    updated_by uuid REFERENCES users(id),
    updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO gateway_rate_settings (singleton) VALUES (true);

CREATE TABLE gateway_app_rate_limits (
    app text PRIMARY KEY CHECK (app ~ '^[a-z0-9_-]{1,63}$'),
    per_min integer NOT NULL CHECK (per_min > 0),
    updated_by uuid REFERENCES users(id),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE gateway_user_rate_limits (
    user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    admin_per_min integer CHECK (admin_per_min > 0),
    self_per_min integer CHECK (self_per_min > 0),
    updated_by uuid REFERENCES users(id),
    updated_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE gateway_user_rate_limits ENABLE ROW LEVEL SECURITY;
ALTER TABLE gateway_user_rate_limits FORCE ROW LEVEL SECURITY;
CREATE POLICY gateway_user_rate_limits_self ON gateway_user_rate_limits
    USING (user_id = app_user_id()) WITH CHECK (user_id = app_user_id());

GRANT SELECT ON gateway_rate_settings, gateway_app_rate_limits TO gateway_app;
GRANT SELECT ON gateway_user_rate_limits TO gateway_app;
GRANT INSERT (user_id, self_per_min, updated_by) ON gateway_user_rate_limits TO gateway_app;
GRANT UPDATE (self_per_min, updated_by, updated_at) ON gateway_user_rate_limits TO gateway_app;
GRANT ALL ON gateway_rate_settings, gateway_app_rate_limits, gateway_user_rate_limits TO gateway_jobs;

-- +goose Down
DROP TABLE IF EXISTS gateway_user_rate_limits;
DROP TABLE IF EXISTS gateway_app_rate_limits;
DROP TABLE IF EXISTS gateway_rate_settings;
