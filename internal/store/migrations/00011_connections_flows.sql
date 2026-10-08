-- In-flight app connection flows (plan 36bakiw8 section 5; decision
-- mh7c6z3v). /connect/{vendor}/start stores the OAuth state, the PKCE
-- verifier and what was requested; /connect/{vendor}/callback consumes the
-- row by state (one use) on whichever replica receives it, so no sticky
-- sessions are needed. Rows expire after a few minutes and the keep-alive
-- job sweeps leftovers. Scoped to the starting user: a callback can only
-- finish a flow the same signed-in user began.

-- +goose Up
CREATE TABLE connect_flows (
    state           text        PRIMARY KEY,
    user_id         uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    vendor_app_id   uuid        NOT NULL REFERENCES vendor_apps(id) ON DELETE CASCADE,
    verifier        text        NOT NULL,
    scopes          text[]      NOT NULL DEFAULT '{}',
    return_to       text        NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL
);
CREATE INDEX connect_flows_expires_at_idx ON connect_flows (expires_at);
ALTER TABLE connect_flows ENABLE ROW LEVEL SECURITY;
ALTER TABLE connect_flows FORCE ROW LEVEL SECURITY;
CREATE POLICY connect_flows_user_scope ON connect_flows
    USING (user_id = app_user_id()) WITH CHECK (user_id = app_user_id());
GRANT SELECT, INSERT, UPDATE, DELETE ON connect_flows TO gateway_app, gateway_jobs;

-- +goose Down
DROP TABLE IF EXISTS connect_flows;
