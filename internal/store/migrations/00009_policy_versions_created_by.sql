-- Policy versions record which admin's change produced them (decision
-- 490o45d0: every role change compiles a new version). NULL means the
-- gateway itself compiled it (startup, a role assignment made through the
-- identity module, a reload on another replica).

-- +goose Up
ALTER TABLE policy_versions ADD COLUMN created_by uuid REFERENCES users(id);

-- +goose Down
ALTER TABLE policy_versions DROP COLUMN IF EXISTS created_by;
