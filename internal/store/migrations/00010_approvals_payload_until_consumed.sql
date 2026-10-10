-- Approvals v2 (decision s0p05diu): the stored argument payload must
-- survive the user's "approve" until the harness retries and the approval
-- is consumed, so the payload may exist while the status is pending OR
-- approved (00005 only allowed pending). Denied, consumed and expired rows
-- still carry no payload. Two metadata columns join the row: the token the
-- call came through (no foreign key, like audit_events: history outlives
-- tokens) and the resource identity the connector extracted (keys and short
-- values only, never arguments), shown on the approval page and kept for
-- the history after the payload is gone.

-- +goose Up
ALTER TABLE approvals DROP CONSTRAINT approvals_check1;
ALTER TABLE approvals ADD CONSTRAINT approvals_payload_only_while_open
    CHECK (status IN ('pending', 'approved') OR payload_ciphertext IS NULL);
ALTER TABLE approvals ADD COLUMN token_id uuid;
ALTER TABLE approvals ADD COLUMN resource jsonb NOT NULL DEFAULT '{}'::jsonb;
-- The consume looks an approved approval up by its binding and digest
-- (retry without approval_id).
CREATE INDEX approvals_binding_digest_idx ON approvals (user_id, connection_id, tool, policy_version_id, digest)
    WHERE status = 'approved' AND consumed_at IS NULL;

-- +goose Down
DROP INDEX IF EXISTS approvals_binding_digest_idx;
ALTER TABLE approvals DROP COLUMN IF EXISTS resource;
ALTER TABLE approvals DROP COLUMN IF EXISTS token_id;
ALTER TABLE approvals DROP CONSTRAINT IF EXISTS approvals_payload_only_while_open;
UPDATE approvals SET payload_key_id = NULL, payload_wrapped_key = NULL, payload_nonce = NULL, payload_ciphertext = NULL
    WHERE status <> 'pending';
ALTER TABLE approvals ADD CONSTRAINT approvals_check1 CHECK (status = 'pending' OR payload_ciphertext IS NULL);
