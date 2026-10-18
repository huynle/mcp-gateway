-- Cross-replica tunnel relay (Brain decision efq0ncag item 5,
-- docs/tunnel.md "Multiple replicas").
--
-- A tunnel's live WebSocket is held in memory by exactly one gateway
-- replica. When that replica accepts the connection it records itself here
-- as the tunnel's holder: its internal relay address
-- (GATEWAY_RELAY_ADVERTISE_ADDR) and a connection epoch drawn from a
-- global sequence, so every connection, on any replica, gets a distinct
-- epoch. A newer connection overwrites the row; a disconnect deletes the
-- row only while it still carries that connection's epoch. Other replicas
-- read the row to forward tunnel requests to the holder, which serves them
-- only while it still holds that epoch.
--
-- Staleness reuses mcp_tunnels.last_seen_at (touched on connect and every
-- heartbeat by the holder): readers ignore a row whose tunnel was not seen
-- recently or is revoked, so a crashed replica's row expires on its own.
--
-- Written and read only by the tunnel endpoint and the relay, which run
-- before any user is known: gateway_jobs (BYPASSRLS) only. The
-- request-path role gets no access; the row holds internal pod addresses
-- and is never shown to users.

-- +goose Up
CREATE SEQUENCE mcp_tunnel_holder_epoch_seq AS bigint;
CREATE TABLE mcp_tunnel_holders (
    tunnel_id  uuid        PRIMARY KEY REFERENCES mcp_tunnels(id) ON DELETE CASCADE,
    holder     text        NOT NULL CHECK (holder <> '' AND length(holder) <= 512),
    epoch      bigint      NOT NULL,
    claimed_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE, DELETE ON mcp_tunnel_holders TO gateway_jobs;
GRANT USAGE ON SEQUENCE mcp_tunnel_holder_epoch_seq TO gateway_jobs;

-- +goose Down
DROP TABLE IF EXISTS mcp_tunnel_holders;
DROP SEQUENCE IF EXISTS mcp_tunnel_holder_epoch_seq;
