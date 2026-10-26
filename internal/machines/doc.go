// Package machines enrolls user machines and authenticates them (Brain
// decision ldjix4y1, docs/machines.md).
//
// A user enrolls a machine once with `mcp-gateway login`. The CLI creates
// an Ed25519 key pair and either runs a device authorization flow (RFC
// 8628 style: POST /machine/device_authorization, the user approves the
// request at /activate after checking the machine's name and key
// fingerprint, the CLI polls POST /machine/token) or presents a one-time
// enrollment code created on the Machines page (POST /machine/enroll),
// for headless hosts. The private key never leaves the machine. The
// /activate page also confirms the authorization server's harness device
// grants (internal/authserver, RFC 8628): both kinds share the user-code
// format, and the store never lets them hold the same code.
//
// Afterwards the machine signs a short-lived JWT assertion (EdDSA,
// audience the token endpoint, jti replay-checked) and trades it for a
// 10-minute machine access token (mgm_..., SHA-256 at rest). Every use of
// the token re-checks the machine (not revoked) and its owner (active).
// The token only reaches the machine API under /machine/v1: describe the
// machine, register its servers (a tunnel linked to the machine and the
// owner's private MCP server behind it), refresh their snapshots (never
// approve), log out, and open the machine's single multiplexed
// WebSocket (internal/federation/tunnel ServeMachine). It is not accepted
// by /mcp, the portal or anything else.
//
// Revocation (owner, admin or the machine itself) revokes the machine's
// tunnels in the same transaction and closes its live connection on this
// replica at once; other replicas close theirs within the tunnel
// service's MachineSyncInterval.
package machines
