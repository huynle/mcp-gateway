// Package tunnel connects stdio and private-network MCP servers to the
// gateway without the gateway spawning programs or reaching into the
// user's network (decision yhd5kcaz, plan 0omkv2e1).
//
// The user runs cmd/mcp-gateway-tunnel next to the server. It dials out to
// the gateway's /tunnel/connect endpoint (Service.Handler) with a per-tunnel
// bearer token (mgt_..., shown once, stored as SHA-256), upgrades to a
// WebSocket and keeps it open. The gateway multiplexes HTTP requests over
// that connection as framed messages with stream ids (see wire.go and
// docs/tunnel.md); the client replays them against the local server and
// streams the responses back.
//
// Gateway code reaches a tunnelled server through Service.HTTPClient,
// whose transport serves only tunnel URLs (tunnel://<tunnel id>/<path>, or
// the http form from ClientURL that internal/federation/client accepts)
// and never dials anything, so netguard is bypassed for exactly those
// URLs. A request to a tunnel with no live connection on this replica
// fails with an *Error of class tunnel_offline.
//
// Live connections are per replica: the replica holding a tunnel's
// connection must serve its calls (sticky routing is future work).
package tunnel
