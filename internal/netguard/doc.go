// Package netguard is the SSRF boundary for every outbound call the gateway
// makes to a user-supplied URL (federated MCP servers, their OAuth
// endpoints, tunnels). It provides one HTTP client/transport that:
//
//   - accepts https only (http only when AllowHTTP is set or the host is
//     allow-listed) and refuses URLs with userinfo;
//   - refuses literal IP hosts in any internal range, and refuses
//     non-canonical numeric hosts (decimal, octal, hex, short forms) that Go
//     and browsers would interpret differently;
//   - resolves the host itself in DialContext, refuses the connection when
//     ANY resolved address is internal (unless allow-listed), and dials the
//     checked IP directly so a second DNS answer cannot rebind it, while TLS
//     SNI and the Host header keep the original name;
//   - re-validates every redirect hop, caps redirects and forbids
//     https→http downgrades;
//   - bounds the request time and the response size.
//
// No other package may build its own http.Client or http.Transport for
// upstream URLs; a test in this package enforces that for
// internal/federation.
//
// Design: Brain plan 0omkv2e1 section 4; decision yhd5kcaz; task qm82mfer.
package netguard
