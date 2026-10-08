// Package mcp owns the /mcp Streamable HTTP endpoint (official MCP Go SDK in
// stateless mode: no session store, no sticky sessions, no reliance on
// server-initiated notifications) and the tool call pipeline that ties
// authentication, tool resolution, account resolution, policy, approvals,
// ledger, the app call and audit together.
//
// Design: Brain plan 36bakiw8 sections 2 and 3; decisions ysorv868, dovthftx.
package mcp
