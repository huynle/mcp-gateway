// Package connector puts user-added MCP servers into the gateway's tool
// pipeline (Brain plan 0omkv2e1 step 4, task fybs78bs): federated tools
// behave like built-in ones, visible per user, policed, approved,
// ledgered and audited.
//
//   - Manager.Load keeps the registry's server apps ("<server>.<tool>") in
//     step with the approved snapshots of active servers; the servers
//     portal calls Manager.ServerChanged after every change (create,
//     edit, publish, disable, delete, snapshot review, credentials), and
//     Manager.Run reloads periodically for other replicas.
//   - Manager.Visibility shows a server's tools only to users who may use
//     the server (owner of a private server, or a role it is published
//     to: store.ListVisibleMCPServers), then applies the policy.
//   - Manager.Accounts gives each such user one account per server: an
//     anchor row in the v1 connections table (vendor "mcp") that
//     approvals, ledger operations and audit rows reference.
//   - Each tool's handler checks the pinned snapshot as the caller, picks
//     the caller's credential (auth.ForUser), dials through netguard or
//     the user's tunnel and maps every failure to a class-level error.
//
// Server names of built-in apps are reserved (ValidateServerName). See
// docs/federation-connector.md.
package connector
