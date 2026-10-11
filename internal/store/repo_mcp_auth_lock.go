package store

import "context"

// LockMCPUserConnection reads userID's connection to serverID under a row
// lock (SELECT ... FOR UPDATE) held until the transaction ends, so one
// token refresh happens at a time per connection across replicas and the
// waiters read the refreshed bundle (federation auth, task k3ff95ec).
// Row-level security applies as for GetMCPUserConnection.
func LockMCPUserConnection(ctx context.Context, q Querier, serverID, userID string) (*MCPUserConnection, error) {
	var c MCPUserConnection
	err := scanMCPUserConnection(q.QueryRow(ctx, `SELECT `+mcpUserConnectionColumns+`
		FROM mcp_server_user_connections WHERE server_id = $1 AND user_id = $2 FOR UPDATE`, serverID, userID), &c)
	if err != nil {
		return nil, notFound(err)
	}
	return &c, nil
}
