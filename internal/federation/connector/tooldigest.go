package connector

import (
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/federation/tooldigest"
)

// reviewedMeta is the _meta of a federated tools/call: the digest of the
// approved snapshot's definition of the tool (tooldigest.MetaKey). A
// server that runs what its definition says (the machine actions server)
// refuses a call whose reviewed definition is not the one it serves;
// other servers ignore the key.
func reviewedMeta(t snapshot.Tool) sdk.Meta {
	return sdk.Meta{tooldigest.MetaKey: tooldigest.Digest(t.Name, t.Description, t.InputSchema)}
}
