//go:build windows

package mcpproxy

import (
	"context"
	"errors"
)

// lockFile: the proxy keeps its refresh token in files whose owner and
// mode cannot be checked on Windows yet (internal/machineclient), so it
// is not supported there.
func lockFile(context.Context, string) (func(), error) {
	return nil, errors.New("mcp-gateway proxy is not supported on Windows yet")
}
