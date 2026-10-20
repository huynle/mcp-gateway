//go:build windows

package machineclient

import (
	"context"
	"errors"
	"os"
)

// errWindows: the private-file checks (owner, mode) have no Windows
// equivalent here yet, and the client fails closed rather than trust a
// file it cannot check. `mcp-gateway tunnel` works on Windows.
var errWindows = errors.New("machine login is not supported on Windows yet; use `mcp-gateway tunnel`")

func openPrivateFile(string, func() int) (*os.File, error) { return nil, errWindows }

func runSecurity(context.Context, string, []string, []byte) ([]byte, error) { return nil, errWindows }
