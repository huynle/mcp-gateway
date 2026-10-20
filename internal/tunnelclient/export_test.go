package tunnelclient

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type environOut struct {
	Env []string `json:"env"`
	Dir string   `json:"dir"`
}

// environServer reports its environment and working directory.
func environServer() *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "environ-server", Version: "1.0.0"}, nil)
	mcp.AddTool(s, &mcp.Tool{Name: "environ", Description: "reports the environment"},
		func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, environOut, error) {
			dir, _ := os.Getwd()
			return nil, environOut{Env: os.Environ(), Dir: dir}, nil
		})
	return s
}

// StartStdio gives the server exactly the environment and directory asked
// for: nothing of the parent's environment leaks.
func TestStartStdioCleanEnvironment(t *testing.T) {
	t.Setenv("PARENT_SECRET", "leak-me")
	dir := t.TempDir()
	srv, err := StartStdio(context.Background(), StdioCommand{
		Argv: []string{os.Args[0], "-test.run=^$"},
		Env:  []string{"MCP_TUNNEL_TEST_ENV_SERVER=1", "PROBE=yes"},
		Dir:  dir,
	}, io.Discard, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()
	h := srv.Handler()
	if rec := post(h, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`); rec.Code != 200 {
		t.Fatalf("initialize: %d %s", rec.Code, rec.Body)
	}
	post(h, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	rec := post(h, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"environ","arguments":{}}}`)
	var resp struct {
		Result struct {
			StructuredContent environOut `json:"structuredContent"`
		} `json:"result"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("%v: %s", err, rec.Body)
	}
	got := resp.Result.StructuredContent
	joined := strings.Join(got.Env, "\n")
	if strings.Contains(joined, "PARENT_SECRET") || !strings.Contains(joined, "PROBE=yes") {
		t.Fatalf("environment:\n%s", joined)
	}
	want, _ := filepath.EvalSymlinks(dir)
	if gotDir, _ := filepath.EvalSymlinks(got.Dir); gotDir != want {
		t.Fatalf("dir %q, want %q", got.Dir, dir)
	}
	srv.Stop()
	select {
	case <-srv.Done():
	default:
		t.Fatal("Done not closed after Stop")
	}
}
