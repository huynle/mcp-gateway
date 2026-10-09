package github_test

import (
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/connectortest"
	"github.com/huynle/mcp-gateway/internal/connectors/github"
)

func TestGitHubPassesContract(t *testing.T) {
	c, err := github.New(github.Options{Tokens: (&tokens{}).source})
	if err != nil {
		t.Fatal(err)
	}
	connectortest.ContractTest(t, c)
}

func TestGitHubDefaultBounds(t *testing.T) {
	c, err := github.New(github.Options{Tokens: (&tokens{}).source})
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range c.Tools() {
		if tool.Bounds.MaxResultBytes != connectors.DefaultMaxResultBytes {
			t.Errorf("%s: MaxResultBytes = %d, want the package default %d", tool.Name, tool.Bounds.MaxResultBytes, connectors.DefaultMaxResultBytes)
		}
		if tool.Bounds.MaxPageSize != 0 && tool.Bounds.MaxPageSize != connectors.DefaultMaxPageSize {
			t.Errorf("%s: MaxPageSize = %d, want 0 or the default %d", tool.Name, tool.Bounds.MaxPageSize, connectors.DefaultMaxPageSize)
		}
	}
}
