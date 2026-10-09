package microsoft_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/connectortest"
	"github.com/huynle/mcp-gateway/internal/connectors/microsoft"
)

func TestMicrosoftPassesContract(t *testing.T) {
	c, err := microsoft.New(microsoft.Options{Tokens: (&tokens{}).source})
	if err != nil {
		t.Fatal(err)
	}
	connectortest.ContractTest(t, c)
}

func TestMicrosoftDefaultBounds(t *testing.T) {
	c, err := microsoft.New(microsoft.Options{Tokens: (&tokens{}).source})
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

// The connector talks to Graph through the hand-written client in the
// graph subpackage (decision bt8ukyrd): neither go.mod nor any source
// file imports the Microsoft Graph SDK, so build time and binary size
// stay unaffected.
func TestNoGraphSDKImported(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	gomod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	for _, forbidden := range []string{"msgraph-sdk-go", "microsoftgraph/msgraph", "kiota"} {
		if strings.Contains(string(gomod), forbidden) {
			t.Errorf("go.mod requires %s; the connector must use the thin graph client", forbidden)
		}
	}
	pkgDir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	err = filepath.WalkDir(pkgDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, line := range strings.Split(string(src), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "\"") && !strings.HasPrefix(line, "import \"") {
				continue
			}
			if strings.Contains(line, "github.com/microsoftgraph/") || strings.Contains(line, "github.com/microsoft/kiota") {
				t.Errorf("%s imports the Graph SDK: %s", path, line)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
