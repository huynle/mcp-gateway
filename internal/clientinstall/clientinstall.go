// Package clientinstall holds the install commands of the mcp-gateway
// client CLI (GitHub Releases, Homebrew tap, Go). The portal's homepage and
// the servers page's tunnel section show them; GET /install redirects to
// the release's install script so the curl command can use the gateway's
// own address.
package clientinstall

import "strings"

// Release locations. The archives carry no version in their names, so
// "latest/download" always resolves.
const (
	ReleasesURL      = "https://github.com/huynle/mcp-gateway/releases/latest"
	InstallScriptURL = ReleasesURL + "/download/install.sh"
	BrewCommand      = "brew install huynle/tap/mcp-gateway"
	GoCommand        = "go install github.com/huynle/mcp-gateway/cmd/mcp-gateway@latest"
	// InstallPath is the gateway route redirecting to InstallScriptURL.
	InstallPath = "/install"
)

// Command is one way to install the CLI: a short tab name, a longer label
// and the command line.
type Command struct{ Tab, Label, Command string }

// Commands returns the install commands for a gateway at baseURL
// (GATEWAY_BASE_URL); an empty baseURL uses the GitHub address of the
// install script.
func Commands(baseURL string) []Command {
	script := InstallScriptURL
	if base := strings.TrimRight(baseURL, "/"); base != "" {
		script = base + InstallPath
	}
	return []Command{
		{Tab: "curl", Label: "Install script (macOS, Linux; checks the release checksum)", Command: "curl -fsSL " + script + " | sh"},
		{Tab: "brew", Label: "Homebrew (macOS, Linux)", Command: BrewCommand},
		{Tab: "go", Label: "Go 1.26 or later", Command: GoCommand},
	}
}
