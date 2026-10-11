package portal_test

import (
	"testing"

	"github.com/huynle/mcp-gateway/internal/federation/connector"
	fedportal "github.com/huynle/mcp-gateway/internal/federation/portal"
)

// The portal refuses exactly the names the connector refuses to load, so a
// server can never be created that would silently never get tools (e.g.
// "mcp", the anchor connection vendor).
func TestPortalReservedNamesMatchConnector(t *testing.T) {
	for _, name := range connector.ReservedNames() {
		if err := fedportal.ValidateName(name); err == nil {
			t.Errorf("ValidateName(%q) = nil, want refused (connector reserves it)", name)
		}
	}
	if err := fedportal.ValidateName("mcp"); err == nil {
		t.Error(`ValidateName("mcp") = nil, want refused`)
	}
	if err := fedportal.ValidateName("brain"); err != nil {
		t.Errorf(`ValidateName("brain") = %v, want ok`, err)
	}
}
