package atlassian

import (
	"errors"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// ErrMissingOperation is returned by every write called without
// Call.OperationID: the ledger stage sets it before dispatch, and the
// marker reconciliation derives from it, so a write without one could
// never be verified after an unknown outcome. It means a pipeline wiring
// bug (a write dispatched without the ledger), never a harness mistake.
var ErrMissingOperation = errors.New("atlassian: write called without a ledger operation id")

// writeTools declares the app's write tools.
func (c *Connector) writeTools() []connectors.Tool { return nil }

// writeHandlers maps the write tools' short names to their implementation.
func (c *Connector) writeHandlers() map[string]handler { return nil }
