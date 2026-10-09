package google

import "github.com/huynle/mcp-gateway/internal/connectors"

// Gmail tools (filled in by the next increments).

func (c *Connector) gmailReadTools() []connectors.Tool { return nil }

func (c *Connector) gmailWriteTools() []connectors.Tool { return nil }

func (c *Connector) gmailReadHandlers() map[string]handler { return map[string]handler{} }

func (c *Connector) gmailWriteHandlers() map[string]handler { return map[string]handler{} }
