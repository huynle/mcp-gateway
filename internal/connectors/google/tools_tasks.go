package google

import "github.com/huynle/mcp-gateway/internal/connectors"

// Tasks tools (filled in by the next increments).

func (c *Connector) tasksReadTools() []connectors.Tool { return nil }

func (c *Connector) tasksWriteTools() []connectors.Tool { return nil }

func (c *Connector) tasksReadHandlers() map[string]handler { return map[string]handler{} }

func (c *Connector) tasksWriteHandlers() map[string]handler { return map[string]handler{} }
