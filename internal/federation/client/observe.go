package client

import (
	"errors"
	"time"
)

// CallInfo describes one finished operation, for metrics (per-call latency
// by server) and tracing. It carries no URLs, arguments or results.
type CallInfo struct {
	// Label is Endpoint.Label (e.g. the server ID).
	Label string
	// Op is "connect" or the MCP method ("tools/call", ...).
	Op string
	// Transport is the transport used (for a failed auto connect, the last
	// one tried).
	Transport Transport
	// Class is "" on success, else the error's class.
	Class Class
	// Duration is the wall time of the operation.
	Duration time.Duration
}

// report calls the OnCall hook, if any.
func (c *Client) report(label, op string, tr Transport, start time.Time, err error) {
	if c.onCall == nil {
		return
	}
	ci := CallInfo{Label: label, Op: op, Transport: tr, Duration: time.Since(start)}
	if err != nil {
		var e *Error
		if errors.As(err, &e) {
			ci.Class = e.Class
		} else {
			ci.Class = ClassProtocol
		}
	}
	c.onCall(ci)
}
