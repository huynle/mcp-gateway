package client

import (
	"errors"
	"io"
	"mime"
	"net/http"

	"github.com/huynle/mcp-gateway/internal/netguard"
)

// errTooLarge is the read error of a response over MaxResultBytes.
var errTooLarge = errors.New("federation client: response exceeds MaxResultBytes")

// limitBody bounds one response body to max bytes per JSON-RPC message:
// a JSON body as a whole, an SSE body per event (a stream may carry many
// messages). Exceeding the bound (or netguard's own cap) records
// ClassTooLarge in obs and fails the read.
func limitBody(resp *http.Response, max int64, obs *observer) {
	ct, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if ct == "text/event-stream" {
		resp.Body = &eventLimitBody{rc: resp.Body, max: max, obs: obs}
		return
	}
	resp.Body = &jsonLimitBody{rc: netguard.LimitedBody(resp.Body, max), obs: obs}
}

type jsonLimitBody struct {
	rc  io.ReadCloser
	obs *observer
}

func (b *jsonLimitBody) Read(p []byte) (int, error) {
	n, err := b.rc.Read(p)
	if errors.Is(err, netguard.ErrResponseTooLarge) {
		b.obs.recordTooLarge()
		return n, errTooLarge
	}
	return n, err
}

func (b *jsonLimitBody) Close() error { return b.rc.Close() }

// eventLimitBody counts the bytes of the current SSE event (since the last
// blank line, any of CRLF / LF / CR line endings) and fails once one event
// exceeds max.
type eventLimitBody struct {
	rc      io.ReadCloser
	max     int64
	obs     *observer
	event   int64 // bytes in the current event
	lineLen int64 // bytes in the current line, terminator excluded
	prevCR  bool
	err     error
}

func (b *eventLimitBody) Read(p []byte) (int, error) {
	if b.err != nil {
		return 0, b.err
	}
	n, err := b.rc.Read(p)
	for i := 0; i < n; i++ {
		c := p[i]
		b.event++
		switch {
		case c == '\n' && b.prevCR: // second half of CRLF
			b.event--
			b.prevCR = false
			continue
		case c == '\n' || c == '\r':
			if b.lineLen == 0 {
				b.event = 0 // blank line: the event is complete
			}
			b.lineLen = 0
		default:
			b.lineLen++
		}
		b.prevCR = c == '\r'
		if b.event > b.max {
			b.err = errTooLarge
			b.obs.recordTooLarge()
			return i, b.err
		}
	}
	if errors.Is(err, netguard.ErrResponseTooLarge) {
		b.err = errTooLarge
		b.obs.recordTooLarge()
		return n, b.err
	}
	return n, err
}

func (b *eventLimitBody) Close() error { return b.rc.Close() }
