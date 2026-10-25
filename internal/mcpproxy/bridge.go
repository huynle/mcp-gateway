package mcpproxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"
)

const (
	// maxMessage bounds one message in either direction.
	maxMessage = 64 << 20
	// codeInternal is the JSON-RPC error the proxy answers with when the
	// gateway cannot.
	codeInternal   = -32603
	codeParseError = -32700
)

// tokens is what the bridge needs from the token source.
type tokens interface {
	Token(ctx context.Context) (string, error)
	Invalidate(tok string)
	resourceURL() string
}

// lineWriter writes one message per line, atomically.
type lineWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lineWriter) writeLine(b []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.w.Write(append(b[:len(b):len(b)], '\n'))
}

// bridge forwards each stdin message to the gateway's /mcp endpoint
// (stateless Streamable HTTP) and writes the answers to stdout.
type bridge struct {
	o   *Options
	ts  tokens
	out *lineWriter

	mu              sync.Mutex
	protocolVersion string
	sessionID       string
}

// message is what the bridge needs to know about an outgoing message.
type message struct {
	body  []byte
	batch bool
	// ids of the requests in it (they expect answers).
	ids        []json.RawMessage
	initialize bool
}

func inspect(body []byte) message {
	m := message{body: body}
	type head struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
	}
	var heads []head
	if body[0] == '[' {
		m.batch = true
		var raw []json.RawMessage
		_ = json.Unmarshal(body, &raw)
		for _, r := range raw {
			var h head
			_ = json.Unmarshal(r, &h)
			heads = append(heads, h)
		}
	} else {
		var h head
		_ = json.Unmarshal(body, &h)
		heads = append(heads, h)
		m.initialize = h.Method == "initialize"
	}
	for _, h := range heads {
		if h.Method != "" && len(h.ID) > 0 && string(h.ID) != "null" {
			m.ids = append(m.ids, h.ID)
		}
	}
	return m
}

// handle forwards one line from stdin. authCtx ends waiting for a token
// (stdin closed); ctx ends everything.
func (b *bridge) handle(ctx, authCtx context.Context, line []byte, report func(error)) {
	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return
	}
	if !json.Valid(line) {
		b.writeError(json.RawMessage("null"), codeParseError, "parse error: the line is not JSON")
		return
	}
	m := inspect(line)
	tokCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(authCtx, cancel)
	defer stop()

	for attempt := 0; ; attempt++ {
		tok, err := b.ts.Token(tokCtx)
		if err != nil {
			report(err)
			b.fail(m, "mcp-gateway proxy: not signed in to the gateway: "+err.Error())
			return
		}
		resp, err := b.post(ctx, tok, m)
		if err != nil {
			if ctx.Err() == nil {
				b.fail(m, "mcp-gateway proxy: cannot reach the gateway: "+err.Error())
			}
			return
		}
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			// Revoked or expired early: renew once and retry.
			drain(resp)
			b.ts.Invalidate(tok)
			continue
		}
		b.deliver(resp, m)
		drain(resp)
		return
	}
}

func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxAuthBody))
	_ = resp.Body.Close()
}

func (b *bridge) post(ctx context.Context, tok string, m message) (*http.Response, error) {
	u := b.ts.resourceURL()
	if u == "" {
		return nil, errors.New("the gateway's MCP endpoint is unknown")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(m.body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("User-Agent", b.o.userAgent())
	b.mu.Lock()
	pv, sid := b.protocolVersion, b.sessionID
	b.mu.Unlock()
	if pv != "" && !m.initialize {
		req.Header.Set("MCP-Protocol-Version", pv)
	}
	if sid != "" && !m.initialize {
		req.Header.Set("Mcp-Session-Id", sid)
	}
	return b.o.HTTP.Do(req)
}

// deliver writes the gateway's answer: a JSON body, or the messages of a
// text/event-stream; 202 and 204 carry none.
func (b *bridge) deliver(resp *http.Response, m message) {
	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" && m.initialize {
		b.mu.Lock()
		b.sessionID = sid
		b.mu.Unlock()
	}
	ct, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	switch {
	case resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusNoContent:
		return
	case resp.StatusCode >= 200 && resp.StatusCode <= 299 && ct == "text/event-stream":
		answered := false
		err := readSSE(resp.Body, func(data []byte) {
			if b.emit(data, m) {
				answered = true
			}
		})
		if err != nil && !answered {
			b.fail(m, "mcp-gateway proxy: the gateway's event stream broke: "+err.Error())
		}
		return
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMessage))
	if err != nil {
		b.fail(m, "mcp-gateway proxy: reading the gateway's answer failed: "+err.Error())
		return
	}
	if isJSONRPC(body) {
		b.emit(body, m)
		return
	}
	if resp.StatusCode == http.StatusNotFound {
		// A session the server forgot: start without one.
		b.mu.Lock()
		b.sessionID = ""
		b.mu.Unlock()
	}
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		b.fail(m, "mcp-gateway proxy: the gateway's answer is not JSON-RPC")
		return
	}
	b.fail(m, fmt.Sprintf("mcp-gateway proxy: the gateway answered HTTP %d%s", resp.StatusCode, describe(body)))
}

// isJSONRPC reports whether body is a JSON-RPC message or batch.
func isJSONRPC(body []byte) bool {
	var probe any
	if json.Unmarshal(body, &probe) != nil {
		return false
	}
	switch v := probe.(type) {
	case map[string]any:
		return v["jsonrpc"] == "2.0"
	case []any:
		if len(v) == 0 {
			return false
		}
		o, ok := v[0].(map[string]any)
		return ok && o["jsonrpc"] == "2.0"
	}
	return false
}

// describe summarises an error body for the harness.
func describe(body []byte) string {
	var e struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if json.Unmarshal(body, &e) == nil && e.Error != "" {
		s := ": " + clean(e.Error)
		if e.Description != "" {
			s += " (" + trimRunes(clean(e.Description), maxDescription) + ")"
		}
		return s
	}
	if t := strings.TrimSpace(clean(string(body))); t != "" {
		return ": " + trimRunes(t, maxDescription)
	}
	return ""
}

// emit writes one message from the gateway as one line; it reports
// whether it wrote anything.
func (b *bridge) emit(data []byte, m message) bool {
	var buf bytes.Buffer
	if err := json.Compact(&buf, data); err != nil {
		say(b.o.Stderr, "mcp-gateway proxy: dropped a message from the gateway that is not JSON\n")
		return false
	}
	if m.initialize {
		var r struct {
			Result struct {
				ProtocolVersion string `json:"protocolVersion"`
			} `json:"result"`
		}
		if json.Unmarshal(buf.Bytes(), &r) == nil && r.Result.ProtocolVersion != "" {
			b.mu.Lock()
			b.protocolVersion = clean(r.Result.ProtocolVersion)
			b.mu.Unlock()
		}
	}
	b.out.writeLine(buf.Bytes())
	return true
}

// fail answers every request of m with a JSON-RPC error.
func (b *bridge) fail(m message, msg string) {
	if len(m.ids) == 0 {
		say(b.o.Stderr, "%s\n", msg)
		return
	}
	if !m.batch {
		b.writeError(m.ids[0], codeInternal, msg)
		return
	}
	out := make([]rpcError, 0, len(m.ids))
	for _, id := range m.ids {
		out = append(out, newRPCError(id, codeInternal, msg))
	}
	data, _ := json.Marshal(out)
	b.out.writeLine(data)
}

type rpcError struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Error   struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func newRPCError(id json.RawMessage, code int, msg string) rpcError {
	e := rpcError{JSONRPC: "2.0", ID: id}
	e.Error.Code, e.Error.Message = code, msg
	return e
}

func (b *bridge) writeError(id json.RawMessage, code int, msg string) {
	data, _ := json.Marshal(newRPCError(id, code, msg))
	b.out.writeLine(data)
}

// readSSE calls fn with the data of each server-sent event.
func readSSE(r io.Reader, fn func(data []byte)) error {
	br := bufio.NewReaderSize(r, 64<<10)
	var data bytes.Buffer
	has := false
	dispatch := func() {
		if has && data.Len() > 0 {
			fn(bytes.Clone(data.Bytes()))
		}
		data.Reset()
		has = false
	}
	for {
		line, err := br.ReadString('\n')
		if len(line) > 0 {
			line = strings.TrimRight(line, "\r\n")
			switch {
			case line == "":
				dispatch()
			case strings.HasPrefix(line, ":"):
			default:
				field, value, _ := strings.Cut(line, ":")
				value = strings.TrimPrefix(value, " ")
				if field == "data" {
					if has {
						data.WriteByte('\n')
					}
					data.WriteString(value)
					has = true
					if data.Len() > maxMessage {
						return errors.New("an event is too large")
					}
				}
			}
		}
		if errors.Is(err, io.EOF) {
			dispatch()
			return nil
		}
		if err != nil {
			return err
		}
	}
}
