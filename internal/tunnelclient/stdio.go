package tunnelclient

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// The stdio bridge turns the gateway's Streamable HTTP requests into
// JSON-RPC lines on a stdio MCP server's stdin and its stdout lines back
// into HTTP responses. It is a JSON-RPC proxy, not an MCP re-implementation,
// so tools, resources, prompts and completions all pass through unchanged.
//
// One stdio process serves every gateway session:
//   - request ids are rewritten to the bridge's own counter and restored on
//     the way back, so concurrent sessions cannot collide;
//   - the process is initialized once: the first initialize request is
//     forwarded (with client capabilities cleared, since the bridge cannot
//     answer server-to-client requests) and its result is cached and
//     returned to later sessions; notifications/initialized is forwarded
//     once;
//   - server/discover (stateless protocol probe) is answered "method not
//     found" locally so clients use the classic initialize handshake that
//     stdio servers expect;
//   - server-to-client requests (sampling, roots, elicitation) are refused
//     with a JSON-RPC error, ping is answered, server notifications are
//     dropped (the gateway does not consume them yet);
//   - responses are plain application/json; GET (standalone SSE stream) is
//     405; JSON-RPC batches are refused.
const (
	maxBridgeBody = 4 << 20  // one request from the gateway
	maxStdioLine  = 16 << 20 // one line from the stdio server

	codeMethodNotFound = -32601
)

type rpcMsg struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

func (m *rpcMsg) hasID() bool { return len(m.ID) > 0 && string(m.ID) != "null" }

type stdioBridge struct {
	w   io.Writer
	wmu sync.Mutex
	log *slog.Logger

	mu      sync.Mutex
	nextID  int64
	pending map[int64]chan *rpcMsg

	done     chan struct{}
	doneOnce sync.Once

	initMu          sync.Mutex
	initResult      json.RawMessage
	initializedSent bool
}

// newStdioBridge reads the server's stdout from r and writes to its stdin
// through w.
func newStdioBridge(r io.Reader, w io.Writer, log *slog.Logger) *stdioBridge {
	b := &stdioBridge{w: w, log: log, pending: map[int64]chan *rpcMsg{}, done: make(chan struct{})}
	go b.readLoop(r)
	return b
}

// Done is closed when the server's stdout ends (the process exited).
func (b *stdioBridge) Done() <-chan struct{} { return b.done }

func (b *stdioBridge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "only POST is supported by the stdio bridge", http.StatusMethodNotAllowed)
		return
	}
	select {
	case <-b.done:
		http.Error(w, "stdio server exited", http.StatusBadGateway)
		return
	default:
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBridgeBody+1))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if len(body) > maxBridgeBody {
		http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		return
	}
	var m rpcMsg
	if t := bytes.TrimSpace(body); len(t) == 0 || t[0] != '{' || json.Unmarshal(t, &m) != nil {
		http.Error(w, "expected one JSON-RPC message (batches are not supported)", http.StatusBadRequest)
		return
	}
	switch {
	case m.Method == "": // a response to a server request we never sent
		w.WriteHeader(http.StatusAccepted)
	case !m.hasID():
		b.notify(w, &m)
	case m.Method == "server/discover":
		writeRPC(w, &rpcMsg{ID: m.ID, Error: rpcError(codeMethodNotFound, "method not found")})
	case m.Method == "initialize":
		b.initialize(w, r.Context(), &m)
	default:
		resp, err := b.call(r.Context(), m.Method, m.Params)
		b.reply(w, &m, resp, err)
	}
}

func (b *stdioBridge) notify(w http.ResponseWriter, m *rpcMsg) {
	if m.Method == "notifications/initialized" {
		b.initMu.Lock()
		sent := b.initializedSent
		b.initializedSent = true
		b.initMu.Unlock()
		if sent {
			w.WriteHeader(http.StatusAccepted)
			return
		}
	}
	if err := b.write(&rpcMsg{Method: m.Method, Params: m.Params}); err != nil {
		http.Error(w, "stdio server unavailable", http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (b *stdioBridge) initialize(w http.ResponseWriter, ctx context.Context, m *rpcMsg) {
	b.initMu.Lock()
	defer b.initMu.Unlock()
	if b.initResult != nil {
		writeRPC(w, &rpcMsg{ID: m.ID, Result: b.initResult})
		return
	}
	params := map[string]json.RawMessage{}
	if len(m.Params) > 0 && json.Unmarshal(m.Params, &params) != nil {
		writeRPC(w, &rpcMsg{ID: m.ID, Error: rpcError(-32602, "invalid params")})
		return
	}
	params["capabilities"] = json.RawMessage(`{}`)
	p, _ := json.Marshal(params)
	resp, err := b.call(ctx, "initialize", p)
	if err == nil && len(resp.Error) == 0 && len(resp.Result) > 0 {
		b.initResult = resp.Result
	}
	b.reply(w, m, resp, err)
}

func (b *stdioBridge) reply(w http.ResponseWriter, req, resp *rpcMsg, err error) {
	switch {
	case errors.Is(err, errChildGone):
		http.Error(w, "stdio server exited", http.StatusBadGateway)
	case err != nil:
		// The caller went away (cancelled); nobody reads this.
		http.Error(w, "request cancelled", http.StatusServiceUnavailable)
	default:
		out := &rpcMsg{ID: req.ID, Result: resp.Result, Error: resp.Error}
		if len(out.Result) == 0 && len(out.Error) == 0 {
			out.Result = json.RawMessage(`{}`)
		}
		writeRPC(w, out)
	}
}

var errChildGone = errors.New("stdio server exited")

// call sends a request with a bridge-owned id and waits for its response.
func (b *stdioBridge) call(ctx context.Context, method string, params json.RawMessage) (*rpcMsg, error) {
	ch := make(chan *rpcMsg, 1)
	b.mu.Lock()
	b.nextID++
	id := b.nextID
	b.pending[id] = ch
	b.mu.Unlock()
	forget := func() {
		b.mu.Lock()
		delete(b.pending, id)
		b.mu.Unlock()
	}
	if err := b.write(&rpcMsg{ID: json.RawMessage(strconv.FormatInt(id, 10)), Method: method, Params: params}); err != nil {
		forget()
		return nil, errChildGone
	}
	select {
	case resp := <-ch:
		return resp, nil
	case <-b.done:
		forget()
		return nil, errChildGone
	case <-ctx.Done():
		forget()
		cancel, _ := json.Marshal(map[string]any{"requestId": id, "reason": "cancelled by the gateway"})
		_ = b.write(&rpcMsg{Method: "notifications/cancelled", Params: cancel})
		return nil, ctx.Err()
	}
}

// write sends one message as a single line.
func (b *stdioBridge) write(m *rpcMsg) error {
	m.JSONRPC = "2.0"
	line, err := json.Marshal(m) // compact: no newlines inside
	if err != nil {
		return err
	}
	b.wmu.Lock()
	defer b.wmu.Unlock()
	_, err = b.w.Write(append(line, '\n'))
	return err
}

func (b *stdioBridge) readLoop(r io.Reader) {
	defer b.doneOnce.Do(func() { close(b.done) })
	br := bufio.NewReaderSize(r, 64<<10)
	for {
		line, err := readLine(br, maxStdioLine)
		if len(bytes.TrimSpace(line)) > 0 {
			b.handleLine(line)
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				b.log.Warn("stdio server output unreadable", "error", err)
			}
			return
		}
	}
}

// readLine returns the next line; a line over max is discarded whole.
func readLine(br *bufio.Reader, maxLen int) ([]byte, error) {
	var buf []byte
	tooLong := false
	for {
		chunk, err := br.ReadSlice('\n')
		if !tooLong {
			if len(buf)+len(chunk) > maxLen {
				tooLong, buf = true, nil
			} else {
				buf = append(buf, chunk...)
			}
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if tooLong && err == nil {
			return nil, nil // skip it, keep reading
		}
		return buf, err
	}
}

func (b *stdioBridge) handleLine(line []byte) {
	var m rpcMsg
	if json.Unmarshal(bytes.TrimSpace(line), &m) != nil {
		b.log.Debug("ignoring non-JSON-RPC output from the stdio server")
		return
	}
	switch {
	case m.Method != "" && m.hasID(): // server-to-client request
		if m.Method == "ping" {
			_ = b.write(&rpcMsg{ID: m.ID, Result: json.RawMessage(`{}`)})
			return
		}
		b.log.Debug("refusing server-to-client request", "method", m.Method)
		_ = b.write(&rpcMsg{ID: m.ID, Error: rpcError(codeMethodNotFound, "not supported through mcp-gateway-tunnel")})
	case m.Method != "": // notification
		b.log.Debug("dropping server notification", "method", m.Method)
	case m.hasID():
		id, err := strconv.ParseInt(string(m.ID), 10, 64)
		if err != nil {
			return
		}
		b.mu.Lock()
		ch := b.pending[id]
		delete(b.pending, id)
		b.mu.Unlock()
		if ch != nil {
			ch <- &m
		}
	}
}

func rpcError(code int, msg string) json.RawMessage {
	b, _ := json.Marshal(map[string]any{"code": code, "message": msg})
	return b
}

func writeRPC(w http.ResponseWriter, m *rpcMsg) {
	m.JSONRPC = "2.0"
	b, _ := json.Marshal(m)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

// stdioProcess is the stdio MCP server started by the tunnel client.
type stdioProcess struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	bridge *stdioBridge
	exited chan struct{}
}

// startStdio starts argv with the tunnel token removed from its
// environment; its stderr goes to ours.
// Cancelling ctx sends SIGTERM (then SIGKILL after WaitDelay).
func startStdio(ctx context.Context, argv []string, stderr io.Writer, log *slog.Logger) (*stdioProcess, error) {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec // the user's own command, by design
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 5 * time.Second
	cmd.Env = childEnv(os.Environ())
	cmd.Stderr = stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	p := &stdioProcess{cmd: cmd, stdin: stdin, exited: make(chan struct{})}
	p.bridge = newStdioBridge(stdout, stdin, log)
	go func() {
		<-p.bridge.Done() // read all output before Wait closes the pipe
		err := cmd.Wait()
		log.Info("stdio server exited", "status", exitStatus(err))
		close(p.exited)
	}()
	return p, nil
}

// stop closes stdin (the polite MCP shutdown), then escalates to SIGTERM
// and SIGKILL.
func (p *stdioProcess) stop() {
	_ = p.stdin.Close()
	for _, sig := range []os.Signal{nil, syscall.SIGTERM, os.Kill} {
		if sig != nil {
			_ = p.cmd.Process.Signal(sig)
		}
		select {
		case <-p.exited:
			return
		case <-time.After(3 * time.Second):
		}
	}
}

func childEnv(env []string) []string {
	out := env[:0:0]
	for _, kv := range env {
		if strings.HasPrefix(kv, EnvToken+"=") {
			continue
		}
		out = append(out, kv)
	}
	return out
}

func exitStatus(err error) string {
	var ee *exec.ExitError
	switch {
	case err == nil:
		return "0"
	case errors.As(err, &ee):
		return ee.String()
	default:
		return "unknown"
	}
}
