package tunnel

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

type StdioBridge struct {
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

// NewStdioBridge is the client-side handler that bridges tunnel requests
// to a stdio MCP server: it reads the server's stdout from r and writes to its stdin
// through w.
func NewStdioBridge(r io.Reader, w io.Writer, log *slog.Logger) *StdioBridge {
	b := &StdioBridge{w: w, log: log, pending: map[int64]chan *rpcMsg{}, done: make(chan struct{})}
	go b.readLoop(r)
	return b
}

// Done is closed when the server's stdout ends (the process exited).
func (b *StdioBridge) Done() <-chan struct{} { return b.done }

func (b *StdioBridge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

func (b *StdioBridge) notify(w http.ResponseWriter, m *rpcMsg) {
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

func (b *StdioBridge) initialize(w http.ResponseWriter, ctx context.Context, m *rpcMsg) {
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

func (b *StdioBridge) reply(w http.ResponseWriter, req, resp *rpcMsg, err error) {
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
func (b *StdioBridge) call(ctx context.Context, method string, params json.RawMessage) (*rpcMsg, error) {
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
func (b *StdioBridge) write(m *rpcMsg) error {
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

func (b *StdioBridge) readLoop(r io.Reader) {
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

func (b *StdioBridge) handleLine(line []byte) {
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
		_ = b.write(&rpcMsg{ID: m.ID, Error: rpcError(codeMethodNotFound, "not supported through the mcp-gateway tunnel")})
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

// StdioOptions start a stdio MCP server next to the tunnel client.
type StdioOptions struct {
	// Command is the program and its arguments (no shell).
	Command []string
	// Env is the child's complete environment ("KEY=value"); nothing is
	// inherited. The caller decides what the server may see (the machine
	// client passes a clean allowlist, the legacy client its own
	// environment minus the tunnel token).
	Env []string
	// Dir is the working directory ("" = the caller's).
	Dir string
	// Stderr receives the server's stderr (nil discards it).
	Stderr io.Writer
	// Log receives bridge events. Default: discard.
	Log *slog.Logger
}

// StdioProcess is a stdio MCP server started by StartStdio.
type StdioProcess struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	bridge *StdioBridge
	exited chan struct{}
	stop   sync.Once
}

// StartStdio starts o.Command with exactly o.Env and returns it with its
// bridge. Cancelling ctx sends SIGTERM (then SIGKILL after WaitDelay).
func StartStdio(ctx context.Context, o StdioOptions) (*StdioProcess, error) {
	if len(o.Command) == 0 || o.Command[0] == "" {
		return nil, errors.New("tunnel: empty stdio command")
	}
	log := o.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	cmd := exec.CommandContext(ctx, o.Command[0], o.Command[1:]...) //nolint:gosec // the user's own command, by design
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 5 * time.Second
	cmd.Env = append([]string{}, o.Env...) // non-nil: never inherit
	cmd.Dir = o.Dir
	cmd.Stderr = o.Stderr
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
	p := &StdioProcess{cmd: cmd, stdin: stdin, exited: make(chan struct{})}
	p.bridge = NewStdioBridge(stdout, stdin, log)
	go func() {
		<-p.bridge.Done() // read all output before Wait closes the pipe
		err := cmd.Wait()
		log.Info("stdio server exited", "status", exitStatus(err))
		close(p.exited)
	}()
	return p, nil
}

// Handler is the bridge serving tunnel requests to the process.
func (p *StdioProcess) Handler() http.Handler { return p.bridge }

// Done is closed when the process's stdout ended (it exited).
func (p *StdioProcess) Done() <-chan struct{} { return p.bridge.Done() }

// Stop closes stdin (the polite MCP shutdown), then escalates to SIGTERM
// and SIGKILL. It returns once the process exited; later calls return at
// once.
func (p *StdioProcess) Stop() {
	p.stop.Do(func() {
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
	})
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
