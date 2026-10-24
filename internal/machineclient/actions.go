package machineclient

// The actions server: an in-process MCP server registered as the http
// server "<machine>-actions", one tool per action (design:
// docs/plans/2026-10-23-ephemeral-secrets-design.md, section 2 and
// correction 5).
//
// A call carries the declared params and the "secret" argument, whose
// value the gateway substituted for the agent's {"$secret": "sec_…"}
// handle, and in _meta (tooldigest.MetaKey) the digest of the definition
// the gateway approved. A call whose digest is missing or is not the one
// of the definition served now (the action was edited under the same
// name since its review) is refused before anything else: the edited
// command never runs with the secret until a human approves the new
// snapshot. Otherwise the client validates every param against its pattern before
// anything runs, starts the fixed argv (never a shell, never the secret
// in argv) with the minimal stdio environment, hands the secret over in
// the configured mode, and returns exit code, duration and the capped
// output scrubbed of the secret.
//
// Secret delivery:
//
//   - stdin: the secret and "\n" on stdin through a pipe, then EOF.
//   - fd: the secret on file descriptor 3 (a pipe), then EOF.
//   - env:NAME: NAME=secret in the child's environment only. Weakest:
//     the command and everything it starts can read it, and on Linux so
//     can same-user processes through /proc/<pid>/environ.
//   - askpass: a private 0700 temporary directory holds a FIFO and a
//     0700 /bin/sh helper that runs `cat` on the FIFO. SUDO_ASKPASS and
//     SSH_ASKPASS point at the helper, SSH_ASKPASS_REQUIRE=force, and
//     DISPLAY is set when the environment has none. The client writes
//     the secret into the FIFO once, for the first reader, and removes the
//     FIFO at that moment, so the helper works exactly once; the
//     directory is deleted after the run. The secret never touches the
//     disk. The helper does not read an inherited fd 3 because ssh and
//     sudo close inherited descriptors before running their askpass
//     program. Limits: sudo uses the helper only with -A, OpenSSH
//     honours SSH_ASKPASS_REQUIRE from 8.4 on, and until the first read a
//     process of the same user could open the FIFO (it could also read
//     this process's memory). Unix only.
//
// The command runs in its own session (setsid: no controlling terminal,
// so a program cannot prompt on the user's terminal) and the whole
// process group is killed on timeout or cancellation.
//
// Go strings cannot be wiped: the []byte copies made for delivery are
// zeroed after the run, but the decoded argument string and the request
// body stay in memory until the garbage collector reuses them.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/federation/tooldigest"
	"github.com/huynle/mcp-gateway/internal/secrets/scrub"
)

const (
	// maxActionOutput caps stdout and stderr each.
	maxActionOutput = 64 << 10
	// actionWaitDelay bounds the wait for pipes held open by leftover
	// children after the command exited or was killed.
	actionWaitDelay = 2 * time.Second
	// actionsMaxBody bounds a request to the actions server.
	actionsMaxBody = 1 << 20
	// secretArgDescription describes the "secret" tool argument.
	secretArgDescription = `Pass {"$secret": "sec_…"} from secrets.request; the gateway substitutes the value`
)

// ActionResult is what a tool call of an action returns (as structured
// content and as its JSON text). Output is scrubbed of the secret.
type ActionResult struct {
	ExitCode        int    `json:"exit_code"`
	DurationMS      int64  `json:"duration_ms"`
	TimedOut        bool   `json:"timed_out"`
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	StdoutTruncated bool   `json:"stdout_truncated"`
	StderrTruncated bool   `json:"stderr_truncated"`
}

// ActionsOptions configure the actions server.
type ActionsOptions struct {
	Version string
	// Environ is the CLI's environment (nil: os.Environ); actions get the
	// same minimal environment as stdio servers (BuildStdioSpec).
	Environ func() []string
	// Log gets one debug line per run (action, exit code, duration).
	Log *slog.Logger

	onStart func(*exec.Cmd) // tests: called just before each start
}

// NewActionsHandler serves actions as an MCP server (Streamable HTTP,
// stateless, JSON responses): one tool per action, named after it.
func NewActionsHandler(actions map[string]*Action, o ActionsOptions) http.Handler {
	return newActionsHandler(actions, o)
}

func newActionsHandler(actions map[string]*Action, o ActionsOptions) http.Handler {
	if o.Environ == nil {
		o.Environ = os.Environ
	}
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	r := &actionRunner{environ: o.Environ, onStart: o.onStart, log: o.Log}
	srv := sdk.NewServer(&sdk.Implementation{Name: "mcp-gateway-actions", Version: o.Version}, &sdk.ServerOptions{
		Logger:       o.Log,
		Capabilities: &sdk.ServerCapabilities{Tools: &sdk.ToolCapabilities{ListChanged: false}},
	})
	cfg := &Config{Actions: actions}
	for _, name := range cfg.ActionNames() {
		a := actions[name]
		tool := actionTool(a)
		srv.AddTool(tool, r.handler(a, toolDigest(tool)))
	}
	return sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return srv }, &sdk.StreamableHTTPOptions{
		// Like the gateway's own endpoint and how it talks to tunnel
		// targets: one JSON body per POST, no sessions.
		Stateless:           true,
		JSONResponse:        true,
		MaxRequestBodyBytes: actionsMaxBody,
		// Requests arrive through the machine connection, never from a
		// local listener a browser could reach.
		DisableLocalhostProtection: true,
		Logger:                     o.Log,
	})
}

// actionTool is the MCP tool of an action. Its description holds the
// fixed command so that the gateway's snapshot review shows what runs.
func actionTool(a *Action) *sdk.Tool {
	props := map[string]any{}
	required := []string{}
	for _, p := range a.ParamNames() {
		props[p] = map[string]any{"type": "string", "pattern": a.Params[p].Pattern}
		required = append(required, p)
	}
	props[SecretArg] = map[string]any{"type": "string", "description": secretArgDescription}
	required = append(required, SecretArg)
	destructive, openWorld := true, false
	return &sdk.Tool{
		Name:        a.Name,
		Description: actionDescription(a),
		InputSchema: map[string]any{
			"type":                 "object",
			"properties":           props,
			"required":             required,
			"additionalProperties": false,
		},
		Annotations: &sdk.ToolAnnotations{DestructiveHint: &destructive, OpenWorldHint: &openWorld},
	}
}

// ActionDigest is the tooldigest of the tool that serves a: what the
// gateway must send (tooldigest.MetaKey) for a call to run.
func ActionDigest(a *Action) string { return toolDigest(actionTool(a)) }

func toolDigest(t *sdk.Tool) string {
	schema, err := json.Marshal(t.InputSchema)
	if err != nil {
		return "" // unreachable: the schema is built from strings
	}
	return tooldigest.Digest(t.Name, t.Description, schema)
}

// reviewedDigest reports whether the call carries digest, the digest of
// the definition served now, as the gateway's approved one. A call
// without it comes from a gateway that did not check it, or was approved
// for another definition: the action was edited under the same name
// since its review.
func reviewedDigest(req *sdk.CallToolRequest, digest string) bool {
	got, _ := req.Params.GetMeta()[tooldigest.MetaKey].(string)
	return digest != "" && got == digest
}

func actionDescription(a *Action) string {
	var b strings.Builder
	if d := strings.TrimSpace(a.Description); d != "" {
		b.WriteString(d + "\n\n")
	}
	fmt.Fprintf(&b, "Runs (fixed command, no shell): %s\n", a.Command())
	switch a.Secret {
	case SecretStdin:
		b.WriteString("Secret: written to standard input, followed by a newline.\n")
	case SecretFD:
		b.WriteString("Secret: readable once on file descriptor 3.\n")
	case SecretAskpass:
		b.WriteString("Secret: printed once by a SUDO_ASKPASS/SSH_ASKPASS helper.\n")
	case SecretEnv:
		fmt.Fprintf(&b, "Secret: in the environment variable %s (weakest: visible to everything the command starts).\n", a.SecretEnv)
	}
	fmt.Fprintf(&b, "Timeout %s. Returns exit_code, duration_ms, stdout and stderr (each capped at %d KiB, scrubbed of the secret).", a.Timeout, maxActionOutput>>10)
	return b.String()
}

type actionRunner struct {
	environ func() []string
	onStart func(*exec.Cmd)
	log     *slog.Logger
}

func errorResult(msg string) *sdk.CallToolResult {
	return &sdk.CallToolResult{IsError: true, Content: []sdk.Content{&sdk.TextContent{Text: msg}}}
}

func (r *actionRunner) handler(a *Action, digest string) sdk.ToolHandler {
	return func(ctx context.Context, req *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
		// First: nothing of an unreviewed definition runs, and its
		// arguments (the secret) are not even decoded.
		if !reviewedDigest(req, digest) {
			return errorResult(fmt.Sprintf("action %s changed since it was reviewed; approve the new version on the Machines page (or the server's review page)", a.Name)), nil
		}
		var args map[string]json.RawMessage
		if raw := req.Params.Arguments; len(raw) > 0 {
			if err := json.Unmarshal(raw, &args); err != nil {
				return errorResult("the arguments must be a JSON object"), nil
			}
		}
		rawSecret, ok := args[SecretArg]
		if !ok {
			return errorResult("the secret argument is missing: " + secretArgDescription), nil
		}
		var secret string
		if err := json.Unmarshal(rawSecret, &secret); err != nil {
			return errorResult("the secret argument must be a string; " + secretArgDescription), nil
		}
		params := map[string]string{}
		for k, v := range args {
			if k == SecretArg {
				continue
			}
			var s string
			if err := json.Unmarshal(v, &s); err != nil {
				return errorResult(fmt.Sprintf("param %q must be a string", k)), nil
			}
			params[k] = s
		}
		scr := scrub.New(secret)
		res, err := r.run(ctx, a, params, secret)
		if err != nil {
			return errorResult(scr.String(err.Error())), nil
		}
		text, err := json.Marshal(res)
		if err != nil {
			return errorResult("cannot encode the result"), nil
		}
		out := &sdk.CallToolResult{
			Content:           []sdk.Content{&sdk.TextContent{Text: string(text)}},
			StructuredContent: res,
			IsError:           res.ExitCode != 0 || res.TimedOut,
		}
		// Defensive second pass over everything returned.
		if clean, ok := scr.Any(out).(*sdk.CallToolResult); ok {
			out = clean
		}
		return out, nil
	}
}

// checkSecret refuses secrets the delivery mode cannot carry intact.
// Errors never contain the value.
func checkSecret(a *Action, secret string) error {
	switch {
	case secret == "":
		return errors.New("the secret is empty")
	case strings.ContainsRune(secret, 0):
		return errors.New("the secret contains a NUL byte")
	case (a.Secret == SecretStdin || a.Secret == SecretAskpass) && strings.ContainsAny(secret, "\r\n"):
		return fmt.Errorf("the secret contains a line break, which %s delivery cannot carry", a.Secret)
	}
	return nil
}

// run validates params and the secret, then runs the action. Errors are
// refusals or start failures (nothing ran to completion); a command that
// ran returns a result, whatever its exit status.
func (r *actionRunner) run(ctx context.Context, a *Action, params map[string]string, secret string) (*ActionResult, error) {
	if err := checkSecret(a, secret); err != nil {
		return nil, err
	}
	argv, err := a.Argv(params)
	if err != nil {
		return nil, err
	}
	if err := platformSupports(a.Secret); err != nil {
		return nil, err
	}
	spec, err := BuildStdioSpec(&Server{Name: a.Name, Kind: KindStdio, Command: argv}, r.environ())
	if err != nil {
		return nil, err
	}
	scr := scrub.New(secret)
	payload := []byte(secret)
	if a.Secret == SecretStdin || a.Secret == SecretAskpass {
		payload = append(payload, '\n')
	}
	defer clear(payload)

	rctx, cancel := context.WithTimeout(ctx, a.Timeout)
	defer cancel()
	cmd := exec.CommandContext(rctx, argv[0], argv[1:]...) //nolint:gosec // the user's configured, fixed command
	cmd.Env = spec.Env
	cmd.WaitDelay = actionWaitDelay
	ownProcessGroup(cmd)
	stdout, stderr := newCapture(len(secret)), newCapture(len(secret))
	cmd.Stdout, cmd.Stderr = stdout, stderr

	var w *pipeWriter
	var childEnd *os.File // the command's end of the secret pipe
	switch a.Secret {
	case SecretStdin, SecretFD:
		pr, pw, err := os.Pipe()
		if err != nil {
			return nil, err
		}
		childEnd = pr
		defer func() { _ = pr.Close() }()
		if a.Secret == SecretStdin {
			cmd.Stdin = pr
		} else {
			cmd.ExtraFiles = []*os.File{pr}
		}
		w = &pipeWriter{f: pw, done: make(chan struct{})}
		defer w.close()
	case SecretEnv:
		cmd.Env = setEnv(cmd.Env, a.SecretEnv, secret)
	case SecretAskpass:
		ap, err := startAskpass(payload)
		if err != nil {
			return nil, scr.Error(err)
		}
		defer ap.close()
		cmd.Env = setEnv(cmd.Env, "SUDO_ASKPASS", ap.script)
		cmd.Env = setEnv(cmd.Env, "SSH_ASKPASS", ap.script)
		cmd.Env = setEnv(cmd.Env, "SSH_ASKPASS_REQUIRE", "force")
		if !hasEnv(cmd.Env, "DISPLAY") {
			cmd.Env = setEnv(cmd.Env, "DISPLAY", ":0")
		}
	}

	if r.onStart != nil {
		r.onStart(cmd)
	}
	start := time.Now()
	if err := cmd.Start(); err != nil {
		return nil, scr.Error(fmt.Errorf("start %s: %w", argv[0], err))
	}
	if childEnd != nil {
		_ = childEnd.Close() // the command holds its own copy
	}
	if w != nil {
		go w.write(payload)
	}
	_ = cmd.Wait() // the exit status is in ProcessState
	if w != nil {
		w.close()
	}
	res := &ActionResult{
		ExitCode:   cmd.ProcessState.ExitCode(),
		DurationMS: time.Since(start).Milliseconds(),
		TimedOut:   errors.Is(rctx.Err(), context.DeadlineExceeded) && ctx.Err() == nil,
	}
	res.Stdout, res.StdoutTruncated = stdout.result(scr)
	res.Stderr, res.StderrTruncated = stderr.result(scr)
	if r.log != nil {
		r.log.Debug("action run", "action", a.Name, "exit_code", res.ExitCode, "timed_out", res.TimedOut, "duration_ms", res.DurationMS)
	}
	return res, nil
}

// pipeWriter delivers the secret on the write end of a pipe and closes
// it; close also unblocks a write the command never reads.
type pipeWriter struct {
	f    *os.File
	done chan struct{}
	once sync.Once
}

func (p *pipeWriter) write(b []byte) {
	defer close(p.done)
	_, _ = p.f.Write(b) // EPIPE when the command does not read
	_ = p.f.Close()
}

// close closes the write end and waits for a running write, so the
// payload can be zeroed afterwards.
func (p *pipeWriter) close() {
	p.once.Do(func() {
		_ = p.f.Close()
		select {
		case <-p.done:
		case <-time.After(actionWaitDelay):
		}
	})
}

func hasEnv(env []string, name string) bool {
	for _, kv := range env {
		if strings.HasPrefix(kv, name+"=") {
			return true
		}
	}
	return false
}

// setEnv sets name in env (KEY=value form), replacing an existing entry.
func setEnv(env []string, name, value string) []string {
	out := make([]string, 0, len(env)+1)
	for _, kv := range env {
		if !strings.HasPrefix(kv, name+"=") {
			out = append(out, kv)
		}
	}
	return append(out, name+"="+value)
}

// capture keeps the first bytes of a stream: the cap plus room to scrub
// a secret that straddles the cut (each form of the secret is at most
// 6 bytes per byte: the JSON \u00XX escape).
type capture struct {
	mu    sync.Mutex
	limit int
	slack int
	b     []byte
	total int
}

func newCapture(secretLen int) *capture {
	slack := 6*secretLen + len(scrub.Mask)
	return &capture{limit: maxActionOutput + 2*slack, slack: slack}
}

func (c *capture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.total += len(p)
	if room := c.limit - len(c.b); room > 0 {
		c.b = append(c.b, p[:min(room, len(p))]...)
	}
	return len(p), nil
}

// result is the scrubbed output, at most maxActionOutput bytes of valid
// UTF-8, and whether anything was cut.
func (c *capture) result(scr *scrub.Scrubber) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	defer clear(c.b)
	text := scr.String(string(c.b))
	truncated := c.total > maxActionOutput
	if c.total > len(c.b) {
		// The capture itself was cut: a partial form of the secret can
		// only sit in the last slack bytes, which scrubbing leaves as
		// they are. Drop them.
		text = text[:max(0, len(text)-c.slack)]
	}
	if len(text) > maxActionOutput {
		text, truncated = text[:maxActionOutput], true
	}
	if !utf8.ValidString(text) {
		text = strings.ToValidUTF8(text, "")
	}
	return text, truncated
}
