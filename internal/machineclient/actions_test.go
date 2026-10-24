//go:build unix

package machineclient

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/federation/tooldigest"
)

const testSecret = "correct horse battery staple"

func sha(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// TestActionHelperProcess is the command the actions tests run: the test
// binary with "-- helper <mode> [arg]". It reports what it received as
// SHA-256 hashes, never the secret itself (except in mode "leak").
func TestActionHelperProcess(*testing.T) {
	args := os.Args
	i := 0
	for i < len(args) && args[i] != "--" {
		i++
	}
	if i+2 >= len(args) || args[i+1] != "helper" {
		return
	}
	mode, rest := args[i+2], args[i+3:]
	code := 0
	switch mode {
	case "stdin":
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		fmt.Printf("got=%s newline=%v\n", sha(strings.TrimSuffix(line, "\n")), strings.HasSuffix(line, "\n"))
	case "fd":
		f := os.NewFile(3, "secret")
		b, err := io.ReadAll(f)
		fmt.Printf("got=%s err=%v\n", sha(string(b)), err)
	case "env":
		fmt.Printf("got=%s\n", sha(os.Getenv(rest[0])))
	case "askpass":
		fmt.Printf("same=%v require=%s display=%v\n", os.Getenv("SSH_ASKPASS") == os.Getenv("SUDO_ASKPASS"), os.Getenv("SSH_ASKPASS_REQUIRE"), os.Getenv("DISPLAY") != "")
		out, err := exec.Command(os.Getenv("SSH_ASKPASS"), "Password:").Output() //nolint:gosec,noctx // test helper
		fmt.Printf("got=%s err=%v\n", sha(strings.TrimSuffix(string(out), "\n")), err)
		out, err = exec.Command(os.Getenv("SUDO_ASKPASS"), "Password:").Output() //nolint:gosec,noctx // test helper
		fmt.Printf("second=%q ok=%v\n", out, err == nil)
	case "report":
		// Hashes of every argv word and environment entry.
		for _, a := range os.Args {
			fmt.Printf("arg=%s\n", sha(a))
		}
		for _, kv := range os.Environ() {
			_, v, _ := strings.Cut(kv, "=")
			fmt.Printf("envkv=%s envv=%s\n", sha(kv), sha(v))
		}
		fmt.Printf("args=%s\n", strings.Join(rest, ","))
	case "leak":
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		s := strings.TrimSuffix(line, "\n")
		fmt.Printf("the secret is %s\n", s)
		fmt.Fprintf(os.Stderr, "b64 %s\n", base64.StdEncoding.EncodeToString([]byte(s)))
		code = 3
	case "big":
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		s := strings.TrimSuffix(line, "\n")
		n, _ := strconv.Atoi(rest[0])
		fmt.Print(strings.Repeat("x", n) + s + strings.Repeat("y", 100<<10))
	case "sleep":
		c := exec.Command("sleep", "60") //nolint:noctx // test helper
		if err := c.Start(); err != nil {
			fmt.Println("start:", err)
			os.Exit(1)
		}
		fmt.Printf("child=%d\n", c.Process.Pid)
		_ = os.Stdout.Sync()
		time.Sleep(60 * time.Second)
	}
	os.Exit(code)
}

// helperAction builds an action that runs the helper in mode.
func helperAction(t *testing.T, secret, mode string, extra ...string) *Action {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	run := fmt.Sprintf("'%s' -test.run=^TestActionHelperProcess$ -- helper %s %s", exe, mode, strings.Join(extra, " "))
	ra := &rawAction{Run: run, Secret: secret}
	if strings.Contains(run, "{host}") {
		ra.Params = map[string]string{"host": "[a-z0-9-]+"}
	}
	a, err := buildAction("helper-"+mode, ra)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

type startLog struct {
	mu   sync.Mutex
	cmds []*exec.Cmd
}

func (s *startLog) add(c *exec.Cmd) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cmds = append(s.cmds, c)
}

func (s *startLog) all() []*exec.Cmd {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*exec.Cmd(nil), s.cmds...)
}

func newTestRunner() (*actionRunner, *startLog) {
	log := &startLog{}
	return &actionRunner{
		environ: func() []string { return append(os.Environ(), "MCP_GATEWAY_TOKEN=nope") },
		onStart: log.add,
	}, log
}

func run(t *testing.T, r *actionRunner, a *Action, params map[string]string) *ActionResult {
	t.Helper()
	res, err := r.run(context.Background(), a, params, testSecret)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestActionDeliveryModes(t *testing.T) {
	want := "got=" + sha(testSecret)
	for _, tc := range []struct {
		secret, mode string
		extra        []string
		check        string
	}{
		{"stdin", "stdin", nil, want + " newline=true"},
		{"fd", "fd", nil, want + " err=<nil>"},
		{"env:PGPASSWORD", "env", []string{"PGPASSWORD"}, want},
		{"askpass", "askpass", nil, want + " err=<nil>"},
	} {
		t.Run(tc.secret, func(t *testing.T) {
			r, log := newTestRunner()
			a := helperAction(t, tc.secret, tc.mode, tc.extra...)
			res := run(t, r, a, nil)
			if res.ExitCode != 0 || !strings.Contains(res.Stdout, tc.check) {
				t.Fatalf("result %+v; want stdout with %q", res, tc.check)
			}
			cmds := log.all()
			if len(cmds) != 1 {
				t.Fatalf("%d commands started", len(cmds))
			}
			for _, arg := range cmds[0].Args {
				if strings.Contains(arg, testSecret) {
					t.Fatalf("the secret is in argv: %q", cmds[0].Args)
				}
			}
			for _, kv := range cmds[0].Env {
				if strings.Contains(kv, testSecret) && kv != "PGPASSWORD="+testSecret {
					t.Fatalf("the secret is in the environment: %q", kv)
				}
				if strings.HasPrefix(kv, "MCP_GATEWAY_TOKEN=") {
					t.Fatal("the environment is not minimal")
				}
			}
			if tc.mode == "askpass" {
				if !strings.Contains(res.Stdout, "same=true require=force display=true") || !strings.Contains(res.Stdout, "ok=false") {
					t.Fatalf("askpass environment or one-shot helper: %s", res.Stdout)
				}
				var helper string
				for _, kv := range cmds[0].Env {
					if v, ok := strings.CutPrefix(kv, "SSH_ASKPASS="); ok {
						helper = v
					}
				}
				if helper == "" {
					t.Fatal("no SSH_ASKPASS")
				}
				if _, err := os.Stat(helper); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("the askpass helper was not removed: %v", err)
				}
			}
		})
	}
}

func TestActionSecretNeverInHelperArgsOrEnv(t *testing.T) {
	r, log := newTestRunner()
	for _, secret := range []string{"stdin", "fd", "askpass"} {
		a := helperAction(t, secret, "report", "{host}")
		res := run(t, r, a, map[string]string{"host": "db-1"})
		if res.ExitCode != 0 || !strings.Contains(res.Stdout, "args=db-1") {
			t.Fatalf("%s: %+v", secret, res)
		}
		h := sha(testSecret)
		if strings.Contains(res.Stdout, h) {
			t.Fatalf("%s: a helper argv word or environment value is the secret:\n%s", secret, res.Stdout)
		}
	}
	for _, c := range log.all() {
		if strings.Contains(strings.Join(c.Args, " "), testSecret) {
			t.Fatalf("argv %q", c.Args)
		}
	}
}

func TestActionBadParamsNeverRun(t *testing.T) {
	r, log := newTestRunner()
	a := helperAction(t, "stdin", "report", "{host}")
	for _, params := range []map[string]string{
		{"host": "db;rm -rf /"}, {"host": "db\n-x"}, {}, {"host": "db", "other": "x"}, {"host": "db", SecretArg: "x"},
	} {
		if _, err := r.run(context.Background(), a, params, testSecret); err == nil {
			t.Fatalf("params %q accepted", params)
		}
	}
	for _, secret := range []string{"", "with\x00nul", "line\nbreak"} {
		if _, err := r.run(context.Background(), a, map[string]string{"host": "db"}, secret); err == nil {
			t.Fatalf("secret %q accepted", secret)
		}
	}
	if n := len(log.all()); n != 0 {
		t.Fatalf("%d commands started", n)
	}
}

func TestActionOutputIsScrubbed(t *testing.T) {
	r, _ := newTestRunner()
	res := run(t, r, helperAction(t, "stdin", "leak"), nil)
	if res.ExitCode != 3 {
		t.Fatalf("exit %d", res.ExitCode)
	}
	b64 := base64.StdEncoding.EncodeToString([]byte(testSecret))
	for _, s := range []string{res.Stdout, res.Stderr} {
		if strings.Contains(s, testSecret) || strings.Contains(s, b64) || !strings.Contains(s, "[secret]") {
			t.Fatalf("not scrubbed: %q", s)
		}
	}
}

func TestActionOutputIsCappedAndScrubbedAtTheCut(t *testing.T) {
	r, _ := newTestRunner()
	// The secret straddles the cut: no prefix of it may survive.
	res := run(t, r, helperAction(t, "stdin", "big", strconv.Itoa(maxActionOutput-5)), nil)
	if !res.StdoutTruncated || len(res.Stdout) > maxActionOutput {
		t.Fatalf("truncated %v, %d bytes", res.StdoutTruncated, len(res.Stdout))
	}
	tail := strings.TrimLeft(res.Stdout, "x")
	mask := "[secret]" // the tail may only be a cut mask
	if strings.Contains(res.Stdout, testSecret[:5]) || !strings.HasPrefix(mask, tail) {
		t.Fatalf("output tail %q", tail)
	}
	if res.StderrTruncated {
		t.Fatal("stderr is not truncated")
	}
}

// TestActionTimeoutKillsTheProcessGroup runs /bin/sh, which starts a
// grandchild and prints its pid at once, and checks that the timeout kills
// the whole group. It does not use the helper process: that is this
// race-instrumented test binary, whose start under `make test` load can
// take longer than the timeout, so the timeout fired before the marker
// was printed (stdout "", the flake). The timed window now only covers a
// shell start; a missing marker still fails the test.
func TestActionTimeoutKillsTheProcessGroup(t *testing.T) {
	r, _ := newTestRunner()
	a, err := buildAction("sh-sleep", &rawAction{Run: `/bin/sh -c "sleep 60 & echo child=$!; wait"`, Secret: "stdin"})
	if err != nil {
		t.Fatal(err)
	}
	a.Timeout = 3 * time.Second
	start := time.Now()
	res := run(t, r, a, nil)
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("took %v", d)
	}
	if !res.TimedOut || res.ExitCode == 0 {
		t.Fatalf("result %+v", res)
	}
	pid := 0
	if _, err := fmt.Sscanf(strings.TrimSpace(res.Stdout), "child=%d", &pid); err != nil || pid <= 0 {
		t.Fatalf("no child pid: %+v", res)
	}
	waitFor(t, "the grandchild to die", func() bool { return syscall.Kill(pid, 0) != nil })
}

func TestActionContextCancelStops(t *testing.T) {
	r, _ := newTestRunner()
	a := helperAction(t, "stdin", "sleep")
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	res, err := r.run(ctx, a, nil, testSecret)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode == 0 {
		t.Fatalf("result %+v", res)
	}
}

func connectActions(t *testing.T, actions map[string]*Action, log *startLog) *sdk.ClientSession {
	t.Helper()
	h := newActionsHandler(actions, ActionsOptions{Version: "v1", Environ: os.Environ, onStart: log.add})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	cl := sdk.NewClient(&sdk.Implementation{Name: "test", Version: "v1"}, nil)
	cs, err := cl.Connect(context.Background(), &sdk.StreamableClientTransport{Endpoint: srv.URL + "/mcp", DisableStandaloneSSE: true, MaxRetries: -1}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func TestActionsServerListsOneToolPerAction(t *testing.T) {
	fakeLookPath(t)
	c, err := ParseConfig([]byte(actionsConfig))
	if err != nil {
		t.Fatal(err)
	}
	cs := connectActions(t, c.Actions, &startLog{})
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Tools) != 4 {
		t.Fatalf("%d tools", len(res.Tools))
	}
	byName := map[string]*sdk.Tool{}
	for _, tl := range res.Tools {
		byName[tl.Name] = tl
	}
	psql := byName["psql-report"]
	if psql == nil {
		t.Fatalf("tools %v", byName)
	}
	for _, want := range []string{`/usr/bin/psql -h {host} -U report --port={port}`, "PGPASSWORD"} {
		if !strings.Contains(psql.Description, want) {
			t.Errorf("description misses %q:\n%s", want, psql.Description)
		}
	}
	if d := byName["sudo-apt-upgrade"].Description; !strings.Contains(d, "Upgrade the packages.") || !strings.Contains(d, "/opt/bin/sudo -A apt-get upgrade -y") {
		t.Errorf("sudo description:\n%s", d)
	}
	b, _ := json.Marshal(psql.InputSchema)
	var schema struct {
		Type       string `json:"type"`
		Properties map[string]struct {
			Type, Pattern, Description string
		} `json:"properties"`
		Required             []string `json:"required"`
		AdditionalProperties *bool    `json:"additionalProperties"`
	}
	if err := json.Unmarshal(b, &schema); err != nil {
		t.Fatal(err)
	}
	if schema.Type != "object" || schema.AdditionalProperties == nil || *schema.AdditionalProperties {
		t.Fatalf("schema %s", b)
	}
	if p := schema.Properties["host"]; p.Type != "string" || p.Pattern != "^(?:[a-z0-9-]+)$" {
		t.Fatalf("host %+v", p)
	}
	if p := schema.Properties[SecretArg]; p.Type != "string" || !strings.Contains(p.Description, `{"$secret": "sec_…"}`) {
		t.Fatalf("secret %+v", p)
	}
	if strings.Join(schema.Required, ",") != "host,port,secret" {
		t.Fatalf("required %v", schema.Required)
	}
	if a := psql.Annotations; a == nil || a.ReadOnlyHint || a.DestructiveHint == nil || !*a.DestructiveHint {
		t.Fatalf("annotations %+v", a)
	}
}

func TestActionsServerCallsTheAction(t *testing.T) {
	log := &startLog{}
	a := helperAction(t, "stdin", "leak")
	b := helperAction(t, "stdin", "report", "{host}")
	cs := connectActions(t, map[string]*Action{a.Name: a, b.Name: b}, log)
	ctx := context.Background()

	res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: a.Name, Arguments: map[string]any{SecretArg: testSecret}, Meta: reviewed(a)})
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := json.Marshal(res)
	if strings.Contains(string(wire), testSecret) {
		t.Fatalf("the result leaks the secret: %s", wire)
	}
	if !res.IsError {
		t.Fatalf("a non-zero exit must be an error result: %s", wire)
	}
	var sc ActionResult
	sb, _ := json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(sb, &sc); err != nil || sc.ExitCode != 3 || !strings.Contains(sc.Stdout, "the secret is [secret]") {
		t.Fatalf("structured %s (%v)", sb, err)
	}

	res, err = cs.CallTool(ctx, &sdk.CallToolParams{Name: b.Name, Arguments: map[string]any{"host": "db-1", SecretArg: testSecret}, Meta: reviewed(b)})
	if err != nil || res.IsError {
		t.Fatalf("%v %+v", err, res)
	}

	// Refused before anything runs: a bad param, an unknown argument, a
	// missing or unsubstituted secret.
	before := len(log.all())
	for _, args := range []map[string]any{
		{"host": "db;id", SecretArg: testSecret},
		{"host": "db-1", SecretArg: testSecret, "extra": "x"},
		{"host": "db-1"},
		{"host": "db-1", SecretArg: map[string]any{"$secret": "sec_abc"}},
		{"host": 7, SecretArg: testSecret},
	} {
		res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: b.Name, Arguments: args, Meta: reviewed(b)})
		if err != nil || !res.IsError {
			t.Fatalf("args %v: %v %+v", args, err, res)
		}
		wire, _ := json.Marshal(res)
		if strings.Contains(string(wire), testSecret) {
			t.Fatalf("the refusal leaks the secret: %s", wire)
		}
	}
	if n := len(log.all()); n != before {
		t.Fatalf("%d commands started by refused calls", n-before)
	}
}

// reviewed is the _meta the gateway sends with a call of a's approved,
// unchanged definition.
func reviewed(a *Action) sdk.Meta {
	return sdk.Meta{tooldigest.MetaKey: ActionDigest(a)}
}

func TestActionDigestIsTheListedToolsDigest(t *testing.T) {
	a := helperAction(t, "stdin", "report", "{host}")
	cs := connectActions(t, map[string]*Action{a.Name: a}, &startLog{})
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil || len(res.Tools) != 1 {
		t.Fatalf("%v %v", res, err)
	}
	tl := res.Tools[0]
	schema, err := json.Marshal(tl.InputSchema)
	if err != nil {
		t.Fatal(err)
	}
	if got := tooldigest.Digest(tl.Name, tl.Description, schema); got != ActionDigest(a) {
		t.Fatalf("listed tool digest %s, ActionDigest %s", got, ActionDigest(a))
	}
}

// The actions server runs only the definition the gateway approved: a
// call without the reviewed digest, or with another definition's, is
// refused before anything starts or the secret is looked at.
func TestActionsServerRunsOnlyTheReviewedDefinition(t *testing.T) {
	log := &startLog{}
	a := helperAction(t, "stdin", "report", "{host}")
	cs := connectActions(t, map[string]*Action{a.Name: a}, log)
	ctx := context.Background()
	args := map[string]any{"host": "db-1", SecretArg: testSecret}

	res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: a.Name, Arguments: args, Meta: reviewed(a)})
	if err != nil || res.IsError {
		t.Fatalf("reviewed call: %v %+v", err, res)
	}
	if n := len(log.all()); n != 1 {
		t.Fatalf("%d starts for the reviewed call", n)
	}

	edited := *a
	edited.Description = "now does something else"
	for name, meta := range map[string]sdk.Meta{
		"missing":     nil,
		"other keys":  {"progressToken": "x"},
		"not text":    {tooldigest.MetaKey: 7},
		"empty":       {tooldigest.MetaKey: ""},
		"other tool":  reviewed(&edited),
		"bogus value": {tooldigest.MetaKey: tooldigest.Prefix + strings.Repeat("0", 64)},
	} {
		res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: a.Name, Arguments: args, Meta: meta})
		if err != nil || !res.IsError {
			t.Fatalf("%s digest: %v %+v", name, err, res)
		}
		wire, _ := json.Marshal(res)
		want := "action " + a.Name + " changed since it was reviewed; approve the new version"
		if !strings.Contains(string(wire), want) {
			t.Errorf("%s digest: refusal %s, want %q", name, wire, want)
		}
		if strings.Contains(string(wire), testSecret) {
			t.Fatalf("%s digest: the refusal leaks the secret: %s", name, wire)
		}
	}
	// Refused even when the secret argument is missing or malformed: the
	// digest is checked first.
	res, err = cs.CallTool(ctx, &sdk.CallToolParams{Name: a.Name, Arguments: map[string]any{"host": "db-1"}})
	if err != nil || !res.IsError {
		t.Fatalf("no secret, no digest: %v %+v", err, res)
	}
	if wire, _ := json.Marshal(res); !strings.Contains(string(wire), "changed since it was reviewed") {
		t.Errorf("no secret, no digest: %s", wire)
	}
	if n := len(log.all()); n != 1 {
		t.Fatalf("%d commands started by refused calls", n-1)
	}
}
