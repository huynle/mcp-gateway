//go:build !windows

package machineclient

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// connStep scripts one Connector.Run call.
type connStep struct {
	connect bool  // call onConnected first
	err     error // then return this (nil: block until the context ends)
}

type connRun struct {
	gateway string
	targets map[string]Target
	token   string
}

// fakeConnector stands in for the multiplexed WebSocket agent.
type fakeConnector struct {
	mu     sync.Mutex
	script []connStep
	runs   []connRun
	active chan connRun
}

func newFakeConnector(script ...connStep) *fakeConnector {
	return &fakeConnector{script: script, active: make(chan connRun, 100)}
}

func (f *fakeConnector) Run(ctx context.Context, gateway string, token func(context.Context) (string, error), targets map[string]Target, onConnected func()) error {
	tok, err := token(ctx)
	if err != nil {
		return err
	}
	r := connRun{gateway: gateway, targets: targets, token: tok}
	f.mu.Lock()
	f.runs = append(f.runs, r)
	i := len(f.runs) - 1
	step := connStep{connect: true}
	if i < len(f.script) {
		step = f.script[i]
	}
	f.mu.Unlock()
	if step.connect {
		onConnected()
	}
	if step.err != nil {
		return step.err
	}
	f.active <- r
	<-ctx.Done()
	return ctx.Err()
}

func (f *fakeConnector) runCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.runs)
}

func (f *fakeConnector) run(i int) connRun {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.runs[i]
}

// fakeProc is a stdio server process.
type fakeProc struct {
	spec    *StdioSpec
	done    chan struct{}
	once    sync.Once
	mu      sync.Mutex
	stopped bool
}

func (p *fakeProc) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "stdio:"+p.spec.Command[0])
	})
}
func (p *fakeProc) Done() <-chan struct{} { return p.done }
func (p *fakeProc) Stop() {
	p.mu.Lock()
	p.stopped = true
	p.mu.Unlock()
	p.exit()
}
func (p *fakeProc) exit() { p.once.Do(func() { close(p.done) }) }
func (p *fakeProc) isStopped() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.stopped
}

type fakeProcs struct {
	mu    sync.Mutex
	procs []*fakeProc
	fail  map[string]bool // command[0] that fails to start
}

func (f *fakeProcs) start(_ context.Context, spec *StdioSpec, _ io.Writer, _ *slog.Logger) (StdioProcess, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail[spec.Command[0]] {
		return nil, errors.New("exec: not found")
	}
	p := &fakeProc{spec: spec, done: make(chan struct{})}
	f.procs = append(f.procs, p)
	return p, nil
}

func (f *fakeProcs) all() []*fakeProc {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*fakeProc(nil), f.procs...)
}

type upHarness struct {
	t      *testing.T
	g      *fakeGateway
	clk    *fakeClock
	dir    string
	conn   *fakeConnector
	procs  *fakeProcs
	out    *logBuffer
	logs   *logBuffer
	reload chan struct{}
	mu     sync.Mutex
	sleeps []time.Duration
	opts   UpOptions
}

func newUpHarness(t *testing.T, config string, script ...connStep) *upHarness {
	t.Helper()
	h := &upHarness{t: t, g: newFakeGateway(t), clk: newFakeClock(), dir: t.TempDir(), conn: newFakeConnector(script...),
		procs: &fakeProcs{fail: map[string]bool{}}, out: &logBuffer{}, reload: make(chan struct{}, 1)}
	h.g.now = h.clk.Now
	h.g.machineName = "m"
	k := testKey(t)
	h.g.pub = k.Public().(ed25519.PublicKey)
	ks := &FileKeyStore{Path: filepath.Join(h.dir, "machine.key")}
	if err := ks.Save(context.Background(), h.g.machineID, k); err != nil {
		t.Fatal(err)
	}
	if err := SaveState(h.dir, &State{Gateway: h.g.URL(), MachineID: h.g.machineID, Name: "m", KeyStore: KeyStoreFile}); err != nil {
		t.Fatal(err)
	}
	h.writeConfig(config)
	log, logs := captureLogger()
	h.logs = logs
	h.opts = UpOptions{
		ConfigPath: filepath.Join(h.dir, "config.yaml"), StateDir: h.dir, Version: "v1",
		Out: h.out, Stderr: io.Discard, Log: log, Connector: h.conn, Reload: h.reload,
		Environ: func() []string { return []string{"PATH=/bin", "HOME=/home/u", "SECRET_THING=nope", "MY_TOKEN=tok"} },
		Now:     h.clk.Now,
		Sleep: func(ctx context.Context, d time.Duration) error {
			h.mu.Lock()
			h.sleeps = append(h.sleeps, d)
			h.mu.Unlock()
			return ctx.Err()
		},
		MinBackoff: time.Second, MaxBackoff: 8 * time.Second,
		startStdio: h.procs.start,
		jitter:     func(d time.Duration) time.Duration { return d },
	}
	return h
}

func (h *upHarness) writeConfig(c string) {
	h.t.Helper()
	if err := os.WriteFile(filepath.Join(h.dir, "config.yaml"), []byte(c), 0o600); err != nil {
		h.t.Fatal(err)
	}
}

func (h *upHarness) start(ctx context.Context) chan error {
	errc := make(chan error, 1)
	go func() { errc <- Up(ctx, h.opts) }()
	return errc
}

func (h *upHarness) sleepsCopy() []time.Duration {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]time.Duration(nil), h.sleeps...)
}

func (h *upHarness) waitActive() connRun {
	h.t.Helper()
	select {
	case r := <-h.conn.active:
		return r
	case <-time.After(5 * time.Second):
		h.t.Fatalf("no connection; output:\n%s", h.out.String())
		return connRun{}
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func waitErr(t *testing.T, errc chan error) error {
	t.Helper()
	select {
	case err := <-errc:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("Up did not return")
		return nil
	}
}

func (h *upHarness) checkNoSecrets() {
	h.t.Helper()
	secrets := append(h.g.secrets(), "SECRET_THING", "nope")
	assertNoSecrets(h.t, "output", h.out.String(), secrets)
	assertNoSecrets(h.t, "log", h.logs.String(), secrets)
}

func targetKinds(targets map[string]Target) []string {
	var out []string
	for tid, t := range targets {
		out = append(out, tid+"="+t.Kind)
	}
	sort.Strings(out)
	return out
}

func TestUpRegistersConnectsAndPrintsReviewLinks(t *testing.T) {
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "http:"+r.URL.Path)
	}))
	defer local.Close()
	h := newUpHarness(t, fmt.Sprintf(`
servers:
  fusion:
    http: %s/mcp
  everything:
    stdio: npx -y server-everything
    env: {API_KEY: "${MY_TOKEN}"}
`, local.URL))
	ctx, cancel := context.WithCancel(context.Background())
	errc := h.start(ctx)
	r := h.waitActive()

	if r.gateway != h.g.URL() || !strings.HasPrefix(r.token, "mgm_") {
		t.Fatalf("run %+v", r)
	}
	// Sorted registration: everything → tun-1, fusion → tun-2.
	if got := targetKinds(r.targets); strings.Join(got, ",") != "tun-1=stdio,tun-2=http" {
		t.Fatalf("targets %v", got)
	}
	if r.targets["tun-2"].URL != local.URL+"/mcp" {
		t.Fatalf("http target %+v", r.targets["tun-2"])
	}
	st := r.targets["tun-1"].Stdio
	if st == nil || strings.Join(st.Command, " ") != "npx -y server-everything" || !contains(st.Env, "API_KEY=tok") || strings.Contains(strings.Join(st.Env, ","), "SECRET_THING") {
		t.Fatalf("stdio target %+v", st)
	}
	// Handlers are wired: the http forwarder reaches the local server, the
	// stdio handler is the process bridge.
	for tid, want := range map[string]string{"tun-2": "http:/mcp", "tun-1": "stdio:npx"} {
		rec := httptest.NewRecorder()
		r.targets[tid].Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{}")))
		if rec.Body.String() != want {
			t.Errorf("%s handler answered %q, want %q", tid, rec.Body.String(), want)
		}
	}
	// After connecting, both new servers are refreshed and their review links printed.
	waitFor(t, "review links", func() bool { return strings.Count(h.out.String(), "/servers/srv-") >= 2 })
	out := h.out.String()
	for _, want := range []string{"everything", "fusion", h.g.URL() + "/servers/srv-1", h.g.URL() + "/servers/srv-2", "3 tools"} {
		if !strings.Contains(out, want) {
			t.Errorf("output misses %q:\n%s", want, out)
		}
	}
	cancel()
	if err := waitErr(t, errc); err != nil {
		t.Fatalf("graceful stop returned %v", err)
	}
	procs := h.procs.all()
	if len(procs) != 1 || !procs[0].isStopped() {
		t.Fatal("the stdio server was not stopped")
	}
	h.checkNoSecrets()

	// A second `up` is idempotent: same tunnels, nothing created, and only
	// servers without approved tools are refreshed again.
	h.g.mu.Lock()
	h.g.servers["fusion"].approved = 4
	h.g.refreshes = nil
	h.g.mu.Unlock()
	ctx2, cancel2 := context.WithCancel(context.Background())
	errc = h.start(ctx2)
	r2 := h.waitActive()
	if got := targetKinds(r2.targets); strings.Join(got, ",") != "tun-1=stdio,tun-2=http" {
		t.Fatalf("targets %v", got)
	}
	waitFor(t, "refresh", func() bool {
		h.g.mu.Lock()
		defer h.g.mu.Unlock()
		return len(h.g.refreshes) > 0
	})
	cancel2()
	_ = waitErr(t, errc)
	h.g.mu.Lock()
	defer h.g.mu.Unlock()
	if len(h.g.servers) != 2 || strings.Join(h.g.refreshes, ",") != "everything" {
		t.Fatalf("servers %d, refreshes %v", len(h.g.servers), h.g.refreshes)
	}
}

func TestUpRegisterOnly(t *testing.T) {
	h := newUpHarness(t, "servers:\n  a:\n    http: http://127.0.0.1:1/mcp\n  b:\n    stdio: srv\n")
	h.opts.RegisterOnly = true
	if err := Up(context.Background(), h.opts); err != nil {
		t.Fatal(err)
	}
	if h.conn.runCount() != 0 || len(h.procs.all()) != 0 {
		t.Fatal("--register-only must not connect or start servers")
	}
	if len(h.g.puts) != 2 {
		t.Fatalf("puts %v", h.g.puts)
	}
	out := h.out.String()
	if !strings.Contains(out, "a") || !strings.Contains(out, "registered") {
		t.Fatalf("output:\n%s", out)
	}
}

func TestUpReconnectsWithBackoff(t *testing.T) {
	transient := errors.New("dial: connection refused")
	h := newUpHarness(t, "servers:\n  a:\n    http: http://127.0.0.1:1/mcp\n",
		connStep{err: transient}, connStep{err: transient}, connStep{err: transient}, connStep{err: transient},
		connStep{err: transient},
		connStep{connect: true, err: transient}, connStep{err: transient})
	ctx, cancel := context.WithCancel(context.Background())
	errc := h.start(ctx)
	h.waitActive()
	cancel()
	if err := waitErr(t, errc); err != nil {
		t.Fatal(err)
	}
	got := h.sleepsCopy()
	want := []time.Duration{1, 2, 4, 8, 8, 1, 2} // seconds; capped at MaxBackoff, reset after a connection
	if len(got) != len(want) {
		t.Fatalf("sleeps %v", got)
	}
	for i := range want {
		if got[i] != want[i]*time.Second {
			t.Fatalf("sleeps %v, want %v s", got, want)
		}
	}
	if !strings.Contains(h.out.String(), "retrying in") {
		t.Errorf("output:\n%s", h.out.String())
	}
}

func TestUpFailedConnectGetsAFreshToken(t *testing.T) {
	h := newUpHarness(t, "servers:\n  a:\n    http: http://127.0.0.1:1/mcp\n", connStep{err: errors.New("handshake: 401")})
	ctx, cancel := context.WithCancel(context.Background())
	errc := h.start(ctx)
	h.waitActive()
	cancel()
	_ = waitErr(t, errc)
	if h.conn.run(0).token == h.conn.run(1).token {
		t.Fatal("a failed connection must not reuse its access token")
	}
}

func TestUpStopsOnTerminalErrors(t *testing.T) {
	for i, terminal := range []error{ErrRevoked, ErrReplaced, ErrMachineRejected} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			h := newUpHarness(t, "servers:\n  b:\n    stdio: srv\n", connStep{connect: true, err: fmt.Errorf("closed: %w", terminal)})
			err := Up(context.Background(), h.opts)
			if !errors.Is(err, terminal) {
				t.Fatalf("want %v, got %v", terminal, err)
			}
			if p := h.procs.all(); len(p) != 1 || !p[0].isStopped() {
				t.Fatal("stdio server not stopped")
			}
		})
	}
	h := newUpHarness(t, "servers:\n  a:\n    http: http://127.0.0.1:1/mcp\n")
	h.g.revoked = true
	if err := Up(context.Background(), h.opts); !errors.Is(err, ErrMachineRejected) && !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked machine: %v", err)
	}
}

func TestUpReloadsOnSignal(t *testing.T) {
	h := newUpHarness(t, "servers:\n  a:\n    stdio: one\n")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := h.start(ctx)
	r1 := h.waitActive()
	if len(r1.targets) != 1 {
		t.Fatalf("targets %v", r1.targets)
	}
	// An invalid config is reported and the running servers stay up.
	h.writeConfig("servers:\n  a:\n    stdio: one\n    bogus: 1\n")
	h.reload <- struct{}{}
	waitFor(t, "reload error", func() bool { return strings.Contains(h.out.String(), "bogus") })
	if h.conn.runCount() != 1 || h.procs.all()[0].isStopped() {
		t.Fatal("an invalid reload must keep the current connection")
	}
	h.writeConfig("servers:\n  a:\n    stdio: one\n  c:\n    stdio: two\n")
	h.reload <- struct{}{}
	r2 := h.waitActive()
	if len(r2.targets) != 2 {
		t.Fatalf("targets after reload %v", targetKinds(r2.targets))
	}
	procs := h.procs.all()
	if len(procs) != 3 || !procs[0].isStopped() || procs[1].isStopped() || procs[2].isStopped() {
		t.Fatalf("reload must restart the stdio servers: %d procs", len(procs))
	}
	waitFor(t, "refresh of the new server", func() bool {
		h.g.mu.Lock()
		defer h.g.mu.Unlock()
		return contains(h.g.refreshes, "c")
	})
	cancel()
	if err := waitErr(t, errc); err != nil {
		t.Fatal(err)
	}
	for _, p := range h.procs.all() {
		if !p.isStopped() {
			t.Fatal("stdio server left running")
		}
	}
}

func TestUpSkipsServersItCannotServe(t *testing.T) {
	h := newUpHarness(t, "servers:\n  taken:\n    http: http://127.0.0.1:1/mcp\n  broken:\n    stdio: nosuchbinary\n  good:\n    stdio: srv\n  zcapped:\n    stdio: srv2\n")
	h.g.nameTakenFor["taken"] = true
	h.g.capAfter = 2 // sorted: broken, good (2 servers), taken (409 name_taken), zcapped (409 cap_exceeded)
	h.procs.fail["nosuchbinary"] = true
	ctx, cancel := context.WithCancel(context.Background())
	errc := h.start(ctx)
	r := h.waitActive()
	cancel()
	_ = waitErr(t, errc)
	if len(r.targets) != 1 {
		t.Fatalf("targets %v", targetKinds(r.targets))
	}
	out := h.out.String()
	for _, want := range []string{`"taken"`, "name_taken", `"broken"`, "exec: not found", "limit of servers", `"zcapped"`} {
		if !strings.Contains(out, want) {
			t.Errorf("output misses %q:\n%s", want, out)
		}
	}
}

func TestUpRestartsAnExitedStdioServer(t *testing.T) {
	h := newUpHarness(t, "servers:\n  a:\n    stdio: srv\n")
	ctx, cancel := context.WithCancel(context.Background())
	errc := h.start(ctx)
	r := h.waitActive()
	h.procs.all()[0].exit()
	waitFor(t, "restart", func() bool { return len(h.procs.all()) == 2 })
	rec := httptest.NewRecorder()
	r.targets["tun-1"].Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", nil))
	if rec.Body.String() != "stdio:srv" {
		t.Fatalf("handler after restart: %d %q", rec.Code, rec.Body.String())
	}
	if !strings.Contains(h.out.String(), "exited") {
		t.Errorf("output:\n%s", h.out.String())
	}
	cancel()
	_ = waitErr(t, errc)
	if !h.procs.all()[1].isStopped() {
		t.Fatal("restarted server not stopped")
	}
}

func TestUpPreconditions(t *testing.T) {
	h := newUpHarness(t, "gateway: https://other.example.com\nservers:\n  a:\n    stdio: srv\n")
	if err := Up(context.Background(), h.opts); err == nil || !strings.Contains(err.Error(), "other.example.com") {
		t.Fatalf("gateway mismatch: %v", err)
	}
	h = newUpHarness(t, "servers: {}\n")
	if err := Up(context.Background(), h.opts); err == nil || !strings.Contains(err.Error(), "no servers") {
		t.Fatalf("no servers: %v", err)
	}
	h = newUpHarness(t, "servers:\n  a:\n    stdio: srv\n")
	h.opts.StateDir = t.TempDir()
	if err := Up(context.Background(), h.opts); !errors.Is(err, ErrNotLoggedIn) {
		t.Fatalf("not logged in: %v", err)
	}
	h = newUpHarness(t, "servers:\n  a:\n    stdio: srv\n")
	h.opts.ConfigPath = filepath.Join(t.TempDir(), "missing.yaml")
	if err := Up(context.Background(), h.opts); err == nil || !strings.Contains(err.Error(), "missing.yaml") {
		t.Fatalf("missing config: %v", err)
	}
}
