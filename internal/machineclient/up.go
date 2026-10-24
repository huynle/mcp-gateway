package machineclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/huynle/mcp-gateway/internal/tunnelclient"
)

// ErrReplaced: a newer connection of the same machine replaced this one
// (another `mcp-gateway up` runs with this machine's key).
var ErrReplaced = errors.New("another `mcp-gateway up` of this machine connected and replaced this one")

// Target is what the machine connection serves for one tunnel.
type Target struct {
	// Kind is KindHTTP or KindStdio.
	Kind string
	// URL is the local HTTP MCP server (KindHTTP).
	URL string
	// Stdio is the stdio server's start specification (KindStdio); the
	// process is already running behind Handler.
	Stdio *StdioSpec
	// Handler serves the gateway's requests for this tunnel: the HTTP
	// forwarder or the stdio bridge. A Connector routes each request
	// (by tunnel id) to it.
	Handler http.Handler
}

// Connector is the machine's single multiplexed connection to the
// gateway (GET /machine/v1/connect). Run connects with a token from token,
// serves targets (keyed by tunnel id) and calls onConnected after each
// successful handshake. It returns when ctx ends or the connection ends;
// a revoked machine returns an error wrapping ErrRevoked, a replaced
// connection ErrReplaced. `up` handles reconnection, so an implementation
// may return on the first disconnect.
type Connector interface {
	Run(ctx context.Context, gateway string, token func(ctx context.Context) (string, error), targets map[string]Target, onConnected func()) error
}

// StdioProcess is a running stdio server (tunnelclient.StdioServer).
type StdioProcess interface {
	Handler() http.Handler
	Done() <-chan struct{}
	Stop()
}

// UpOptions configure Up.
type UpOptions struct {
	ConfigPath string
	StateDir   string
	Version    string
	// Out gets status lines for the user; Stderr the stdio servers' stderr.
	Out, Stderr io.Writer
	// Log gets debug lines (never secrets); nil: none.
	Log       *slog.Logger
	Connector Connector
	// Reload triggers a config reload (SIGHUP).
	Reload <-chan struct{}
	// RegisterOnly registers the servers and returns without connecting.
	RegisterOnly bool
	// Environ is the CLI's environment for stdio servers (nil: os.Environ).
	Environ func() []string
	// Now and Sleep are the clock (nil: real time).
	Now   func() time.Time
	Sleep func(ctx context.Context, d time.Duration) error
	// MinBackoff and MaxBackoff bound reconnect and restart delays
	// (default 1 s and 1 min).
	MinBackoff, MaxBackoff time.Duration

	startStdio  func(ctx context.Context, spec *StdioSpec, stderr io.Writer, log *slog.Logger) (StdioProcess, error)
	newKeyStore func(name, dir string) (KeyStore, error)
	jitter      func(time.Duration) time.Duration
}

// Refresh retries while the gateway does not see the new connection yet.
const (
	refreshAttempts = 3
	refreshRetry    = 2 * time.Second
)

// Up serves the config's servers through one connection: it registers
// each server (PUT, idempotent), starts stdio servers with a clean
// environment, connects, refreshes the tool snapshot of servers that are
// new or have no approved tools and prints their review links, reconnects
// with backoff, reloads the config on Reload and stops the stdio servers
// gracefully when ctx ends (then it returns nil).
func Up(ctx context.Context, o UpOptions) error {
	o.defaults()
	st, err := LoadState(o.StateDir)
	if err != nil {
		return err
	}
	cfg, err := loadUpConfig(o.ConfigPath, st)
	if err != nil {
		return err
	}
	ks, err := o.newKeyStore(st.KeyStore, o.StateDir)
	if err != nil {
		return err
	}
	key, err := ks.Load(ctx, st.MachineID)
	if err != nil {
		return err
	}
	client := NewClient(st.Gateway, o.Version, o.Log)
	ts := &TokenSource{Client: client, MachineID: st.MachineID, Key: key, Now: o.Now}
	u := &upRunner{o: o, st: st, ts: ts, api: &MachineAPI{Client: client, Tokens: ts}, refreshed: map[string]bool{}}
	return u.loop(ctx, cfg)
}

func (o *UpOptions) defaults() {
	if o.Environ == nil {
		o.Environ = os.Environ
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Sleep == nil {
		o.Sleep = sleepCtx
	}
	if o.MinBackoff <= 0 {
		o.MinBackoff = time.Second
	}
	if o.MaxBackoff < o.MinBackoff {
		o.MaxBackoff = max(time.Minute, o.MinBackoff)
	}
	if o.Stderr == nil {
		o.Stderr = io.Discard
	}
	if o.startStdio == nil {
		o.startStdio = startStdioProcess
	}
	if o.newKeyStore == nil {
		o.newKeyStore = NewKeyStore
	}
	if o.jitter == nil {
		// ±20 % so machines do not reconnect in lockstep after an outage.
		o.jitter = func(d time.Duration) time.Duration {
			return time.Duration(float64(d) * (0.8 + 0.4*rand.Float64())) //nolint:gosec // jitter, not security
		}
	}
}

func startStdioProcess(ctx context.Context, spec *StdioSpec, stderr io.Writer, log *slog.Logger) (StdioProcess, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return tunnelclient.StartStdio(ctx, tunnelclient.StdioCommand{Argv: spec.Command, Env: spec.Env, Dir: spec.Dir}, stderr, log)
}

func loadUpConfig(path string, st *State) (*Config, error) {
	cfg, err := LoadConfig(path)
	if err != nil {
		return nil, err
	}
	if cfg.Gateway != "" && cfg.Gateway != st.Gateway {
		return nil, fmt.Errorf("%s names gateway %s but this machine is logged in to %s; fix the config or log in again", path, cfg.Gateway, st.Gateway)
	}
	if _, err := cfg.ActionsServerName(st.Name); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(cfg.Servers) == 0 && len(cfg.Actions) == 0 {
		return nil, fmt.Errorf("no servers in %s (add them under `servers`, or commands under `actions`)", path)
	}
	return cfg, nil
}

// servedServers are the config's servers plus, when it has actions, the
// in-process actions server "<machine>-actions" (kind http), sorted by
// name. The config was validated by loadUpConfig.
func servedServers(cfg *Config, machine string) []*Server {
	out := make([]*Server, 0, len(cfg.Servers)+1)
	for _, name := range cfg.ServerNames() {
		out = append(out, cfg.Servers[name])
	}
	if name, err := cfg.ActionsServerName(machine); err == nil && name != "" {
		out = append(out, &Server{Name: name, Kind: KindHTTP, actions: cfg.Actions})
		sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	}
	return out
}

type upRunner struct {
	o   UpOptions
	st  *State
	ts  *TokenSource
	api *MachineAPI

	refreshMu sync.Mutex
	refreshed map[string]bool // servers whose snapshot this process refreshed
}

// generation is one config's registered and running servers.
type generation struct {
	targets     map[string]Target
	names       []string        // served server names, sorted
	needsReview map[string]bool // by server name
	// always: servers refreshed once per generation whatever their
	// review state (the actions server, whose definition comes from this
	// config), and whether that refresh is done.
	always    map[string]bool
	refreshed map[string]bool
	stdio     []*stdioSupervisor
}

func (g *generation) stop() {
	var wg sync.WaitGroup
	for _, s := range g.stdio {
		wg.Go(s.stop)
	}
	wg.Wait()
}

func (u *upRunner) say(format string, args ...any) {
	say(u.o.Out, "mcp-gateway up: "+format+"\n", args...)
}

func (u *upRunner) loop(ctx context.Context, cfg *Config) error {
	for {
		gen, err := u.prepare(ctx, cfg)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if u.o.RegisterOnly {
			gen.stop()
			u.say("registered; run `mcp-gateway up` to connect (new servers are reviewed after the first connection)")
			return nil
		}
		next, err := u.serve(ctx, gen)
		gen.stop()
		if err != nil || next == nil {
			return err
		}
		cfg = next
	}
}

// isTerminal: errors that reconnecting cannot fix.
func isTerminal(err error) bool {
	return errors.Is(err, ErrRevoked) || errors.Is(err, ErrReplaced) || errors.Is(err, ErrMachineRejected)
}

// prepare registers the servers (retrying transient failures with
// backoff) and starts them.
func (u *upRunner) prepare(ctx context.Context, cfg *Config) (*generation, error) {
	backoff := u.o.MinBackoff
	for {
		gen, err := u.register(ctx, cfg)
		if err == nil {
			return gen, nil
		}
		if isTerminal(err) || ctx.Err() != nil {
			return nil, err
		}
		d := u.o.jitter(backoff)
		u.say("cannot register the servers (%v); retrying in %s", err, d.Round(time.Millisecond))
		if err := u.o.Sleep(ctx, d); err != nil {
			return nil, err
		}
		backoff = min(backoff*2, u.o.MaxBackoff)
	}
}

func (u *upRunner) register(ctx context.Context, cfg *Config) (*generation, error) {
	type reg struct {
		srv *Server
		res *PutResult
	}
	var regs []reg
	for _, srv := range servedServers(cfg, u.st.Name) {
		name := srv.Name
		res, err := u.api.PutServer(ctx, name, srv.Kind)
		var ae *APIError
		switch {
		case err == nil:
			regs = append(regs, reg{srv, res})
		case isTerminal(err) || ctx.Err() != nil:
			return nil, err
		case errors.As(err, &ae) && ae.Status >= 400 && ae.Status < 500:
			u.say("server %q: not registered: %v", name, err)
		default:
			return nil, err
		}
	}
	approved := map[string]int{}
	if self, err := u.api.Self(ctx); err == nil {
		for _, s := range self.Servers {
			approved[s.Name] = s.ApprovedTools
		}
	} else if isTerminal(err) {
		return nil, err
	}

	gen := &generation{targets: map[string]Target{}, needsReview: map[string]bool{}, always: map[string]bool{}, refreshed: map[string]bool{}}
	for _, r := range regs {
		name := r.srv.Name
		if u.o.RegisterOnly {
			state := "registered"
			if r.res.Created {
				state = "registered (new)"
			}
			u.say("server %q: %s; review at %s", name, state, r.res.ReviewURL)
			continue
		}
		t, err := u.target(ctx, r.srv)
		if err != nil {
			u.say("server %q: not served: %v", name, err)
			continue
		}
		if t.Stdio != nil {
			gen.stdio = append(gen.stdio, t.Handler.(*stdioSupervisor))
		}
		gen.targets[r.res.TunnelID] = t
		gen.names = append(gen.names, name)
		// New, or no approved tools yet (unknown counts as none).
		gen.needsReview[name] = r.res.Created || approved[name] == 0
		// The actions server is refreshed on every start and reload, so
		// that an action edited under the same name becomes a pending
		// review. A refresh never approves: calls keep being checked
		// against the approved snapshot (and refused by the digest check
		// of the actions server) until a human approves it.
		gen.always[name] = r.srv.actions != nil
	}
	if !u.o.RegisterOnly && len(gen.targets) == 0 {
		gen.stop()
		return nil, errors.New("none of the configured servers can be served")
	}
	return gen, nil
}

func (u *upRunner) target(ctx context.Context, s *Server) (Target, error) {
	if s.actions != nil {
		h := newActionsHandler(s.actions, ActionsOptions{Version: u.o.Version, Environ: u.o.Environ, Log: u.o.Log})
		return Target{Kind: KindHTTP, Handler: h}, nil
	}
	if s.Kind == KindHTTP {
		target, err := url.Parse(s.URL)
		if err != nil {
			return Target{}, err
		}
		return Target{Kind: KindHTTP, URL: s.URL, Handler: tunnelclient.NewHTTPForwarder(target)}, nil
	}
	spec, err := BuildStdioSpec(s, u.o.Environ())
	if err != nil {
		return Target{}, err
	}
	sup, err := u.startSupervisor(ctx, s.Name, spec)
	if err != nil {
		return Target{}, err
	}
	return Target{Kind: KindStdio, Stdio: spec, Handler: sup}, nil
}

// serve keeps the connection up until ctx ends (nil, nil), a terminal
// error, or a valid config reload (the new config).
func (u *upRunner) serve(ctx context.Context, gen *generation) (*Config, error) {
	backoff := u.o.MinBackoff
	var refreshes sync.WaitGroup
	defer refreshes.Wait()
	for {
		runCtx, cancel := context.WithCancel(ctx)
		var connected atomic.Bool
		var lastMu sync.Mutex
		var lastTok string
		token := func(c context.Context) (string, error) {
			tok, err := u.ts.Token(c)
			lastMu.Lock()
			lastTok = tok
			lastMu.Unlock()
			return tok, err
		}
		onConnected := func() {
			if !connected.Swap(true) {
				u.say("connected to %s; serving %s", hostOf(u.st.Gateway), strings.Join(gen.names, ", "))
			}
			refreshes.Go(func() { u.refreshNew(runCtx, gen) })
		}
		errc := make(chan error, 1)
		go func() { errc <- u.o.Connector.Run(runCtx, u.st.Gateway, token, gen.targets, onConnected) }()

		var runErr error
	wait:
		for {
			select {
			case runErr = <-errc:
				break wait
			case <-u.o.Reload:
				next, err := loadUpConfig(u.o.ConfigPath, u.st)
				if err != nil {
					u.say("config reload failed: %v; keeping the current servers", err)
					continue
				}
				u.say("reloading %s", u.o.ConfigPath)
				cancel()
				<-errc
				return next, nil
			case <-ctx.Done():
				cancel()
				<-errc
				return nil, nil
			}
		}
		cancel()
		switch {
		case ctx.Err() != nil:
			return nil, nil
		case isTerminal(runErr):
			return nil, runErr
		}
		if connected.Load() {
			backoff = u.o.MinBackoff
		} else {
			// The handshake may have failed on this token: get a new one.
			lastMu.Lock()
			u.ts.Invalidate(lastTok)
			lastMu.Unlock()
		}
		d := u.o.jitter(backoff)
		u.say("disconnected (%v); retrying in %s", runErr, d.Round(time.Millisecond))
		if err := u.o.Sleep(ctx, d); err != nil {
			return nil, nil
		}
		backoff = min(backoff*2, u.o.MaxBackoff)
	}
}

// refreshNew snapshots the tools of servers that need a review (once per
// process), and of the actions server once per generation, and prints
// their review links.
func (u *upRunner) refreshNew(ctx context.Context, gen *generation) {
	u.refreshMu.Lock()
	defer u.refreshMu.Unlock()
	for _, name := range gen.names {
		switch {
		case gen.always[name]:
			if gen.refreshed[name] {
				continue
			}
		case !gen.needsReview[name] || u.refreshed[name]:
			continue
		}
		res, err := u.refreshOne(ctx, name)
		if err != nil {
			if ctx.Err() == nil {
				u.say("server %q: tool refresh failed: %v (retried on the next connection, or use Refresh in the portal)", name, err)
			}
			continue
		}
		u.refreshed[name], gen.refreshed[name] = true, true
		if res.Added+res.Changed+res.Removed == 0 {
			if !gen.needsReview[name] {
				continue // the routine check of a reviewed actions server
			}
			u.say("server %q: no tool changes; review at %s", name, res.ReviewURL)
			continue
		}
		u.say("server %q: %d tools found (%d new, %d changed, %d removed); review and approve them at %s",
			name, res.Added+res.Changed, res.Added, res.Changed, res.Removed, res.ReviewURL)
	}
}

func (u *upRunner) refreshOne(ctx context.Context, name string) (*RefreshResult, error) {
	for attempt := 1; ; attempt++ {
		res, err := u.api.RefreshServer(ctx, name)
		var ae *APIError
		if err == nil || attempt == refreshAttempts || !errors.As(err, &ae) || ae.Code != "offline" {
			return res, err
		}
		if err := u.o.Sleep(ctx, refreshRetry); err != nil {
			return nil, err
		}
	}
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return u.Host
}

// stdioSupervisor serves a stdio server and restarts it with backoff when
// it exits on its own.
type stdioSupervisor struct {
	u      *upRunner
	name   string
	spec   *StdioSpec
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}

	mu  sync.Mutex
	cur StdioProcess
}

func (u *upRunner) startSupervisor(ctx context.Context, name string, spec *StdioSpec) (*stdioSupervisor, error) {
	// The process outlives ctx's cancellation until stop() has closed its
	// stdin: shutdown is graceful.
	procCtx := context.WithoutCancel(ctx)
	p, err := u.o.startStdio(procCtx, spec, u.o.Stderr, u.o.Log)
	if err != nil {
		return nil, fmt.Errorf("start %s: %w", filepath.Base(spec.Command[0]), err)
	}
	sctx, cancel := context.WithCancel(procCtx)
	s := &stdioSupervisor{u: u, name: name, spec: spec, ctx: sctx, cancel: cancel, done: make(chan struct{}), cur: p}
	go s.watch(p)
	return s, nil
}

func (s *stdioSupervisor) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	p := s.cur
	s.mu.Unlock()
	if p == nil {
		http.Error(w, "stdio server restarting", http.StatusServiceUnavailable)
		return
	}
	p.Handler().ServeHTTP(w, r)
}

func (s *stdioSupervisor) watch(p StdioProcess) {
	defer close(s.done)
	o := s.u.o
	backoff := o.MinBackoff
	started := o.Now()
	for {
		select {
		case <-p.Done():
		case <-s.ctx.Done():
			return
		}
		if s.ctx.Err() != nil {
			return
		}
		s.mu.Lock()
		s.cur = nil
		s.mu.Unlock()
		if o.Now().Sub(started) > time.Minute {
			backoff = o.MinBackoff
		}
		for {
			s.u.say("stdio server %q exited; restarting in %s", s.name, backoff)
			if o.Sleep(s.ctx, backoff) != nil {
				return
			}
			backoff = min(backoff*2, o.MaxBackoff)
			np, err := o.startStdio(context.WithoutCancel(s.ctx), s.spec, o.Stderr, o.Log)
			if err != nil {
				s.u.say("stdio server %q: restart failed: %v", s.name, err)
				continue
			}
			if s.ctx.Err() != nil {
				np.Stop()
				return
			}
			s.mu.Lock()
			s.cur = np
			s.mu.Unlock()
			p, started = np, o.Now()
			break
		}
	}
}

// stop stops the watcher, then the process (gracefully).
func (s *stdioSupervisor) stop() {
	s.cancel()
	<-s.done
	s.mu.Lock()
	p := s.cur
	s.cur = nil
	s.mu.Unlock()
	if p != nil {
		p.Stop()
	}
}
