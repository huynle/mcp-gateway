//go:build unix

package machineclient

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const upActionsConfig = `
servers:
  a:
    stdio: srv
actions:
  hello:
    run: sh -c 'exit 0'
    secret: stdin
    description: Says hello.
`

func listToolNames(t *testing.T, target Target) []string {
	t.Helper()
	srv := httptest.NewServer(target.Handler)
	defer srv.Close()
	cl := sdk.NewClient(&sdk.Implementation{Name: "test", Version: "v1"}, nil)
	cs, err := cl.Connect(context.Background(), &sdk.StreamableClientTransport{Endpoint: srv.URL, DisableStandaloneSSE: true, MaxRetries: -1}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cs.Close() }()
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tl := range res.Tools {
		names = append(names, tl.Name)
	}
	return names
}

func TestUpRegistersTheActionsServer(t *testing.T) {
	h := newUpHarness(t, upActionsConfig)
	ctx, cancel := context.WithCancel(context.Background())
	errc := h.start(ctx)
	r := h.waitActive()
	// Sorted registration: a → tun-1, m-actions → tun-2.
	if got := strings.Join(targetKinds(r.targets), ","); got != "tun-1=stdio,tun-2=http" {
		t.Fatalf("targets %v", got)
	}
	h.g.mu.Lock()
	s := h.g.servers["m-actions"]
	h.g.mu.Unlock()
	if s == nil || s.kind != KindHTTP {
		t.Fatalf("the actions server is not registered as an http server: %+v", s)
	}
	if names := listToolNames(t, r.targets["tun-2"]); strings.Join(names, ",") != "hello" {
		t.Fatalf("tools %v", names)
	}
	waitFor(t, "the actions server's review link", func() bool { return strings.Contains(h.out.String(), `server "m-actions": 3 tools`) })
	if !strings.Contains(h.out.String(), "serving a, m-actions") {
		t.Errorf("output:\n%s", h.out.String())
	}
	cancel()
	if err := waitErr(t, errc); err != nil {
		t.Fatal(err)
	}
}

// The actions server's snapshot is refreshed on every start and every
// reload, even when it has approved tools: an action edited under the
// same name then shows up as a pending review (and its calls are refused
// by the digest check until it is approved).
func TestUpRefreshesTheActionsServerOnEveryStart(t *testing.T) {
	h := newUpHarness(t, upActionsConfig)
	refreshes := func() []string {
		h.g.mu.Lock()
		defer h.g.mu.Unlock()
		return append([]string(nil), h.g.refreshes...)
	}
	countOf := func(name string) int {
		n := 0
		for _, r := range refreshes() {
			if r == name {
				n++
			}
		}
		return n
	}
	ctx, cancel := context.WithCancel(context.Background())
	errc := h.start(ctx)
	h.waitActive()
	waitFor(t, "first refreshes", func() bool { return countOf("a") == 1 && countOf("m-actions") == 1 })
	cancel()
	if err := waitErr(t, errc); err != nil {
		t.Fatal(err)
	}

	// Both have approved tools now: only the actions server is refreshed.
	h.g.mu.Lock()
	h.g.servers["a"].approved, h.g.servers["m-actions"].approved = 2, 1
	h.g.refreshes = nil
	h.g.mu.Unlock()
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	errc = h.start(ctx)
	h.waitActive()
	waitFor(t, "the actions server's refresh on start", func() bool { return countOf("m-actions") == 1 })

	// A reload (the action edited under the same name) refreshes it again.
	h.writeConfig(strings.Replace(upActionsConfig, "exit 0", "exit 1", 1))
	h.reload <- struct{}{}
	h.waitActive()
	waitFor(t, "the actions server's refresh on reload", func() bool { return countOf("m-actions") == 2 })
	cancel()
	if err := waitErr(t, errc); err != nil {
		t.Fatal(err)
	}
	if n := countOf("a"); n != 0 {
		t.Fatalf("server a (approved) refreshed %d times: %v", n, refreshes())
	}
}

func TestUpServesActionsWithoutServers(t *testing.T) {
	h := newUpHarness(t, "actions:\n  hello:\n    run: sh -c 'exit 0'\n    secret: fd\n")
	ctx, cancel := context.WithCancel(context.Background())
	errc := h.start(ctx)
	r := h.waitActive()
	if got := strings.Join(targetKinds(r.targets), ","); got != "tun-1=http" {
		t.Fatalf("targets %v", got)
	}
	cancel()
	if err := waitErr(t, errc); err != nil {
		t.Fatal(err)
	}
}

func TestUpRefusesAnActionsServerNameCollision(t *testing.T) {
	h := newUpHarness(t, "servers:\n  m-actions:\n    stdio: srv\nactions:\n  hello:\n    run: sh -c 'exit 0'\n    secret: stdin\n")
	if err := Up(context.Background(), h.opts); err == nil || !strings.Contains(err.Error(), "m-actions") {
		t.Fatalf("collision: %v", err)
	}
	if len(h.g.puts) != 0 {
		t.Fatalf("registered %v despite the collision", h.g.puts)
	}
}

func TestUpRegisterOnlyIncludesTheActionsServer(t *testing.T) {
	h := newUpHarness(t, upActionsConfig)
	h.opts.RegisterOnly = true
	if err := Up(context.Background(), h.opts); err != nil {
		t.Fatal(err)
	}
	if strings.Join(h.g.puts, ",") != "a,m-actions" {
		t.Fatalf("puts %v", h.g.puts)
	}
}

func TestStatusListsTheActionsServer(t *testing.T) {
	h := newUpHarness(t, upActionsConfig)
	out := &logBuffer{}
	o := StatusOptions{ConfigPath: h.opts.ConfigPath, StateDir: h.dir, Version: "v1", Out: out, Log: h.opts.Log, Now: h.clk.Now}
	if err := Status(context.Background(), o); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	s := out.String()
	for _, want := range []string{"1 servers (a)", "1 actions (hello)", "m-actions", "not registered"} {
		if !strings.Contains(s, want) {
			t.Errorf("status misses %q:\n%s", want, s)
		}
	}
	// A collision is a status problem.
	h.writeConfig("servers:\n  m-actions:\n    stdio: srv\nactions:\n  hello:\n    run: sh -c 'exit 0'\n    secret: stdin\n")
	out = &logBuffer{}
	o.Out = out
	if err := Status(context.Background(), o); err == nil || !strings.Contains(out.String(), "m-actions") {
		t.Fatalf("collision: %v\n%s", err, out.String())
	}
}
