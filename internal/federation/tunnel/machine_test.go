package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// Machine connections (Brain decision ldjix4y1): one WebSocket per
// enrolled machine carries every tunnel linked to it. The machines
// package authenticates the machine token and hands the request to
// Service.ServeMachine; these tests stand in for it with
// testMachineEndpoint ("Bearer <machine id>").

const machineOne = "aaaaaaaa-0000-4000-8000-000000000001"

func testMachineEndpoint(svc *Service) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := bearerToken(r)
		switch {
		case !ok:
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		case id == "revoked":
			http.Error(w, "revoked", http.StatusForbidden)
		default:
			svc.ServeMachine(w, r, id)
		}
	})
}

// textHandler answers every request with body.
func textHandler(body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = io.WriteString(w, body+" "+r.URL.RequestURI())
	})
}

type machineRun struct {
	agent *MachineAgent
	done  chan error
	mu    sync.Mutex
	ids   [][]string
	stats []Status
}

func (m *machineRun) tunnelsSeen() [][]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.ids)
}

func (g *gw) startMachine(t *testing.T, token string, targets map[string]http.Handler) *machineRun {
	t.Helper()
	run := &machineRun{done: make(chan error, 1)}
	a, err := NewMachineAgent(MachineAgentOptions{
		GatewayURL: g.srv.URL, HTTPClient: g.srv.Client(), Targets: targets,
		Token:      func(context.Context) (string, error) { return token, nil },
		Log:        slog.New(slog.DiscardHandler),
		MinBackoff: 10 * time.Millisecond, MaxBackoff: 50 * time.Millisecond,
		OnTunnels: func(ids []string) {
			run.mu.Lock()
			run.ids = append(run.ids, ids)
			run.mu.Unlock()
		},
		OnStatus: func(s Status) {
			run.mu.Lock()
			run.stats = append(run.stats, s)
			run.mu.Unlock()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	run.agent = a
	ctx, cancel := context.WithCancel(context.Background())
	go func() { run.done <- a.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-waitOr(run.done) })
	return run
}

func (g *gw) get(t *testing.T, id string) (int, string) {
	t.Helper()
	code, body, err := g.try(id)
	if err != nil {
		t.Fatalf("request through tunnel %s: %v", id, err)
	}
	return code, body
}

// try is get without failing the test (for eventually conditions).
func (g *gw) try(id string) (int, string, error) {
	resp, err := g.do(http.MethodPost, "tunnel://"+id+"/mcp", strings.NewReader("{}"))
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), nil
}

func waitDone(t *testing.T, run *machineRun) error {
	t.Helper()
	select {
	case err := <-run.done:
		run.done <- err
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("machine agent still running")
		return nil
	}
}

func TestMachineConnectionCarriesEveryTunnelOfTheMachine(t *testing.T) {
	g := newGW(t, Limits{})
	one, _ := g.newTunnel(t)
	two, _ := g.newTunnel(t)
	g.ms.setMachine(machineOne, true, one, two)
	run := g.startMachine(t, machineOne, map[string]http.Handler{one: textHandler("one"), two: textHandler("two")})
	eventually(t, "both tunnels online", func() bool { return g.svc.Online(one) && g.svc.Online(two) })

	for id, want := range map[string]string{one: "one /mcp", two: "two /mcp"} {
		if code, body := g.get(t, id); code != http.StatusOK || body != want {
			t.Fatalf("tunnel %s: %d %q, want %q", id, code, body, want)
		}
	}
	eventually(t, "tunnel list sent", func() bool { return len(run.tunnelsSeen()) > 0 })
	got := run.tunnelsSeen()[0]
	slices.Sort(got)
	want := []string{one, two}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("tunnels frame = %v, want %v", got, want)
	}
}

func TestMachineConnectionPicksUpNewTunnelsWithoutReconnecting(t *testing.T) {
	g := newGW(t, Limits{})
	one, _ := g.newTunnel(t)
	g.ms.setMachine(machineOne, true, one)
	three, _ := g.newTunnel(t)
	run := g.startMachine(t, machineOne, map[string]http.Handler{one: textHandler("one"), three: textHandler("three")})
	eventually(t, "online", func() bool { return g.svc.Online(one) })
	if g.svc.Online(three) {
		t.Fatal("a tunnel not linked to the machine is online")
	}
	g.ms.setMachine(machineOne, true, one, three)
	g.svc.SyncMachine(machineOne)
	eventually(t, "new tunnel online", func() bool { return g.svc.Online(three) })
	if code, body := g.get(t, three); code != http.StatusOK || body != "three /mcp" {
		t.Fatalf("new tunnel: %d %q", code, body)
	}
	eventually(t, "updated tunnel list", func() bool {
		seen := run.tunnelsSeen()
		return len(seen) > 0 && slices.Contains(seen[len(seen)-1], three)
	})
	if n := connects(run); n != 1 {
		t.Fatalf("the agent connected %d times, want 1", n)
	}
}

func connects(run *machineRun) int {
	run.mu.Lock()
	defer run.mu.Unlock()
	n := 0
	for _, s := range run.stats {
		if s.State == StateConnected {
			n++
		}
	}
	return n
}

func TestMachineSyncTickNoticesNewTunnelsAndRevocation(t *testing.T) {
	g := newGW(t, Limits{MachineSyncInterval: 20 * time.Millisecond})
	one, _ := g.newTunnel(t)
	two, _ := g.newTunnel(t)
	g.ms.setMachine(machineOne, true, one)
	run := g.startMachine(t, machineOne, map[string]http.Handler{one: textHandler("one"), two: textHandler("two")})
	eventually(t, "online", func() bool { return g.svc.Online(one) })
	g.ms.setMachine(machineOne, true, one, two) // e.g. added through another replica
	eventually(t, "picked up by the sync tick", func() bool { return g.svc.Online(two) })

	g.ms.setMachine(machineOne, false, one, two) // revoked through another replica
	if err := waitDone(t, run); !errors.Is(err, ErrRevoked) {
		t.Fatalf("agent ended with %v, want ErrRevoked", err)
	}
	if g.svc.Online(one) || g.svc.Online(two) {
		t.Fatal("tunnels of a revoked machine still online")
	}
}

func TestDropMachineClosesTheConnectionAsRevoked(t *testing.T) {
	g := newGW(t, Limits{})
	one, _ := g.newTunnel(t)
	g.ms.setMachine(machineOne, true, one)
	run := g.startMachine(t, machineOne, map[string]http.Handler{one: textHandler("one")})
	eventually(t, "online", func() bool { return g.svc.Online(one) })
	g.ms.setMachine(machineOne, false, one)
	g.svc.DropMachine(machineOne)
	if err := waitDone(t, run); !errors.Is(err, ErrRevoked) {
		t.Fatalf("agent ended with %v, want ErrRevoked", err)
	}
	if g.svc.Online(one) {
		t.Fatal("tunnel of a dropped machine still online")
	}
}

func TestMachineRefusedAtConnectStops(t *testing.T) {
	g := newGW(t, Limits{})
	run := g.startMachine(t, "revoked", nil)
	if err := waitDone(t, run); !errors.Is(err, ErrRevoked) {
		t.Fatalf("agent ended with %v, want ErrRevoked", err)
	}
}

func TestNewerMachineConnectionReplacesTheOlder(t *testing.T) {
	g := newGW(t, Limits{})
	one, _ := g.newTunnel(t)
	g.ms.setMachine(machineOne, true, one)
	first := g.startMachine(t, machineOne, map[string]http.Handler{one: textHandler("first")})
	eventually(t, "online", func() bool { return g.svc.Online(one) })
	g.startMachine(t, machineOne, map[string]http.Handler{one: textHandler("second")})
	if err := waitDone(t, first); !errors.Is(err, ErrReplaced) {
		t.Fatalf("first agent ended with %v, want ErrReplaced", err)
	}
	// The replacement serves before the old connection is closed: once the
	// first agent has been told it was replaced, the tunnel is never offline.
	if _, body := g.get(t, one); body != "second /mcp" {
		t.Fatalf("after the handover the tunnel answered %q, want the new connection", body)
	}
}

func TestRevokingOneTunnelOfAMachineKeepsTheOthers(t *testing.T) {
	g := newGW(t, Limits{})
	one, _ := g.newTunnel(t)
	two, _ := g.newTunnel(t)
	g.ms.setMachine(machineOne, true, one, two)
	run := g.startMachine(t, machineOne, map[string]http.Handler{one: textHandler("one"), two: textHandler("two")})
	eventually(t, "online", func() bool { return g.svc.Online(one) && g.svc.Online(two) })
	if err := g.svc.Revoke(context.Background(), ownerA, one); err != nil {
		t.Fatal(err)
	}
	if g.svc.Online(one) {
		t.Fatal("revoked tunnel still online")
	}
	if code, body := g.get(t, two); code != http.StatusOK || body != "two /mcp" {
		t.Fatalf("other tunnel after revoking one: %d %q", code, body)
	}
	select {
	case err := <-run.done:
		t.Fatalf("machine agent stopped: %v", err)
	default:
	}
}

func TestMachineAgentAnswersUnknownTunnel(t *testing.T) {
	g := newGW(t, Limits{})
	one, _ := g.newTunnel(t)
	g.ms.setMachine(machineOne, true, one)
	g.startMachine(t, machineOne, map[string]http.Handler{}) // no target configured for it
	eventually(t, "online", func() bool { return g.svc.Online(one) })
	if code, _ := g.get(t, one); code != http.StatusBadGateway {
		t.Fatalf("request to a tunnel without a local target: %d, want 502", code)
	}
}

func TestMachineAgentTargetsCanChange(t *testing.T) {
	g := newGW(t, Limits{})
	one, _ := g.newTunnel(t)
	g.ms.setMachine(machineOne, true, one)
	run := g.startMachine(t, machineOne, map[string]http.Handler{one: textHandler("old")})
	eventually(t, "online", func() bool { return g.svc.Online(one) })
	run.agent.SetTargets(map[string]http.Handler{one: textHandler("new")})
	if _, body := g.get(t, one); body != "new /mcp" {
		t.Fatalf("after SetTargets: %q", body)
	}
}

func TestLegacyFramesCarryNoMachineFields(t *testing.T) {
	b, err := json.Marshal(&frame{Type: frameRequest, ID: 1, Method: "POST", Path: "/"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "tid") || strings.Contains(string(b), "ids") {
		t.Fatalf("legacy request frame = %s", b)
	}
}

func TestRelayReachesEveryTunnelOfAMachineHeldElsewhere(t *testing.T) {
	a, b := newPair(t, Limits{})
	one, _ := a.newTunnel(t)
	two, _ := a.newTunnel(t)
	a.ms.setMachine(machineOne, true, one, two)
	a.startMachine(t, machineOne, map[string]http.Handler{one: textHandler("one"), two: textHandler("two")})
	eventually(t, "B sees both tunnels", func() bool { return b.svc.Online(one) && b.svc.Online(two) })
	for id, want := range map[string]string{one: "one /mcp", two: "two /mcp"} {
		if code, body := b.get(t, id); code != http.StatusOK || body != want {
			t.Fatalf("through B to %s: %d %q", id, code, body)
		}
	}
}

func TestNewMachineAgentValidates(t *testing.T) {
	tok := func(context.Context) (string, error) { return "x", nil }
	for name, o := range map[string]MachineAgentOptions{
		"no token":    {GatewayURL: "https://gw.example"},
		"bad gateway": {GatewayURL: "ftp://gw.example", Token: tok},
		"user info":   {GatewayURL: "https://u:p@gw.example", Token: tok},
	} {
		if _, err := NewMachineAgent(o); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestMachineNewerConnectionOnAnotherReplicaReplacesTheOlder(t *testing.T) {
	a, b := newPair(t, Limits{HeartbeatInterval: 30 * time.Millisecond})
	one, _ := a.newTunnel(t)
	two, _ := a.newTunnel(t)
	a.ms.setMachine(machineOne, true, one, two)
	first := a.startMachine(t, machineOne, map[string]http.Handler{one: textHandler("first"), two: textHandler("first")})
	eventually(t, "online on A", func() bool { return a.svc.MachineConnected(machineOne) && a.svc.Online(one) })
	b.startMachine(t, machineOne, map[string]http.Handler{one: textHandler("second"), two: textHandler("second")})
	if err := waitDone(t, first); !errors.Is(err, ErrReplaced) {
		t.Fatalf("connection on A ended with %v, want ErrReplaced", err)
	}
	// A dropped its connection before the agent saw 4001: it no longer
	// lists it, and forwards to B once B's holder rows are visible.
	if a.svc.MachineConnected(machineOne) {
		t.Fatal("A still lists the replaced machine connection")
	}
	eventually(t, "A forwards to B", func() bool {
		_, body, err := a.try(two)
		return err == nil && body == "second /mcp"
	})
}

func TestMachinesAreIndependent(t *testing.T) {
	const machineTwo = "aaaaaaaa-0000-4000-8000-000000000002"
	g := newGW(t, Limits{})
	one, _ := g.newTunnel(t)
	two, _ := g.newTunnel(t)
	g.ms.setMachine(machineOne, true, one)
	g.ms.setMachine(machineTwo, true, two)
	runOne := g.startMachine(t, machineOne, map[string]http.Handler{one: textHandler("one"), two: textHandler("stolen")})
	runTwo := g.startMachine(t, machineTwo, map[string]http.Handler{two: textHandler("two")})
	eventually(t, "online", func() bool { return g.svc.Online(one) && g.svc.Online(two) })
	if _, body := g.get(t, two); body != "two /mcp" {
		t.Fatalf("machine two's tunnel served by %q", body)
	}
	g.ms.setMachine(machineOne, false, one)
	g.svc.DropMachine(machineOne)
	if err := waitDone(t, runOne); !errors.Is(err, ErrRevoked) {
		t.Fatalf("machine one ended with %v", err)
	}
	if _, body := g.get(t, two); body != "two /mcp" {
		t.Fatalf("machine two after revoking one: %q", body)
	}
	select {
	case err := <-runTwo.done:
		t.Fatalf("machine two stopped: %v", err)
	default:
	}
}
