//go:build !windows

package machineclient

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStatus(t *testing.T) {
	h := newUpHarness(t, "servers:\n  a:\n    http: http://127.0.0.1:1/mcp\n  b:\n    stdio: srv\n")
	// "a" is registered with approved tools, "b" is not registered yet.
	h.g.servers["a"] = &fakeServer{name: "a", serverID: "srv-1", tunnelID: "tun-1", approved: 2}
	out := &logBuffer{}
	o := StatusOptions{ConfigPath: h.opts.ConfigPath, StateDir: h.dir, Version: "v1", Out: out, Log: h.opts.Log, Now: h.clk.Now}
	if err := Status(context.Background(), o); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	s := out.String()
	for _, want := range []string{
		h.opts.ConfigPath, "2 servers", h.g.machineID, `"m"`, h.g.URL(), "file", "Huy",
		"a", "2 approved tools", h.g.URL() + "/servers/srv-1",
		"b", "not registered",
		FormatFingerprint(Thumbprint(h.g.pub)),
	} {
		if !strings.Contains(s, want) {
			t.Errorf("status misses %q:\n%s", want, s)
		}
	}
	assertNoSecrets(t, "status", s, h.g.secrets())
}

func TestStatusProblems(t *testing.T) {
	h := newUpHarness(t, "servers:\n  a:\n    http: http://127.0.0.1:1/mcp\n    bogus: 1\n")
	out := &logBuffer{}
	o := StatusOptions{ConfigPath: h.opts.ConfigPath, StateDir: h.dir, Out: out}
	err := Status(context.Background(), o)
	if err == nil || !strings.Contains(out.String(), "bogus") {
		t.Fatalf("invalid config must fail status: %v\n%s", err, out.String())
	}
	// Still reports the machine.
	if !strings.Contains(out.String(), h.g.machineID) {
		t.Errorf("status:\n%s", out.String())
	}

	h = newUpHarness(t, "servers: {}\n")
	h.g.revoked = true
	out = &logBuffer{}
	o = StatusOptions{ConfigPath: h.opts.ConfigPath, StateDir: h.dir, Out: out, Now: h.clk.Now}
	if err := Status(context.Background(), o); err == nil || !strings.Contains(out.String(), "rejected") {
		t.Fatalf("revoked machine: %v\n%s", err, out.String())
	}

	out = &logBuffer{}
	o = StatusOptions{ConfigPath: filepath.Join(t.TempDir(), "none.yaml"), StateDir: t.TempDir(), Out: out}
	if err := Status(context.Background(), o); err == nil || !strings.Contains(out.String(), "not logged in") {
		t.Fatalf("not logged in: %v\n%s", err, out.String())
	}
}

func TestLogout(t *testing.T) {
	h := newUpHarness(t, "servers: {}\n")
	out := &logBuffer{}
	o := LogoutOptions{StateDir: h.dir, Version: "v1", Out: out, Now: h.clk.Now}
	if err := Logout(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if h.g.logouts != 1 {
		t.Fatal("the gateway was not told")
	}
	if _, err := LoadState(h.dir); !errors.Is(err, ErrNotLoggedIn) {
		t.Fatalf("state left: %v", err)
	}
	if _, err := os.Stat(filepath.Join(h.dir, "machine.key")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("key left behind")
	}
	if err := Logout(context.Background(), o); !errors.Is(err, ErrNotLoggedIn) {
		t.Fatalf("second logout: %v", err)
	}
}

func TestLogoutWhenTheGatewayCannotBeReached(t *testing.T) {
	h := newUpHarness(t, "servers: {}\n")
	h.g.srv.Close()
	out := &logBuffer{}
	if err := Logout(context.Background(), LogoutOptions{StateDir: h.dir, Out: out, Now: h.clk.Now}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Machines page") {
		t.Fatalf("the user must be told to revoke it in the portal:\n%s", out.String())
	}
	if _, err := LoadState(h.dir); !errors.Is(err, ErrNotLoggedIn) {
		t.Fatal("local state must still be removed")
	}
}
