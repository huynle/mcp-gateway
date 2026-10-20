//go:build !windows

package machineclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"
)

type loginHarness struct {
	g      *fakeGateway
	clk    *fakeClock
	sleeps []time.Duration
	opened []string
	out    bytes.Buffer
	logs   *logBuffer
	opts   LoginOptions
}

func newLoginHarness(t *testing.T) *loginHarness {
	t.Helper()
	h := &loginHarness{g: newFakeGateway(t), clk: newFakeClock()}
	h.g.now = h.clk.Now
	log, logs := captureLogger()
	h.logs = logs
	h.opts = LoginOptions{
		Gateway: h.g.URL(), Name: "huy-mac", KeyStore: KeyStoreFile, StateDir: t.TempDir(), Version: "v9",
		Out: &h.out, Log: log, Now: h.clk.Now,
		Sleep: func(ctx context.Context, d time.Duration) error {
			h.sleeps = append(h.sleeps, d)
			h.clk.Advance(d)
			return ctx.Err()
		},
	}
	return h
}

func (h *loginHarness) checkNoSecrets(t *testing.T, err error) {
	t.Helper()
	secrets := h.g.secrets()
	assertNoSecrets(t, "output", h.out.String(), secrets)
	assertNoSecrets(t, "log", h.logs.String(), secrets)
	assertNoSecrets(t, "error", err2s(err), secrets)
}

func TestLoginDeviceFlow(t *testing.T) {
	h := newLoginHarness(t)
	h.g.pollScript = []string{"authorization_pending", "slow_down", "authorization_pending"}
	h.opts.OpenBrowser = func(u string) error { h.opened = append(h.opened, u); return nil }
	st, err := Login(context.Background(), h.opts)
	if err != nil {
		t.Fatal(err)
	}
	if st.MachineID != h.g.machineID || st.Name != "huy-mac" || st.Gateway != h.g.URL() || st.KeyStore != KeyStoreFile {
		t.Fatalf("state %+v", st)
	}
	// RFC 8628 3.5: wait the interval before each poll; slow_down adds 5 s for good.
	want := []time.Duration{5 * time.Second, 5 * time.Second, 10 * time.Second, 10 * time.Second}
	if len(h.sleeps) != len(want) {
		t.Fatalf("sleeps %v, want %v", h.sleeps, want)
	}
	for i := range want {
		if h.sleeps[i] != want[i] {
			t.Fatalf("sleeps %v, want %v", h.sleeps, want)
		}
	}
	out := h.out.String()
	for _, s := range []string{"BCDF-GHJK", h.g.URL() + "/activate", "huy-mac", FormatFingerprint(Thumbprint(h.g.pub))} {
		if !strings.Contains(out, s) {
			t.Errorf("output misses %q:\n%s", s, out)
		}
	}
	if len(h.opened) != 1 || h.opened[0] != h.g.URL()+"/activate?code=BCDF-GHJK" {
		t.Errorf("browser opened %v", h.opened)
	}
	saved, err := LoadState(h.opts.StateDir)
	if err != nil || *saved != *st {
		t.Fatalf("saved %+v %v", saved, err)
	}
	ks, _ := NewKeyStore(KeyStoreFile, h.opts.StateDir)
	k, err := ks.Load(context.Background(), st.MachineID)
	if err != nil {
		t.Fatal(err)
	}
	if Thumbprint(k.Public().(ed25519.PublicKey)) != Thumbprint(h.g.pub) {
		t.Fatal("stored key is not the enrolled key")
	}
	h.checkNoSecrets(t, nil)
	// A second login refuses to replace the enrolled machine.
	if _, err := Login(context.Background(), h.opts); err == nil || !strings.Contains(err.Error(), "already logged in") {
		t.Fatalf("second login: %v", err)
	}
}

func TestLoginDeviceFlowFailures(t *testing.T) {
	for _, tc := range []struct {
		code string
		want error
	}{
		{"access_denied", ErrLoginDenied},
		{"expired_token", ErrLoginExpired},
	} {
		t.Run(tc.code, func(t *testing.T) {
			h := newLoginHarness(t)
			h.g.pollScript = []string{"authorization_pending", tc.code}
			_, err := Login(context.Background(), h.opts)
			if !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
			if _, err := LoadState(h.opts.StateDir); !errors.Is(err, ErrNotLoggedIn) {
				t.Fatalf("state written after failure: %v", err)
			}
			h.checkNoSecrets(t, err)
		})
	}
}

func TestLoginDeviceFlowDeadline(t *testing.T) {
	h := newLoginHarness(t)
	for range 500 {
		h.g.pollScript = append(h.g.pollScript, "authorization_pending")
	}
	_, err := Login(context.Background(), h.opts)
	if !errors.Is(err, ErrLoginExpired) {
		t.Fatalf("want ErrLoginExpired, got %v", err)
	}
	if h.g.polls > 121 {
		t.Fatalf("polled %d times past the 600 s expiry", h.g.polls)
	}
}

func TestLoginDeviceFlowCancel(t *testing.T) {
	h := newLoginHarness(t)
	h.g.pollScript = []string{"authorization_pending", "authorization_pending", "authorization_pending"}
	ctx, cancel := context.WithCancel(context.Background())
	h.opts.Sleep = func(ctx context.Context, d time.Duration) error {
		cancel()
		return ctx.Err()
	}
	if _, err := Login(ctx, h.opts); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}

func TestLoginEnrollCode(t *testing.T) {
	h := newLoginHarness(t)
	h.opts.EnrollCode = "mge_wrong"
	_, err := Login(context.Background(), h.opts)
	if err == nil || !strings.Contains(err.Error(), "invalid_code") || strings.Contains(err.Error(), "mge_wrong") {
		t.Fatalf("err %v", err)
	}
	h.opts.EnrollCode = "mge_ENROLLSECRET"
	st, err := Login(context.Background(), h.opts)
	if err != nil {
		t.Fatal(err)
	}
	if st.MachineID != h.g.machineID || len(h.sleeps) != 0 || len(h.g.deviceReqs) != 0 {
		t.Fatalf("%+v sleeps %v", st, h.sleeps)
	}
	h.checkNoSecrets(t, err)
}

func TestLoginValidation(t *testing.T) {
	h := newLoginHarness(t)
	for name, mut := range map[string]func(o *LoginOptions){
		"no gateway":       func(o *LoginOptions) { o.Gateway = "" },
		"http gateway":     func(o *LoginOptions) { o.Gateway = "http://gateway.example.com" },
		"bad name":         func(o *LoginOptions) { o.Name = "Bad Name" },
		"bad enroll code":  func(o *LoginOptions) { o.EnrollCode = "abc" },
		"unknown keystore": func(o *LoginOptions) { o.KeyStore = "vault" },
	} {
		t.Run(name, func(t *testing.T) {
			o := h.opts
			mut(&o)
			if _, err := Login(context.Background(), o); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	if len(h.g.deviceReqs)+len(h.g.enrollReqs) != 0 {
		t.Fatal("validation errors must happen before any request")
	}
}

func TestLoginRefusesForeignGatewayHost(t *testing.T) {
	h := newLoginHarness(t)
	h.opts.EnrollCode = "mge_ENROLLSECRET"
	h.opts.Gateway = strings.Replace(h.g.URL(), "127.0.0.1", "localhost", 1)
	_, err := Login(context.Background(), h.opts)
	if err == nil || !strings.Contains(err.Error(), "--gateway") {
		t.Fatalf("a gateway answering with another host must be refused: %v", err)
	}
}
