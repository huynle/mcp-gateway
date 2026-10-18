//go:build integration || e2e || security

package security

// Cross-replica tunnel relay attacks (decision efq0ncag item 5): the relay
// lives only on its internal listener (never the public handler), and only
// a request signed with the shared secret, fresh, unreplayed and naming
// the current holder epoch reaches the tunnel.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/federation/tunnel"
	"github.com/huynle/mcp-gateway/internal/store"
)

const relaySecret = "security-suite-relay-secret-0123456789abcdef"

// signRelay builds a relay round trip as a peer replica would (the wire
// format in internal/federation/tunnel/relay.go), signed with secret.
func signRelay(t *testing.T, ctx context.Context, base, secret, id string, epoch int64, at time.Time, nonce string, body []byte) *http.Request {
	t.Helper()
	hb, _ := json.Marshal(map[string]any{"m": http.MethodPost, "p": "/", "h": map[string][]string{"Content-Type": {"text/plain"}}})
	head := base64.RawURLEncoding.EncodeToString(hb)
	sum := sha256.Sum256(body)
	m := hmac.New(sha256.New, []byte(secret))
	_, _ = fmt.Fprintf(m, "mcp-gateway-relay.v1\n%s\n%d\n%d\n%s\n%s\n%x", id, epoch, at.Unix(), nonce, head, sum)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+tunnel.RelayPath, strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Mgw-Relay-Tunnel", id)
	req.Header.Set("X-Mgw-Relay-Epoch", strconv.FormatInt(epoch, 10))
	req.Header.Set("X-Mgw-Relay-Time", strconv.FormatInt(at.Unix(), 10))
	req.Header.Set("X-Mgw-Relay-Nonce", nonce)
	req.Header.Set("X-Mgw-Relay-Request", head)
	req.Header.Set("X-Mgw-Relay-Signature", hex.EncodeToString(m.Sum(nil)))
	return req
}

func relayStatus(t *testing.T, req *http.Request) (int, string, string) {
	t.Helper()
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	return res.StatusCode, res.Header.Get("X-Mgw-Relay-Error"), string(b)
}

// TestSecurityFedTunnelRelay: the public handler never serves the relay
// path, even for a correctly signed request; the relay listener refuses
// missing, wrong-secret, tampered, stale, replayed and wrong-epoch
// requests, and serves only the exact signed one, once; the secret never
// reaches the log.
func TestSecurityFedTunnelRelay(t *testing.T) {
	w := newWorld(t, options{federation: true, tunnelRelay: true})
	ctx := t.Context()
	tun, raw, err := w.fed.Tunnels.CreateTunnel(ctx, w.alice.id, "alice-relay")
	if err != nil {
		t.Fatal(err)
	}
	w.forbid(raw, "tunnel token")
	agent, err := tunnel.NewAgent(tunnel.AgentOptions{
		GatewayURL: w.srv.URL, Token: raw, Log: slog.New(slog.DiscardHandler),
		Handler: http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			_, _ = rw.Write(append([]byte("local:"), b...))
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	actx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { _ = agent.Run(actx); close(done) }()
	defer func() { cancel(); <-done }()

	var epoch int64
	deadline := time.Now().Add(10 * time.Second)
	for epoch == 0 {
		_ = w.st.WithJobs(ctx, func(tx store.Tx) error {
			h, err := store.GetMCPTunnelHolder(ctx, tx, tun.ID)
			if err == nil {
				epoch = h.Epoch
			}
			return nil
		})
		if time.Now().After(deadline) {
			t.Fatal("no holder row for the connected tunnel")
		}
		time.Sleep(20 * time.Millisecond)
	}
	now := time.Now()

	// The public handler: a valid signature makes no difference.
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		req := signRelay(t, ctx, w.srv.URL, relaySecret, tun.ID, epoch, now, "public-"+method, []byte("x"))
		req.Method = method
		code, cls, body := relayStatus(t, req)
		if cls != "" || strings.Contains(body, "local:") || code == http.StatusOK {
			t.Errorf("public %s %s: %d %q %q, want it not to reach the relay", method, tunnel.RelayPath, code, cls, body)
		}
	}

	// The relay listener: everything but the exact signed request is refused.
	missing := signRelay(t, ctx, w.relay.URL, relaySecret, tun.ID, epoch, now, "missing", []byte("x"))
	missing.Header.Del("X-Mgw-Relay-Signature")
	tampered := signRelay(t, ctx, w.relay.URL, relaySecret, tun.ID, epoch, now, "tampered", []byte("x"))
	tampered.Header.Set("X-Mgw-Relay-Tunnel", "00000000-0000-4000-8000-000000000001")
	for name, req := range map[string]*http.Request{
		"missing signature": missing,
		"no headers": func() *http.Request {
			r, _ := http.NewRequestWithContext(ctx, http.MethodPost, w.relay.URL+tunnel.RelayPath, strings.NewReader("x"))
			return r
		}(),
		"wrong secret":    signRelay(t, ctx, w.relay.URL, "another-secret-that-is-long-enough-000000", tun.ID, epoch, now, "wrong", []byte("x")),
		"tampered tunnel": tampered,
		"stale":           signRelay(t, ctx, w.relay.URL, relaySecret, tun.ID, epoch, now.Add(-5*time.Minute), "stale", []byte("x")),
	} {
		if code, cls, body := relayStatus(t, req); code != http.StatusUnauthorized || cls != "unauthorized" || strings.Contains(body, "local:") {
			t.Errorf("%s: %d %q %q, want 401 unauthorized", name, code, cls, body)
		}
	}
	if code, cls, _ := relayStatus(t, signRelay(t, ctx, w.relay.URL, relaySecret, tun.ID, epoch+1000, now, "epoch", []byte("x"))); code != http.StatusConflict || cls != "not_holder" {
		t.Errorf("wrong epoch: %d %q, want 409 not_holder", code, cls)
	}
	if code, _, body := relayStatus(t, signRelay(t, ctx, w.relay.URL, relaySecret, tun.ID, epoch, now, "good", []byte("hello"))); code != http.StatusOK || body != "local:hello" {
		t.Fatalf("signed request: %d %q", code, body)
	}
	if code, cls, _ := relayStatus(t, signRelay(t, ctx, w.relay.URL, relaySecret, tun.ID, epoch, now, "good", []byte("hello"))); code != http.StatusUnauthorized || cls != "unauthorized" {
		t.Errorf("replay: %d %q, want 401", code, cls)
	}
}
