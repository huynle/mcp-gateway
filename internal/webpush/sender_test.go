package webpush

import (
	"context"
	"crypto/ecdh"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/netguard"
)

const secretPath = "/push/secret-capability-token"

type captured struct {
	method string
	header http.Header
	body   []byte
}

type pushServer struct {
	srv    *httptest.Server
	mu     sync.Mutex
	reqs   []captured
	status int
	header map[string]string
}

func newPushServer(t *testing.T, status int, header map[string]string) *pushServer {
	t.Helper()
	ps := &pushServer{status: status, header: header}
	ps.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		ps.mu.Lock()
		ps.reqs = append(ps.reqs, captured{method: r.Method, header: r.Header.Clone(), body: body})
		ps.mu.Unlock()
		for k, v := range ps.header {
			w.Header().Set(k, v)
		}
		w.WriteHeader(ps.status)
		_, _ = io.WriteString(w, strings.Repeat("response body ", 1000))
	}))
	t.Cleanup(ps.srv.Close)
	return ps
}

// newTestSender builds a Sender whose endpoint check also admits the local
// TLS test server (127.0.0.1 is never on the production allow-list).
func newTestSender(t *testing.T, ps *pushServer) (*Sender, *Keys) {
	t.Helper()
	k, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Options{
		Keys:    k,
		Subject: "mailto:ops@example.com",
		Client:  ps.srv.Client(),
		Now:     func() time.Time { return time.Unix(1_700_000_000, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	s.checkEndpoint = func(raw string) error {
		if strings.HasPrefix(raw, ps.srv.URL+"/") {
			return nil
		}
		return ValidateEndpoint(raw)
	}
	return s, k
}

func testSub(t *testing.T, endpoint string) (Subscription, *ecdh.PrivateKey) {
	t.Helper()
	ua, auth := newUAKeys(t)
	return Subscription{Endpoint: endpoint, P256dh: ua.PublicKey().Bytes(), Auth: auth}, ua
}

func TestSendSuccess(t *testing.T) {
	ps := newPushServer(t, http.StatusCreated, nil)
	s, k := newTestSender(t, ps)
	sub, ua := testSub(t, ps.srv.URL+secretPath)
	payload := []byte(`{"title":"Approval requested","id":"abc"}`)
	if err := s.Send(context.Background(), sub, payload, SendOptions{TTL: 30 * time.Minute, Urgency: "normal", Topic: "approval-abc_1"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(ps.reqs) != 1 {
		t.Fatalf("server got %d requests", len(ps.reqs))
	}
	r := ps.reqs[0]
	if r.method != http.MethodPost {
		t.Errorf("method = %s", r.method)
	}
	for h, want := range map[string]string{
		"Content-Encoding": "aes128gcm",
		"Content-Type":     "application/octet-stream",
		"Ttl":              "1800",
		"Urgency":          "normal",
		"Topic":            "approval-abc_1",
	} {
		if got := r.header.Get(h); got != want {
			t.Errorf("%s = %q, want %q", h, got, want)
		}
	}
	auth := r.header.Get("Authorization")
	if !strings.HasPrefix(auth, "vapid t=") || !strings.HasSuffix(auth, ", k="+k.PublicKey()) {
		t.Errorf("Authorization = %q", auth)
	}
	got, err := decryptForTest(ua, sub.Auth, r.body)
	if err != nil {
		t.Fatalf("decrypt body: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("decrypted %q", got)
	}
}

func TestSendDefaults(t *testing.T) {
	ps := newPushServer(t, http.StatusAccepted, nil)
	s, _ := newTestSender(t, ps)
	sub, _ := testSub(t, ps.srv.URL+secretPath)
	if err := s.Send(context.Background(), sub, []byte("hi"), SendOptions{}); err != nil {
		t.Fatal(err)
	}
	r := ps.reqs[0]
	if r.header.Get("Ttl") != "3600" || r.header.Get("Urgency") != "high" {
		t.Errorf("TTL=%q Urgency=%q", r.header.Get("Ttl"), r.header.Get("Urgency"))
	}
	if _, ok := r.header["Topic"]; ok {
		t.Error("Topic sent without being set")
	}
}

func TestSendCapsTTL(t *testing.T) {
	ps := newPushServer(t, http.StatusCreated, nil)
	s, _ := newTestSender(t, ps)
	sub, _ := testSub(t, ps.srv.URL+secretPath)
	if err := s.Send(context.Background(), sub, []byte("hi"), SendOptions{TTL: 72 * time.Hour}); err != nil {
		t.Fatal(err)
	}
	if got := ps.reqs[0].header.Get("Ttl"); got != "86400" {
		t.Errorf("TTL = %q, want 86400", got)
	}
}

func TestSendStatusMapping(t *testing.T) {
	tests := []struct {
		status int
		header map[string]string
		want   error
	}{
		{http.StatusOK, nil, nil},
		{http.StatusCreated, nil, nil},
		{http.StatusAccepted, nil, nil},
		{http.StatusNotFound, nil, ErrGone},
		{http.StatusGone, nil, ErrGone},
		{http.StatusRequestEntityTooLarge, nil, ErrPayloadTooLarge},
		{http.StatusTooManyRequests, map[string]string{"Retry-After": "120"}, ErrRateLimited},
		{http.StatusInternalServerError, nil, nil},
		{http.StatusTemporaryRedirect, map[string]string{"Location": "https://example.com/elsewhere"}, nil},
	}
	for _, tc := range tests {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			ps := newPushServer(t, tc.status, tc.header)
			s, _ := newTestSender(t, ps)
			sub, _ := testSub(t, ps.srv.URL+secretPath)
			err := s.Send(context.Background(), sub, []byte("hi"), SendOptions{})
			if tc.status < 300 {
				if err != nil {
					t.Fatalf("err = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatal("err = nil")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			var se *StatusError
			if !errors.As(err, &se) || se.StatusCode != tc.status {
				t.Fatalf("err = %#v, want *StatusError with %d", err, tc.status)
			}
			if strings.Contains(err.Error(), "secret-capability-token") {
				t.Fatalf("error leaks the endpoint path: %v", err)
			}
			if !strings.Contains(err.Error(), "127.0.0.1") {
				t.Errorf("error %q does not name the host", err)
			}
			if tc.status == http.StatusTooManyRequests && se.RetryAfter != 120*time.Second {
				t.Errorf("RetryAfter = %v", se.RetryAfter)
			}
			if len(ps.reqs) != 1 {
				t.Errorf("server got %d requests (redirect followed?)", len(ps.reqs))
			}
		})
	}
}

func TestSendRetryAfterHTTPDate(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	ps := newPushServer(t, http.StatusTooManyRequests, map[string]string{
		"Retry-After": now.Add(90 * time.Second).UTC().Format(http.TimeFormat),
	})
	s, _ := newTestSender(t, ps)
	sub, _ := testSub(t, ps.srv.URL+secretPath)
	err := s.Send(context.Background(), sub, []byte("hi"), SendOptions{})
	var se *StatusError
	if !errors.As(err, &se) || se.RetryAfter != 90*time.Second {
		t.Fatalf("err = %v, RetryAfter = %v", err, se)
	}
}

func TestSendRejectsDisallowedEndpointWithoutRequest(t *testing.T) {
	ps := newPushServer(t, http.StatusCreated, nil)
	k, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Options{Keys: k, Subject: "https://gateway.example.com", Client: ps.srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	sub, _ := testSub(t, ps.srv.URL+secretPath) // production check: 127.0.0.1 refused
	err = s.Send(context.Background(), sub, []byte("hi"), SendOptions{})
	if !errors.Is(err, ErrEndpointNotAllowed) {
		t.Fatalf("err = %v, want ErrEndpointNotAllowed", err)
	}
	if strings.Contains(err.Error(), "secret-capability-token") {
		t.Fatalf("error leaks the endpoint path: %v", err)
	}
	if len(ps.reqs) != 0 {
		t.Fatal("request sent to a disallowed endpoint")
	}
}

func TestSendOptionValidation(t *testing.T) {
	ps := newPushServer(t, http.StatusCreated, nil)
	s, _ := newTestSender(t, ps)
	sub, _ := testSub(t, ps.srv.URL+secretPath)
	bad := map[string]SendOptions{
		"urgency":        {Urgency: "urgent"},
		"topic too long": {Topic: strings.Repeat("a", 33)},
		"topic chars":    {Topic: "a b"},
		"topic plus":     {Topic: "a+b"},
		"negative ttl":   {TTL: -time.Second},
	}
	for name, o := range bad {
		if err := s.Send(context.Background(), sub, []byte("hi"), o); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for _, u := range []string{"very-low", "low", "normal", "high"} {
		if err := s.Send(context.Background(), sub, []byte("hi"), SendOptions{Urgency: u, Topic: strings.Repeat("A", 32)}); err != nil {
			t.Errorf("urgency %s: %v", u, err)
		}
	}
	if err := s.Send(context.Background(), sub, make([]byte, MaxPayloadSize+1), SendOptions{}); !errors.Is(err, ErrPayloadTooLarge) {
		t.Errorf("oversized payload: %v", err)
	}
	if len(ps.reqs) != 4 {
		t.Errorf("server got %d requests, want 4", len(ps.reqs))
	}
}

func TestSendContextCancellation(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer srv.Close()
	defer close(release)
	ps := &pushServer{srv: srv}
	s, _ := newTestSender(t, ps)
	sub, _ := testSub(t, srv.URL+secretPath)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	err := s.Send(ctx, sub, []byte("hi"), SendOptions{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if strings.Contains(err.Error(), "secret-capability-token") {
		t.Fatalf("error leaks the endpoint path: %v", err)
	}

	pre, cancelPre := context.WithCancel(context.Background())
	cancelPre()
	if err := s.Send(pre, sub, []byte("hi"), SendOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancelled: err = %v", err)
	}
}

func TestNewValidation(t *testing.T) {
	k, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	for _, subj := range []string{"", "http://example.com", "ops@example.com", "https://", "mailto:", "https://user@example.com"} {
		if _, err := New(Options{Keys: k, Subject: subj}); err == nil {
			t.Errorf("subject %q accepted", subj)
		}
	}
	if _, err := New(Options{Subject: "mailto:ops@example.com"}); err == nil {
		t.Error("nil Keys accepted")
	}
	s, err := New(Options{Keys: k, Subject: "https://gateway.example.com/contact"})
	if err != nil {
		t.Fatal(err)
	}
	if s.client == nil || s.client.Timeout != DefaultTimeout || DefaultTimeout != 10*time.Second {
		t.Fatalf("default client = %+v", s.client)
	}
	if s.client.Transport == nil {
		t.Fatal("default client must use the netguard transport")
	}
}

func TestNewDoesNotMutateCallerClient(t *testing.T) {
	k, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	c := &http.Client{}
	if _, err := New(Options{Keys: k, Subject: "mailto:a@b.c", Client: c}); err != nil {
		t.Fatal(err)
	}
	if c.CheckRedirect != nil {
		t.Fatal("New modified the caller's client")
	}
}

// TestDefaultClientRefusesInternalAddress checks the second SSRF layer:
// even with the endpoint allow-list bypassed, the default netguard client
// refuses to reach a loopback address.
func TestDefaultClientRefusesInternalAddress(t *testing.T) {
	ps := newPushServer(t, http.StatusCreated, nil)
	k, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Options{Keys: k, Subject: "mailto:ops@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	s.checkEndpoint = func(string) error { return nil }
	sub, _ := testSub(t, ps.srv.URL+secretPath)
	err = s.Send(context.Background(), sub, []byte("hi"), SendOptions{})
	var be *netguard.BlockedError
	if !errors.As(err, &be) {
		t.Fatalf("err = %v, want *netguard.BlockedError", err)
	}
	if strings.Contains(err.Error(), "secret-capability-token") {
		t.Fatalf("error leaks the endpoint path: %v", err)
	}
	if len(ps.reqs) != 0 {
		t.Fatal("guarded client reached the loopback server")
	}
}
