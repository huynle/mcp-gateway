package client

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// TestEndpointRefusesCredentialAndHopByHopHeaders: static endpoint headers
// are never credentials or transport headers, whatever their case, even if
// a header_config was written below the servers portal (defence in depth,
// Brain task 68ss4tpc).
func TestEndpointRefusesCredentialAndHopByHopHeaders(t *testing.T) {
	for _, name := range []string{
		"Authorization", "authorization", "AUTHORIZATION",
		"Proxy-Authorization", "proxy-authorization",
		"Cookie", "cookie", "Set-Cookie",
		"Host", "host",
		"X-Api-Key", "x-api-key", "X-API-KEY",
		"Connection", "Keep-Alive", "Proxy-Connection", "Proxy-Authenticate",
		"Te", "TE", "Trailer", "Transfer-Encoding", "transfer-encoding", "Upgrade",
		"Content-Length", "Content-Type", "Accept", "Mcp-Session-Id", "mcp-protocol-version",
	} {
		_, err := validate(Endpoint{URL: "https://example.com/mcp", Headers: map[string]string{name: "x"}})
		if !errors.Is(err, ErrInvalidEndpoint) {
			t.Errorf("static header %q: err = %v, want ErrInvalidEndpoint", name, err)
		}
	}
	// An ordinary routing header is fine.
	v, err := validate(Endpoint{URL: "https://example.com/mcp", Headers: map[string]string{"x-client": "gateway"}})
	if err != nil {
		t.Fatalf("X-Client: %v", err)
	}
	if got := v.headers.Get("X-Client"); got != "gateway" {
		t.Errorf("X-Client = %q", got)
	}
}

// TestInitializeDeclaresNoClientCapabilities: the gateway serves no roots,
// sampling or elicitation to upstreams, so the initialize request declares
// no client capability at all (the go-sdk default would declare roots).
func TestInitializeDeclaresNoClientCapabilities(t *testing.T) {
	var mu sync.Mutex
	var initBody string
	ts := streamableServer(t, fullServer(0, 0), func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			if strings.Contains(string(body), `"initialize"`) {
				mu.Lock()
				initBody = string(body)
				mu.Unlock()
			}
			r.Body = io.NopCloser(strings.NewReader(string(body)))
			h.ServeHTTP(w, r)
		})
	})
	c := newTestClient(t, nil)
	connect(t, c, Endpoint{URL: ts.URL + "/mcp"})

	mu.Lock()
	defer mu.Unlock()
	var init struct {
		Method string `json:"method"`
		Params struct {
			Capabilities map[string]json.RawMessage `json:"capabilities"`
		} `json:"params"`
	}
	if err := json.Unmarshal([]byte(initBody), &init); err != nil || init.Method != "initialize" {
		t.Fatalf("initialize body %q: %v", initBody, err)
	}
	if len(init.Params.Capabilities) != 0 {
		t.Errorf("client capabilities = %s, want none", initBody)
	}
	for _, c := range []string{"roots", "sampling", "elicitation"} {
		if _, ok := init.Params.Capabilities[c]; ok {
			t.Errorf("the client declares %s", c)
		}
	}
}
