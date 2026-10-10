//go:build integration || e2e || security

package security

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/huynle/mcp-gateway/internal/tokens"
)

// vendorTells are fragments of a vendor's error body (beyond the token
// shapes in secretCorpus) that must never reach a client, a log, an
// audit row or a portal page: internal hostnames, stack frames, HTML.
var vendorTells = []string{"vendor.internal", "handler.go", "upstream internal-api", "502 Bad Gateway", "Handler.serve"}

// classRE is the shape of an audit / ledger error class: a short
// snake_case word, never vendor text.
var classRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// TestSecurityRedactionUnderLoad: 50 concurrent calls while the GitHub
// and Slack stubs answer with error bodies full of secrets (every shape
// in secretCorpus), internal hostnames and stack traces, as JSON
// messages, Slack ok:false codes and 5xx HTML pages. Nothing of it
// reaches the MCP error payloads (tool results with isError and JSON-RPC
// errors alike), the gateway log, the audit rows, the ledger rows or the
// portal pages (/operations, /activity, /admin/audit); clients get a
// class-level message; audit and ledger classes stay short identifiers.
func TestSecurityRedactionUnderLoad(t *testing.T) {
	w := newWorld(t, options{})
	for _, c := range secretCorpus {
		w.forbid(c.value, c.what)
	}
	for _, tell := range vendorTells {
		w.forbid(tell, "vendor body fragment")
	}
	soup := secretSoup() + " upstream internal-api-7f3a.vendor.internal:8443 at vendor.Handler.serve (handler.go:217)"
	jsonSoup, _ := json.Marshal(soup)

	// Every stub answer is hostile; the shape rotates per request.
	var n atomic.Int64
	w.github.setOverride(func(rw http.ResponseWriter, r *http.Request) bool {
		switch n.Add(1) % 3 {
		case 0: // 5xx JSON with a message
			rw.Header().Set("Content-Type", "application/json")
			rw.WriteHeader(http.StatusInternalServerError)
			_, _ = fmt.Fprintf(rw, `{"message":%s,"documentation_url":"https://vendor.internal/docs?token=%s"}`, jsonSoup, secretCorpus[0].value)
		case 1: // 5xx HTML page
			rw.Header().Set("Content-Type", "text/html")
			rw.WriteHeader(http.StatusBadGateway)
			_, _ = rw.Write([]byte(htmlBody))
		default: // 4xx JSON with a message (the shape the connector relays to the model)
			rw.Header().Set("Content-Type", "application/json")
			rw.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = fmt.Fprintf(rw, `{"message":%s,"errors":[{"resource":"Issue","code":"custom","message":%s}]}`, jsonSoup, jsonSoup)
		}
		return true
	})
	w.slack.setOverride(func(rw http.ResponseWriter, r *http.Request) bool {
		switch n.Add(1) % 3 {
		case 0: // ok:false with a hostile error code
			rw.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(rw, `{"ok":false,"error":%s,"needed":"chat:write","provided":%s}`, jsonSoup, jsonSoup)
		case 1: // 5xx HTML page
			rw.Header().Set("Content-Type", "text/html")
			rw.WriteHeader(http.StatusInternalServerError)
			_, _ = rw.Write([]byte(htmlBody))
		default: // 200 with an HTML body (a proxy in the way)
			rw.Header().Set("Content-Type", "text/html")
			_, _ = rw.Write([]byte(htmlBody))
		}
		return true
	})

	alice := w.token(w.alice, tokens.CreateRequest{Name: "redaction"})
	calls := []struct {
		tool string
		args map[string]any
	}{
		{"github.get_me", map[string]any{}},
		{"github.search_issues", map[string]any{"q": "is:open"}},
		{"slack.list_channels", map[string]any{}},
		{"github.create_issue", map[string]any{"owner": "acme-labs", "repo": "web", "title": "t"}}, // allowed write: ledger path
	}
	const concurrency = 50
	type answer struct {
		status int
		body   string
	}
	answers := make([]answer, concurrency)
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c := calls[i%len(calls)]
			args := map[string]any{}
			for k, v := range c.args {
				args[k] = v
			}
			if c.tool == "github.create_issue" {
				args["title"] = fmt.Sprintf("load %d", i) // distinct digests: no idempotent replay
			}
			status, h, body := w.rawCall(alice, c.tool, args)
			if ct := h.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				t.Errorf("call %d: Content-Type %q (a vendor HTML page must never become the answer's type)", i, ct)
			}
			answers[i] = answer{status, string(body)}
		}(i)
	}
	wg.Wait()

	// Every answer is a tool error or a JSON-RPC error, or a read marked
	// unavailable; none carries vendor text.
	leaks := func(where, s string) {
		t.Helper()
		for _, c := range secretCorpus {
			if strings.Contains(s, c.value) {
				t.Errorf("%s leaks the %s", where, c.what)
			}
		}
		for _, tell := range vendorTells {
			if strings.Contains(s, tell) {
				t.Errorf("%s carries vendor body text %q", where, tell)
			}
		}
	}
	var toolErrors, rpcErrors int
	for i, a := range answers {
		if a.status != http.StatusOK {
			t.Errorf("call %d: HTTP %d: %s", i, a.status, a.body)
			continue
		}
		var env struct {
			Result *struct {
				IsError bool `json:"isError"`
				Content []struct {
					Text string `json:"text"`
				} `json:"content"`
			} `json:"result"`
			Error *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal([]byte(a.body), &env); err != nil {
			t.Fatalf("call %d: %s: %v", i, a.body, err)
		}
		switch {
		case env.Result != nil:
			toolErrors++
		case env.Error != nil:
			rpcErrors++
		}
		leaks(fmt.Sprintf("MCP answer %d (%s)", i, calls[i%len(calls)].tool), a.body)
	}
	if toolErrors+rpcErrors != concurrency {
		t.Errorf("tool errors %d + rpc errors %d != %d", toolErrors, rpcErrors, concurrency)
	}

	// Audit: one row per call, short classes, no vendor text anywhere.
	var audited int
	for _, ev := range w.events(w.alice) {
		if ev.EventType != "tool_call" {
			continue
		}
		audited++
		// A read against an unreachable vendor is a succeeded call whose
		// result says "could not look" (class unavailable); everything
		// else failed with a class.
		if ev.Outcome != "failed" && (ev.Outcome != "succeeded" || ev.ErrorClass != "unavailable") {
			t.Errorf("audit %s: outcome %q class %q", ev.Tool, ev.Outcome, ev.ErrorClass)
		}
		if !classRE.MatchString(ev.ErrorClass) {
			t.Errorf("audit %s: error class %q is not a class", ev.Tool, ev.ErrorClass)
		}
		b, _ := json.Marshal(ev)
		leaks("audit row", string(b))
	}
	if audited != concurrency {
		t.Errorf("audit rows = %d, want %d", audited, concurrency)
	}
	// Ledger: the writes are failed (4xx) or unknown (5xx: the vendor did
	// not confirm the outcome) operations with a class, never the body.
	var writes int
	for _, op := range w.ops(w.alice) {
		writes++
		if (op.State != "failed" && op.State != "unknown") || op.ErrorCode == nil || !classRE.MatchString(*op.ErrorCode) {
			t.Errorf("ledger %s: state %q class %v", op.ID, op.State, op.ErrorCode)
		}
		b, _ := json.Marshal(op)
		leaks("ledger row", string(b))
	}
	if writes == 0 {
		t.Error("no ledger rows for the failed writes")
	}
	if w.opFor(w.alice, "github.create_issue", "unknown") == nil {
		t.Error("no write against a 5xx vendor ended unknown (awaiting reconciliation)")
	}
	// Portal pages, as alice and as the admin.
	for _, page := range []struct {
		u    user
		path string
	}{{w.alice, "/operations"}, {w.alice, "/activity"}, {w.admin, "/admin/audit?user=" + w.alice.id}, {w.admin, "/admin/audit"}} {
		status, _, body := w.get(page.u, page.path)
		if status != http.StatusOK {
			t.Errorf("GET %s = %d", page.path, status)
		}
		leaks("portal "+page.path, body)
	}
	// The log: scanForLeaks (cleanup) checks every forbidden value; here
	// the vendor tells too, and that the vendor's text did not reach the
	// gateway's own error lines in any form.
	leaks("gateway log", w.logs.String())
}
