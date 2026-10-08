package audit_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/audit"
)

// TestEventFieldSetIsExact pins the audit Event to the field set approved in
// plan 36bakiw8 section 3 step 9 and decision dovthftx: metadata only. Adding
// a field makes this test fail so a reviewer must consciously approve it.
func TestEventFieldSetIsExact(t *testing.T) {
	want := map[string]string{
		"Time":             "time.Time",
		"UserID":           "string",
		"TokenID":          "string",
		"Tool":             "string",
		"AccountID":        "string",
		"AccountLabel":     "string",
		"ResourceIdentity": "map[string]string",
		"Decision":         "string",
		"PolicyVersion":    "string",
		"ApprovalID":       "string",
		"OperationID":      "string",
		"Outcome":          "string",
		"Latency":          "time.Duration",
		"RequestID":        "string",
		"ErrorClass":       "string",
	}
	typ := reflect.TypeOf(audit.Event{})
	got := map[string]string{}
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		got[f.Name] = f.Type.String()
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("audit.Event field set changed.\n got: %v\nwant: %v", got, want)
	}
}

// TestEventNeverCarriesArgumentsOrContent is the compile-time-adjacent guard:
// any field whose name smells like a payload fails the suite, whatever its
// type.
func TestEventNeverCarriesArgumentsOrContent(t *testing.T) {
	forbidden := []string{"argument", "args", "content", "body", "payload", "param", "input", "output", "response", "result", "secret", "token_value"}
	typ := reflect.TypeOf(audit.Event{})
	for i := 0; i < typ.NumField(); i++ {
		name := strings.ToLower(typ.Field(i).Name)
		for _, bad := range forbidden {
			if strings.Contains(name, bad) {
				t.Errorf("audit.Event has field %q which looks like %s; audit events carry metadata only", typ.Field(i).Name, bad)
			}
		}
	}
}

// TestResourceIdentityValuesAreCapped: resource identity is for repo, channel,
// site names and IDs, not for smuggling content. Long values are truncated.
func TestResourceIdentityValuesAreCapped(t *testing.T) {
	long := strings.Repeat("x", audit.MaxResourceValueLen+50)
	ev := audit.Event{ResourceIdentity: map[string]string{"repo": long, "ok": "short"}}
	ev.Normalize()
	if got := len(ev.ResourceIdentity["repo"]); got != audit.MaxResourceValueLen {
		t.Errorf("repo value length = %d, want %d", got, audit.MaxResourceValueLen)
	}
	if ev.ResourceIdentity["ok"] != "short" {
		t.Errorf("short value altered: %q", ev.ResourceIdentity["ok"])
	}
}

// TestResourceIdentityKeyCountIsCapped bounds the map so a connector cannot
// turn resource identity into a dump of every argument.
func TestResourceIdentityKeyCountIsCapped(t *testing.T) {
	m := map[string]string{}
	for i := 0; i < audit.MaxResourceKeys+10; i++ {
		m[strings.Repeat("k", i+1)] = "v"
	}
	ev := audit.Event{ResourceIdentity: m}
	ev.Normalize()
	if got := len(ev.ResourceIdentity); got != audit.MaxResourceKeys {
		t.Errorf("key count = %d, want %d", got, audit.MaxResourceKeys)
	}
	// Deterministic: the shortest keys (sorted) survive.
	if _, ok := ev.ResourceIdentity["k"]; !ok {
		t.Error("expected shortest key 'k' to survive the cap")
	}
}
