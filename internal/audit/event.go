package audit

import (
	"sort"
	"time"
)

// Limits on the resource identity map. Resource identity names a repo,
// channel, site, calendar, issue key and the like; it is not a place for
// arguments, so both the number of keys and the length of each value are
// bounded (decision dovthftx).
const (
	MaxResourceKeys     = 8
	MaxResourceValueLen = 128
	MaxResourceKeyLen   = 32
)

// Event is one audit record. It carries exactly the metadata approved in
// plan 36bakiw8 section 3 step 9 and decision dovthftx: who, token, tool,
// account, resource identity, decision, policy version, approval, operation,
// outcome, latency, request ID and a short error class. It has no field for
// arguments, content, bodies or responses and event_test.go fails the build
// of the test suite if one is ever added.
//
// Empty strings mean "not applicable" (for example a failed authentication
// has no UserID, a read has no OperationID). UserID empty marks a system
// event, which the Recorder stores through the bypass scope.
type Event struct {
	Time             time.Time
	UserID           string
	TokenID          string
	Tool             string
	AccountID        string
	AccountLabel     string
	ResourceIdentity map[string]string
	Decision         string
	PolicyVersion    string
	ApprovalID       string
	OperationID      string
	Outcome          string
	Latency          time.Duration
	RequestID        string
	ErrorClass       string
}

// Normalize enforces the resource identity caps in place: at most
// MaxResourceKeys entries (the lexically smallest keys win, so the result is
// deterministic), keys truncated to MaxResourceKeyLen and values to
// MaxResourceValueLen bytes. It also fills Time when unset.
func (e *Event) Normalize() {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	if len(e.ResourceIdentity) == 0 {
		return
	}
	keys := make([]string, 0, len(e.ResourceIdentity))
	for k := range e.ResourceIdentity {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > MaxResourceKeys {
		keys = keys[:MaxResourceKeys]
	}
	out := make(map[string]string, len(keys))
	for _, k := range keys {
		v := e.ResourceIdentity[k]
		if len(v) > MaxResourceValueLen {
			v = v[:MaxResourceValueLen]
		}
		kk := k
		if len(kk) > MaxResourceKeyLen {
			kk = kk[:MaxResourceKeyLen]
		}
		out[kk] = v
	}
	e.ResourceIdentity = out
}
