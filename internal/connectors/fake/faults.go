package fake

import (
	"strings"
	"sync"
	"time"
)

// FaultMode is what an injected fault does to a call.
type FaultMode string

// The fault modes. A Fault with the zero mode only adds Latency.
const (
	// FaultFail returns a plain error (Message) without touching state:
	// the vendor refused the call.
	FaultFail FaultMode = "fail"
	// FaultUnknown returns connectors.ErrOutcomeUnknown at once. With
	// Applied the write is performed first, as when the vendor committed
	// but the reply was lost.
	FaultUnknown FaultMode = "unknown"
	// FaultHang blocks until the context is done, then returns
	// connectors.ErrOutcomeUnknown wrapping the context error. Applied
	// performs the write before blocking.
	FaultHang FaultMode = "hang"
	// FaultRateLimited returns *connectors.RateLimited with RetryAfter.
	FaultRateLimited FaultMode = "rate_limited"
	// FaultPartial makes a read succeed with Result.Partial set.
	FaultPartial FaultMode = "partial"
	// FaultUnavailable makes a read return Result.Unavailable with no
	// content.
	FaultUnavailable FaultMode = "unavailable"
)

// Fault is one injected failure for one tool.
type Fault struct {
	Mode FaultMode
	// Latency delays the call before anything else happens; the context
	// is honoured while waiting.
	Latency time.Duration
	// RetryAfter is the vendor's Retry-After for FaultRateLimited.
	RetryAfter time.Duration
	// Message is the error text for FaultFail (default "injected fault").
	Message string
	// Applied makes FaultUnknown and FaultHang perform the write before
	// reporting, so reconciliation finds it.
	Applied bool
	// Remaining is how many calls the fault fires for; 0 means until
	// cleared.
	Remaining int
}

// Faults is a thread-safe table of faults by tool name, usable from any
// package's tests (the pipeline, ledger and approvals tests drive the fake
// through it). Tool names may be short ("create_item") or full
// ("fake.create_item").
type Faults struct {
	mu     sync.Mutex
	byTool map[string]*Fault
}

// NewFaults returns an empty table.
func NewFaults() *Faults { return &Faults{byTool: map[string]*Fault{}} }

// Inject sets the fault for tool, replacing any previous one.
func (f *Faults) Inject(tool string, fault Fault) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.byTool[shortName(tool)] = &fault
}

// Clear removes the fault for tool.
func (f *Faults) Clear(tool string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.byTool, shortName(tool))
}

// ClearAll removes every fault.
func (f *Faults) ClearAll() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.byTool = map[string]*Fault{}
}

// Take returns the fault for tool, if any, and spends one of its
// Remaining calls (removing it when spent).
func (f *Faults) Take(tool string) (Fault, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	name := shortName(tool)
	fault, ok := f.byTool[name]
	if !ok {
		return Fault{}, false
	}
	out := *fault
	if fault.Remaining > 0 {
		fault.Remaining--
		if fault.Remaining == 0 {
			delete(f.byTool, name)
		}
	}
	return out, true
}

func shortName(tool string) string {
	return strings.TrimPrefix(tool, App+".")
}
