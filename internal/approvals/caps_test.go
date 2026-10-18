package approvals_test

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/approvals"
	"github.com/huynle/mcp-gateway/internal/caps"
	"github.com/huynle/mcp-gateway/internal/mcp"
)

type capLimits struct {
	v       caps.Values
	refused atomic.Int64
}

func (c *capLimits) Limit(_ context.Context, _ string, r caps.Resource) int { return c.v[r] }
func (c *capLimits) Refused(context.Context, string, caps.Resource, int)    { c.refused.Add(1) }

func TestCreateRefusedAtPendingApprovalCap(t *testing.T) {
	f := newFixture(t)
	l := &capLimits{v: caps.Values{caps.PendingApprovals: 2}}
	f.svc.SetCaps(l)
	first := f.create(t, sampleArgs)
	f.create(t, sampleArgs)
	req := approvals.Request{UserID: alice, AccountID: acctA, Tool: "fake.create_item", Args: sampleArgs, PolicyVersionID: policyV1}
	_, err := f.svc.Create(t.Context(), req)
	var ce *caps.ExceededError
	if !errors.As(err, &ce) || ce.Resource != caps.PendingApprovals || ce.Limit != 2 {
		t.Fatalf("third = %v, want pending approvals cap", err)
	}
	if f.st.Count() != 2 || l.refused.Load() != 1 {
		t.Fatalf("rows = %d refused = %d", f.st.Count(), l.refused.Load())
	}
	// Deciding one frees a slot.
	if _, err := f.svc.Deny(t.Context(), alice, first.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Create(t.Context(), req); err != nil {
		t.Fatalf("after deny: %v", err)
	}
	// Expired pending approvals do not count.
	f.advance(time.Hour)
	if _, err := f.svc.Create(t.Context(), req); err != nil {
		t.Fatalf("after expiry: %v", err)
	}
}

func TestConfirmAtCapAnswersCapExceeded(t *testing.T) {
	p := newPipeline(t, 10*time.Millisecond)
	p.svc.SetCaps(&capLimits{v: caps.Values{caps.PendingApprovals: 1}})
	if _, _, err := p.call(t, "fake.create_item", map[string]any{"id": "it-1", "name": "a"}); toolErr(t, err).Code != mcp.CodeApprovalRequired {
		t.Fatalf("first = %v", err)
	}
	_, _, err := p.call(t, "fake.create_item", map[string]any{"id": "it-2", "name": "b"})
	te := toolErr(t, err)
	if te.Class() != caps.Class || !strings.Contains(te.Message, "You have reached the limit of 1 pending approvals") {
		t.Fatalf("second = %d %q class %s", te.Code, te.Message, te.Class())
	}
}
