package caps_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/caps"
)

func TestExceededErrorMessageClassAndIs(t *testing.T) {
	cases := map[caps.Resource]string{
		caps.Servers:           "You have reached the limit of 3 MCP servers",
		caps.Tunnels:           "You have reached the limit of 3 tunnels",
		caps.ConnectionsPerApp: "You have reached the limit of 3 connected accounts for this app",
		caps.ConnectionsTotal:  "You have reached the limit of 3 connected accounts",
		caps.PendingApprovals:  "You have reached the limit of 3 pending approvals",
	}
	for r, want := range cases {
		err := fmt.Errorf("wrapped: %w", &caps.ExceededError{Resource: r, Limit: 3})
		if !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "ask an admin") {
			t.Errorf("%s: message %q, want %q and an admin hint", r, err.Error(), want)
		}
		if !errors.Is(err, caps.ErrExceeded) {
			t.Errorf("%s: errors.Is(ErrExceeded) = false", r)
		}
		var ce interface{ ErrorClass() string }
		if !errors.As(err, &ce) || ce.ErrorClass() != caps.Class || caps.Class != "cap_exceeded" {
			t.Errorf("%s: class not cap_exceeded", r)
		}
	}
	if errors.Is(errors.New("other"), caps.ErrExceeded) {
		t.Error("unrelated error matched")
	}
}

func TestValidAndBuiltinDefaults(t *testing.T) {
	for _, r := range caps.Resources {
		if !caps.Valid(r) {
			t.Errorf("%s not valid", r)
		}
		if caps.Builtin[r] <= 0 {
			t.Errorf("builtin %s = %d, want > 0 (never unlimited by default)", r, caps.Builtin[r])
		}
	}
	if caps.Valid("users") || caps.Valid("") {
		t.Error("unknown resource valid")
	}
}
