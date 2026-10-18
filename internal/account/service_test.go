package account

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestErrorsMatchTheirSentinels(t *testing.T) {
	err := fmt.Errorf("wrapped: %w", &ExportTooSoonError{RetryAfter: 90 * time.Second})
	if !errors.Is(err, ErrExportTooSoon) {
		t.Error("ExportTooSoonError does not match ErrExportTooSoon")
	}
	var soon *ExportTooSoonError
	if !errors.As(err, &soon) || soon.RetryAfter != 90*time.Second {
		t.Errorf("errors.As = %v", soon)
	}
	blocked := error(&BlockedError{Reasons: []string{"a", "b"}})
	if !errors.Is(blocked, ErrBlocked) || errors.Is(blocked, ErrExportTooSoon) {
		t.Error("BlockedError sentinel matching is wrong")
	}
}

func TestRowLimits(t *testing.T) {
	if rowLimit("audit_events") != 10000 || rowLimit("tokens") != DefaultRowLimit {
		t.Errorf("row limits = %d / %d", rowLimit("audit_events"), rowLimit("tokens"))
	}
}

func TestDefaults(t *testing.T) {
	s := New(nil, nil, Options{})
	if s.o.ExportInterval != 10*time.Minute || s.ReauthWindow() != 10*time.Minute {
		t.Errorf("defaults = %v / %v", s.o.ExportInterval, s.ReauthWindow())
	}
}
