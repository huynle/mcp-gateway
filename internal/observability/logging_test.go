package observability_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/observability"
)

func TestNewLoggerJSONRespectsLevel(t *testing.T) {
	var buf bytes.Buffer
	log, err := observability.NewLogger(&buf, "warn", "json")
	if err != nil {
		t.Fatal(err)
	}
	log.Info("hidden")
	log.Warn("shown", "k", "v")
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("want exactly one line, got %q", buf.String())
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if rec["msg"] != "shown" || rec["k"] != "v" || rec["level"] != "WARN" {
		t.Errorf("unexpected record %v", rec)
	}
}

func TestNewLoggerText(t *testing.T) {
	var buf bytes.Buffer
	log, err := observability.NewLogger(&buf, "debug", "text")
	if err != nil {
		t.Fatal(err)
	}
	log.Debug("hello")
	if !strings.Contains(buf.String(), "level=DEBUG") || !strings.Contains(buf.String(), "msg=hello") {
		t.Errorf("unexpected text output %q", buf.String())
	}
}

func TestNewLoggerRejectsBadInputs(t *testing.T) {
	if _, err := observability.NewLogger(&bytes.Buffer{}, "loud", "json"); err == nil {
		t.Error("expected error for bad level")
	}
	if _, err := observability.NewLogger(&bytes.Buffer{}, "info", "xml"); err == nil {
		t.Error("expected error for bad format")
	}
}
