package ledger_test

import (
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/ledger"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestConfigFromEnvDefaults(t *testing.T) {
	cfg, err := ledger.ConfigFromEnv(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.IdempotencyWindow != 24*time.Hour || cfg.StaleAfter != 2*time.Minute || cfg.MaxReconcileAttempts != 6 || cfg.MaxReconcileAge != 24*time.Hour {
		t.Errorf("defaults = %+v", cfg)
	}
}

func TestConfigFromEnvReadsAndValidates(t *testing.T) {
	cfg, err := ledger.ConfigFromEnv(env(map[string]string{
		ledger.EnvIdempotencyWindow:    " 1h ",
		ledger.EnvStaleAfter:           "90s",
		ledger.EnvMaxReconcileAttempts: "3",
		ledger.EnvMaxReconcileAge:      "6h",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.IdempotencyWindow != time.Hour || cfg.StaleAfter != 90*time.Second || cfg.MaxReconcileAttempts != 3 || cfg.MaxReconcileAge != 6*time.Hour {
		t.Errorf("parsed = %+v", cfg)
	}
	bad := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"window not a duration", map[string]string{ledger.EnvIdempotencyWindow: "soon"}, ledger.EnvIdempotencyWindow},
		{"window zero", map[string]string{ledger.EnvIdempotencyWindow: "0"}, "window"},
		{"stale negative", map[string]string{ledger.EnvStaleAfter: "-1m"}, "stale"},
		{"attempts not an int", map[string]string{ledger.EnvMaxReconcileAttempts: "six"}, ledger.EnvMaxReconcileAttempts},
		{"attempts zero", map[string]string{ledger.EnvMaxReconcileAttempts: "0"}, "attempts"},
		{"age below stale", map[string]string{ledger.EnvMaxReconcileAge: "1m", ledger.EnvStaleAfter: "2m"}, "age"},
	}
	for _, tc := range bad {
		if _, err := ledger.ConfigFromEnv(env(tc.env)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want mention of %q", tc.name, err, tc.want)
		}
	}
}

func TestDigestIsCanonicalAndStable(t *testing.T) {
	a := ledger.Digest(map[string]any{"b": 1, "a": map[string]any{"y": "z", "x": []any{1, "two"}}})
	b := ledger.Digest(map[string]any{"a": map[string]any{"x": []any{1, "two"}, "y": "z"}, "b": 1})
	if len(a) != 32 || string(a) != string(b) {
		t.Errorf("digest differs for the same canonical arguments: %x vs %x", a, b)
	}
	if string(ledger.Digest(map[string]any{"b": 2})) == string(a) {
		t.Error("digest ignores values")
	}
	if string(ledger.Digest(nil)) != string(ledger.Digest(map[string]any{})) {
		t.Error("nil and empty arguments must digest alike")
	}
}

func TestKeyScopes(t *testing.T) {
	if k := ledger.ApprovalKey("ap-1"); k != "approval:ap-1" {
		t.Errorf("approval key = %q", k)
	}
	d := ledger.Digest(map[string]any{"x": 1})
	k1 := ledger.DigestKey("u1", "acct", "fake.create_item", d)
	k2 := ledger.DigestKey("u1", "acct", "fake.create_item", d)
	if k1 != k2 || !strings.HasPrefix(k1, "digest:") {
		t.Errorf("digest key unstable or unprefixed: %q %q", k1, k2)
	}
	for _, other := range []string{
		ledger.DigestKey("u2", "acct", "fake.create_item", d),
		ledger.DigestKey("u1", "acct2", "fake.create_item", d),
		ledger.DigestKey("u1", "acct", "fake.post_note", d),
		ledger.DigestKey("u1", "acct", "fake.create_item", ledger.Digest(map[string]any{"x": 2})),
	} {
		if other == k1 {
			t.Errorf("key collision: %q", other)
		}
	}
}

func TestSanitizeResultIDsCapsAndDrops(t *testing.T) {
	long := strings.Repeat("x", ledger.MaxResultIDValueLen+1)
	in := map[string]string{
		"id":  "42",
		"url": "https://example.com/i/42",
		"":    "dropped-empty-key",
		strings.Repeat("k", ledger.MaxResultIDKeyLen+1): "dropped-long-key",
		"too_long": long,
		"empty":    "",
		"nl":       "a\nb",
	}
	got := ledger.SanitizeResultIDs(in)
	if len(got) != 2 || got["id"] != "42" || got["url"] != "https://example.com/i/42" {
		t.Errorf("sanitized = %v", got)
	}
	many := map[string]string{}
	for i := 0; i < ledger.MaxResultIDs+5; i++ {
		many["k"+strings.Repeat("0", 2-len(string(rune('0'+i%10))))+string(rune('a'+i%26))+string(rune('a'+i/26))] = "v"
	}
	if got := ledger.SanitizeResultIDs(many); len(got) != ledger.MaxResultIDs {
		t.Errorf("count = %d, want %d", len(got), ledger.MaxResultIDs)
	}
	// Deterministic: the lexically smallest keys win.
	a, b := ledger.SanitizeResultIDs(many), ledger.SanitizeResultIDs(many)
	for k := range a {
		if _, ok := b[k]; !ok {
			t.Errorf("non-deterministic cap: %q", k)
		}
	}
	if ledger.SanitizeResultIDs(nil) != nil {
		t.Error("nil in must be nil out")
	}
}
