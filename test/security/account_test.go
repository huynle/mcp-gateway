//go:build integration || e2e || security

package security

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/account"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

// TestSecurityAccountLifecycle: the data export carries only the caller's
// metadata (never a token, secret or another user's row) and is rate
// limited; deletion needs the typed phrase, cuts every credential at once
// (token refused on /mcp, session gone, app connections revoked with
// their secrets deleted) and keeps the audit trail; members cannot reach
// the admin variant.
func TestSecurityAccountLifecycle(t *testing.T) {
	w := newWorld(t, options{})
	aliceTok := w.token(w.alice, tokens.CreateRequest{Name: "alice-laptop"})
	bobTok := w.token(w.bob, tokens.CreateRequest{Name: "bob-laptop"})
	if code, _, _ := w.rawCall(bobTok, "fake.list_items", map[string]any{}); code != http.StatusOK {
		t.Fatalf("bob's token before deletion = %d", code)
	}

	code, hdr, body := w.post(w.alice, "/account/export", nil)
	if code != http.StatusOK || !strings.HasPrefix(hdr.Get("Content-Disposition"), "attachment;") {
		t.Fatalf("export = %d %v", code, hdr)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("export is not JSON: %v", err)
	}
	if doc["user_id"] != w.alice.id || !strings.Contains(body, "alice-laptop") {
		t.Error("export lacks alice's own data")
	}
	for _, leak := range []string{w.bob.id, "bob-laptop", aliceTok, bobTok, w.alice.cookie.Value, "ciphertext", "token_hash"} {
		if strings.Contains(body, leak) {
			t.Errorf("export contains %q", leak)
		}
	}
	for value, what := range w.secrets {
		if strings.Contains(body, value) {
			t.Errorf("export contains a secret (%s)", what)
		}
	}
	if code, hdr, _ := w.post(w.alice, "/account/export", nil); code != http.StatusTooManyRequests || hdr.Get("Retry-After") == "" {
		t.Errorf("second export = %d, want 429 with Retry-After", code)
	}

	// Members cannot reach the admin variant.
	if code, _, _ := w.get(w.alice, "/admin/users/"+w.bob.id+"/delete"); code != http.StatusNotFound {
		t.Errorf("member GET admin delete = %d, want 404", code)
	}
	if code, _, _ := w.post(w.alice, "/admin/users/"+w.bob.id+"/delete", url.Values{"confirm": {account.AdminConfirmPhrase}}); code != http.StatusNotFound {
		t.Errorf("member POST admin delete = %d, want 404", code)
	}

	// Bob deletes himself (signed in moments ago by the world).
	if code, _, _ := w.post(w.bob, "/account/delete", url.Values{"confirm": {"yes"}}); code != http.StatusUnprocessableEntity {
		t.Errorf("wrong phrase = %d, want 422", code)
	}
	code, hdr, _ = w.post(w.bob, "/account/delete", url.Values{"confirm": {account.ConfirmPhrase}})
	if code != http.StatusSeeOther || hdr.Get("Location") != "/account/deleted" {
		t.Fatalf("delete = %d %q", code, hdr.Get("Location"))
	}
	if code, _, _ := w.rawCall(bobTok, "fake.list_items", map[string]any{}); code != http.StatusUnauthorized {
		t.Errorf("bob's token after deletion = %d, want 401", code)
	}
	if code, hdr, _ := w.get(w.bob, "/account"); code != http.StatusSeeOther || !strings.HasPrefix(hdr.Get("Location"), "/signin") {
		t.Errorf("bob's session after deletion = %d %q, want redirect to sign-in", code, hdr.Get("Location"))
	}
	if n := w.queryString(`SELECT count(*)::text FROM connections WHERE user_id = $1 AND status <> 'revoked'`, w.bob.id); n != "0" {
		t.Errorf("bob's live connections = %s", n)
	}
	if n := w.queryString(`SELECT count(*)::text FROM connection_secrets WHERE user_id = $1`, w.bob.id); n != "0" {
		t.Errorf("bob's connection secrets = %s", n)
	}
	if n := w.queryString(`SELECT count(*)::text FROM audit_events WHERE user_id = $1 AND resource->>'action' = 'user.deleted'`, w.bob.id); n != "1" {
		t.Errorf("user.deleted events = %s", n)
	}
	// Alice is untouched.
	if code, _, _ := w.rawCall(aliceTok, "fake.list_items", map[string]any{}); code != http.StatusOK {
		t.Errorf("alice's token after bob's deletion = %d", code)
	}
}
