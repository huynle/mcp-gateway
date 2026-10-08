package connections_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/store"
)

func slackApp(secrets map[string]string) connections.VendorApp {
	app := connections.Defaults(connections.VendorSlack, "")
	app.ClientID = "slack-cid"
	app.ClientSecret = "slack-client-secret"
	app.Secrets = secrets
	return app
}

func TestSaveVendorAppStoresExtraSecretsEncryptedAndVendorSecretsReadsThem(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	saved, err := env.svc.SaveVendorApp(ctx, userAlice, slackApp(map[string]string{
		connections.SecretSlackBotToken:      "xoxb-bot-token-1",
		connections.SecretSlackSigningSecret: "sign-me-1",
	}))
	if err != nil {
		t.Fatalf("SaveVendorApp: %v", err)
	}
	// Never returned on the read side; the editor only learns which keys exist.
	if saved.ClientSecret != "" || len(saved.Secrets) != 0 || !saved.HasSecret {
		t.Fatalf("saved = %+v", saved)
	}
	if got := strings.Join(saved.SecretKeys, ","); got != "bot_token,signing_secret" {
		t.Errorf("SecretKeys = %q", got)
	}
	// Nothing in the row is plaintext.
	for _, row := range env.store.VendorAppRows() {
		for _, plain := range []string{"xoxb-bot-token-1", "sign-me-1", "slack-client-secret"} {
			if strings.Contains(string(row.ClientSecret.Ciphertext), plain) || strings.Contains(string(row.Config), plain) {
				t.Errorf("plaintext %q stored in row", plain)
			}
		}
	}
	got, err := env.svc.VendorSecrets(ctx, "slack", "", connections.SecretSlackBotToken, connections.SecretSlackSigningSecret, "missing")
	if err != nil {
		t.Fatalf("VendorSecrets: %v", err)
	}
	if got[connections.SecretSlackBotToken] != "xoxb-bot-token-1" || got[connections.SecretSlackSigningSecret] != "sign-me-1" {
		t.Errorf("VendorSecrets = %v", got)
	}
	if _, ok := got["missing"]; ok {
		t.Errorf("missing key reported: %v", got)
	}
	// The client secret is part of the same bundle.
	cs, err := env.svc.VendorSecrets(ctx, "slack", "", connections.SecretClientSecret)
	if err != nil || cs[connections.SecretClientSecret] != "slack-client-secret" {
		t.Errorf("client secret = %v, %v", cs, err)
	}
}

func TestSaveVendorAppKeepsSecretsLeftBlankAndReplacesTheOnesGiven(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	if _, err := env.svc.SaveVendorApp(ctx, userAlice, slackApp(map[string]string{
		connections.SecretSlackBotToken: "xoxb-1", connections.SecretSlackSigningSecret: "sign-1",
	})); err != nil {
		t.Fatal(err)
	}
	// Second save: no client secret, a new bot token, blank signing secret.
	again := slackApp(map[string]string{connections.SecretSlackBotToken: "xoxb-2", connections.SecretSlackSigningSecret: ""})
	again.ClientSecret = ""
	saved, err := env.svc.SaveVendorApp(ctx, userAlice, again)
	if err != nil {
		t.Fatalf("second save: %v", err)
	}
	if got := strings.Join(saved.SecretKeys, ","); got != "bot_token,signing_secret" {
		t.Errorf("SecretKeys = %q", got)
	}
	got, err := env.svc.VendorSecrets(ctx, "slack", "", connections.SecretClientSecret, connections.SecretSlackBotToken, connections.SecretSlackSigningSecret)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"client_secret": "slack-client-secret", "bot_token": "xoxb-2", "signing_secret": "sign-1"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}

func TestVendorSecretsOnUnconfiguredVendorIsNotConfigured(t *testing.T) {
	env := newTestEnv(t)
	_, err := env.svc.VendorSecrets(context.Background(), "slack", "", connections.SecretSlackBotToken)
	if !errors.Is(err, connections.ErrNotConfigured) {
		t.Fatalf("err = %v, want ErrNotConfigured", err)
	}
}

// Rows written before the bundle format hold the raw client secret as the
// envelope plaintext; they must keep working (and gain extra secrets on
// the next save).
func TestLegacyRawClientSecretRowsStillDecrypt(t *testing.T) {
	kp, err := crypto.NewStaticProvider("k1", map[string][]byte{"k1": bytesRepeat(7, 32)})
	if err != nil {
		t.Fatal(err)
	}
	env := newTestEnv(t)
	ctx := context.Background()
	saved, err := env.svc.SaveVendorApp(ctx, userAlice, slackApp(nil))
	if err != nil {
		t.Fatal(err)
	}
	// Overwrite the envelope with the legacy layout: plaintext = client secret.
	env.store.Bypass(ctx, func(tx connections.Tx) error { //nolint:errcheck // test setup
		row, err := tx.GetVendorApp(ctx, saved.ID)
		if err != nil {
			return err
		}
		envl, err := crypto.Encrypt(ctx, kp, crypto.AAD{Kind: "vendor_app", RecordID: row.ID}, []byte("legacy-secret"))
		if err != nil {
			return err
		}
		row.ClientSecret = store.Encrypted(envl)
		return tx.UpsertVendorApp(ctx, row)
	})
	got, err := env.svc.VendorSecrets(ctx, "slack", "", connections.SecretClientSecret, connections.SecretSlackBotToken)
	if err != nil {
		t.Fatalf("VendorSecrets: %v", err)
	}
	if got[connections.SecretClientSecret] != "legacy-secret" {
		t.Errorf("client secret = %v", got)
	}
	if _, ok := got[connections.SecretSlackBotToken]; ok {
		t.Errorf("legacy row has a bot token: %v", got)
	}
	app, err := env.svc.VendorApp(ctx, "slack", "")
	if err != nil || !app.HasSecret || len(app.SecretKeys) != 0 {
		t.Errorf("VendorApp = %+v, %v", app, err)
	}
	// Adding a bot token on a legacy row keeps the client secret.
	more := slackApp(map[string]string{connections.SecretSlackBotToken: "xoxb-3"})
	more.ClientSecret = ""
	if _, err := env.svc.SaveVendorApp(ctx, userAlice, more); err != nil {
		t.Fatal(err)
	}
	got, err = env.svc.VendorSecrets(ctx, "slack", "", connections.SecretClientSecret, connections.SecretSlackBotToken)
	if err != nil || got["client_secret"] != "legacy-secret" || got["bot_token"] != "xoxb-3" {
		t.Errorf("after upgrade = %v, %v", got, err)
	}
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func TestSlackEditorTakesBotTokenAndSigningSecretWriteOnly(t *testing.T) {
	h := newHarness(t)
	admin, ap := h.session(t, adminSub, "Admin")
	rec := h.do(t, request{method: http.MethodGet, path: "/admin/vendor-apps/slack", cookie: admin})
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, `name="bot_token"`) || !strings.Contains(body, `name="signing_secret"`) {
		t.Fatalf("slack editor = %d:\n%s", rec.Code, body)
	}
	// Other vendors do not show them.
	if rec := h.do(t, request{method: http.MethodGet, path: "/admin/vendor-apps/github", cookie: admin}); strings.Contains(rec.Body.String(), `name="bot_token"`) {
		t.Fatalf("github editor shows slack secrets")
	}
	form := url.Values{
		"_csrf": {ap.CSRFToken}, "client_id": {"slack-cid"}, "client_secret": {"slack-sekrit"},
		"bot_token": {"xoxb-editor-token"}, "signing_secret": {"editor-signing"},
		"auth_url": {"https://slack.com/oauth/v2/authorize"}, "token_url": {"https://slack.com/api/oauth.v2.access"}, "enabled": {"1"},
	}
	rec = h.do(t, request{method: http.MethodPost, path: "/admin/vendor-apps/slack", cookie: admin, form: form})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("save = %d:\n%s", rec.Code, rec.Body)
	}
	got, err := h.conn.VendorSecrets(context.Background(), "slack", "", connections.SecretSlackBotToken, connections.SecretSlackSigningSecret)
	if err != nil || got["bot_token"] != "xoxb-editor-token" || got["signing_secret"] != "editor-signing" {
		t.Fatalf("VendorSecrets = %v, %v", got, err)
	}
	// Re-rendered as stored, values never shown; a blank re-save keeps them.
	rec = h.do(t, request{method: http.MethodGet, path: "/admin/vendor-apps/slack", cookie: admin})
	body = rec.Body.String()
	if strings.Count(body, "(stored; leave blank to keep it)") != 2 || strings.Contains(body, "xoxb-editor-token") || strings.Contains(body, "editor-signing") || strings.Contains(body, "slack-sekrit") {
		t.Fatalf("editor after save:\n%s", body)
	}
	form.Set("client_secret", "")
	form.Set("bot_token", "")
	form.Set("signing_secret", "")
	if rec := h.do(t, request{method: http.MethodPost, path: "/admin/vendor-apps/slack", cookie: admin, form: form}); rec.Code != http.StatusSeeOther {
		t.Fatalf("blank re-save = %d:\n%s", rec.Code, rec.Body)
	}
	got, err = h.conn.VendorSecrets(context.Background(), "slack", "", connections.SecretClientSecret, connections.SecretSlackBotToken, connections.SecretSlackSigningSecret)
	if err != nil || got["client_secret"] != "slack-sekrit" || got["bot_token"] != "xoxb-editor-token" || got["signing_secret"] != "editor-signing" {
		t.Fatalf("after blank re-save = %v, %v", got, err)
	}
	if strings.Contains(h.logs.String(), "xoxb-editor-token") || strings.Contains(h.logs.String(), "editor-signing") {
		t.Fatalf("secret in logs:\n%s", h.logs.String())
	}
}
