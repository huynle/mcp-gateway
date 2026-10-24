package main

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/approvals"
	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/pushnotify"
)

func pushEnv(vars map[string]string) func(string) string {
	return func(k string) string { return vars[k] }
}

// TestPushWiringFollowsTheFlag: Web Push is built only with
// GATEWAY_WEBPUSH_ENABLED, a key provider and a usable VAPID subject; an
// unparsable flag fails startup, the other gaps keep it off with a
// warning. When built it joins the approvals notifiers and the portal.
func TestPushWiringFollowsTheFlag(t *testing.T) {
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	kp, err := crypto.NewStaticProvider("k1", map[string][]byte{"k1": bytes.Repeat([]byte{1}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	https := config.Default()
	https.BaseURL = "https://gw.example.com"
	plain := config.Default() // http://localhost:18080

	on := map[string]string{pushnotify.EnvEnabled: "true"}
	cases := []struct {
		name  string
		cfg   config.Config
		keys  crypto.KeyProvider
		env   map[string]string
		built bool
		fails bool
		log   string
	}{
		{name: "default off", cfg: https, keys: kp, env: nil},
		{name: "unparsable flag", cfg: https, keys: kp, env: map[string]string{pushnotify.EnvEnabled: "maybe"}, fails: true},
		{name: "no key provider", cfg: https, keys: nil, env: on, log: "no key provider"},
		{name: "http without contact", cfg: plain, keys: kp, env: on, log: "VAPID subject"},
		{name: "https", cfg: https, keys: kp, env: on, built: true, log: "web push ready"},
		{name: "http with contact", cfg: plain, keys: kp, env: map[string]string{pushnotify.EnvEnabled: "1", "GATEWAY_LEGAL_CONTACT_EMAIL": "ops@example.com"}, built: true, log: "mailto:ops@example.com"},
	}
	for _, c := range cases {
		logs.Reset()
		svc, err := newPush(c.cfg, nil, c.keys, audit.NopRecorder{}, pushEnv(c.env), log)
		if (err != nil) != c.fails {
			t.Errorf("%s: err = %v", c.name, err)
		}
		if (svc != nil) != c.built {
			t.Errorf("%s: built = %v, want %v", c.name, svc != nil, c.built)
		}
		if c.log != "" && !strings.Contains(logs.String(), c.log) {
			t.Errorf("%s: log lacks %q:\n%s", c.name, c.log, logs.String())
		}
	}
	if strings.Contains(logs.String(), "/fcm/send/") {
		t.Error("log names an endpoint")
	}

	// A nil service is not added to the notifiers; a built one is.
	var none *pushnotify.Service
	if got := notifiers(none); len(got) != 1 {
		t.Errorf("notifiers(nil push) = %d entries, want the portal only", len(got))
	}
	svc, err := newPush(https, nil, kp, audit.NopRecorder{}, pushEnv(on), log)
	if err != nil || svc == nil {
		t.Fatal(err)
	}
	list := notifiers(none, svc)
	if len(list) != 2 {
		t.Fatalf("notifiers(push) = %d entries", len(list))
	}
	if _, ok := list[1].(*pushnotify.Service); !ok {
		t.Errorf("second notifier = %T", list[1])
	}
	if _, err := newApprovals(https, nil, kp, audit.NopRecorder{}, observability.NewMetrics(), func(string) string { return "" }, log, nil, svc); err != nil {
		t.Errorf("newApprovals with the push notifier: %v", err)
	}
	var _ approvals.Notifier = svc

	// The portal gets the service through portalSettings (nil stays nil,
	// not a typed-nil interface).
	if (portalSettings{}).Push() != nil {
		t.Error("portalSettings without push returns a non-nil Push")
	}
	if (portalSettings{push: svc}).Push() == nil {
		t.Error("portalSettings drops the push service")
	}
}
