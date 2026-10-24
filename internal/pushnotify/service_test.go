package pushnotify_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/pushnotify"
	"github.com/huynle/mcp-gateway/internal/webpush"
)

const (
	alice = "11111111-1111-4111-8111-111111111111"
	bob   = "22222222-2222-4222-8222-222222222222"
)

// sent is one recorded Send call.
type sent struct {
	endpoint string
	payload  []byte
	opts     webpush.SendOptions
}

// fakeSender records sends and answers with result(endpoint) (nil: ok).
type fakeSender struct {
	mu     sync.Mutex
	calls  []sent
	keys   *webpush.Keys
	result func(ctx context.Context, endpoint string) error
}

func (f *fakeSender) Send(ctx context.Context, sub webpush.Subscription, payload []byte, o webpush.SendOptions) error {
	f.mu.Lock()
	f.calls = append(f.calls, sent{endpoint: sub.Endpoint, payload: append([]byte(nil), payload...), opts: o})
	result := f.result
	f.mu.Unlock()
	if len(sub.P256dh) != 65 || len(sub.Auth) != 16 {
		return errors.New("fake sender: subscription keys not decrypted")
	}
	if result != nil {
		return result(ctx, sub.Endpoint)
	}
	return nil
}

func (f *fakeSender) sent() []sent {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]sent(nil), f.calls...)
}

// recorder is an in-memory audit.Recorder.
type recorder struct {
	mu     sync.Mutex
	events []audit.Event
}

func (r *recorder) Record(_ context.Context, ev audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
	return nil
}

func (r *recorder) actions() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, e := range r.events {
		out = append(out, e.ResourceIdentity["action"])
	}
	return out
}

type fixture struct {
	svc    *pushnotify.Service
	st     *memStore
	sender *fakeSender
	audit  *recorder
	kp     crypto.KeyProvider
	now    time.Time
}

func keyProvider(t *testing.T) crypto.KeyProvider {
	t.Helper()
	kp, err := crypto.NewStaticProvider("k1", map[string][]byte{"k1": bytes.Repeat([]byte{7}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

func newFixture(t *testing.T, opts ...func(*pushnotify.Options)) *fixture {
	t.Helper()
	f := &fixture{st: newMemStore(), sender: &fakeSender{}, audit: &recorder{}, kp: keyProvider(t), now: time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)}
	o := pushnotify.Options{
		Subject: "https://gw.example.com",
		NewSender: func(k *webpush.Keys) (pushnotify.Sender, error) {
			f.sender.keys = k
			return f.sender, nil
		},
		Audit: f.audit,
		Log:   slog.New(slog.DiscardHandler),
		Now:   func() time.Time { return f.now },
	}
	for _, fn := range opts {
		fn(&o)
	}
	svc, err := pushnotify.New(f.st, f.kp, o)
	if err != nil {
		t.Fatal(err)
	}
	f.svc = svc
	return f
}

// subscription returns a browser-like PushSubscription.toJSON() for a
// fresh endpoint on host, with valid keys.
func subscription(t *testing.T, host string) (endpoint string, js []byte) {
	t.Helper()
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	endpoint = "https://" + host + "/fcm/send/" + base64.RawURLEncoding.EncodeToString(b[:])
	return endpoint, subscriptionFor(t, endpoint)
}

func subscriptionFor(t *testing.T, endpoint string) []byte {
	t.Helper()
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	auth := make([]byte, 16)
	if _, err := rand.Read(auth); err != nil {
		t.Fatal(err)
	}
	js, err := json.Marshal(map[string]any{
		"endpoint": endpoint, "expirationTime": nil,
		"keys": map[string]string{
			"p256dh": base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()),
			"auth":   base64.RawURLEncoding.EncodeToString(auth),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return js
}

func TestConfigFromEnv(t *testing.T) {
	env := func(v string) func(string) string {
		return func(k string) string {
			if k == pushnotify.EnvEnabled {
				return v
			}
			return ""
		}
	}
	if pushnotify.EnvEnabled != "GATEWAY_WEBPUSH_ENABLED" {
		t.Fatalf("EnvEnabled = %q", pushnotify.EnvEnabled)
	}
	for v, want := range map[string]bool{"": false, "false": false, "0": false, "true": true, "1": true, "TRUE": true} {
		cfg, err := pushnotify.ConfigFromEnv(env(v))
		if err != nil || cfg.Enabled != want {
			t.Errorf("ConfigFromEnv(%q) = %+v, %v; want Enabled=%v", v, cfg, err, want)
		}
	}
	if _, err := pushnotify.ConfigFromEnv(env("maybe")); err == nil || !strings.Contains(err.Error(), pushnotify.EnvEnabled) {
		t.Errorf("unparsable flag error = %v", err)
	}
}

func TestSubject(t *testing.T) {
	cases := []struct {
		base, contact, want string
		ok                  bool
	}{
		{"https://gw.example.com", "", "https://gw.example.com", true},
		{"https://gw.example.com", "ops@example.com", "https://gw.example.com", true},
		{"http://localhost:18080", "ops@example.com", "mailto:ops@example.com", true},
		{"http://localhost:18080", "", "", false},
		{"http://localhost:18080", "not an address", "", false},
	}
	for _, c := range cases {
		got, err := pushnotify.Subject(c.base, c.contact)
		if (err == nil) != c.ok || got != c.want {
			t.Errorf("Subject(%q, %q) = %q, %v; want %q ok=%v", c.base, c.contact, got, err, c.want, c.ok)
		}
	}
}

func TestNewValidates(t *testing.T) {
	kp := keyProvider(t)
	if _, err := pushnotify.New(nil, kp, pushnotify.Options{Subject: "https://gw.example.com"}); err == nil {
		t.Error("nil store accepted")
	}
	if _, err := pushnotify.New(newMemStore(), nil, pushnotify.Options{Subject: "https://gw.example.com"}); err == nil {
		t.Error("nil key provider accepted")
	}
	if _, err := pushnotify.New(newMemStore(), kp, pushnotify.Options{Subject: "http://gw.example.com"}); err == nil {
		t.Error("http subject accepted (webpush requires https or mailto)")
	}
}

func TestDeviceLabel(t *testing.T) {
	cases := map[string]string{
		"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Mobile Safari/537.36":                       "Android Chrome",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1": "iPhone Safari",
		"Mozilla/5.0 (iPad; CPU OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1":          "iPad Safari",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:131.0) Gecko/20100101 Firefox/131.0":                                                    "Mac Firefox",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36 Edg/129.0":                   "Windows Edge",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36":                                       "Linux Chrome",
		"Mozilla/5.0 (Linux; Android 14; SM-S921B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/26.0 Chrome/122.0 Mobile Safari/537.36":  "Android Samsung Internet",
		"":           "Browser",
		"curl/8.7.1": "Browser",
	}
	for ua, want := range cases {
		if got := pushnotify.DeviceLabel(ua); got != want {
			t.Errorf("DeviceLabel(%.40q) = %q, want %q", ua, got, want)
		}
	}
}

// Two replicas (services over one store) asking for the key at once end
// up with the same key; later calls are served from memory.
func TestPublicKeyCreatedOnceAndCached(t *testing.T) {
	f := newFixture(t)
	other, err := pushnotify.New(f.st, f.kp, pushnotify.Options{Subject: "https://gw.example.com", Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	keys := make([]string, 2)
	errs := make([]error, 2)
	for i, svc := range []*pushnotify.Service{f.svc, other} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			keys[i], errs[i] = svc.PublicKey(t.Context())
		}()
	}
	wg.Wait()
	if errs[0] != nil || errs[1] != nil {
		t.Fatalf("PublicKey errors: %v, %v", errs[0], errs[1])
	}
	raw, err := base64.RawURLEncoding.DecodeString(keys[0])
	if keys[0] != keys[1] || err != nil || len(raw) != 65 || raw[0] != 4 {
		t.Fatalf("keys = %q, %q (decode %v): want one uncompressed P-256 point", keys[0], keys[1], err)
	}
	// The private key is envelope-encrypted under the record's AAD.
	k := f.st.key
	if bytes.Contains(k.PrivateKey.Ciphertext, raw) || k.PrivateKey.KeyID != "k1" {
		t.Errorf("stored key = %+v", k)
	}
	if _, err := crypto.Decrypt(t.Context(), f.kp, crypto.AAD{Kind: pushnotify.KeyKind, RecordID: k.ID}, crypto.Envelope(k.PrivateKey)); err != nil {
		t.Errorf("private key does not open under {webpush_key, id}: %v", err)
	}
	reads := f.st.keyReads
	for range 3 {
		if _, err := f.svc.PublicKey(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if f.st.keyReads != reads {
		t.Errorf("key re-read %d times after it was cached", f.st.keyReads-reads)
	}
}

// A stored key that does not open (tampered row, wrong provider) is an
// error, never a silently replaced key.
func TestPublicKeyRefusesUnreadableKey(t *testing.T) {
	f := newFixture(t)
	if _, err := f.svc.PublicKey(t.Context()); err != nil {
		t.Fatal(err)
	}
	f.st.key.ID = "33333333-3333-4333-8333-333333333333" // AAD no longer matches
	fresh := newFixture(t)
	fresh.st.key = f.st.key
	if _, err := fresh.svc.PublicKey(t.Context()); err == nil {
		t.Fatal("unreadable key accepted")
	}
	if fresh.st.key.ID != f.st.key.ID {
		t.Error("unreadable key replaced")
	}
}

func TestSubscribeStoresSealedAndUpserts(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	endpoint, js := subscription(t, "fcm.googleapis.com")
	dev, err := f.svc.Subscribe(ctx, alice, js, "  My\tphone\n ")
	if err != nil {
		t.Fatal(err)
	}
	if dev.ID == "" || dev.Label != "My phone" || dev.Host != "fcm.googleapis.com" || dev.CreatedAt.IsZero() {
		t.Fatalf("device = %+v", dev)
	}
	rows := f.st.all()
	if len(rows) != 1 {
		t.Fatalf("rows = %d", len(rows))
	}
	row := rows[0]
	if bytes.Contains(row.Sealed.Ciphertext, []byte(endpoint)) || len(row.EndpointSHA256) != 32 || row.UserID != alice {
		t.Errorf("stored row = %+v", row)
	}
	plain, err := crypto.Decrypt(ctx, f.kp, crypto.AAD{UserID: alice, Kind: pushnotify.SubscriptionKind, RecordID: row.ID}, crypto.Envelope(row.Sealed))
	if err != nil || !strings.Contains(string(plain), endpoint) {
		t.Errorf("sealed subscription does not open under {alice, push_subscription, id}: %v", err)
	}

	// Re-subscribing the same endpoint (new keys after the browser
	// renewed them) updates the row in place.
	again, err := f.svc.Subscribe(ctx, alice, subscriptionFor(t, endpoint), "")
	if err != nil {
		t.Fatal(err)
	}
	rows = f.st.all()
	if len(rows) != 1 || again.ID != dev.ID || bytes.Equal(rows[0].Sealed.Ciphertext, row.Sealed.Ciphertext) {
		t.Errorf("re-subscribe: %d rows, id %s (was %s)", len(rows), again.ID, dev.ID)
	}
	if again.Label != "Browser" {
		t.Errorf("empty label = %q, want the generic default", again.Label)
	}

	// A long label is cut to MaxLabelLen characters.
	_, js2 := subscription(t, "web.push.apple.com")
	long, err := f.svc.Subscribe(ctx, alice, js2, strings.Repeat("ä", 150))
	if err != nil || len([]rune(long.Label)) != pushnotify.MaxLabelLen {
		t.Errorf("long label = %d runes, %v", len([]rune(long.Label)), err)
	}

	// Audit: user events, never the endpoint.
	if got := strings.Join(f.audit.actions(), ","); got != "push.subscribed,push.subscribed,push.subscribed" {
		t.Errorf("audit actions = %s", got)
	}
	for _, e := range f.audit.events {
		if e.UserID != alice || e.Tool != "" {
			t.Errorf("audit event = %+v", e)
		}
		for k, v := range e.ResourceIdentity {
			if strings.Contains(v, "/fcm/send/") || strings.Contains(k, "endpoint") {
				t.Errorf("audit leaks the endpoint: %s=%s", k, v)
			}
		}
	}
}

func TestSubscribeRejectsBadSubscriptions(t *testing.T) {
	f := newFixture(t)
	for name, js := range map[string][]byte{
		"not json":        []byte(`{`),
		"no keys":         []byte(`{"endpoint":"https://fcm.googleapis.com/fcm/send/x"}`),
		"internal host":   subscriptionFor(t, "https://169.254.169.254/latest"),
		"unknown service": subscriptionFor(t, "https://push.attacker.example/x"),
		"http":            subscriptionFor(t, "http://fcm.googleapis.com/fcm/send/x"),
		"too large":       append([]byte(`{"endpoint":"`), bytes.Repeat([]byte("a"), webpush.MaxSubscriptionJSON)...),
	} {
		_, err := f.svc.Subscribe(t.Context(), alice, js, "")
		if !errors.Is(err, pushnotify.ErrInvalidSubscription) {
			t.Errorf("%s: err = %v, want ErrInvalidSubscription", name, err)
		}
		if err != nil && strings.Contains(err.Error(), "/latest") {
			t.Errorf("%s: error names the endpoint path: %v", name, err)
		}
	}
	if n := len(f.st.all()); n != 0 {
		t.Errorf("stored %d bad subscriptions", n)
	}
}

func TestSubscribeCapIsPerUser(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	var first string
	for i := range pushnotify.MaxSubscriptionsPerUser {
		ep, js := subscription(t, "fcm.googleapis.com")
		if i == 0 {
			first = ep
		}
		if _, err := f.svc.Subscribe(ctx, alice, js, fmt.Sprint("device ", i)); err != nil {
			t.Fatalf("subscription %d: %v", i, err)
		}
	}
	_, js := subscription(t, "fcm.googleapis.com")
	if _, err := f.svc.Subscribe(ctx, alice, js, ""); !errors.Is(err, pushnotify.ErrLimit) {
		t.Fatalf("subscription over the cap = %v, want ErrLimit", err)
	}
	// Renewing an existing one is not a new subscription.
	if _, err := f.svc.Subscribe(ctx, alice, subscriptionFor(t, first), ""); err != nil {
		t.Errorf("renew at the cap: %v", err)
	}
	// Another user has their own budget.
	if _, err := f.svc.Subscribe(ctx, bob, js, ""); err != nil {
		t.Errorf("bob: %v", err)
	}
	if n := len(f.st.all()); n != pushnotify.MaxSubscriptionsPerUser+1 {
		t.Errorf("rows = %d", n)
	}
}

// One browser endpoint belongs to one account: subscribing it as bob hands
// it over from alice, so alice's approvals stop showing on that device.
func TestSubscribeHandsEndpointOver(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	endpoint, js := subscription(t, "web.push.apple.com")
	if _, err := f.svc.Subscribe(ctx, alice, js, "iPhone"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Subscribe(ctx, bob, subscriptionFor(t, endpoint), "iPhone"); err != nil {
		t.Fatalf("bob: %v", err)
	}
	if devs, _ := f.svc.Devices(ctx, alice); len(devs) != 0 {
		t.Errorf("alice still has %d devices", len(devs))
	}
	if devs, _ := f.svc.Devices(ctx, bob); len(devs) != 1 {
		t.Errorf("bob has %d devices", len(devs))
	}
}

func TestUnsubscribeAndRemoveDevice(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	ep1, js1 := subscription(t, "fcm.googleapis.com")
	_, js2 := subscription(t, "fcm.googleapis.com")
	if _, err := f.svc.Subscribe(ctx, alice, js1, "one"); err != nil {
		t.Fatal(err)
	}
	two, err := f.svc.Subscribe(ctx, alice, js2, "two")
	if err != nil {
		t.Fatal(err)
	}
	// Bob can neither turn off nor remove alice's devices.
	if err := f.svc.Unsubscribe(ctx, bob, ep1); err != nil {
		t.Errorf("bob unsubscribing an unknown endpoint = %v, want nil (idempotent)", err)
	}
	if err := f.svc.RemoveDevice(ctx, bob, two.ID); !errors.Is(err, pushnotify.ErrNotFound) {
		t.Errorf("bob removing alice's device = %v, want ErrNotFound", err)
	}
	if err := f.svc.RemoveDevice(ctx, alice, "not-a-uuid"); !errors.Is(err, pushnotify.ErrNotFound) {
		t.Errorf("malformed id = %v, want ErrNotFound", err)
	}
	if n := len(f.st.all()); n != 2 {
		t.Fatalf("rows after bob = %d", n)
	}
	if err := f.svc.Unsubscribe(ctx, alice, ep1); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Unsubscribe(ctx, alice, ep1); err != nil {
		t.Errorf("second unsubscribe = %v, want nil", err)
	}
	if err := f.svc.RemoveDevice(ctx, alice, two.ID); err != nil {
		t.Fatal(err)
	}
	if n := len(f.st.all()); n != 0 {
		t.Errorf("rows = %d", n)
	}
	got := strings.Join(f.audit.actions(), ",")
	if got != "push.subscribed,push.subscribed,push.unsubscribed,push.unsubscribed" {
		t.Errorf("audit actions = %s", got)
	}
}

func TestDevicesListsMetadataOnly(t *testing.T) {
	f := newFixture(t)
	_, js := subscription(t, "updates.push.services.mozilla.com")
	if _, err := f.svc.Subscribe(t.Context(), alice, js, "Firefox"); err != nil {
		t.Fatal(err)
	}
	devs, err := f.svc.Devices(t.Context(), alice)
	if err != nil || len(devs) != 1 {
		t.Fatalf("devices = %v, %v", devs, err)
	}
	out, _ := json.Marshal(devs[0])
	if strings.Contains(string(out), "/fcm/send/") || strings.Contains(strings.ToLower(string(out)), "endpoint\"") {
		t.Errorf("device carries the endpoint: %s", out)
	}
	if devs[0].Host != "updates.push.services.mozilla.com" || devs[0].LastSuccessAt != nil {
		t.Errorf("device = %+v", devs[0])
	}
}

func TestOnDisableUserDeletesSubscriptions(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	for _, u := range []string{alice, alice, bob} {
		_, js := subscription(t, "fcm.googleapis.com")
		if _, err := f.svc.Subscribe(ctx, u, js, ""); err != nil {
			t.Fatal(err)
		}
	}
	// A nil transaction: the hook opens its own (jobs scope).
	if err := f.svc.OnDisableUser(ctx, nil, alice); err != nil {
		t.Fatal(err)
	}
	rows := f.st.all()
	if len(rows) != 1 || rows[0].UserID != bob {
		t.Errorf("rows after disabling alice = %+v", rows)
	}
}
