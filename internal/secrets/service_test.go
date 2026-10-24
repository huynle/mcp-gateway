package secrets_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/secrets"
	"github.com/huynle/mcp-gateway/internal/secrets/secretstest"
	"github.com/huynle/mcp-gateway/internal/store"
)

const (
	alice   = "00000000-0000-4000-8000-00000000000a"
	bob     = "00000000-0000-4000-8000-00000000000b"
	harness = "tok-laptop"
	server  = "00000000-0000-4000-8000-0000000000f1"
	value   = "correct horse battery staple"
)

var binding = secrets.Binding{ServerID: server, Tool: "vault.login", Arg: "password"}

// clock is a settable fake time source.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type fixture struct {
	svc *secrets.Service
	mem *secretstest.MemStore
	clk *clock
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	keys, err := crypto.NewStaticProvider("k1", map[string][]byte{"k1": bytes.Repeat([]byte{7}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	mem := secretstest.NewMemStore()
	svc, err := secrets.New(mem, keys, secrets.Options{})
	if err != nil {
		t.Fatal(err)
	}
	clk := &clock{t: time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)}
	svc.SetClock(clk.Now)
	return &fixture{svc: svc, mem: mem, clk: clk}
}

func (f *fixture) request(t *testing.T, owner string, ttl time.Duration, uses int) secrets.Requested {
	t.Helper()
	r, err := f.svc.Request(context.Background(), owner, harness, "vault password", binding, ttl, uses)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	return r
}

func (f *fixture) provided(t *testing.T, owner string, ttl time.Duration, uses int) secrets.Requested {
	t.Helper()
	r := f.request(t, owner, ttl, uses)
	if _, err := f.svc.Provide(context.Background(), owner, r.RequestID, []byte(value)); err != nil {
		t.Fatalf("provide: %v", err)
	}
	return r
}

func TestNewRequiresStoreAndKeyProvider(t *testing.T) {
	keys, _ := crypto.NewStaticProvider("k1", map[string][]byte{"k1": bytes.Repeat([]byte{7}, 32)})
	if _, err := secrets.New(secretstest.NewMemStore(), nil, secrets.Options{}); err == nil {
		t.Error("New without a key provider succeeded")
	}
	if _, err := secrets.New(nil, keys, secrets.Options{}); err == nil {
		t.Error("New without a store succeeded")
	}
}

func TestRequestDefaultsAndLimitsOfTTLAndUses(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	cases := []struct {
		ttl      time.Duration
		uses     int
		wantTTL  time.Duration
		wantUses int
	}{
		{0, 0, 15 * time.Minute, 1},
		{2 * time.Hour, 50, time.Hour, 10},
		{time.Hour, 10, time.Hour, 10},
		{10 * time.Second, 3, time.Minute, 3},
		{30 * time.Minute, 1, 30 * time.Minute, 1},
	}
	for _, c := range cases {
		r, err := f.svc.Request(ctx, alice, harness, "label", binding, c.ttl, c.uses)
		if err != nil {
			t.Fatalf("request(%v, %d): %v", c.ttl, c.uses, err)
		}
		if r.Secret.TTL != c.wantTTL || r.Secret.UsesTotal != c.wantUses || r.Secret.UsesLeft != c.wantUses {
			t.Errorf("request(%v, %d) = ttl %v, uses %d/%d; want %v, %d", c.ttl, c.uses,
				r.Secret.TTL, r.Secret.UsesLeft, r.Secret.UsesTotal, c.wantTTL, c.wantUses)
		}
		if r.Secret.State != secrets.StatePending || r.Secret.ExpiresAt != nil ||
			!r.Secret.LinkExpiresAt.Equal(f.clk.Now().Add(secrets.LinkTTL)) {
			t.Errorf("request record = %+v", r.Secret)
		}
		// Keep under the pending limit.
		if _, err := f.svc.Deny(ctx, alice, r.RequestID); err != nil {
			t.Fatal(err)
		}
	}
	for name, try := range map[string]func() error{
		"negative ttl":  func() error { _, err := f.svc.Request(ctx, alice, harness, "l", binding, -time.Second, 1); return err },
		"negative uses": func() error { _, err := f.svc.Request(ctx, alice, harness, "l", binding, 0, -1); return err },
		"no label":      func() error { _, err := f.svc.Request(ctx, alice, harness, "  ", binding, 0, 0); return err },
		"long label": func() error {
			_, err := f.svc.Request(ctx, alice, harness, strings.Repeat("x", 101), binding, 0, 0)
			return err
		},
		"no harness": func() error { _, err := f.svc.Request(ctx, alice, "", "l", binding, 0, 0); return err },
		"no server": func() error {
			_, err := f.svc.Request(ctx, alice, harness, "l", secrets.Binding{Tool: "t"}, 0, 0)
			return err
		},
		"no tool": func() error {
			_, err := f.svc.Request(ctx, alice, harness, "l", secrets.Binding{ServerID: server}, 0, 0)
			return err
		},
		"no owner": func() error { _, err := f.svc.Request(ctx, "", harness, "l", binding, 0, 0); return err },
	} {
		if err := try(); !errors.Is(err, secrets.ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
}

func TestRequestReturnsRandomValuesAndStoresOnlyHashes(t *testing.T) {
	f := newFixture(t)
	a := f.request(t, alice, 0, 0)
	b := f.request(t, alice, 0, 0)
	if !strings.HasPrefix(a.Handle, secrets.HandlePrefix) || !secrets.ValidHandle(a.Handle) {
		t.Errorf("handle %q is not a valid sec_ handle", a.Handle)
	}
	if len(a.Handle) < len(secrets.HandlePrefix)+43 || len(a.RequestID) < 43 {
		t.Errorf("values too short for 256 bits: handle %q, request %q", a.Handle, a.RequestID)
	}
	if a.Handle == b.Handle || a.RequestID == b.RequestID || a.RequestID == a.Handle {
		t.Error("values repeat")
	}
	if secrets.RequestIDForHandle(a.Handle) != a.RequestID {
		t.Error("request id is not derived from the handle")
	}
	rec := f.mem.Record(a.Secret.ID)
	if rec == nil {
		t.Fatal("no stored record")
	}
	for _, raw := range []string{a.Handle, a.RequestID} {
		if bytes.Contains(rec.RequestHash, []byte(raw)) || bytes.Contains(rec.HandleHash, []byte(raw)) || len(rec.RequestHash) != 32 || len(rec.HandleHash) != 32 {
			t.Errorf("stored hashes carry the raw value or are not SHA-256")
		}
	}
	if rec.OwnerUserID != alice || rec.HarnessID != harness || rec.ServerID != server || rec.Tool != "vault.login" || rec.Arg == nil || *rec.Arg != "password" {
		t.Errorf("stored binding = %+v", rec)
	}
	// A machine action has no argument: stored as NULL.
	r, err := f.svc.Request(context.Background(), alice, harness, "sudo", secrets.Binding{ServerID: server, Tool: "box-actions.apt-upgrade"}, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if f.mem.Record(r.Secret.ID).Arg != nil {
		t.Error("machine action binding stored an argument")
	}
}

func TestValidHandleIsLenient(t *testing.T) {
	for h, want := range map[string]bool{
		"sec_" + strings.Repeat("a", 43):       true,
		"sec_" + strings.Repeat("Z9", 20):      true,
		"sec_short":                            false,
		"sec_" + strings.Repeat("a", 42) + "-": false,
		"tok_" + strings.Repeat("a", 43):       false,
		"":                                     false,
		"sec_" + strings.Repeat("a", 200):      false,
	} {
		if got := secrets.ValidHandle(h); got != want {
			t.Errorf("ValidHandle(%q) = %v, want %v", h, got, want)
		}
	}
}

func TestGenerateHookIsReplaceable(t *testing.T) {
	f := newFixture(t)
	orig := secrets.GenerateHandle
	t.Cleanup(func() { secrets.GenerateHandle = orig })
	secrets.GenerateHandle = func() (string, error) { return "sec_" + strings.Repeat("Q", 43), nil }
	r := f.request(t, alice, 0, 0)
	if r.Handle != "sec_"+strings.Repeat("Q", 43) || r.RequestID != secrets.RequestIDForHandle(r.Handle) {
		t.Errorf("hook not used: %q", r.Handle)
	}
}

func TestRequestLimits(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	var first secrets.Requested
	for i := range secrets.MaxPendingPerOwner {
		r := f.request(t, alice, 0, 0)
		if i == 0 {
			first = r
		}
	}
	if _, err := f.svc.Request(ctx, alice, harness, "l", binding, 0, 0); !errors.Is(err, secrets.ErrLimited) {
		t.Fatalf("pending over the limit = %v, want ErrLimited", err)
	}
	// Another user is not affected.
	f.request(t, bob, 0, 0)
	// Answering one frees a pending slot.
	if _, err := f.svc.Deny(ctx, alice, first.RequestID); err != nil {
		t.Fatal(err)
	}
	f.request(t, alice, 0, 0)

	// Rolling hour: links expire after 10 minutes, so pending is not the
	// limit; the hourly count is.
	made := secrets.MaxPendingPerOwner + 1
	for made < secrets.MaxRequestsPerHour {
		f.clk.Advance(secrets.LinkTTL + time.Second)
		for i := 0; i < secrets.MaxPendingPerOwner && made < secrets.MaxRequestsPerHour; i++ {
			f.request(t, alice, 0, 0)
			made++
		}
	}
	f.clk.Advance(secrets.LinkTTL + time.Second)
	if _, err := f.svc.Request(ctx, alice, harness, "l", binding, 0, 0); !errors.Is(err, secrets.ErrLimited) {
		t.Fatalf("request %d within the hour = %v, want ErrLimited", made+1, err)
	}
	f.clk.Advance(time.Hour)
	f.request(t, alice, 0, 0)
}

func TestLookupRequestHidesEverythingButALiveOwnPendingLink(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	r := f.request(t, alice, 0, 0)
	got, err := f.svc.LookupRequest(ctx, alice, r.RequestID)
	if err != nil || got.ID != r.Secret.ID || got.Label != "vault password" || got.Binding != binding || got.HarnessID != harness {
		t.Fatalf("lookup = %+v, %v", got, err)
	}
	for name, try := range map[string]func() error{
		"other owner": func() error { _, err := f.svc.LookupRequest(ctx, bob, r.RequestID); return err },
		"garbage":     func() error { _, err := f.svc.LookupRequest(ctx, alice, "../x"); return err },
		"unknown":     func() error { _, err := f.svc.LookupRequest(ctx, alice, strings.Repeat("a", 43)); return err },
		"handle":      func() error { _, err := f.svc.LookupRequest(ctx, alice, r.Handle); return err },
	} {
		if err := try(); !errors.Is(err, secrets.ErrNotFound) {
			t.Errorf("%s: %v, want ErrNotFound", name, err)
		}
	}
	// Answered: not found.
	if _, err := f.svc.Provide(ctx, alice, r.RequestID, []byte(value)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.LookupRequest(ctx, alice, r.RequestID); !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("provided: %v, want ErrNotFound", err)
	}
	// Link expired: not found, cannot be provided or denied.
	e := f.request(t, alice, 0, 0)
	f.clk.Advance(secrets.LinkTTL)
	if _, err := f.svc.LookupRequest(ctx, alice, e.RequestID); !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("expired link: %v, want ErrNotFound", err)
	}
	if _, err := f.svc.Provide(ctx, alice, e.RequestID, []byte(value)); !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("provide after link expiry: %v, want ErrNotFound", err)
	}
	if _, err := f.svc.Deny(ctx, alice, e.RequestID); !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("deny after link expiry: %v, want ErrNotFound", err)
	}
}

func TestProvideValidatesEncryptsAndIsSingleUse(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	r := f.request(t, alice, 20*time.Minute, 2)
	if _, err := f.svc.Provide(ctx, alice, r.RequestID, []byte("1234567")); !errors.Is(err, secrets.ErrTooShort) {
		t.Fatalf("7 bytes = %v, want ErrTooShort", err)
	}
	if _, err := f.svc.Provide(ctx, alice, r.RequestID, bytes.Repeat([]byte("x"), secrets.MaxValueLen+1)); !errors.Is(err, secrets.ErrTooLong) {
		t.Fatalf("too long = %v, want ErrTooLong", err)
	}
	if _, err := f.svc.Provide(ctx, bob, r.RequestID, []byte(value)); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("bob provides = %v, want ErrNotFound", err)
	}
	// Still pending after the refusals.
	if _, err := f.svc.LookupRequest(ctx, alice, r.RequestID); err != nil {
		t.Fatalf("lookup after refusals: %v", err)
	}
	f.clk.Advance(time.Minute)
	got, err := f.svc.Provide(ctx, alice, r.RequestID, []byte(value))
	if err != nil {
		t.Fatal(err)
	}
	if got.State != secrets.StateProvided || got.ExpiresAt == nil || !got.ExpiresAt.Equal(f.clk.Now().Add(20*time.Minute)) ||
		!got.HasValue || got.UsesLeft != 2 {
		t.Fatalf("provided = %+v", got)
	}
	rec := f.mem.Record(r.Secret.ID)
	if rec.Value == nil || bytes.Contains(rec.Value.Ciphertext, []byte(value)) {
		t.Fatal("value not stored encrypted")
	}
	if _, err := f.svc.Provide(ctx, alice, r.RequestID, []byte(value)); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("second provide = %v, want ErrNotFound", err)
	}
	// The envelope is bound to the record (AAD): moved to another row it
	// does not open.
	other := f.provided(t, alice, 0, 1)
	f.mem.SwapValue(r.Secret.ID, other.Secret.ID)
	if _, err := f.svc.Consume(ctx, alice, harness, other.Handle, binding); err == nil || errors.Is(err, secrets.ErrUnavailable) {
		t.Fatalf("consume with a moved envelope = %v, want a decryption error", err)
	}
	if f.mem.Record(other.Secret.ID).UsesLeft != 1 {
		t.Error("a failed decryption consumed a use")
	}
}

func TestConsumeHappyPathAndUses(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	r := f.provided(t, alice, 0, 2)
	for i := range 2 {
		c, err := f.svc.Consume(ctx, alice, harness, r.Handle, binding)
		if err != nil || string(c.Value) != value || c.SecretID != r.Secret.ID || c.Label != "vault password" {
			t.Fatalf("consume %d = %+v, %v", i, c, err)
		}
	}
	if _, err := f.svc.Consume(ctx, alice, harness, r.Handle, binding); !errors.Is(err, secrets.ErrUnavailable) {
		t.Fatalf("used up = %v, want ErrUnavailable", err)
	}
}

func TestConsumeMismatchesAreOneGenericError(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	r := f.provided(t, alice, 0, 5)
	noArg := binding
	noArg.Arg = ""
	cases := map[string]func() error{
		"other owner":   func() error { _, err := f.svc.Consume(ctx, bob, harness, r.Handle, binding); return err },
		"other harness": func() error { _, err := f.svc.Consume(ctx, alice, "tok-other", r.Handle, binding); return err },
		"other server": func() error {
			b := binding
			b.ServerID = "00000000-0000-4000-8000-0000000000f2"
			_, err := f.svc.Consume(ctx, alice, harness, r.Handle, b)
			return err
		},
		"other tool": func() error {
			b := binding
			b.Tool = "vault.read"
			_, err := f.svc.Consume(ctx, alice, harness, r.Handle, b)
			return err
		},
		"other arg": func() error {
			b := binding
			b.Arg = "token"
			_, err := f.svc.Consume(ctx, alice, harness, r.Handle, b)
			return err
		},
		"no arg":         func() error { _, err := f.svc.Consume(ctx, alice, harness, r.Handle, noArg); return err },
		"garbage handle": func() error { _, err := f.svc.Consume(ctx, alice, harness, "sec_!!", binding); return err },
		"unknown handle": func() error {
			_, err := f.svc.Consume(ctx, alice, harness, "sec_"+strings.Repeat("b", 43), binding)
			return err
		},
		"request id as handle": func() error { _, err := f.svc.Consume(ctx, alice, harness, r.RequestID, binding); return err },
	}
	var msg string
	for name, try := range cases {
		err := try()
		if !errors.Is(err, secrets.ErrUnavailable) {
			t.Errorf("%s: %v, want ErrUnavailable", name, err)
			continue
		}
		if msg == "" {
			msg = err.Error()
		} else if err.Error() != msg {
			t.Errorf("%s: message %q differs from %q", name, err.Error(), msg)
		}
	}
	if got := f.mem.Record(r.Secret.ID).UsesLeft; got != 5 {
		t.Errorf("mismatches consumed uses: %d left", got)
	}
}

func TestConsumePendingDeniedRevokedExpired(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	p := f.request(t, alice, 0, 1)
	if _, err := f.svc.Consume(ctx, alice, harness, p.Handle, binding); !errors.Is(err, secrets.ErrPending) {
		t.Errorf("pending = %v, want ErrPending", err)
	}
	// Pending but someone else's harness: generic.
	if _, err := f.svc.Consume(ctx, alice, "tok-other", p.Handle, binding); !errors.Is(err, secrets.ErrUnavailable) {
		t.Errorf("pending, other harness = %v, want ErrUnavailable", err)
	}
	if _, err := f.svc.Consume(ctx, bob, harness, p.Handle, binding); !errors.Is(err, secrets.ErrUnavailable) {
		t.Errorf("pending, other owner = %v, want ErrUnavailable", err)
	}

	d := f.request(t, alice, 0, 1)
	if _, err := f.svc.Deny(ctx, alice, d.RequestID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Consume(ctx, alice, harness, d.Handle, binding); !errors.Is(err, secrets.ErrDenied) {
		t.Errorf("denied = %v, want ErrDenied", err)
	}
	if _, err := f.svc.Consume(ctx, alice, "tok-other", d.Handle, binding); !errors.Is(err, secrets.ErrUnavailable) {
		t.Errorf("denied, other harness = %v, want ErrUnavailable", err)
	}

	rv := f.provided(t, alice, 0, 3)
	if _, err := f.svc.Revoke(ctx, bob, rv.Secret.ID); !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("bob revokes = %v, want ErrNotFound", err)
	}
	got, err := f.svc.Revoke(ctx, alice, rv.Secret.ID)
	if err != nil || got.State != secrets.StateRevoked || got.HasValue {
		t.Fatalf("revoke = %+v, %v", got, err)
	}
	if _, err := f.svc.Revoke(ctx, alice, rv.Secret.ID); !errors.Is(err, secrets.ErrNotFound) {
		t.Errorf("second revoke = %v, want ErrNotFound", err)
	}
	if _, err := f.svc.Consume(ctx, alice, harness, rv.Handle, binding); !errors.Is(err, secrets.ErrUnavailable) {
		t.Errorf("revoked = %v, want ErrUnavailable", err)
	}

	e := f.provided(t, alice, time.Minute, 3)
	f.clk.Advance(time.Minute)
	if _, err := f.svc.Consume(ctx, alice, harness, e.Handle, binding); !errors.Is(err, secrets.ErrUnavailable) {
		t.Errorf("ttl passed = %v, want ErrUnavailable", err)
	}
	// A pending request whose link expired is unavailable, not pending.
	pl := f.request(t, alice, 0, 1)
	f.clk.Advance(secrets.LinkTTL)
	if _, err := f.svc.Consume(ctx, alice, harness, pl.Handle, binding); !errors.Is(err, secrets.ErrUnavailable) {
		t.Errorf("expired link = %v, want ErrUnavailable", err)
	}
}

func TestRefundIsCappedAndOnlyWhileUsable(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	r := f.provided(t, alice, 5*time.Minute, 1)
	if err := f.svc.Refund(ctx, alice, r.Secret.ID); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("refund at full uses = %v, want ErrNotFound", err)
	}
	if _, err := f.svc.Consume(ctx, alice, harness, r.Handle, binding); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Refund(ctx, bob, r.Secret.ID); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("bob refunds = %v, want ErrNotFound", err)
	}
	if err := f.svc.Refund(ctx, alice, r.Secret.ID); err != nil {
		t.Fatalf("refund: %v", err)
	}
	if err := f.svc.Refund(ctx, alice, r.Secret.ID); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("refund above uses_total = %v, want ErrNotFound", err)
	}
	if _, err := f.svc.Consume(ctx, alice, harness, r.Handle, binding); err != nil {
		t.Fatalf("consume after refund: %v", err)
	}
	f.clk.Advance(5 * time.Minute)
	if err := f.svc.Refund(ctx, alice, r.Secret.ID); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("refund after expiry = %v, want ErrNotFound", err)
	}
}

func TestStatus(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	r := f.request(t, alice, 0, 1)
	st, err := f.svc.Status(ctx, alice, harness, r.Handle)
	if err != nil || st.Status != secrets.StatusPending || st.RequestID != r.RequestID || st.Secret == nil || st.Secret.ID != r.Secret.ID {
		t.Fatalf("pending status = %+v, %v", st, err)
	}
	for name, try := range map[string]func() (secrets.StatusResult, error){
		"other owner":   func() (secrets.StatusResult, error) { return f.svc.Status(ctx, bob, harness, r.Handle) },
		"other harness": func() (secrets.StatusResult, error) { return f.svc.Status(ctx, alice, "tok-x", r.Handle) },
		"garbage":       func() (secrets.StatusResult, error) { return f.svc.Status(ctx, alice, harness, "nope") },
	} {
		st, err := try()
		if err != nil || st.Status != secrets.StatusUnavailable || st.Secret != nil || st.RequestID != "" {
			t.Errorf("%s: %+v, %v; want unavailable with nothing else", name, st, err)
		}
	}
	if _, err := f.svc.Provide(ctx, alice, r.RequestID, []byte(value)); err != nil {
		t.Fatal(err)
	}
	if st, err := f.svc.Status(ctx, alice, harness, r.Handle); err != nil || st.Status != secrets.StatusProvided || st.RequestID != "" {
		t.Fatalf("provided status = %+v, %v", st, err)
	}
	if _, err := f.svc.Consume(ctx, alice, harness, r.Handle, binding); err != nil {
		t.Fatal(err)
	}
	if st, _ := f.svc.Status(ctx, alice, harness, r.Handle); st.Status != secrets.StatusUnavailable {
		t.Fatalf("used up status = %+v", st)
	}
	d := f.request(t, alice, 0, 1)
	if _, err := f.svc.Deny(ctx, alice, d.RequestID); err != nil {
		t.Fatal(err)
	}
	if st, _ := f.svc.Status(ctx, alice, harness, d.Handle); st.Status != secrets.StatusDenied {
		t.Fatalf("denied status = %+v", st)
	}
	l := f.request(t, alice, 0, 1)
	f.clk.Advance(secrets.LinkTTL)
	if st, _ := f.svc.Status(ctx, alice, harness, l.Handle); st.Status != secrets.StatusUnavailable {
		t.Fatalf("expired link status = %+v", st)
	}
}

func TestListShowsOnlyOwnRowsWithoutValues(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.provided(t, alice, 0, 1)
	f.clk.Advance(time.Second)
	p := f.request(t, alice, 0, 1)
	f.request(t, bob, 0, 1)
	list, err := f.svc.List(ctx, alice)
	if err != nil || len(list) != 2 || list[0].ID != p.Secret.ID || list[1].State != secrets.StateProvided || !list[1].HasValue {
		t.Fatalf("list = %+v, %v", list, err)
	}
}

func TestExpireWipesAndDeletes(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	used := f.provided(t, alice, time.Hour, 1)
	if _, err := f.svc.Consume(ctx, alice, harness, used.Handle, binding); err != nil {
		t.Fatal(err)
	}
	ttl := f.provided(t, alice, time.Minute, 1)
	live := f.provided(t, alice, time.Hour, 1)
	link := f.request(t, alice, 0, 1)
	f.clk.Advance(secrets.LinkTTL)
	res, err := f.svc.Expire(ctx)
	if err != nil || res.Expired != 3 || res.Deleted != 0 {
		t.Fatalf("expire = %+v, %v; want 3 expired", res, err)
	}
	for _, id := range []string{used.Secret.ID, ttl.Secret.ID, link.Secret.ID} {
		if r := f.mem.Record(id); r.State != store.SecretExpired || r.Value != nil || r.EndedAt == nil {
			t.Errorf("%s = %+v", id, r)
		}
	}
	if r := f.mem.Record(live.Secret.ID); r.State != store.SecretProvided || r.Value == nil {
		t.Errorf("live = %+v", r)
	}
	f.clk.Advance(secrets.Retention)
	res, err = f.svc.Expire(ctx)
	if err != nil || res.Deleted != 3 || res.Expired != 1 {
		t.Fatalf("second expire = %+v, %v; want 1 expired (live TTL), 3 deleted", res, err)
	}
	if f.mem.Record(used.Secret.ID) != nil {
		t.Error("ended row not deleted after retention")
	}

	job := f.svc.ExpiryJob(0)
	if job.Name() != "secrets.expire" || job.Interval() != 30*time.Second {
		t.Errorf("job = %s every %v", job.Name(), job.Interval())
	}
	if err := job.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if f.svc.ExpiryJob(time.Minute).Interval() != time.Minute {
		t.Error("interval override ignored")
	}
}

func TestOnDisableUserRevokesAndWipes(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	p := f.provided(t, alice, 0, 1)
	q := f.request(t, alice, 0, 1)
	b := f.provided(t, bob, 0, 1)
	// nil tx: the hook opens its own jobs transaction (non-PostgreSQL
	// identity store), like the tokens hook.
	if err := f.svc.OnDisableUser(ctx, nil, alice); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{p.Secret.ID, q.Secret.ID} {
		if r := f.mem.Record(id); r.State != store.SecretRevoked || r.Value != nil {
			t.Errorf("%s = %+v", id, r)
		}
	}
	if r := f.mem.Record(b.Secret.ID); r.State != store.SecretProvided {
		t.Errorf("bob's = %+v", r)
	}
}

func TestConfigFromEnv(t *testing.T) {
	env := map[string]string{}
	get := func(k string) string { return env[k] }
	cfg, err := secrets.ConfigFromEnv(get)
	if err != nil || cfg.Enabled {
		t.Fatalf("default = %+v, %v", cfg, err)
	}
	env[secrets.EnvEnabled] = "true"
	if cfg, err = secrets.ConfigFromEnv(get); err != nil || !cfg.Enabled {
		t.Fatalf("enabled = %+v, %v", cfg, err)
	}
	env[secrets.EnvEnabled] = "maybe"
	if _, err = secrets.ConfigFromEnv(get); err == nil {
		t.Fatal("bad bool accepted")
	}
}
