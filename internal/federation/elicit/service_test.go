package elicit_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/huynle/mcp-gateway/internal/federation/elicit"
	"github.com/huynle/mcp-gateway/internal/jobs"
)

var _ jobs.Job = (*elicit.ExpiryJob)(nil)

const (
	alice    = "0b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d"
	bob      = "1c2d3e4f-5061-4b7c-9d8e-0f1a2b3c4d5e"
	server   = "2d3e4f50-6172-4c8d-ae9f-1a2b3c4d5e6f"
	harness  = "tok-claude"
	upURL    = "https://connect.example.com/start?state=abc"
	upID     = "up-123"
	upMsgRaw = "Please connect your account"
)

// clock is a settable time source safe for the race detector.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type fixture struct {
	svc *elicit.Service
	mem *memStore
	clk *clock
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	mem := newMemStore()
	svc, err := elicit.New(mem, elicit.Options{Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	clk := &clock{t: time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)}
	svc.SetClock(clk.Now)
	return &fixture{svc: svc, mem: mem, clk: clk}
}

func (f *fixture) create(t *testing.T, owner string) (string, elicit.Elicitation) {
	t.Helper()
	link, rec, err := f.svc.Create(context.Background(), owner, harness, server, upURL, upID, upMsgRaw)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	return link, rec
}

func TestNewNeedsAStore(t *testing.T) {
	if _, err := elicit.New(nil, elicit.Options{}); err == nil {
		t.Error("New(nil) succeeded")
	}
}

func TestCreateStoresOnlyTheLinkHash(t *testing.T) {
	f := newFixture(t)
	link, rec := f.create(t, alice)
	if len(link) != 43 || strings.Trim(link, "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") != "" {
		t.Errorf("link id %q is not 43 base62 characters", link)
	}
	if rec.ID == "" || rec.OwnerUserID != alice || rec.ServerID != server || rec.HarnessID != harness || rec.URL != upURL ||
		rec.UpstreamElicitationID != upID || rec.Message != upMsgRaw {
		t.Errorf("record = %+v", rec)
	}
	if want := f.clk.Now().Add(elicit.LinkTTL); !rec.ExpiresAt.Equal(want) || elicit.LinkTTL != 10*time.Minute {
		t.Errorf("expires = %v, want %v (10 minutes)", rec.ExpiresAt, want)
	}
	rows := f.mem.all()
	if len(rows) != 1 {
		t.Fatalf("rows = %d", len(rows))
	}
	h := sha256.Sum256([]byte(link))
	if string(rows[0].LinkHash) != string(h[:]) {
		t.Error("stored link hash is not SHA-256 of the link id")
	}
	// Two links never collide.
	other, _ := f.create(t, alice)
	if other == link {
		t.Error("two links are equal")
	}
}

func TestCreateValidates(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	long := strings.Repeat("a", 2049)
	for name, c := range map[string]struct{ owner, harness, server, url, upID string }{
		"no owner":         {"", harness, server, upURL, upID},
		"owner not a uuid": {"alice", harness, server, upURL, upID},
		"server not uuid":  {alice, harness, "srv", upURL, upID},
		"no url":           {alice, harness, server, "", upID},
		"http url":         {alice, harness, server, "http://connect.example.com/", upID},
		"relative url":     {alice, harness, server, "/connect", upID},
		"userinfo":         {alice, harness, server, "https://u:p@connect.example.com/", upID},
		"control char":     {alice, harness, server, "https://connect.example.com/\n", upID},
		"url too long":     {alice, harness, server, "https://connect.example.com/" + long, upID},
		"harness too long": {alice, strings.Repeat("h", 201), server, upURL, upID},
		"id too long":      {alice, harness, server, upURL, strings.Repeat("i", 201)},
	} {
		if _, _, err := f.svc.Create(ctx, c.owner, c.harness, c.server, c.url, c.upID, ""); !errors.Is(err, elicit.ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
	if n := len(f.mem.all()); n != 0 {
		t.Errorf("%d rows stored", n)
	}
}

func TestCreateCleansTheMessage(t *testing.T) {
	f := newFixture(t)
	msg := "line one\nline\x00two\x1b[31m " + strings.Repeat("é", 600)
	_, rec, err := f.svc.Create(context.Background(), alice, harness, server, upURL, upID, msg)
	if err != nil {
		t.Fatal(err)
	}
	if utf8.RuneCountInString(rec.Message) > elicit.MaxMessageLen || elicit.MaxMessageLen != 500 {
		t.Errorf("message has %d characters, want <= 500", utf8.RuneCountInString(rec.Message))
	}
	if strings.ContainsAny(rec.Message, "\x00\x1b") {
		t.Errorf("message keeps control characters: %q", rec.Message)
	}
	if !strings.HasPrefix(rec.Message, "line one\nline") {
		t.Errorf("message = %q, want newlines kept", rec.Message[:20])
	}
	// Invalid UTF-8 is replaced, not stored.
	_, rec, err = f.svc.Create(context.Background(), alice, harness, server, upURL, upID, "bad \xff byte")
	if err != nil || !utf8.ValidString(rec.Message) {
		t.Errorf("invalid utf-8 message = %q, %v", rec.Message, err)
	}
}

func TestCreateCapsLiveElicitationsPerOwner(t *testing.T) {
	f := newFixture(t)
	for range elicit.MaxLivePerOwner {
		f.create(t, alice)
	}
	ctx := context.Background()
	if _, _, err := f.svc.Create(ctx, alice, harness, server, upURL, upID, ""); !errors.Is(err, elicit.ErrLimited) {
		t.Fatalf("21st live = %v, want ErrLimited", err)
	}
	if elicit.MaxLivePerOwner != 20 {
		t.Errorf("MaxLivePerOwner = %d, want 20", elicit.MaxLivePerOwner)
	}
	// Other owners are not affected.
	f.create(t, bob)
	// Expired ones free every slot.
	f.clk.Add(elicit.LinkTTL)
	if _, _, err := f.svc.Create(ctx, alice, harness, server, upURL, upID, ""); err != nil {
		t.Errorf("after expiry = %v", err)
	}
}

func TestCancelFreesASlot(t *testing.T) {
	f := newFixture(t)
	var first string
	for i := range elicit.MaxLivePerOwner {
		l, _ := f.create(t, alice)
		if i == 0 {
			first = l
		}
	}
	if _, err := f.svc.Cancel(context.Background(), alice, first); err != nil {
		t.Fatal(err)
	}
	f.create(t, alice)
}

func TestLookupOpenCancel(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	link, rec := f.create(t, alice)

	got, err := f.svc.Lookup(ctx, alice, link)
	if err != nil || got.ID != rec.ID || got.URL != upURL {
		t.Fatalf("lookup = %+v, %v", got, err)
	}
	// Someone else, a malformed or unknown id: not found.
	for name, c := range map[string]struct{ owner, link string }{
		"other user": {bob, link},
		"unknown":    {alice, strings.Repeat("Z", 43)},
		"malformed":  {alice, "../../etc"},
		"empty":      {alice, ""},
		"bad owner":  {"x", link},
	} {
		if _, err := f.svc.Lookup(ctx, c.owner, c.link); !errors.Is(err, elicit.ErrNotFound) {
			t.Errorf("lookup %s = %v, want ErrNotFound", name, err)
		}
		if _, err := f.svc.Open(ctx, c.owner, c.link); !errors.Is(err, elicit.ErrNotFound) {
			t.Errorf("open %s = %v, want ErrNotFound", name, err)
		}
		if _, err := f.svc.Cancel(ctx, c.owner, c.link); !errors.Is(err, elicit.ErrNotFound) {
			t.Errorf("cancel %s = %v, want ErrNotFound", name, err)
		}
	}
	// Open returns the stored URL and may be repeated within the TTL.
	o, err := f.svc.Open(ctx, alice, link)
	if err != nil || o.URL != upURL || o.OpenedAt == nil {
		t.Fatalf("open = %+v, %v", o, err)
	}
	f.clk.Add(time.Minute)
	again, err := f.svc.Open(ctx, alice, link)
	if err != nil || again.URL != upURL || !again.OpenedAt.Equal(*o.OpenedAt) {
		t.Errorf("second open = %+v, %v", again, err)
	}
	// Cancel ends it.
	c, err := f.svc.Cancel(ctx, alice, link)
	if err != nil || c.CancelledAt == nil {
		t.Fatalf("cancel = %+v, %v", c, err)
	}
	if _, err := f.svc.Open(ctx, alice, link); !errors.Is(err, elicit.ErrNotFound) {
		t.Errorf("open after cancel = %v", err)
	}
	if _, err := f.svc.Lookup(ctx, alice, link); !errors.Is(err, elicit.ErrNotFound) {
		t.Errorf("lookup after cancel = %v", err)
	}
}

func TestExpiredIsNotFound(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	link, _ := f.create(t, alice)
	f.clk.Add(elicit.LinkTTL - time.Second)
	if _, err := f.svc.Lookup(ctx, alice, link); err != nil {
		t.Fatalf("just before expiry = %v", err)
	}
	f.clk.Add(time.Second)
	if _, err := f.svc.Lookup(ctx, alice, link); !errors.Is(err, elicit.ErrNotFound) {
		t.Errorf("at expiry lookup = %v", err)
	}
	if _, err := f.svc.Open(ctx, alice, link); !errors.Is(err, elicit.ErrNotFound) {
		t.Errorf("at expiry open = %v", err)
	}
}

func TestExpireDeletesRowsADayAfterExpiry(t *testing.T) {
	f := newFixture(t)
	f.create(t, alice)
	f.clk.Add(elicit.LinkTTL + elicit.Retention - time.Second)
	f.create(t, bob)
	n, err := f.svc.Expire(context.Background())
	if err != nil || n != 0 {
		t.Fatalf("expire before retention = %d, %v", n, err)
	}
	f.clk.Add(time.Second)
	n, err = f.svc.Expire(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("expire = %d, %v; want 1", n, err)
	}
	if rows := f.mem.all(); len(rows) != 1 || rows[0].OwnerUserID != bob {
		t.Errorf("rows = %+v", rows)
	}
	if elicit.Retention != 24*time.Hour {
		t.Errorf("Retention = %v", elicit.Retention)
	}
}

func TestExpiryJob(t *testing.T) {
	f := newFixture(t)
	j := f.svc.ExpiryJob(0)
	if j.Name() != "elicit.expire" || j.Interval() != elicit.DefaultExpiryInterval {
		t.Errorf("job = %s every %v", j.Name(), j.Interval())
	}
	if j := f.svc.ExpiryJob(time.Second); j.Interval() != time.Second {
		t.Errorf("interval = %v", j.Interval())
	}
	f.create(t, alice)
	f.clk.Add(elicit.LinkTTL + elicit.Retention)
	if err := j.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := len(f.mem.all()); n != 0 {
		t.Errorf("rows after job = %d", n)
	}
}

func TestElicitationIDIsStableAndOpaque(t *testing.T) {
	f := newFixture(t)
	_, a := f.create(t, alice)
	_, b := f.create(t, alice)
	id := elicit.ElicitationID(a)
	if !strings.HasPrefix(id, elicit.ElicitationIDPrefix) || elicit.ElicitationIDPrefix != "gwe_" {
		t.Errorf("id %q lacks gwe_", id)
	}
	if id != elicit.ElicitationID(a) {
		t.Error("ElicitationID is not stable")
	}
	if id == elicit.ElicitationID(b) {
		t.Error("two records share an elicitation id")
	}
	if strings.Contains(id, a.ID) || strings.Contains(id, strings.ReplaceAll(a.ID, "-", "")) {
		t.Errorf("id %q exposes the record uuid", id)
	}
	if !elicit.ValidElicitationID(id) || elicit.ValidElicitationID("gwe_x") || elicit.ValidElicitationID(a.ID) {
		t.Error("ValidElicitationID")
	}
}

func TestStoreErrorsPassThrough(t *testing.T) {
	f := newFixture(t)
	boom := errors.New("db down")
	f.mem.failCreate = boom
	if _, _, err := f.svc.Create(context.Background(), alice, harness, server, upURL, upID, ""); !errors.Is(err, boom) {
		t.Errorf("create = %v, want the store error", err)
	}
}
