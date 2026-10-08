package connections_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/store"
)

// memNotifier records notifications.
type memNotifier struct {
	mu    sync.Mutex
	notes []connections.Notification
}

func (m *memNotifier) Notify(_ context.Context, n connections.Notification) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.notes = append(m.notes, n)
	return nil
}

func (m *memNotifier) all() []connections.Notification {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]connections.Notification(nil), m.notes...)
}

// memMetrics counts refresh failures per app.
type memMetrics struct {
	mu       sync.Mutex
	failures map[string]int
}

func (m *memMetrics) ConnectionRefreshFailure(app string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failures == nil {
		m.failures = map[string]int{}
	}
	m.failures[app]++
}

func (m *memMetrics) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.failures["fake"]
}

func TestTokenSourceRefreshesOnceUnderLockAndRotatesRefreshToken(t *testing.T) {
	env := newTestEnv(t)
	v := newFakeVendor(t)
	registerFakeApp(t, env, v)
	ctx := context.Background()
	info, err := connect(t, env, userAlice, "acct-company")
	if err != nil {
		t.Fatal(err)
	}
	ts := env.svc.TokenSource(ctx, userAlice, info.ID)

	// While the access token is valid no vendor call happens.
	before := v.tokenCalls.Load()
	tok, err := ts.Token()
	if err != nil || !strings.HasPrefix(tok.AccessToken, "access-1-") {
		t.Fatalf("Token = %+v, %v", tok, err)
	}
	if v.tokenCalls.Load() != before {
		t.Fatal("valid token triggered a vendor call")
	}

	// Past expiry, ten concurrent callers produce exactly one refresh and
	// all get the same new token.
	env.svc.SetClock(func() time.Time { return time.Now().Add(2 * time.Hour) })
	v.refreshDelay = 50 * time.Millisecond
	var wg sync.WaitGroup
	results := make([]string, 10)
	errs := make([]error, 10)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tok, err := env.svc.TokenSource(ctx, userAlice, info.ID).Token()
			if err == nil {
				results[i] = tok.AccessToken
			}
			errs[i] = err
		}(i)
	}
	wg.Wait()
	for i := range results {
		if errs[i] != nil || results[i] != results[0] || !strings.HasPrefix(results[i], "access-2-") {
			t.Fatalf("caller %d: %q, %v (first %q)", i, results[i], errs[i], results[0])
		}
	}
	if n := v.refreshCalls.Load(); n != 1 {
		t.Fatalf("refresh calls = %d, want 1", n)
	}
	// The rotated refresh token was persisted: the next refresh succeeds
	// although the vendor killed the first refresh token.
	env.svc.SetClock(func() time.Time { return time.Now().Add(4 * time.Hour) })
	tok, err = ts.Token()
	if err != nil || !strings.HasPrefix(tok.AccessToken, "access-3-") {
		t.Fatalf("second refresh = %+v, %v", tok, err)
	}
	if n := v.refreshCalls.Load(); n != 2 {
		t.Fatalf("refresh calls = %d, want 2", n)
	}
	rows := env.store.ConnectionRows()
	if rows[0].LastRefreshedAt == nil || rows[0].LastRefreshedAt.Before(time.Now().Add(3*time.Hour)) {
		t.Fatalf("last_refreshed_at not updated: %+v", rows[0].LastRefreshedAt)
	}
	// No token ever reached the logs; the stored bundle is still ciphertext.
	for _, raw := range v.allTokens() {
		if strings.Contains(env.logs.String(), raw) {
			t.Fatalf("token %q in logs", raw)
		}
		for _, s := range env.store.SecretRows() {
			if strings.Contains(string(s.Secret.Ciphertext), raw) {
				t.Fatalf("token %q stored in clear", raw)
			}
		}
	}
	// Bob cannot read alice's token (row-level security stand-in).
	if _, err := env.svc.TokenSource(ctx, userBob, info.ID).Token(); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("bob err = %v", err)
	}
	// A tampered ciphertext fails to decrypt.
	env.store.TamperSecret(info.ID)
	if _, err := ts.Token(); err == nil {
		t.Fatal("tampered secret decrypted")
	}
}

func TestInvalidGrantMarksNeedsReconnectAndNotifies(t *testing.T) {
	env := newTestEnv(t)
	v := newFakeVendor(t)
	registerFakeApp(t, env, v)
	notes := &memNotifier{}
	metrics := &memMetrics{}
	env.svc.SetNotifier(notes)
	env.svc.SetMetrics(metrics)
	ctx := context.Background()
	info, err := connect(t, env, userAlice, "acct-company")
	if err != nil {
		t.Fatal(err)
	}
	v.invalidGrant.Store(true)
	env.svc.SetClock(func() time.Time { return time.Now().Add(2 * time.Hour) })
	_, err = env.svc.TokenSource(ctx, userAlice, info.ID).Token()
	if !errors.Is(err, connections.ErrNeedsReconnect) {
		t.Fatalf("err = %v", err)
	}
	list, err := env.svc.Connections(ctx, userAlice)
	if err != nil || len(list) != 1 || list[0].Status != store.ConnectionNeedsReconnect {
		t.Fatalf("connections = %+v, %v", list, err)
	}
	if n := notes.all(); len(n) != 1 || n[0].Kind != connections.NotifyNeedsReconnect || n[0].UserID != userAlice || n[0].ConnectionID != info.ID || n[0].Vendor != "fake" {
		t.Fatalf("notifications = %+v", n)
	}
	if metrics.count() != 1 {
		t.Fatalf("refresh failures = %d", metrics.count())
	}
	// The second call does not hit the vendor again and the account is no
	// longer listed for tool calls.
	calls := v.refreshCalls.Load()
	if _, err := env.svc.TokenSource(ctx, userAlice, info.ID).Token(); !errors.Is(err, connections.ErrNeedsReconnect) || v.refreshCalls.Load() != calls {
		t.Fatalf("second call: %v, refresh calls %d -> %d", err, calls, v.refreshCalls.Load())
	}
	accts, err := env.svc.ListAccounts(ctx, userAlice, "fake")
	if err != nil || len(accts) != 0 {
		t.Fatalf("accounts = %+v, %v", accts, err)
	}
	// Reconnecting the same account revives it.
	v.invalidGrant.Store(false)
	again, err := connect(t, env, userAlice, "acct-company")
	if err != nil || again.ID != info.ID || again.Status != store.ConnectionActive {
		t.Fatalf("reconnect = %+v, %v", again, err)
	}
	// A transient vendor failure is not a reconnect: the status stays and
	// the metric counts it.
	env.svc.SetClock(func() time.Time { return time.Now().Add(6 * time.Hour) })
	v.srv.Close()
	if _, err := env.svc.TokenSource(ctx, userAlice, info.ID).Token(); err == nil || errors.Is(err, connections.ErrNeedsReconnect) {
		t.Fatalf("transient err = %v", err)
	}
	if metrics.count() != 2 {
		t.Fatalf("refresh failures = %d", metrics.count())
	}
	if list, _ := env.svc.Connections(ctx, userAlice); list[0].Status != store.ConnectionActive {
		t.Fatalf("status after transient failure = %s", list[0].Status)
	}
}

func TestDisconnectRevokesDeletesSecretsAndKeepsAudit(t *testing.T) {
	env := newTestEnv(t)
	v := newFakeVendor(t)
	registerFakeApp(t, env, v)
	ctx := context.Background()
	info, err := connect(t, env, userAlice, "acct-company")
	if err != nil {
		t.Fatal(err)
	}
	// Bob cannot disconnect alice's connection.
	if err := env.svc.Disconnect(ctx, userBob, info.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("bob disconnect err = %v", err)
	}
	if err := env.svc.Disconnect(ctx, userAlice, info.ID); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	if revoked := v.revokedTokens(); len(revoked) != 1 || !strings.HasPrefix(revoked[0], "refresh-1-") {
		t.Fatalf("revoked at vendor = %v", revoked)
	}
	if n := len(env.store.SecretRows()); n != 0 {
		t.Fatalf("secrets left = %d", n)
	}
	rows := env.store.ConnectionRows()
	if len(rows) != 1 || rows[0].Status != store.ConnectionRevoked {
		t.Fatalf("connection rows = %+v", rows)
	}
	var connected, disconnected int
	for _, ev := range env.audit.events {
		switch ev.ResourceIdentity["action"] {
		case "connected":
			connected++
		case "disconnected":
			disconnected++
			if ev.AccountID != info.ID || ev.UserID != userAlice {
				t.Fatalf("disconnect audit = %+v", ev)
			}
		}
	}
	if connected != 1 || disconnected != 1 {
		t.Fatalf("audit: connected %d, disconnected %d", connected, disconnected)
	}
	if _, err := env.svc.TokenSource(ctx, userAlice, info.ID).Token(); !errors.Is(err, connections.ErrNeedsReconnect) {
		t.Fatalf("token after disconnect err = %v", err)
	}
	if accts, _ := env.svc.ListAccounts(ctx, userAlice, "fake"); len(accts) != 0 {
		t.Fatalf("accounts after disconnect = %+v", accts)
	}
	// Disconnecting twice is not an error; a reconnect starts fresh.
	if err := env.svc.Disconnect(ctx, userAlice, info.ID); err != nil {
		t.Fatalf("second disconnect: %v", err)
	}
	again, err := connect(t, env, userAlice, "acct-company", "repo")
	if err != nil || again.ID != info.ID || again.Status != store.ConnectionActive || strings.Join(again.Scopes, " ") != "read:user repo" {
		t.Fatalf("reconnect = %+v, %v", again, err)
	}
}

func TestDisableHookDisconnectsEverything(t *testing.T) {
	env := newTestEnv(t)
	v := newFakeVendor(t)
	registerFakeApp(t, env, v)
	ctx := context.Background()
	if _, err := connect(t, env, userAlice, "acct-company"); err != nil {
		t.Fatal(err)
	}
	if _, err := connect(t, env, userAlice, "acct-personal"); err != nil {
		t.Fatal(err)
	}
	if _, err := connect(t, env, userBob, "acct-company"); err != nil {
		t.Fatal(err)
	}
	if err := env.svc.DisableHook()(ctx, nil, userAlice); err != nil {
		t.Fatalf("hook: %v", err)
	}
	if n := len(v.revokedTokens()); n != 2 {
		t.Fatalf("revoked at vendor = %d", n)
	}
	secrets := env.store.SecretRows()
	if len(secrets) != 1 || secrets[0].UserID != userBob {
		t.Fatalf("secrets = %+v", secrets)
	}
	for _, c := range env.store.ConnectionRows() {
		want := store.ConnectionActive
		if c.UserID == userAlice {
			want = store.ConnectionRevoked
		}
		if c.Status != want {
			t.Fatalf("connection %s of %s = %s, want %s", c.ID, c.UserID, c.Status, want)
		}
	}
	if accts, _ := env.svc.ListAccounts(ctx, userBob, "fake"); len(accts) != 1 {
		t.Fatalf("bob's accounts = %+v", accts)
	}
}

func TestAccountSourceListsOnlyOwnActiveConnections(t *testing.T) {
	env := newTestEnv(t)
	v := newFakeVendor(t)
	registerFakeApp(t, env, v)
	ctx := context.Background()
	a1, _ := connect(t, env, userAlice, "acct-company", "repo")
	a2, _ := connect(t, env, userAlice, "acct-personal")
	b1, _ := connect(t, env, userBob, "acct-company")

	accts, err := env.svc.ListAccounts(ctx, userAlice, "fake")
	if err != nil || len(accts) != 2 {
		t.Fatalf("alice = %+v, %v", accts, err)
	}
	if accts[0].ID != a1.ID || accts[0].Label != "company" || accts[0].DisplayName != "alice" || accts[0].App != "fake" || strings.Join(accts[0].Scopes, " ") != "read:user repo" {
		t.Fatalf("alice[0] = %+v", accts[0])
	}
	if accts[1].ID != a2.ID || accts[1].Label != "personal" {
		t.Fatalf("alice[1] = %+v", accts[1])
	}
	bobs, _ := env.svc.ListAccounts(ctx, userBob, "fake")
	if len(bobs) != 1 || bobs[0].ID != b1.ID {
		t.Fatalf("bob = %+v", bobs)
	}
	if none, _ := env.svc.ListAccounts(ctx, userAlice, "github"); len(none) != 0 {
		t.Fatalf("github = %+v", none)
	}
	// A connector app that uses the vendor's accounts under another name
	// sees them with its own app name.
	env.svc.MapApp("items", "fake")
	items, _ := env.svc.ListAccounts(ctx, userAlice, "items")
	if len(items) != 2 || items[0].App != "items" {
		t.Fatalf("items = %+v", items)
	}
	// Infos for the portal carry the vendor and never tokens.
	list, err := env.svc.Connections(ctx, userAlice)
	if err != nil || len(list) != 2 || list[0].Vendor != "fake" || list[0].ExternalAccountID != "acct-company" {
		t.Fatalf("Connections = %+v, %v", list, err)
	}
}

func TestKeepAliveRefreshesStaleTokensAndPurgesFlows(t *testing.T) {
	env := newTestEnv(t)
	v := newFakeVendor(t)
	registerFakeApp(t, env, v)
	ctx := context.Background()
	fresh, _ := connect(t, env, userAlice, "acct-company")
	stale, _ := connect(t, env, userBob, "acct-company")
	// Bob's connection was last refreshed 31 days ago; alice's an hour ago.
	env.store.Backdate(stale.ID, time.Now().Add(-31*24*time.Hour))
	env.store.Backdate(fresh.ID, time.Now().Add(-time.Hour))
	// A forgotten flow from an hour ago.
	if _, err := env.svc.Start(ctx, connections.StartRequest{UserID: userAlice, Vendor: "fake"}); err != nil {
		t.Fatal(err)
	}
	env.store.ExpireFlows(time.Now().Add(-time.Hour))

	job := env.svc.KeepAliveJob()
	if job.Name() != "connections.keepalive" || job.Interval() != 24*time.Hour {
		t.Fatalf("job = %s / %s", job.Name(), job.Interval())
	}
	if err := job.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if n := v.refreshCalls.Load(); n != 1 {
		t.Fatalf("refresh calls = %d, want 1 (only the stale one)", n)
	}
	for _, c := range env.store.ConnectionRows() {
		if c.ID == stale.ID && (c.LastRefreshedAt == nil || c.LastRefreshedAt.Before(time.Now().Add(-time.Minute))) {
			t.Fatalf("stale connection not refreshed: %+v", c.LastRefreshedAt)
		}
	}
	if env.store.FlowCount() != 0 {
		t.Fatalf("expired flows left = %d", env.store.FlowCount())
	}
	// A stale connection whose refresh token is dead becomes
	// needs_reconnect, and the job carries on.
	v.invalidGrant.Store(true)
	env.store.Backdate(fresh.ID, time.Now().Add(-40*24*time.Hour))
	if err := job.Run(ctx); err != nil {
		t.Fatalf("Run 2: %v", err)
	}
	list, _ := env.svc.Connections(ctx, userAlice)
	if list[0].Status != store.ConnectionNeedsReconnect {
		t.Fatalf("alice status = %s", list[0].Status)
	}
}
