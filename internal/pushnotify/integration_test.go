//go:build integration

package pushnotify_test

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/pushnotify"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/store/migrations"
	"github.com/huynle/mcp-gateway/internal/webpush"
)

// The Web Push integration tests run against their own database
// (gateway_pushnotify_test, created from GATEWAY_TEST_DATABASE_URL) so
// they never race the store package's TRUNCATE (quirk 01mepmn6).

const (
	pushTestDB    = "gateway_pushnotify_test"
	itAppPassword = "gateway-app-test"
	itJobsPass    = "gateway-jobs-test"
)

type pgWorld struct {
	st     *store.Store
	super  *pgx.Conn
	kp     crypto.KeyProvider
	alice  string
	bob    string
	sender *fakeSender
}

func openWorld(t *testing.T) *pgWorld {
	t.Helper()
	raw := os.Getenv("GATEWAY_TEST_DATABASE_URL")
	if raw == "" {
		t.Skip("GATEWAY_TEST_DATABASE_URL not set; skipping integration test")
	}
	ctx := t.Context()
	admin, err := pgx.Connect(ctx, raw)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = admin.Close(ctx) }()
	var exists bool
	if err := admin.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)`, pushTestDB).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		if _, err := admin.Exec(ctx, `CREATE DATABASE `+pushTestDB); err != nil {
			t.Fatalf("create database: %v", err)
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + pushTestDB
	if err := migrations.Up(ctx, u.String()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	super, err := pgx.Connect(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = super.Close(context.Background()) })
	for _, stmt := range []string{
		"ALTER ROLE gateway_app LOGIN PASSWORD '" + itAppPassword + "'",
		"ALTER ROLE gateway_jobs LOGIN PASSWORD '" + itJobsPass + "'",
		"TRUNCATE users, webpush_keys CASCADE",
	} {
		if err := execRetrying(ctx, super, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	appURL, jobsURL := *u, *u
	appURL.User = url.UserPassword("gateway_app", itAppPassword)
	jobsURL.User = url.UserPassword("gateway_jobs", itJobsPass)
	st, err := store.New(ctx, appURL.String(), store.WithJobsURL(jobsURL.String()))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(st.Close)
	w := &pgWorld{st: st, super: super, kp: keyProvider(t), sender: &fakeSender{}}
	for _, p := range []*string{&w.alice, &w.bob} {
		if err := super.QueryRow(ctx, `INSERT INTO users (display_name) VALUES ('it') RETURNING id::text`).Scan(p); err != nil {
			t.Fatal(err)
		}
	}
	return w
}

// replica is one gateway process's service over the shared database.
func (w *pgWorld) replica(t *testing.T) *pushnotify.Service {
	t.Helper()
	svc, err := pushnotify.New(pushnotify.NewPostgresStore(w.st), w.kp, pushnotify.Options{
		Subject:   "https://gw.example.com",
		NewSender: func(*webpush.Keys) (pushnotify.Sender, error) { return w.sender, nil },
		Log:       slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

// execRetrying retries "tuple concurrently updated" (quirk aihn7hjb).
func execRetrying(ctx context.Context, conn *pgx.Conn, stmt string) error {
	var err error
	for range 20 {
		if _, err = conn.Exec(ctx, stmt); err == nil || !strings.Contains(err.Error(), "concurrently updated") {
			return err
		}
		time.Sleep(100 * time.Millisecond)
	}
	return err
}

func TestIntegrationPushKeyCreatedOnceAcrossReplicas(t *testing.T) {
	w := openWorld(t)
	a, b := w.replica(t), w.replica(t)
	var wg sync.WaitGroup
	keys := make([]string, 2)
	errs := make([]error, 2)
	for i, svc := range []*pushnotify.Service{a, b} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			keys[i], errs[i] = svc.PublicKey(t.Context())
		}()
	}
	wg.Wait()
	if errs[0] != nil || errs[1] != nil || keys[0] == "" || keys[0] != keys[1] {
		t.Fatalf("keys = %q, %q; errors %v, %v", keys[0], keys[1], errs[0], errs[1])
	}
	var n int
	var pub string
	if err := w.super.QueryRow(t.Context(), `SELECT count(*), max(public_key) FROM webpush_keys`).Scan(&n, &pub); err != nil || n != 1 || pub != keys[0] {
		t.Fatalf("stored keys = %d (%q), %v", n, pub, err)
	}
	// A third replica started later loads the same key.
	if k, err := w.replica(t).PublicKey(t.Context()); err != nil || k != keys[0] {
		t.Errorf("later replica key = %q, %v", k, err)
	}
}

func TestIntegrationPushSubscribeCapRowSecurityAndNotify(t *testing.T) {
	w := openWorld(t)
	svc := w.replica(t)
	ctx := t.Context()
	var eps []string
	for range pushnotify.MaxSubscriptionsPerUser {
		ep, js := subscription(t, "fcm.googleapis.com")
		if _, err := svc.Subscribe(ctx, w.alice, js, ""); err != nil {
			t.Fatal(err)
		}
		eps = append(eps, ep)
	}
	_, js := subscription(t, "fcm.googleapis.com")
	if _, err := svc.Subscribe(ctx, w.alice, js, ""); !errors.Is(err, pushnotify.ErrLimit) {
		t.Fatalf("11th subscription = %v, want ErrLimit", err)
	}
	// Re-subscribing updates in place (no new row, still at the cap).
	if _, err := svc.Subscribe(ctx, w.alice, subscriptionFor(t, eps[0]), "renewed"); err != nil {
		t.Fatalf("renew: %v", err)
	}
	// Row security: bob sees none of alice's devices and cannot remove them.
	devs, err := svc.Devices(ctx, w.bob)
	if err != nil || len(devs) != 0 {
		t.Fatalf("bob's devices = %d, %v", len(devs), err)
	}
	alices, _ := svc.Devices(ctx, w.alice)
	if err := svc.RemoveDevice(ctx, w.bob, alices[0].ID); !errors.Is(err, pushnotify.ErrNotFound) {
		t.Errorf("bob removing alice's device = %v", err)
	}
	// The endpoint never sits in the clear.
	var leaked int
	if err := w.super.QueryRow(ctx, `SELECT count(*) FROM push_subscriptions WHERE position(convert_to($1, 'UTF8') IN sub_ciphertext) > 0
		OR endpoint_host LIKE '%/%' OR device_label LIKE '%https:%'`, eps[0]).Scan(&leaked); err != nil || leaked != 0 {
		t.Errorf("rows exposing the endpoint = %d, %v", leaked, err)
	}

	// Notify: the gone subscription is deleted, the rest record a success.
	w.sender.result = func(_ context.Context, ep string) error {
		if ep == eps[1] {
			return &webpush.StatusError{StatusCode: 404, Host: "fcm.googleapis.com"}
		}
		return nil
	}
	a := pendingApproval(&fixture{now: time.Now()}, 10*time.Minute)
	a.UserID = w.alice
	if err := svc.Notify(ctx, a); err != nil {
		t.Fatal(err)
	}
	devs, _ = svc.Devices(ctx, w.alice)
	if len(devs) != pushnotify.MaxSubscriptionsPerUser-1 {
		t.Fatalf("devices after a 404 = %d", len(devs))
	}
	for _, d := range devs {
		if d.LastSuccessAt == nil {
			t.Errorf("device %s has no delivery recorded", d.ID)
		}
	}

	// Disabling the user deletes the subscriptions in the identity
	// transaction (jobs scope).
	err = w.st.WithJobs(ctx, func(tx store.Tx) error { return svc.OnDisableUser(ctx, tx, w.alice) })
	if err != nil {
		t.Fatal(err)
	}
	if devs, _ := svc.Devices(ctx, w.alice); len(devs) != 0 {
		t.Errorf("devices after disable = %d", len(devs))
	}
	var hook identity.DisableHook = svc.OnDisableUser
	_ = hook
}
