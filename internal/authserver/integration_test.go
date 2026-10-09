//go:build integration

package authserver_test

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/huynle/mcp-gateway/internal/authserver"
	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/store/migrations"
)

// The authserver integration tests run against their own database
// (gateway_authserver_test, created from GATEWAY_TEST_DATABASE_URL) so
// they never race the store package's TRUNCATE (quirk 01mepmn6).

const (
	testDB      = "gateway_authserver_test"
	appPassword = "gateway-app-test"
	jobsPass    = "gateway-jobs-test"
)

func openTestStore(t *testing.T) *store.Store {
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
	if err := admin.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)`, testDB).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		if _, err := admin.Exec(ctx, `CREATE DATABASE `+testDB); err != nil {
			t.Fatalf("create database: %v", err)
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + testDB
	superURL := u.String()
	if err := migrations.Up(ctx, superURL); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	super, err := pgx.Connect(ctx, superURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = super.Close(ctx) }()
	for _, stmt := range []string{
		"ALTER ROLE gateway_app LOGIN PASSWORD '" + appPassword + "'",
		"ALTER ROLE gateway_jobs LOGIN PASSWORD '" + jobsPass + "'",
		"TRUNCATE users, identities, sessions, roles, role_assignments, oauth_clients, oauth_refresh_tokens, oauth_authorization_codes, signing_keys, audit_events, job_locks CASCADE",
	} {
		if err := execRetryingConcurrentUpdate(ctx, super, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	appURL, jobsURL := *u, *u
	appURL.User = url.UserPassword("gateway_app", appPassword)
	jobsURL.User = url.UserPassword("gateway_jobs", jobsPass)
	st, err := store.New(ctx, appURL.String(), store.WithJobsURL(jobsURL.String()))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(st.Close)
	return st
}

func execRetryingConcurrentUpdate(ctx context.Context, conn *pgx.Conn, stmt string) error {
	var err error
	for attempt := 0; attempt < 20; attempt++ {
		if _, err = conn.Exec(ctx, stmt); err == nil || !strings.Contains(err.Error(), "concurrently updated") {
			return err
		}
		time.Sleep(100 * time.Millisecond)
	}
	return err
}

// pgWorld is the authorization server over PostgreSQL with two signed-in
// users and one registered public client.
type pgWorld struct {
	st       *store.Store
	svc      *authserver.Service
	idSvc    *identity.Service
	alice    string
	bob      string
	user     string // who the portal pages run as
	clientID string
	cfg      authserver.Config
}

func newPGWorld(t *testing.T) *pgWorld {
	t.Helper()
	st := openTestStore(t)
	ctx := t.Context()
	log := slog.New(slog.DiscardHandler)
	w := &pgWorld{st: st}
	idSvc, err := identity.New(identity.Config{
		BaseURL:         "http://localhost:18080",
		Providers:       []config.OIDCProvider{{Name: "dex", DisplayName: "dex", Issuer: dexIssuer, ClientID: "gateway", ClientSecret: "s", AllowedDomains: []string{"example.com"}}},
		DefaultRole:     "member",
		IdleTimeout:     12 * time.Hour,
		AbsoluteTimeout: 7 * 24 * time.Hour,
	}, identity.NewPostgresStore(st), log)
	if err != nil {
		t.Fatal(err)
	}
	w.idSvc = idSvc
	signIn := func(sub string) string {
		s, err := idSvc.SignIn(ctx, "dex", identity.Claims{Issuer: dexIssuer, Subject: sub, Name: sub, Email: sub + "@example.com", EmailVerified: true})
		if err != nil {
			t.Fatalf("SignIn %s: %v", sub, err)
		}
		return s.Principal.UserID
	}
	w.alice = signIn("alice-subject")
	w.bob = signIn("bob-subject")
	w.user = w.alice
	w.cfg = authserver.DefaultConfig()
	w.cfg.Issuer = "http://localhost:18080"
	w.svc, err = authserver.New(w.cfg, authserver.NewPostgresStore(st), mustProviderWith(t, 5), authserver.Options{Log: log})
	if err != nil {
		t.Fatal(err)
	}
	w.svc.SetIdentity(func(*http.Request) (string, string) { return w.user, csrf })
	idSvc.OnDisable(w.svc.DisableHook())
	reg, err := w.svc.Register(ctx, authserver.RegistrationRequest{ClientName: "Claude Code", RedirectURIs: []string{redirectURI}})
	if err != nil {
		t.Fatal(err)
	}
	w.clientID = reg.ClientID
	return w
}

func (w *pgWorld) params() url.Values {
	return url.Values{
		"client_id": {w.clientID}, "redirect_uri": {redirectURI}, "response_type": {"code"},
		"code_challenge": {challenge()}, "code_challenge_method": {"S256"}, "state": {"s"}, "scope": {"mcp"}, "resource": {w.cfg.Resource()},
	}
}

func (w *pgWorld) code(t *testing.T) string {
	t.Helper()
	form := w.params()
	form.Set("action", "approve")
	form.Set("_csrf", csrf)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, authserver.ConsentPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	w.svc.ServeConsent(rec, req)
	loc := redirect(t, rec)
	if loc.Query().Get("code") == "" {
		t.Fatalf("no code: %s", loc)
	}
	return loc.Query().Get("code")
}

func (w *pgWorld) token(t *testing.T, form url.Values) (int, map[string]any) {
	t.Helper()
	form.Set("client_id", w.clientID)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, authserver.TokenPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	w.svc.ServeToken(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func (w *pgWorld) exchange(t *testing.T, code string) (int, map[string]any) {
	return w.token(t, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI}, "code_verifier": {verifier}, "resource": {w.cfg.Resource()}})
}

func (w *pgWorld) refresh(t *testing.T, refresh string) (int, map[string]any) {
	return w.token(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}})
}

// TestIntegrationOAuthFlowOnPostgres runs the code flow, refresh rotation,
// reuse detection and revocation against the real tables.
func TestIntegrationOAuthFlowOnPostgres(t *testing.T) {
	w := newPGWorld(t)
	ctx := t.Context()
	code := w.code(t)
	status, out := w.exchange(t, code)
	if status != http.StatusOK {
		t.Fatalf("exchange: %d %v", status, out)
	}
	access, refresh1 := out["access_token"].(string), out["refresh_token"].(string)
	p, err := w.svc.Authenticator().Authenticate(ctx, access)
	if err != nil || p.UserID != w.alice {
		t.Fatalf("authenticate: %v %v", p, err)
	}
	if status, out := w.exchange(t, code); status != http.StatusBadRequest || out["error"] != "invalid_grant" {
		t.Errorf("replay: %d %v", status, out)
	}
	// The replay revoked the family.
	if status, _ := w.refresh(t, refresh1); status != http.StatusBadRequest {
		t.Errorf("refresh after replay should fail")
	}
	// A fresh family: rotate, then reuse.
	_, out = w.exchange(t, w.code(t))
	refresh1 = out["refresh_token"].(string)
	status, out = w.refresh(t, refresh1)
	if status != http.StatusOK {
		t.Fatalf("refresh: %d %v", status, out)
	}
	refresh2 := out["refresh_token"].(string)
	if status, _ := w.refresh(t, refresh1); status != http.StatusBadRequest {
		t.Errorf("reuse accepted")
	}
	if status, _ := w.refresh(t, refresh2); status != http.StatusBadRequest {
		t.Errorf("current token survived reuse detection")
	}
	// Rows: every token of that family is revoked; the admin view shows
	// family and rotation columns and never the hash.
	var live int
	err = w.st.WithJobs(ctx, func(tx store.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM admin_oauth_refresh_tokens WHERE user_id = $1 AND revoked_at IS NULL`, w.alice).Scan(&live)
	})
	if err != nil || live != 0 {
		t.Errorf("live tokens after reuse = %d (%v)", live, err)
	}
	// Disable hook inside the identity transaction.
	_, out = w.exchange(t, w.code(t))
	pending := w.code(t)
	if err := w.idSvc.DisableUser(ctx, "", w.alice); err != nil {
		t.Fatal(err)
	}
	if status, _ := w.refresh(t, out["refresh_token"].(string)); status != http.StatusBadRequest {
		t.Error("refresh after disable")
	}
	if status, _ := w.exchange(t, pending); status != http.StatusBadRequest {
		t.Error("pending code after disable")
	}
}

// TestIntegrationRowLevelSecurity: codes and refresh tokens are the
// user's rows; another user sees nothing and cannot write them.
func TestIntegrationRowLevelSecurity(t *testing.T) {
	w := newPGWorld(t)
	ctx := t.Context()
	_, out := w.exchange(t, w.code(t))
	if out["refresh_token"] == nil {
		t.Fatal("no tokens")
	}
	list, err := w.svc.ListHarnesses(ctx, w.alice)
	if err != nil || len(list) != 1 || list[0].ClientName != "Claude Code" {
		t.Fatalf("alice's harnesses = %+v (%v)", list, err)
	}
	family := list[0].FamilyID
	if list, err := w.svc.ListHarnesses(ctx, w.bob); err != nil || len(list) != 0 {
		t.Errorf("bob's harnesses = %+v (%v)", list, err)
	}
	if err := w.svc.RevokeHarness(ctx, w.bob, family); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("bob revoking alice's harness: %v", err)
	}
	// Bob's scope cannot touch alice's rows directly either (each
	// expected failure in its own transaction, quirk 01mepmn6).
	var n int64
	_ = w.st.WithUser(ctx, w.bob, func(tx store.Tx) error {
		var err error
		n, err = store.RevokeOAuthRefreshFamily(ctx, tx, family, time.Now())
		return err
	})
	if n != 0 {
		t.Errorf("bob revoked %d of alice's tokens", n)
	}
	err = w.st.WithUser(ctx, w.bob, func(tx store.Tx) error {
		return store.CreateOAuthCode(ctx, tx, &store.OAuthCode{CodeHash: []byte("x"), UserID: w.alice, ClientID: clientRowID(t, w), RedirectURI: redirectURI, Resource: w.cfg.Resource(), CodeChallenge: "c", ExpiresAt: time.Now().Add(time.Minute)})
	})
	if err == nil || !strings.Contains(err.Error(), "42501") {
		t.Errorf("bob inserting a code for alice: %v", err)
	}
	var visible int
	_ = w.st.WithUser(ctx, w.bob, func(tx store.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM oauth_refresh_tokens`).Scan(&visible)
	})
	if visible != 0 {
		t.Errorf("bob sees %d refresh tokens", visible)
	}
	if err := w.svc.RevokeHarness(ctx, w.alice, family); err != nil {
		t.Errorf("alice revoking her harness: %v", err)
	}
}

func clientRowID(t *testing.T, w *pgWorld) string {
	t.Helper()
	var id string
	err := w.st.WithJobs(t.Context(), func(tx store.Tx) error {
		c, err := store.FindOAuthClientByClientID(t.Context(), tx, w.clientID)
		if err != nil {
			return err
		}
		id = c.ID
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// TestIntegrationSingleUseUnderConcurrency: concurrent exchanges of one
// code and concurrent refreshes of one token each have exactly one winner.
func TestIntegrationSingleUseUnderConcurrency(t *testing.T) {
	w := newPGWorld(t)
	code := w.code(t)
	const n = 8
	var wg sync.WaitGroup
	wins := make(chan map[string]any, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if status, out := w.exchange(t, code); status == http.StatusOK {
				wins <- out
			}
		}()
	}
	wg.Wait()
	close(wins)
	var winners []map[string]any
	for o := range wins {
		winners = append(winners, o)
	}
	if len(winners) != 1 {
		t.Fatalf("%d concurrent exchanges succeeded, want 1", len(winners))
	}
	// Losers were treated as replays, which revoked the winner's family:
	// the strict reading of OAuth 2.1 section 4.1.3.
	if status, _ := w.refresh(t, winners[0]["refresh_token"].(string)); status != http.StatusBadRequest {
		t.Errorf("family survived a concurrent replay")
	}

	_, out := w.exchange(t, w.code(t))
	refresh := out["refresh_token"].(string)
	ok := make(chan struct{}, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if status, _ := w.refresh(t, refresh); status == http.StatusOK {
				ok <- struct{}{}
			}
		}()
	}
	wg.Wait()
	close(ok)
	if got := len(ok); got != 1 {
		t.Errorf("%d concurrent refreshes succeeded, want 1", got)
	}
}

// TestIntegrationSigningKeysAndPrune: keys are stored encrypted, rotation
// retires and later deletes them, and pruning cascades to a client's
// tokens and codes.
func TestIntegrationSigningKeysAndPrune(t *testing.T) {
	w := newPGWorld(t)
	ctx := t.Context()
	_, out := w.exchange(t, w.code(t))
	access := out["access_token"].(string)
	var kid, alg string
	var ct []byte
	err := w.st.WithJobs(ctx, func(tx store.Tx) error {
		return tx.QueryRow(ctx, `SELECT kid, algorithm, private_ciphertext FROM signing_keys WHERE status = 'active'`).Scan(&kid, &alg, &ct)
	})
	if err != nil || kid != kidOf(t, access) || alg != "ES256" || len(ct) == 0 || strings.Contains(string(ct), "PRIVATE") {
		t.Fatalf("active key row: kid=%s alg=%s ct=%d err=%v", kid, alg, len(ct), err)
	}
	if err := w.svc.Keys().Rotate(ctx); err != nil {
		t.Fatal(err)
	}
	var active, retired int
	_ = w.st.WithJobs(ctx, func(tx store.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE status = 'active'), count(*) FILTER (WHERE status = 'retired') FROM signing_keys`).Scan(&active, &retired)
	})
	if active != 1 || retired != 1 {
		t.Errorf("after rotation: active=%d retired=%d", active, retired)
	}
	if _, err := w.svc.Authenticator().Authenticate(ctx, access); err != nil {
		t.Errorf("token signed by the retired key rejected inside grace: %v", err)
	}
	set, err := w.svc.Keys().JWKS(ctx)
	if err != nil || len(set.Keys) != 2 {
		t.Errorf("JWKS = %d keys (%v)", len(set.Keys), err)
	}
	// Push the retirement past the grace period and sweep.
	_ = w.st.WithJobs(ctx, func(tx store.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE signing_keys SET retired_at = now() - interval '3 hours' WHERE status = 'retired'`)
		return err
	})
	if _, err := w.svc.Keys().RotateIfDue(ctx, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	_ = w.st.WithJobs(ctx, func(tx store.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE status = 'active'), count(*) FILTER (WHERE status = 'retired') FROM signing_keys`).Scan(&active, &retired)
	})
	if active != 1 || retired != 0 {
		t.Errorf("after sweep: active=%d retired=%d", active, retired)
	}

	// Prune: age the client, run the job, everything of it is gone.
	_ = w.st.WithJobs(ctx, func(tx store.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE oauth_clients SET last_used_at = now() - interval '31 days', created_at = now() - interval '31 days'`)
		return err
	})
	clients, _, err := w.svc.Prune(ctx)
	if err != nil || clients != 1 {
		t.Fatalf("Prune = %d, %v", clients, err)
	}
	var left int
	_ = w.st.WithJobs(ctx, func(tx store.Tx) error {
		return tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM oauth_clients) + (SELECT count(*) FROM oauth_refresh_tokens) + (SELECT count(*) FROM oauth_authorization_codes)`).Scan(&left)
	})
	if left != 0 {
		t.Errorf("%d rows left after prune", left)
	}
	if status, out := w.exchange(t, "whatever"); status != http.StatusUnauthorized || out["error"] != "invalid_client" {
		t.Errorf("pruned client still usable: %d %v", status, out)
	}
}
