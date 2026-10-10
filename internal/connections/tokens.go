package connections

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/store"
)

// ErrNeedsReconnect means the connection has no usable tokens: the vendor
// rejected the refresh token (invalid_grant), the user disconnected, or
// the account was never connected. The user must connect again from the
// portal.
var ErrNeedsReconnect = errors.New("connections: account needs to be reconnected")

// TokenSource returns an oauth2.TokenSource for one of userID's
// connections. Token refreshes the access token when it is expired (or
// within RefreshSkew of expiring) under a row lock on the connection, so
// one refresh happens at a time per connection across every replica and
// the waiters pick up the fresh token; rotating refresh tokens are
// persisted; an invalid_grant marks the connection needs_reconnect, notifies
// the user and counts connection_refresh_failures_total{app}. Connectors
// hand it to oauth2.NewClient. Every Token call is one short database
// transaction: no token is cached in memory.
func (s *Service) TokenSource(ctx context.Context, userID, connectionID string) oauth2.TokenSource {
	return &tokenSource{s: s, ctx: ctx, userID: userID, connectionID: connectionID}
}

type tokenSource struct {
	s                    *Service
	ctx                  context.Context
	userID, connectionID string
}

// Token implements oauth2.TokenSource.
func (t *tokenSource) Token() (*oauth2.Token, error) {
	return t.s.token(t.ctx, t.userID, t.connectionID, false)
}

// token loads the connection's token, refreshing it when needed (always
// when force is set and a refresh token exists: the keep-alive job).
func (s *Service) token(ctx context.Context, userID, connectionID string, force bool) (*oauth2.Token, error) {
	var (
		out            *oauth2.Token
		needsReconnect bool
		vendor         string
		display        string
	)
	err := s.store.AsUser(ctx, userID, func(tx Tx) error {
		conn, err := tx.LockConnection(ctx, connectionID)
		if err != nil {
			return err
		}
		if conn.Status != store.ConnectionActive {
			needsReconnect = true
			return nil
		}
		row, err := tx.GetVendorApp(ctx, conn.VendorAppID)
		if err != nil {
			return fmt.Errorf("connections: vendor app of %s: %w", connectionID, err)
		}
		app, err := fromRow(row)
		if err != nil {
			return err
		}
		vendor, display = app.Vendor, conn.DisplayName
		tok, err := s.getToken(ctx, tx, userID, connectionID, app.Vendor)
		if err != nil {
			return err
		}
		now := s.clock()
		fresh := tok.Expiry.IsZero() || tok.Expiry.After(now.Add(s.cfg.RefreshSkew))
		if fresh && !force {
			out = tok
			return nil
		}
		if tok.RefreshToken == "" {
			if fresh {
				out = tok // nothing to exercise
				return nil
			}
			s.sink().ConnectionRefreshFailure(app.Vendor)
			s.log.Warn("token expired and no refresh token", "event", "connections.refresh_failed", "user_id", userID, "connection_id", connectionID, "vendor", app.Vendor, "vendor_error", "no_refresh_token")
			needsReconnect = true
			return tx.SetConnectionStatus(ctx, connectionID, store.ConnectionNeedsReconnect)
		}
		secret, err := s.clientSecret(ctx, row)
		if err != nil {
			return err
		}
		conf := s.oauthConfig(app, secret, nil)
		// An empty access token makes x/oauth2 refresh unconditionally.
		newTok, err := conf.TokenSource(s.oauthContext(ctx), &oauth2.Token{RefreshToken: tok.RefreshToken}).Token()
		if err != nil {
			code := vendorErrorCode(err)
			s.sink().ConnectionRefreshFailure(app.Vendor)
			s.log.Warn("token refresh failed", "event", "connections.refresh_failed", "user_id", userID, "connection_id", connectionID, "vendor", app.Vendor, "vendor_error", code)
			if code == "invalid_grant" {
				needsReconnect = true
				return tx.SetConnectionStatus(ctx, connectionID, store.ConnectionNeedsReconnect)
			}
			return fmt.Errorf("connections: refresh token for %s: vendor answered %s: %w", app.Vendor, code, err)
		}
		if newTok.RefreshToken == "" {
			newTok.RefreshToken = tok.RefreshToken
		}
		s.normalizeExpiry(newTok)
		if err := s.putToken(ctx, tx, userID, connectionID, app.Vendor, newTok); err != nil {
			return err
		}
		if err := tx.TouchConnectionRefreshed(ctx, connectionID, now); err != nil {
			return err
		}
		s.log.Info("token refreshed", "event", "connections.refreshed", "user_id", userID, "connection_id", connectionID, "vendor", app.Vendor, "rotated", newTok.RefreshToken != tok.RefreshToken)
		out = newTok
		return nil
	})
	if err != nil {
		return nil, err
	}
	if needsReconnect {
		if vendor != "" {
			s.notify(ctx, Notification{
				UserID: userID, ConnectionID: connectionID, Vendor: vendor, DisplayName: display, Kind: NotifyNeedsReconnect,
				Message: fmt.Sprintf("Your %s account %s needs to be reconnected: open the portal's Connections page.", vendor, display),
			})
		}
		return nil, fmt.Errorf("%w: %s", ErrNeedsReconnect, connectionID)
	}
	return out, nil
}

// normalizeExpiry recomputes the token's expiry from the vendor's
// expires_in against the service clock, so freshness checks and the
// vendor's answer use one time source (x/oauth2 uses the wall clock).
func (s *Service) normalizeExpiry(tok *oauth2.Token) {
	if tok != nil && tok.ExpiresIn > 0 {
		tok.Expiry = s.clock().Add(time.Duration(tok.ExpiresIn) * time.Second)
	}
}

func (s *Service) notify(ctx context.Context, n Notification) {
	if err := s.notifications().Notify(ctx, n); err != nil {
		s.log.Error("notification failed", "event", "connections.notify_failed", "user_id", n.UserID, "connection_id", n.ConnectionID, "error", observability.RedactError(err))
	}
}

// SetNotifier replaces the notifier (late wiring: the approvals task's
// notifier is built after this service).
func (s *Service) SetNotifier(n Notifier) {
	if n == nil {
		n = LogNotifier{Log: s.log}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.notifier = n
}

// SetMetrics replaces the metrics sink.
func (s *Service) SetMetrics(m Metrics) {
	if m == nil {
		m = nopMetrics{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.metrics = m
}

// --- listing -----------------------------------------------------------------

// Connections lists userID's connections (every status) for the portal.
func (s *Service) Connections(ctx context.Context, userID string) ([]Info, error) {
	var out []Info
	err := s.store.AsUser(ctx, userID, func(tx Tx) error {
		rows, err := tx.ListConnections(ctx, userID)
		if err != nil {
			return err
		}
		for i := range rows {
			out = append(out, toInfo(&rows[i].Connection, rows[i].Vendor, rows[i].AppName))
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("connections: list: %w", err)
	}
	return out, nil
}

// ListAccounts implements connectors.AccountSource over the connections
// table: the user's active connections of the vendor that app uses
// (MapApp), as accounts whose ID is the connection's UUID. Row-level
// security hides everyone else's rows.
func (s *Service) ListAccounts(ctx context.Context, userID, app string) ([]connectors.Account, error) {
	if userID == "" {
		return nil, nil
	}
	vendor := s.vendorFor(app)
	list, err := s.Connections(ctx, userID)
	if err != nil {
		return nil, err
	}
	var out []connectors.Account
	for _, c := range list {
		if c.Vendor != vendor || !c.Active() {
			continue
		}
		out = append(out, connectors.Account{
			ID: c.ID, Label: connectors.AccountLabel(c.Label), DisplayName: c.DisplayName, App: app, Scopes: append([]string(nil), c.Scopes...),
		})
	}
	return out, nil
}

var _ connectors.AccountSource = (*Service)(nil)

// --- disconnect ----------------------------------------------------------------

// Disconnect revokes the connection's tokens at the vendor (best effort,
// when the app has a revoke URL), deletes the stored token bundle and
// marks the connection revoked. The row itself stays (approvals, ledger
// rows and audit events reference it) and reconnecting the same account
// revives it. store.ErrNotFound for a connection the user does not own.
func (s *Service) Disconnect(ctx context.Context, userID, connectionID string) error {
	var (
		conn *store.Connection
		app  VendorApp
		row  *store.VendorApp
		tok  *oauth2.Token
	)
	err := s.store.AsUser(ctx, userID, func(tx Tx) (err error) {
		if conn, err = tx.GetConnection(ctx, connectionID); err != nil {
			return err
		}
		if row, err = tx.GetVendorApp(ctx, conn.VendorAppID); err != nil {
			return err
		}
		if app, err = fromRow(row); err != nil {
			return err
		}
		tok, err = s.getToken(ctx, tx, userID, connectionID, app.Vendor)
		if errors.Is(err, store.ErrNotFound) {
			return nil // already disconnected
		}
		return err
	})
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return store.ErrNotFound
		}
		return fmt.Errorf("connections: disconnect: %w", err)
	}
	if tok != nil {
		s.revokeAtVendor(ctx, app, row, tok, userID, connectionID)
	}
	err = s.store.AsUser(ctx, userID, func(tx Tx) error {
		if _, err := tx.DeleteSecret(ctx, connectionID); err != nil {
			return err
		}
		return tx.SetConnectionStatus(ctx, connectionID, store.ConnectionRevoked)
	})
	if err != nil {
		return fmt.Errorf("connections: disconnect: %w", err)
	}
	if conn.Status != store.ConnectionRevoked || tok != nil {
		s.record(ctx, userID, connectionID, conn.Label, map[string]string{"action": "disconnected", "vendor": app.Vendor, "variant": app.Variant}, "succeeded", "")
		s.log.Info("account disconnected", "event", "connections.disconnected", "user_id", userID, "connection_id", connectionID, "vendor", app.Vendor, "label", conn.Label)
	}
	return nil
}

// revokeAtVendor posts the refresh token (or the access token when there
// is none) to the app's revoke URL. Failures are logged and otherwise
// ignored: the secret is deleted either way.
func (s *Service) revokeAtVendor(ctx context.Context, app VendorApp, row *store.VendorApp, tok *oauth2.Token, userID, connectionID string) {
	if app.RevokeURL == "" {
		return
	}
	secret, err := s.clientSecret(ctx, row)
	if err != nil {
		s.log.Warn("revoke skipped", "event", "connections.revoke_failed", "connection_id", connectionID, "vendor", app.Vendor, "error", observability.RedactError(err))
		return
	}
	token, hint := tok.RefreshToken, "refresh_token"
	if token == "" {
		token, hint = tok.AccessToken, "access_token"
	}
	form := url.Values{"token": {token}, "token_type_hint": {hint}, "client_id": {app.ClientID}}
	ctx, cancel := context.WithTimeout(ctx, s.cfg.VendorTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, app.RevokeURL, strings.NewReader(form.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(app.ClientID), url.QueryEscape(secret))
	res, err := s.client.Do(req)
	if err != nil {
		s.log.Warn("revoke at vendor failed", "event", "connections.revoke_failed", "user_id", userID, "connection_id", connectionID, "vendor", app.Vendor, "error", observability.RedactError(err))
		return
	}
	_ = res.Body.Close()
	if res.StatusCode >= 300 {
		s.log.Warn("revoke at vendor refused", "event", "connections.revoke_failed", "user_id", userID, "connection_id", connectionID, "vendor", app.Vendor, "status", res.StatusCode)
		return
	}
	s.log.Info("token revoked at vendor", "event", "connections.revoked", "user_id", userID, "connection_id", connectionID, "vendor", app.Vendor)
}

// DisableHook returns the identity.DisableHook that disconnects every
// connection of a user being disabled: best-effort revocation at each
// vendor, then (inside the disabling transaction when there is one; tx is
// nil on non-PostgreSQL stores) every secret deleted and every connection
// marked revoked.
func (s *Service) DisableHook() identity.DisableHook {
	return func(ctx context.Context, tx store.Tx, userID string) error {
		run := func(t Tx) error { return s.disconnectAll(ctx, t, userID) }
		var err error
		if tx != nil {
			err = run(pgTx{tx})
		} else {
			err = s.store.Bypass(ctx, run)
		}
		if err != nil {
			return fmt.Errorf("connections: disconnect on disable: %w", err)
		}
		return nil
	}
}

func (s *Service) disconnectAll(ctx context.Context, tx Tx, userID string) error {
	list, err := tx.ListConnections(ctx, userID)
	if err != nil {
		return err
	}
	for i := range list {
		c := &list[i]
		if c.Status == store.ConnectionRevoked {
			continue
		}
		row, err := tx.GetVendorApp(ctx, c.VendorAppID)
		if err != nil {
			return err
		}
		app, err := fromRow(row)
		if err != nil {
			return err
		}
		tok, err := s.getToken(ctx, tx, userID, c.ID, app.Vendor)
		if err == nil {
			s.revokeAtVendor(ctx, app, row, tok, userID, c.ID)
		} else if !errors.Is(err, store.ErrNotFound) {
			s.log.Warn("token unreadable on disable", "event", "connections.revoke_failed", "connection_id", c.ID, "error", observability.RedactError(err))
		}
	}
	revoked, err := tx.RevokeUserConnections(ctx, userID)
	if err != nil {
		return err
	}
	for _, c := range revoked {
		s.record(ctx, userID, c.ID, c.Label, map[string]string{"action": "disconnected_on_disable"}, "succeeded", "")
	}
	s.log.Info("connections revoked on disable", "event", "connections.revoked_on_disable", "user_id", userID, "revoked", len(revoked))
	return nil
}

// --- keep-alive ----------------------------------------------------------------

// KeepAliveJob refreshes tokens that have not been refreshed for
// KeepAliveAfter (30 days) so vendors that expire idle refresh tokens
// (Google: six months, Microsoft: 90 days) keep them alive, and sweeps
// expired connect flows. It satisfies the jobs runner's contract (Name,
// Interval, Run) and runs on one replica.
type KeepAliveJob struct {
	svc   *Service
	batch int
}

// KeepAliveBatch bounds how many connections one run refreshes.
const KeepAliveBatch = 500

// KeepAliveJob returns the job over the service.
func (s *Service) KeepAliveJob() *KeepAliveJob { return &KeepAliveJob{svc: s, batch: KeepAliveBatch} }

// Name implements the jobs contract.
func (j *KeepAliveJob) Name() string { return "connections.keepalive" }

// Interval implements the jobs contract.
func (j *KeepAliveJob) Interval() time.Duration { return 24 * time.Hour }

// Run refreshes every stale connection once (a dead refresh token marks
// the connection needs_reconnect and the run continues) and purges
// expired flows. It returns an error only when the listing itself fails.
func (j *KeepAliveJob) Run(ctx context.Context) error {
	s := j.svc
	now := s.clock()
	var stale []store.Connection
	err := s.store.Bypass(ctx, func(tx Tx) (err error) {
		if n, err := tx.PurgeConnectFlows(ctx, now); err != nil {
			return err
		} else if n > 0 {
			s.log.Info("expired connect flows purged", "event", "connections.flows_purged", "count", n)
		}
		stale, err = tx.ListStaleConnections(ctx, now.Add(-s.cfg.KeepAliveAfter), j.batch)
		return err
	})
	if err != nil {
		return fmt.Errorf("connections: keep-alive: %w", err)
	}
	var refreshed, failed int
	for _, c := range stale {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if _, err := s.token(ctx, c.UserID, c.ID, true); err != nil {
			failed++
			s.log.Warn("keep-alive refresh failed", "event", "connections.keepalive_failed", "user_id", c.UserID, "connection_id", c.ID, "error", observability.RedactError(err))
			continue
		}
		refreshed++
	}
	s.log.Info("keep-alive run", "event", "connections.keepalive", "stale", len(stale), "refreshed", refreshed, "failed", failed)
	return nil
}
