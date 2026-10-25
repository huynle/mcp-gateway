package mcpproxy

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"time"
)

var (
	// ErrSignInDenied: the user pressed Deny on /activate.
	ErrSignInDenied = errors.New("the sign-in was denied on the gateway")
	// ErrSignInExpired: the code expired before anyone approved it.
	ErrSignInExpired = errors.New("the sign-in code expired before it was approved; start the proxy again to get a new code")
)

const (
	defaultInterval  = 5 * time.Second
	slowDownStep     = 5 * time.Second
	defaultExpiresIn = 600
	defaultLifetime  = time.Hour
	refreshMargin    = time.Minute
)

// signInError ends the proxy: the device flow failed for good.
type signInError struct{ err error }

func (e *signInError) Error() string { return "sign-in failed: " + e.err.Error() }
func (e *signInError) Unwrap() error { return e.err }

// tokenSource hands out the access token, kept in memory only. It
// refreshes it shortly before expiry or when told it was rejected, and
// signs in with the device flow when there is no usable refresh token.
// Renewals are serialised in the process (sem) and between proxies of
// the same user and gateway (the store's lock), and always start from
// the refresh token persisted last, so two proxies never present a
// rotated token (which would revoke the family).
type tokenSource struct {
	o     *Options
	oc    *oauthClient
	store *credStore
	sem   chan struct{}

	mu     sync.Mutex
	ep     *endpoints
	access string
	expiry time.Time
	// unsaved holds a refresh token the store failed to persist: it is
	// newer than the stored one.
	unsaved string
}

func newTokenSource(o *Options, oc *oauthClient, store *credStore) *tokenSource {
	return &tokenSource{o: o, oc: oc, store: store, sem: make(chan struct{}, 1)}
}

func (ts *tokenSource) current() (string, bool) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.access != "" && ts.o.Now().Before(ts.expiry) {
		return ts.access, true
	}
	return "", false
}

// Token returns a valid access token, renewing it when needed.
func (ts *tokenSource) Token(ctx context.Context) (string, error) {
	if tok, ok := ts.current(); ok {
		return tok, nil
	}
	select {
	case ts.sem <- struct{}{}:
	case <-ctx.Done():
		return "", ctx.Err()
	}
	defer func() { <-ts.sem }()
	if tok, ok := ts.current(); ok {
		return tok, nil
	}
	return ts.renew(ctx)
}

// Invalidate drops tok after /mcp rejected it, so the next Token renews.
func (ts *tokenSource) Invalidate(tok string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.access == tok {
		ts.access = ""
	}
}

// resourceURL is the MCP endpoint found by discovery ("" before).
func (ts *tokenSource) resourceURL() string {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if ts.ep == nil {
		return ""
	}
	return ts.ep.resource
}

func (ts *tokenSource) endpoints(ctx context.Context) (*endpoints, error) {
	ts.mu.Lock()
	ep := ts.ep
	ts.mu.Unlock()
	if ep != nil {
		return ep, nil
	}
	ep, err := ts.oc.discover(ctx)
	if err != nil {
		return nil, err
	}
	ts.mu.Lock()
	ts.ep = ep
	ts.mu.Unlock()
	return ep, nil
}

func (ts *tokenSource) renew(ctx context.Context) (string, error) {
	ep, err := ts.endpoints(ctx)
	if err != nil {
		return "", err
	}
	unlock, err := ts.store.lock(ctx)
	if err != nil {
		return "", err
	}
	defer unlock()
	cr, err := ts.store.load(ctx)
	if err != nil {
		return "", fmt.Errorf("read the stored sign-in: %w", err)
	}
	ts.mu.Lock()
	if ts.unsaved != "" {
		cr.RefreshToken = ts.unsaved
	}
	ts.mu.Unlock()
	switch {
	case cr.ClientID == "" || cr.RefreshToken == "":
	case cr.Scope != ts.o.Scope:
		ts.say("the stored sign-in is for scope %q; signing in again for %q.", cr.Scope, ts.o.Scope)
	default:
		tr, err := ts.oc.token(ctx, ep, url.Values{
			"grant_type": {grantRefreshToken}, "refresh_token": {cr.RefreshToken}, "client_id": {cr.ClientID}, "resource": {ep.resource},
		})
		switch {
		case err == nil:
			return ts.accept(ctx, cr.ClientID, tr), nil
		case isOAuthError(err, "invalid_grant"):
			ts.say("the gateway no longer accepts this sign-in (%v); sign in again.", err)
			ts.forgetUnsaved()
			if derr := ts.store.dropRefresh(ctx); derr != nil {
				return "", derr
			}
		case isOAuthError(err, "invalid_client"):
			ts.say("the gateway no longer knows this proxy's client; registering again.")
			ts.forgetUnsaved()
			if derr := ts.store.dropClient(ctx); derr != nil {
				return "", derr
			}
			cr.ClientID = ""
		default:
			return "", fmt.Errorf("refresh the access token: %w", err)
		}
	}
	return ts.signIn(ctx, ep, cr.ClientID)
}

func (ts *tokenSource) forgetUnsaved() {
	ts.mu.Lock()
	ts.unsaved = ""
	ts.mu.Unlock()
}

// signIn runs the device flow (RFC 8628), registering first when there
// is no client.
func (ts *tokenSource) signIn(ctx context.Context, ep *endpoints, clientID string) (string, error) {
	var da *deviceAuthorization
	for attempt := 0; ; attempt++ {
		if clientID == "" {
			id, err := ts.oc.register(ctx, ep, ts.o.ClientName, ts.o.Version)
			if err != nil {
				return "", err
			}
			clientID = id
			if err := ts.store.saveClient(ctx, clientID, ""); err != nil {
				return "", fmt.Errorf("save the client registration: %w", err)
			}
		}
		var err error
		da, err = ts.oc.authorizeDevice(ctx, ep, clientID, ts.o.Scope)
		if err == nil {
			break
		}
		if attempt == 0 && isOAuthError(err, "invalid_client") {
			if derr := ts.store.dropClient(ctx); derr != nil {
				return "", derr
			}
			clientID = ""
			continue
		}
		return "", fmt.Errorf("start the sign-in: %w", err)
	}

	ts.say("sign in to %s to connect this harness.", ts.o.Gateway)
	say(ts.o.Stderr, "To sign in, open %s and enter %s\n", clean(da.VerificationURI), clean(da.UserCode))
	if da.VerificationURIComplete != "" {
		say(ts.o.Stderr, "  or open %s\n", clean(da.VerificationURIComplete))
	}
	say(ts.o.Stderr, "The page shows the client %q. Waiting for approval...\n", ts.o.ClientName)

	interval := time.Duration(da.Interval) * time.Second
	if interval <= 0 {
		interval = defaultInterval
	}
	expires := da.ExpiresIn
	if expires <= 0 {
		expires = defaultExpiresIn
	}
	deadline := ts.o.Now().Add(time.Duration(expires) * time.Second)
	form := url.Values{"grant_type": {grantDeviceCode}, "device_code": {da.DeviceCode}, "client_id": {clientID}}
	for {
		if err := ts.o.Sleep(ctx, interval); err != nil {
			return "", err
		}
		if !ts.o.Now().Before(deadline) {
			return "", &signInError{ErrSignInExpired}
		}
		tr, err := ts.oc.token(ctx, ep, form)
		var oe *oauthError
		switch {
		case err == nil:
			tok := ts.accept(ctx, clientID, tr)
			ts.say("Signed in to %s.", ts.o.Gateway)
			return tok, nil
		case ctx.Err() != nil:
			return "", ctx.Err()
		case !errors.As(err, &oe):
			// A network error: keep polling until the code expires.
			if ts.o.Log != nil {
				ts.o.Log.Debug("sign-in poll failed; retrying", "error", err)
			}
		case oe.Code == "authorization_pending":
		case oe.Code == "slow_down":
			interval += slowDownStep
		case oe.Code == "access_denied":
			return "", &signInError{ErrSignInDenied}
		case oe.Code == "expired_token":
			return "", &signInError{ErrSignInExpired}
		default:
			return "", &signInError{fmt.Errorf("the gateway refused the sign-in: %w", err)}
		}
	}
}

// accept keeps the access token and persists the rotated refresh token.
// A failed save is reported, not fatal: the in-memory token keeps working
// and the next renewal uses it.
func (ts *tokenSource) accept(ctx context.Context, clientID string, tr *tokenResponse) string {
	lifetime := time.Duration(tr.ExpiresIn) * time.Second
	if lifetime <= 0 {
		lifetime = defaultLifetime
	}
	unsaved := ""
	if tr.RefreshToken != "" {
		if err := ts.store.saveRefresh(ctx, tr.RefreshToken); err != nil {
			ts.say("could not store the refresh token (%v); you will have to sign in again after this session.", err)
			unsaved = tr.RefreshToken
		}
	}
	if err := ts.store.saveClient(ctx, clientID, ts.o.Scope); err != nil {
		ts.say("could not save the sign-in state: %v", err)
	}
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.unsaved = unsaved
	ts.access = tr.AccessToken
	ts.expiry = ts.o.Now().Add(lifetime - min(refreshMargin, lifetime/2))
	return ts.access
}

func (ts *tokenSource) say(format string, args ...any) {
	say(ts.o.Stderr, "mcp-gateway proxy: "+format+"\n", args...)
}
