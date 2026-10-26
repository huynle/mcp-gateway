package authserver

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

// The device authorization grant (RFC 8628) for harnesses that cannot
// receive a loopback redirect (a harness on a remote SSH host). A public
// client registered for the grant asks POST /oauth/device_authorization
// for a device code and a user code; the user enters the code at
// /activate (internal/machines serves the page for machine enrollment and
// harness grants alike, through LookupDeviceGrant, ApproveDeviceGrant and
// DenyDeviceGrant) after checking the client, the scope and the address
// and User-Agent the request came from; the harness polls the token
// endpoint with the device_code grant. Redemption issues exactly what the
// authorization code grant issues (createRefresh, mintResponse), so
// revocation, the harnesses page, the sign-in max age and the audit trail
// apply unchanged. Both codes are stored as SHA-256 only; the user code
// shares its format and hash derivation with machine device requests and
// the store never lets the two hold the same code.

// Device grant limits.
const (
	// DeviceCodePrefix starts every device code.
	DeviceCodePrefix = "gwd_"
	// DefaultDeviceInterval is the initial polling interval in seconds;
	// slow_down raises it by deviceSlowDownStep up to maxDeviceInterval.
	DefaultDeviceInterval = 5
	deviceSlowDownStep    = 5
	maxDeviceInterval     = 60
	// MaxPendingDeviceGrants caps a client's pending, unexpired grants.
	MaxPendingDeviceGrants = 10
	maxUserAgent           = 256
	maxRequestIP           = 64
)

// ErrDeviceGrantGone: no device grant with this code or id is waiting
// for approval (unknown, decided, redeemed or expired).
var ErrDeviceGrantGone = errors.New("authserver: the device grant is not waiting for approval")

var errDeviceCapped = errors.New("authserver: too many pending device grants")

// DeviceGrantView is a harness device grant as the approval page shows
// it. UserCode is set by LookupDeviceGrant only.
type DeviceGrantView struct {
	ID         string
	UserCode   string
	ClientName string
	ClientID   string
	Scope      string
	Scopes     []string
	Resource   string
	RequestIP  string
	UserAgent  string
	CreatedAt  time.Time
	ExpiresAt  time.Time
}

// deviceAuthorizationResponse is the RFC 8628 section 3.2 answer.
type deviceAuthorizationResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int64  `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// ServeDeviceAuthorization is POST /oauth/device_authorization.
func (s *Service) ServeDeviceAuthorization(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	if allowed, wait := s.devices.Allow(ip); !allowed {
		w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(wait.Seconds()))))
		writeError(w, http.StatusTooManyRequests, "too_many_requests", "too many device authorizations from this address; retry later")
		return
	}
	s.devices.Fail(ip) // every attempt, valid or not, spends the budget
	form, client, terr := s.parseClientRequest(w, r)
	if terr != nil {
		s.writeTokenError(w, terr)
		return
	}
	scope, terr := checkDeviceRequest(s.cfg, client, form)
	if terr != nil {
		s.writeTokenError(w, terr)
		return
	}
	resp, g, err := s.createDeviceGrant(r.Context(), client, scope, trimRunes(ip, maxRequestIP), cleanUserAgent(r.UserAgent()))
	switch {
	case errors.Is(err, errDeviceCapped):
		w.Header().Set("Retry-After", strconv.Itoa(int(s.cfg.CodeTTL/time.Second)))
		writeError(w, http.StatusTooManyRequests, "too_many_requests", "too many pending device authorizations for this client; retry later")
		return
	case err != nil:
		s.log.Error("device authorization failed", "event", "authserver.device_failed", "error", observability.RedactError(err),
			"request_id", observability.RequestIDFromContext(r.Context()))
		writeError(w, http.StatusServiceUnavailable, "server_error", "device authorization is temporarily unavailable")
		return
	}
	s.log.Info("device authorization requested", "event", "authserver.device_requested", "client_id", client.ClientID, "device_grant_id", g.ID, "scope", scope)
	s.recordWith(r.Context(), "", "", "oauth_device_authorization_requested", client, "allow", "succeeded",
		map[string]string{"device_grant_id": g.ID, "scope": scope, "request_ip": g.RequestIP})
	writeJSON(w, http.StatusOK, resp)
}

// checkDeviceRequest validates the client's grant, the scope and the
// resource indicator (the same rules as the authorization endpoint).
func checkDeviceRequest(cfg Config, client *store.OAuthClient, form url.Values) (string, *tokenError) {
	meta := clientMeta(client)
	if !slices.Contains(meta.GrantTypes, GrantDeviceCode) {
		return "", badRequest("unauthorized_client", "the client is not registered for the device_code grant")
	}
	scope, ok := ParseScope(form.Get("scope"))
	if !ok {
		return "", badRequest("invalid_scope", "scope must be a subset of: "+strings.Join(ScopesSupported, " "))
	}
	if meta.Scope != "" && !scopeWithin(scope, meta.Scope) {
		return "", badRequest("invalid_scope", "scope exceeds what the client registered")
	}
	switch resource := form.Get("resource"); {
	case resource == "":
		return "", badRequest("invalid_target", "resource is required and must be "+cfg.Resource())
	case !sameResource(resource, cfg.Resource()):
		return "", badRequest("invalid_target", "resource must be "+cfg.Resource())
	}
	return scope, nil
}

// createDeviceGrant stores a pending grant under the client's cap,
// drawing another user code when one is taken.
func (s *Service) createDeviceGrant(ctx context.Context, client *store.OAuthClient, scope, ip, userAgent string) (*deviceAuthorizationResponse, *store.OAuthDeviceGrant, error) {
	now := s.now()
	for range 3 {
		deviceCode, err := randomToken(32)
		if err != nil {
			return nil, nil, fmt.Errorf("device code: %w", err)
		}
		deviceCode = DeviceCodePrefix + deviceCode
		userCode, err := tokens.NewUserCode()
		if err != nil {
			return nil, nil, err
		}
		normalized, _ := tokens.NormalizeUserCode(userCode)
		g := &store.OAuthDeviceGrant{
			DeviceCodeHash: hashSecret(deviceCode), UserCodeHash: hashSecret(normalized), ClientID: client.ID, Scope: scope,
			Resource: s.cfg.Resource(), RequestIP: ip, UserAgent: userAgent, Interval: DefaultDeviceInterval, ExpiresAt: now.Add(s.cfg.CodeTTL),
		}
		// One transaction per attempt: a unique violation aborts it.
		err = s.st.Bypass(ctx, func(tx Tx) error {
			n, err := tx.CountPendingDeviceGrants(ctx, client.ID, now)
			if err != nil {
				return err
			}
			if n >= MaxPendingDeviceGrants {
				return errDeviceCapped
			}
			return tx.CreateDeviceGrant(ctx, g)
		})
		if errors.Is(err, store.ErrUserCodeTaken) {
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		return &deviceAuthorizationResponse{
			DeviceCode: deviceCode, UserCode: userCode, VerificationURI: s.cfg.URL(ActivatePath),
			VerificationURIComplete: s.cfg.URL(ActivatePath) + "?code=" + userCode,
			ExpiresIn:               int64(s.cfg.CodeTTL / time.Second), Interval: DefaultDeviceInterval,
		}, g, nil
	}
	return nil, nil, errors.New("authserver: could not allocate a unique user code")
}

// LookupDeviceGrant finds the pending, unexpired grant a user code (as
// typed: any case, spaces and dashes) belongs to; ErrDeviceGrantGone
// otherwise. It does not rate limit: the /activate page does.
func (s *Service) LookupDeviceGrant(ctx context.Context, userCode string) (*DeviceGrantView, error) {
	normalized, ok := tokens.NormalizeUserCode(userCode)
	if !ok {
		return nil, ErrDeviceGrantGone
	}
	now := s.now()
	var v *DeviceGrantView
	err := s.st.Bypass(ctx, func(tx Tx) error {
		g, err := tx.FindDeviceGrantByUserCode(ctx, hashSecret(normalized))
		if errors.Is(err, store.ErrNotFound) {
			return ErrDeviceGrantGone
		}
		if err != nil {
			return err
		}
		if g.Status != store.OAuthDevicePending || !now.Before(g.ExpiresAt) {
			return ErrDeviceGrantGone
		}
		v, err = deviceView(ctx, tx, g)
		return err
	})
	if err != nil {
		return nil, err
	}
	v.UserCode = tokens.FormatUserCode(normalized)
	return v, nil
}

// ApproveDeviceGrant allows a pending grant for userID, who becomes the
// sign-in user of the tokens the harness redeems; ErrDeviceGrantGone when
// it is not pending any more.
func (s *Service) ApproveDeviceGrant(ctx context.Context, userID, id string) (*DeviceGrantView, error) {
	v, client, err := s.decideDeviceGrant(ctx, userID, id, store.OAuthDeviceApproved)
	if err != nil {
		return nil, err
	}
	s.log.Info("device grant approved", "event", "authserver.device_approved", "user_id", userID, "client_id", v.ClientID, "device_grant_id", id, "scope", v.Scope)
	s.recordWith(ctx, userID, "", "oauth_device_approved", client, "allow", "succeeded", map[string]string{"device_grant_id": id, "scope": v.Scope})
	return v, nil
}

// DenyDeviceGrant refuses a pending grant; the harness's next poll gets
// access_denied.
func (s *Service) DenyDeviceGrant(ctx context.Context, userID, id string) error {
	v, client, err := s.decideDeviceGrant(ctx, userID, id, store.OAuthDeviceDenied)
	if err != nil {
		return err
	}
	s.log.Info("device grant denied", "event", "authserver.device_denied", "user_id", userID, "client_id", v.ClientID, "device_grant_id", id)
	s.recordWith(ctx, userID, "", "oauth_device_denied", client, "deny", "denied", map[string]string{"device_grant_id": id})
	return nil
}

func (s *Service) decideDeviceGrant(ctx context.Context, userID, id, status string) (*DeviceGrantView, *store.OAuthClient, error) {
	now := s.now()
	var v *DeviceGrantView
	var client *store.OAuthClient
	err := s.st.Bypass(ctx, func(tx Tx) error {
		g, err := tx.LockDeviceGrantByID(ctx, id)
		if errors.Is(err, store.ErrNotFound) || isBadUUID(err) {
			return ErrDeviceGrantGone
		}
		if err != nil {
			return err
		}
		if g.Status != store.OAuthDevicePending || !now.Before(g.ExpiresAt) {
			return ErrDeviceGrantGone
		}
		g.Status, g.UserID, g.DecidedAt = status, userID, &now
		if err := tx.UpdateDeviceGrant(ctx, g); err != nil {
			return err
		}
		if client, err = tx.GetClient(ctx, g.ClientID); err != nil {
			return err
		}
		v = viewOf(g, client)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return v, client, nil
}

func deviceView(ctx context.Context, tx Tx, g *store.OAuthDeviceGrant) (*DeviceGrantView, error) {
	client, err := tx.GetClient(ctx, g.ClientID)
	if err != nil {
		return nil, err
	}
	return viewOf(g, client), nil
}

func viewOf(g *store.OAuthDeviceGrant, client *store.OAuthClient) *DeviceGrantView {
	return &DeviceGrantView{
		ID: g.ID, ClientName: client.ClientName, ClientID: client.ClientID, Scope: g.Scope, Scopes: describeScopes(g.Scope),
		Resource: g.Resource, RequestIP: g.RequestIP, UserAgent: g.UserAgent, CreatedAt: g.CreatedAt, ExpiresAt: g.ExpiresAt,
	}
}

// exchangeDeviceCode is the device_code grant (RFC 8628 section 3.4).
// The poll, its interval bookkeeping and the redemption (refresh-token
// family included) are one transaction on the locked grant, so two polls
// racing on an approved grant redeem it once; the loser sees a redeemed
// grant, which is replay and revokes the family.
func (s *Service) exchangeDeviceCode(ctx context.Context, client *store.OAuthClient, form url.Values) (*tokenResponse, *tokenError) {
	raw := form.Get("device_code")
	meta := clientMeta(client)
	switch {
	case !slices.Contains(meta.GrantTypes, GrantDeviceCode):
		return nil, badRequest("unauthorized_client", "the client is not registered for the device_code grant")
	case raw == "":
		return nil, badRequest("invalid_request", "device_code is required")
	}
	now := s.now()
	var g *store.OAuthDeviceGrant
	var outcome *tokenError
	var replay bool
	var refreshRaw, familyID string
	err := s.st.Bypass(ctx, func(tx Tx) error {
		var err error
		if g, err = tx.LockDeviceGrant(ctx, hashSecret(raw)); err != nil {
			return err
		}
		switch {
		case g.ClientID != client.ID:
			outcome = errInvalidClient
			return nil
		case g.Status == store.OAuthDeviceRedeemed:
			replay = true
			return nil
		case !now.Before(g.ExpiresAt):
			outcome = badRequest("expired_token", "the device code has expired; start the sign-in again")
			return nil
		case g.Status == store.OAuthDeviceDenied:
			outcome = badRequest("access_denied", "the user denied the request")
			return nil
		case g.Status == store.OAuthDevicePending:
			outcome = badRequest("authorization_pending", "waiting for the user to approve the request")
			if g.LastPolledAt != nil && now.Sub(*g.LastPolledAt) < time.Duration(g.Interval)*time.Second {
				outcome = badRequest("slow_down", "polling too fast; add 5 seconds to the interval")
				g.Interval = min(g.Interval+deviceSlowDownStep, maxDeviceInterval)
			}
			g.LastPolledAt = &now
			return tx.UpdateDeviceGrant(ctx, g)
		}
		facts, err := tx.FindUserAuthFacts(ctx, g.UserID)
		switch {
		case errors.Is(err, store.ErrNotFound):
			outcome = badRequest("invalid_grant", "the user no longer exists")
			return nil
		case err != nil:
			return err
		case facts.Status != store.UserActive:
			outcome = badRequest("invalid_grant", "the user is disabled")
			return nil
		}
		if slices.Contains(meta.GrantTypes, GrantRefreshToken) {
			refreshRaw, familyID, err = s.createRefresh(ctx, tx, issue{userID: g.UserID, client: client, scope: g.Scope, resource: g.Resource}, now)
			if err != nil {
				return err
			}
			g.FamilyID = &familyID
		}
		g.Status, g.RedeemedAt, g.LastPolledAt = store.OAuthDeviceRedeemed, &now, &now
		return tx.UpdateDeviceGrant(ctx, g)
	})
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.log.Warn("unknown device code", "event", "authserver.device_code_unknown", "client_id", client.ClientID)
		return nil, badRequest("invalid_grant", "the device code is invalid")
	case err != nil:
		return nil, s.serverError("redeem device code", err)
	case outcome == errInvalidClient:
		s.log.Warn("device code presented by another client", "event", "authserver.device_code_wrong_client", "client_id", client.ClientID)
		return nil, outcome
	case replay:
		s.revokeFamilyOnDeviceReplay(ctx, g, client)
		return nil, badRequest("invalid_grant", "the device code was already used")
	case outcome != nil:
		return nil, outcome
	}
	resp, terr := s.mintResponse(ctx, Grant{UserID: g.UserID, ClientID: client.ClientID, Scope: g.Scope, Resource: g.Resource, FamilyID: familyID}, refreshRaw, now)
	if terr != nil {
		return nil, terr
	}
	s.log.Info("tokens issued", "event", "authserver.tokens_issued", "grant", GrantDeviceCode, "user_id", g.UserID, "client_id", client.ClientID, "family_id", familyID, "scope", g.Scope)
	s.recordWith(ctx, g.UserID, familyID, "oauth_device_redeemed", client, "allow", "succeeded", map[string]string{"device_grant_id": g.ID, "scope": g.Scope})
	return resp, nil
}

// revokeFamilyOnDeviceReplay revokes the refresh-token family a replayed
// device code produced and records the event (the authorization code
// replay rule).
func (s *Service) revokeFamilyOnDeviceReplay(ctx context.Context, g *store.OAuthDeviceGrant, client *store.OAuthClient) {
	s.log.Warn("device code replayed", "event", "authserver.device_code_replayed", "client_id", client.ClientID, "user_id", g.UserID, "device_grant_id", g.ID)
	if g.FamilyID == nil {
		return
	}
	now := s.now()
	err := s.st.Bypass(ctx, func(tx Tx) error {
		_, err := tx.RevokeRefreshFamily(ctx, *g.FamilyID, now)
		return err
	})
	if err != nil {
		s.log.Error("family not revoked after device code replay", "event", "authserver.replay_revoke_failed", "error", observability.RedactError(err))
		return
	}
	s.recordWith(ctx, g.UserID, *g.FamilyID, "oauth_device_code_replayed", client, "deny", "denied", map[string]string{"device_grant_id": g.ID})
}

// cleanUserAgent keeps a User-Agent displayable and storable: valid
// UTF-8, no control characters, at most maxUserAgent characters.
func cleanUserAgent(ua string) string {
	ua = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.ToValidUTF8(ua, ""))
	return trimRunes(strings.TrimSpace(ua), maxUserAgent)
}

func trimRunes(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}
