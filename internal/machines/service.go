package machines

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

// Lifetimes and bounds.
const (
	// DeviceRequestTTL is how long a device request can be approved.
	DeviceRequestTTL = 10 * time.Minute
	// DefaultPollInterval is the device flow's initial polling interval.
	DefaultPollInterval = 5
	// maxPollInterval bounds the interval slow_down raises.
	maxPollInterval = 60
	// AccessTokenTTL is a machine access token's lifetime.
	AccessTokenTTL = 10 * time.Minute
	// MaxUsableEnrollmentCodes bounds a user's unused, unexpired codes.
	MaxUsableEnrollmentCodes = 10
	// maxClientVersion bounds client_version.
	maxClientVersion = 64
	// maxLabel bounds an enrollment code's label.
	maxLabel = 100
)

// EnrollmentCodeLifetimes are the lifetimes a code can be created with.
var EnrollmentCodeLifetimes = []time.Duration{time.Hour, 24 * time.Hour, 7 * 24 * time.Hour}

// Errors.
var (
	// ErrRequestGone: the device request is not pending any more
	// (decided, consumed or expired) or unknown.
	ErrRequestGone = errors.New("machines: the request is no longer waiting for approval")
	// ErrInactiveOwner: the approving or owning user is not active.
	ErrInactiveOwner = errors.New("machines: the account is not active")
	// ErrInvalidCode: an enrollment code that cannot be used (unknown,
	// used, revoked, expired, or its owner is not active).
	ErrInvalidCode = errors.New("machines: invalid enrollment code")
	// ErrTooManyCodes: the user already has MaxUsableEnrollmentCodes.
	ErrTooManyCodes = errors.New("machines: too many unused enrollment codes; revoke one first")
	// ErrInvalidLifetime: not one of EnrollmentCodeLifetimes.
	ErrInvalidLifetime = errors.New("machines: an enrollment code lasts 1 hour, 24 hours or 7 days")
	// ErrUnknownUserCode: no pending request has this user code.
	ErrUnknownUserCode = errors.New("machines: no pending request has this code")
	// ErrTooManyAttempts: too many wrong user codes from this user.
	ErrTooManyAttempts = errors.New("machines: too many wrong codes; wait a minute and try again")
	// ErrServerNameTaken: the server name belongs to another server.
	ErrServerNameTaken = errors.New("machines: server name taken")
	// ErrNotPermitted: the owner may not add MCP servers.
	ErrNotPermitted = errors.New("machines: not permitted to add MCP servers")
	// ErrServerLocked: the server is published; only an admin changes it.
	ErrServerLocked = errors.New("machines: published server")
	// ErrInvalidServerName: not a valid (or a reserved) server name.
	ErrInvalidServerName = errors.New("machines: invalid server name")

	errCodeCollision = errors.New("machines: code collision")
)

// PollDecision is what a device token poll does to its request.
type PollDecision struct {
	// Interval is the request's polling interval from now on.
	Interval int
	// Consume marks an approved request consumed.
	Consume bool
}

// Store is the machines' persistence. NewStore adapts *store.Store; every
// method is one transaction. Lookups answer store.ErrNotFound.
type Store interface {
	// CreateDeviceRequest stores a pending request (errCodeCollision
	// when a code hash is taken).
	CreateDeviceRequest(ctx context.Context, d *store.MachineDeviceRequest) error
	DeviceRequestByUserCode(ctx context.Context, hash []byte) (*store.MachineDeviceRequest, error)
	// PollDeviceRequest locks the request with this device code hash,
	// applies fn's decision and returns the request as fn saw it.
	PollDeviceRequest(ctx context.Context, hash []byte, at time.Time, fn func(*store.MachineDeviceRequest) PollDecision) (*store.MachineDeviceRequest, error)
	// ApproveDeviceRequest creates the machine for approver from the
	// pending, unexpired request and marks it approved. An approver's
	// live machine of the same name is replaced (revoked as "replaced",
	// its tunnels moved to the new machine); its id is returned.
	// ErrRequestGone, ErrInactiveOwner, *caps.ExceededError (machines).
	ApproveDeviceRequest(ctx context.Context, requestID, approver string, at time.Time) (*store.Machine, string, error)
	// DenyDeviceRequest: ErrRequestGone when not pending.
	DenyDeviceRequest(ctx context.Context, requestID, by string, at time.Time) error
	// Enroll consumes the code and stores m for the code's owner (same
	// replacement rule); ErrInvalidCode, *caps.ExceededError.
	Enroll(ctx context.Context, codeHash []byte, m *store.Machine, at time.Time) (string, error)
	// Machine returns a machine with its owner's name and status.
	Machine(ctx context.Context, id string) (*store.Machine, error)
	// RecordJTI reports whether an assertion id is new (false: replay).
	RecordJTI(ctx context.Context, machineID, jti string, exp, now time.Time) (bool, error)
	// IssueToken stores an access token hash and records last seen / IP.
	IssueToken(ctx context.Context, hash []byte, machineID string, exp time.Time, ip string, at time.Time) error
	// TokenMachine returns the machine of an unexpired access token
	// (revoked or not: the caller checks Live).
	TokenMachine(ctx context.Context, hash []byte, at time.Time) (*store.MachineAccess, error)
	// Revoke revokes a live machine and its tunnels; ownerID "" allows any
	// owner (admin). store.ErrNotFound otherwise.
	Revoke(ctx context.Context, id, ownerID, actorID, reason string, at time.Time) (*store.Machine, error)
	ListMachines(ctx context.Context, ownerID string) ([]store.Machine, error)
	ListAllMachines(ctx context.Context) ([]store.Machine, error)
	// MachineTunnels returns the machine's tunnels, revoked ones included.
	MachineTunnels(ctx context.Context, machineID string) ([]store.MCPTunnel, error)
	// EnsureTunnel returns the machine's live tunnel for server, creating
	// it (tunnel cap) when there is none; created reports which.
	EnsureTunnel(ctx context.Context, m *store.Machine, server string) (*store.MCPTunnel, bool, error)
	// RevokeTunnel revokes one tunnel (undo of a failed registration).
	RevokeTunnel(ctx context.Context, tunnelID string, at time.Time) error
	// CreateEnrollmentCode stores a code (ErrTooManyCodes at maxUsable).
	CreateEnrollmentCode(ctx context.Context, c *store.MachineEnrollmentCode, maxUsable int, at time.Time) error
	ListEnrollmentCodes(ctx context.Context, ownerID string) ([]store.MachineEnrollmentCode, error)
	RevokeEnrollmentCode(ctx context.Context, ownerID, id string, at time.Time) error
}

// Servers is the owner's MCP servers as the machine API manages them.
// NewServers adapts the federation (connector Manager, snapshots,
// upstream sessions).
type Servers interface {
	// OwnServer returns ownerID's own server called name (ErrNotFound).
	OwnServer(ctx context.Context, ownerID, name string) (*store.MCPServer, error)
	// CreateServer stores a private server for s.OwnerUserID:
	// ErrServerNameTaken, ErrNotPermitted, ErrInvalidServerName,
	// *caps.ExceededError (servers).
	CreateServer(ctx context.Context, s *store.MCPServer) error
	// SetServerURL stores s.URL (ErrServerLocked for a published server).
	SetServerURL(ctx context.Context, ownerID string, s *store.MCPServer) error
	// Refresh rediscovers the server as its owner (never approves) and
	// returns the new snapshot version and the diff to the approved one.
	Refresh(ctx context.Context, ownerID string, s *store.MCPServer) (int, snapshot.Diff, error)
	// Review returns how many tools are enabled in the approved snapshot
	// and whether a newer snapshot waits for review.
	Review(ctx context.Context, ownerID, serverID string) (approved int, pending bool, err error)
}

// Tunnels is the part of *tunnel.Service the machines use.
type Tunnels interface {
	ServeMachine(w http.ResponseWriter, r *http.Request, machineID string)
	SyncMachine(machineID string)
	DropMachine(machineID string)
	Online(tunnelID string) bool
}

// RateLimits bound the unauthenticated endpoints per client address
// (requests per minute; zero takes the default).
type RateLimits struct {
	// DeviceAuthorization: every request spends (default 10).
	DeviceAuthorization int
	// Enroll: every request spends (default 10).
	Enroll int
	// TokenFailures: failed token requests (default 30).
	TokenFailures int
	// UserCodeFailures: wrong user codes per signed-in user (default 10).
	UserCodeFailures int
}

// Options configure a Service. Store, Servers and Tunnels are required.
type Options struct {
	Store   Store
	Servers Servers
	Tunnels Tunnels
	// BaseURL is the gateway's public URL (GATEWAY_BASE_URL): the
	// verification URI, the assertion audience and the review links.
	BaseURL string
	// Audit records machine events (never keys, codes, tokens or
	// assertions). Default: audit.NopRecorder.
	Audit audit.Recorder
	Log   *slog.Logger
	Now   func() time.Time
	// ClientIP is the rate-limit key and the address shown on the
	// approval page. Default: the host part of RemoteAddr.
	ClientIP func(*http.Request) string
	Limits   RateLimits
}

// Service enrolls and authenticates machines and serves the machine API.
type Service struct {
	o        Options
	base     string
	audience string
	log      *slog.Logger
	now      func() time.Time
	audit    audit.Recorder
	clientIP func(*http.Request) string

	deviceLimiter   *tokens.FailureLimiter
	enrollLimiter   *tokens.FailureLimiter
	tokenLimiter    *tokens.FailureLimiter
	userCodeLimiter *tokens.FailureLimiter
}

// New builds a Service.
func New(o Options) (*Service, error) {
	switch {
	case o.Store == nil || o.Servers == nil || o.Tunnels == nil:
		return nil, errors.New("machines: Store, Servers and Tunnels are required")
	case o.BaseURL == "":
		return nil, errors.New("machines: BaseURL is required")
	}
	s := &Service{o: o, base: strings.TrimRight(o.BaseURL, "/"), log: o.Log, now: o.Now, audit: o.Audit, clientIP: o.ClientIP}
	s.audience = s.base + TokenPath
	if s.log == nil {
		s.log = slog.Default()
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.audit == nil {
		s.audit = audit.NopRecorder{}
	}
	if s.clientIP == nil {
		s.clientIP = remoteIP
	}
	l := o.Limits
	s.deviceLimiter = tokens.NewFailureLimiter(orDefault(l.DeviceAuthorization, 10), time.Minute)
	s.enrollLimiter = tokens.NewFailureLimiter(orDefault(l.Enroll, 10), time.Minute)
	s.tokenLimiter = tokens.NewFailureLimiter(orDefault(l.TokenFailures, 30), time.Minute)
	s.userCodeLimiter = tokens.NewFailureLimiter(orDefault(l.UserCodeFailures, 10), time.Minute)
	for _, lim := range []*tokens.FailureLimiter{s.deviceLimiter, s.enrollLimiter, s.tokenLimiter, s.userCodeLimiter} {
		lim.SetClock(s.now)
	}
	return s, nil
}

func orDefault(v, d int) int {
	if v <= 0 {
		return d
	}
	return v
}

// BaseURL is the gateway URL the service was built with.
func (s *Service) BaseURL() string { return s.base }

// ReviewURL is the review page of a server.
func (s *Service) ReviewURL(serverID string) string {
	return s.base + "/servers/" + serverID + "/review"
}

// record writes an audit event; a failure is logged (the change is
// committed already).
func (s *Service) record(ctx context.Context, userID, action string, fields map[string]string) {
	r := map[string]string{"action": action}
	for k, v := range fields {
		if v != "" {
			r[k] = v
		}
	}
	ev := audit.Event{Time: s.now(), UserID: userID, ResourceIdentity: r, Decision: "allow", Outcome: "succeeded",
		RequestID: observability.RequestIDFromContext(ctx)}
	if action == "machine.denied" {
		ev.Decision, ev.Outcome = "deny", "denied"
	}
	if err := s.audit.Record(ctx, ev); err != nil {
		s.log.Error("machines: audit event not recorded", "action", action, "error", observability.RedactError(err))
	}
}

func machineFields(m *store.Machine) map[string]string {
	return map[string]string{"machine_id": m.ID, "machine_name": m.Name, "fingerprint": DisplayFingerprint(m.Fingerprint)}
}

// --- device flow -------------------------------------------------------------------

// DeviceAuthorization is the answer to a device request.
type DeviceAuthorization struct {
	DeviceCode string
	UserCode   string
	ExpiresIn  int
	Interval   int
}

// RequestDevice starts a device authorization for a machine name and
// public key, requested from ip.
func (s *Service) RequestDevice(ctx context.Context, name string, pub []byte, clientVersion, ip string) (*DeviceAuthorization, error) {
	now := s.now()
	for range 3 {
		dc, err := NewSecret(DeviceCodePrefix)
		if err != nil {
			return nil, err
		}
		uc, err := NewUserCode()
		if err != nil {
			return nil, err
		}
		n, _ := NormalizeUserCode(uc)
		d := &store.MachineDeviceRequest{
			DeviceCodeHash: HashSecret(dc), UserCodeHash: HashSecret(n), Name: name, PublicKey: pub,
			Fingerprint: Thumbprint(pub), ClientVersion: clientVersion, RequestIP: ip,
			ExpiresAt: now.Add(DeviceRequestTTL), Interval: DefaultPollInterval,
		}
		err = s.o.Store.CreateDeviceRequest(ctx, d)
		if errors.Is(err, errCodeCollision) {
			continue
		}
		if err != nil {
			return nil, err
		}
		s.record(ctx, "", "machine.device_requested", map[string]string{"request_id": d.ID, "machine_name": name, "fingerprint": DisplayFingerprint(d.Fingerprint)})
		return &DeviceAuthorization{DeviceCode: dc, UserCode: uc, ExpiresIn: int(DeviceRequestTTL / time.Second), Interval: DefaultPollInterval}, nil
	}
	return nil, errors.New("machines: could not allocate a unique code")
}

// Poll outcomes of a device token request (RFC 8628 §3.5 error codes).
var (
	errAuthorizationPending = errors.New("authorization_pending")
	errSlowDown             = errors.New("slow_down")
	errAccessDenied         = errors.New("access_denied")
	errExpiredToken         = errors.New("expired_token")
)

// PollDevice answers one device token poll: the machine once approved,
// else errAuthorizationPending, errSlowDown, errAccessDenied or
// errExpiredToken.
func (s *Service) PollDevice(ctx context.Context, deviceCode string) (*store.Machine, error) {
	if !ValidSecret(DeviceCodePrefix, deviceCode) {
		return nil, errExpiredToken
	}
	now := s.now()
	var outcome error
	d, err := s.o.Store.PollDeviceRequest(ctx, HashSecret(deviceCode), now, func(d *store.MachineDeviceRequest) PollDecision {
		interval := d.Interval
		switch {
		case d.Status == store.MachineRequestConsumed || (d.Status == store.MachineRequestPending && !now.Before(d.ExpiresAt)):
			outcome = errExpiredToken
		case d.Status == store.MachineRequestDenied:
			outcome = errAccessDenied
		case d.Status == store.MachineRequestApproved:
			return PollDecision{Interval: interval, Consume: true}
		case d.LastPolledAt != nil && now.Sub(*d.LastPolledAt) < time.Duration(interval)*time.Second:
			outcome = errSlowDown
			interval = min(interval+5, maxPollInterval)
		default:
			outcome = errAuthorizationPending
		}
		return PollDecision{Interval: interval}
	})
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, errExpiredToken
	case err != nil:
		return nil, err
	case outcome != nil:
		return nil, outcome
	}
	m, err := s.o.Store.Machine(ctx, d.MachineID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, errExpiredToken
	}
	return m, err
}

// LookupUserCode finds the pending request a signed-in user typed the
// code of: ErrUnknownUserCode (counted against the user) or
// ErrTooManyAttempts.
func (s *Service) LookupUserCode(ctx context.Context, userID, code string) (*store.MachineDeviceRequest, error) {
	if ok, _ := s.userCodeLimiter.Allow(userID); !ok {
		return nil, ErrTooManyAttempts
	}
	n, ok := NormalizeUserCode(code)
	if !ok {
		s.userCodeLimiter.Fail(userID)
		return nil, ErrUnknownUserCode
	}
	d, err := s.o.Store.DeviceRequestByUserCode(ctx, HashSecret(n))
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.userCodeLimiter.Fail(userID)
		return nil, ErrUnknownUserCode
	case err != nil:
		return nil, err
	case d.Status != store.MachineRequestPending || !s.now().Before(d.ExpiresAt):
		s.userCodeLimiter.Fail(userID)
		return nil, ErrUnknownUserCode
	}
	return d, nil
}

// Approve creates the machine of a pending request for approverID (the
// machine is the approver's, whoever started the request).
func (s *Service) Approve(ctx context.Context, approverID, requestID string) (*store.Machine, error) {
	m, replaced, err := s.o.Store.ApproveDeviceRequest(ctx, requestID, approverID, s.now())
	if err != nil {
		return nil, err
	}
	s.afterEnroll(ctx, m, replaced, "machine.approved")
	return m, nil
}

// Deny refuses a pending request.
func (s *Service) Deny(ctx context.Context, userID, requestID string) error {
	if err := s.o.Store.DenyDeviceRequest(ctx, requestID, userID, s.now()); err != nil {
		return err
	}
	s.record(ctx, userID, "machine.denied", map[string]string{"request_id": requestID})
	return nil
}

func (s *Service) afterEnroll(ctx context.Context, m *store.Machine, replaced, action string) {
	if replaced != "" {
		s.o.Tunnels.DropMachine(replaced)
		s.record(ctx, m.OwnerUserID, "machine.revoked", map[string]string{"machine_id": replaced, "machine_name": m.Name, "reason": store.MachineReplaced})
	}
	s.record(ctx, m.OwnerUserID, action, machineFields(m))
	s.log.Info("machine enrolled", "event", action, "user_id", m.OwnerUserID, "machine_id", m.ID, "replaced", replaced)
}

// Enroll enrolls a machine with a one-time code.
func (s *Service) Enroll(ctx context.Context, code, name string, pub []byte, clientVersion, ip string) (*store.Machine, error) {
	if !ValidSecret(EnrollmentCodePrefix, code) {
		return nil, ErrInvalidCode
	}
	m := &store.Machine{Name: name, PublicKey: pub, Fingerprint: Thumbprint(pub), ClientVersion: clientVersion,
		EnrolledVia: store.MachineEnrolledCode, EnrolledIP: ip}
	replaced, err := s.o.Store.Enroll(ctx, HashSecret(code), m, s.now())
	if err != nil {
		return nil, err
	}
	s.afterEnroll(ctx, m, replaced, "machine.enrolled")
	return m, nil
}

// --- tokens ------------------------------------------------------------------------

// TokenFromAssertion verifies a machine assertion and mints an access
// token. Every failure is ErrInvalidAssertion-matching (logged with its
// reason by the caller).
func (s *Service) TokenFromAssertion(ctx context.Context, raw, ip string) (string, time.Time, error) {
	now := s.now()
	var m *store.Machine
	a, err := VerifyAssertion(raw, func(id string) (ed25519.PublicKey, error) {
		var err error
		m, err = s.o.Store.Machine(ctx, id)
		if err != nil {
			return nil, err
		}
		if !m.Live() {
			return nil, ErrInactiveOwner
		}
		return ed25519.PublicKey(m.PublicKey), nil
	}, s.audience, now)
	if err != nil {
		return "", time.Time{}, err
	}
	fresh, err := s.o.Store.RecordJTI(ctx, a.MachineID, a.JTI, a.ExpiresAt.Add(ClockSkew), now)
	if err != nil {
		return "", time.Time{}, err
	}
	if !fresh {
		return "", time.Time{}, invalid("replay")
	}
	tok, err := NewSecret(AccessTokenPrefix)
	if err != nil {
		return "", time.Time{}, err
	}
	exp := now.Add(AccessTokenTTL)
	if err := s.o.Store.IssueToken(ctx, HashSecret(tok), m.ID, exp, ip, now); err != nil {
		return "", time.Time{}, err
	}
	return tok, exp, nil
}

// Token errors of the machine API.
var (
	errInvalidToken = errors.New("invalid_token")
	errRevoked      = errors.New("revoked")
)

// Authenticate resolves a machine access token: errInvalidToken for an
// unknown, malformed or expired one, errRevoked when the machine is
// revoked or its owner is not active.
func (s *Service) Authenticate(ctx context.Context, raw string) (*store.Machine, error) {
	if !ValidSecret(AccessTokenPrefix, raw) {
		return nil, errInvalidToken
	}
	a, err := s.o.Store.TokenMachine(ctx, HashSecret(raw), s.now())
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, errInvalidToken
	case err != nil:
		return nil, err
	case !a.Live():
		return nil, errRevoked
	}
	return &a.Machine, nil
}

// --- revocation ----------------------------------------------------------------------

// Revoke revokes a machine (ownerID "" for an admin) and closes its live
// connection on this replica.
func (s *Service) Revoke(ctx context.Context, machineID, ownerID, actorID, reason string) error {
	if !uuidRE.MatchString(machineID) {
		return store.ErrNotFound
	}
	m, err := s.o.Store.Revoke(ctx, machineID, ownerID, actorID, reason, s.now())
	if err != nil {
		return err
	}
	s.o.Tunnels.DropMachine(machineID)
	f := machineFields(m)
	f["reason"] = reason
	if actorID != "" && actorID != m.OwnerUserID {
		f["owner_user_id"] = m.OwnerUserID
	}
	user := actorID
	if user == "" {
		user = m.OwnerUserID
	}
	s.record(ctx, user, "machine.revoked", f)
	s.log.Info("machine revoked", "event", "machine.revoked", "machine_id", machineID, "reason", reason)
	return nil
}

// ListMachines returns ownerID's machines.
func (s *Service) ListMachines(ctx context.Context, ownerID string) ([]store.Machine, error) {
	return s.o.Store.ListMachines(ctx, ownerID)
}

// ListAllMachines returns every machine (admin).
func (s *Service) ListAllMachines(ctx context.Context) ([]store.Machine, error) {
	return s.o.Store.ListAllMachines(ctx)
}

// MachineTunnels returns a machine's tunnels.
func (s *Service) MachineTunnels(ctx context.Context, machineID string) ([]store.MCPTunnel, error) {
	return s.o.Store.MachineTunnels(ctx, machineID)
}

// Online reports whether a tunnel is connected.
func (s *Service) Online(tunnelID string) bool { return s.o.Tunnels.Online(tunnelID) }

// --- enrollment codes ----------------------------------------------------------------

// CreateEnrollmentCode creates a one-time code for ownerID and returns it
// in clear (shown once) with its row.
func (s *Service) CreateEnrollmentCode(ctx context.Context, ownerID, label string, ttl time.Duration) (string, *store.MachineEnrollmentCode, error) {
	ok := false
	for _, l := range EnrollmentCodeLifetimes {
		ok = ok || l == ttl
	}
	if !ok {
		return "", nil, ErrInvalidLifetime
	}
	label = strings.TrimSpace(label)
	if len(label) > maxLabel || !printableText(label) {
		return "", nil, fmt.Errorf("machines: a label is at most %d printable characters", maxLabel)
	}
	raw, err := NewSecret(EnrollmentCodePrefix)
	if err != nil {
		return "", nil, err
	}
	now := s.now()
	c := &store.MachineEnrollmentCode{OwnerUserID: ownerID, CodeHash: HashSecret(raw), Label: label, ExpiresAt: now.Add(ttl)}
	if err := s.o.Store.CreateEnrollmentCode(ctx, c, MaxUsableEnrollmentCodes, now); err != nil {
		return "", nil, err
	}
	s.record(ctx, ownerID, "machine.enrollment_code_created", map[string]string{"code_id": c.ID, "expires_in": ttl.String()})
	return raw, c, nil
}

// ListEnrollmentCodes returns ownerID's codes (never the codes themselves).
func (s *Service) ListEnrollmentCodes(ctx context.Context, ownerID string) ([]store.MachineEnrollmentCode, error) {
	return s.o.Store.ListEnrollmentCodes(ctx, ownerID)
}

// RevokeEnrollmentCode revokes one of ownerID's unused codes.
func (s *Service) RevokeEnrollmentCode(ctx context.Context, ownerID, id string) error {
	if !uuidRE.MatchString(id) {
		return store.ErrNotFound
	}
	if err := s.o.Store.RevokeEnrollmentCode(ctx, ownerID, id, s.now()); err != nil {
		return err
	}
	s.record(ctx, ownerID, "machine.enrollment_code_revoked", map[string]string{"code_id": id})
	return nil
}

func printableText(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}
