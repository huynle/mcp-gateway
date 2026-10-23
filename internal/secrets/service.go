package secrets

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/store"
)

// States mirror the secrets.state column.
const (
	StatePending  = store.SecretPending
	StateProvided = store.SecretProvided
	StateDenied   = store.SecretDenied
	StateRevoked  = store.SecretRevoked
	StateExpired  = store.SecretExpired
)

// Status answers what a harness holding a handle should do next.
const (
	// StatusPending: not entered yet; answer with the same link again.
	StatusPending = "pending"
	// StatusProvided: usable now.
	StatusProvided = "provided"
	// StatusDenied: the user pressed Deny.
	StatusDenied = "denied"
	// StatusUnavailable: anything else (expired, used up, revoked, not
	// this caller's), deliberately not told apart.
	StatusUnavailable = "unavailable"
)

// Errors. Consume reports ErrUnavailable for every case the caller must
// not be able to tell apart; ErrPending and ErrDenied only for the
// caller's own request with a matching binding.
var (
	// ErrInvalid reports a malformed request (missing field, negative TTL
	// or uses, label too long).
	ErrInvalid = errors.New("secrets: invalid request")
	// ErrLimited: the owner has MaxPendingPerOwner live requests or made
	// MaxRequestsPerHour in the last hour.
	ErrLimited = errors.New("secrets: too many secret requests")
	// ErrNotFound: no such request or secret for this user, or the link
	// has expired, or it is no longer pending (entry page, revoke, refund).
	ErrNotFound = errors.New("secrets: not found")
	// ErrTooShort / ErrTooLong: the value is outside MinValueLen..MaxValueLen.
	ErrTooShort = errors.New("secrets: value too short")
	ErrTooLong  = errors.New("secrets: value too long")
	// ErrUnavailable: the secret cannot be used for this call.
	ErrUnavailable = errors.New("secret unavailable")
	// ErrPending: the caller's request has not been answered yet.
	ErrPending = errors.New("secret not entered yet")
	// ErrDenied: the user denied the caller's request.
	ErrDenied = errors.New("secret request denied")
)

// valueKind is the AAD kind for secret values.
const valueKind = "secret"

// HandlePrefix starts every handle.
const HandlePrefix = "sec_"

// Lenient format checks for incoming handles and request ids: the prefix,
// the base62 charset and a length range, so the generator can change.
const (
	minTokenLen = 20
	maxTokenLen = 100
	// tokenLen is the base62 length of 256 random bits.
	tokenLen = 43
)

// requestIDDomain separates the request id derivation from other hashes.
const requestIDDomain = "mcp-gateway/secret-request/v1\x00"

// GenerateHandle makes a new handle: HandlePrefix + base62 of 256 random
// bits. It is a variable so the reference package can replace it; any
// replacement must return values ValidHandle accepts.
var GenerateHandle = func() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("secrets: random handle: %w", err)
	}
	return HandlePrefix + base62(b), nil
}

// RequestIDForHandle is the one-time request id (the /s/<id> link) of a
// handle: base62 of SHA-256 over a domain tag and the handle. Deriving it
// lets the gateway answer a retry with the same link while storing only
// hashes; whoever holds the handle was given the link with it anyway, and
// the link only opens for the signed-in owner.
func RequestIDForHandle(handle string) string {
	h := sha256.Sum256([]byte(requestIDDomain + handle))
	return base62(h[:])
}

// ValidHandle reports whether s looks like a handle (prefix, charset,
// length). It does not say whether the handle exists.
func ValidHandle(s string) bool {
	body, ok := strings.CutPrefix(s, HandlePrefix)
	return ok && validToken(body)
}

func validRequestID(s string) bool { return validToken(s) }

func validToken(s string) bool {
	if len(s) < minTokenLen || len(s) > maxTokenLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			return false
		}
	}
	return true
}

// base62 encodes b as a fixed-width (for 32 bytes, tokenLen) base62 string.
func base62(b []byte) string {
	s := new(big.Int).SetBytes(b).Text(62)
	if len(s) < tokenLen {
		s = strings.Repeat("0", tokenLen-len(s)) + s
	}
	return s
}

func hashOf(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

var uuidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func isUUID(s string) bool { return uuidRE.MatchString(s) }

func equalCT(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

// Binding is the one target a secret may be used for: a server (id), one
// of its tools and the argument the value goes into. Arg is empty for a
// machine action, where the value is delivered outside the arguments.
type Binding struct {
	ServerID string
	Tool     string
	Arg      string
}

func (b Binding) store() store.SecretBinding {
	sb := store.SecretBinding{ServerID: b.ServerID, Tool: b.Tool}
	if b.Arg != "" {
		arg := b.Arg
		sb.Arg = &arg
	}
	return sb
}

func (b Binding) validate() bool {
	return isUUID(b.ServerID) && b.Tool != "" && len(b.Tool) <= 200 && len(b.Arg) <= 200
}

func (b Binding) equal(o Binding) bool {
	return equalCT(b.ServerID, o.ServerID) && equalCT(b.Tool, o.Tool) && equalCT(b.Arg, o.Arg)
}

// Secret is a secret as the rest of the gateway sees it: metadata only,
// never the value. HasValue says whether the encrypted value is stored.
type Secret struct {
	ID            string
	OwnerUserID   string
	HarnessID     string
	Label         string
	Binding       Binding
	UsesTotal     int
	UsesLeft      int
	TTL           time.Duration
	LinkExpiresAt time.Time
	ExpiresAt     *time.Time
	State         string
	HasValue      bool
	ProvidedAt    *time.Time
	EndedAt       *time.Time
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// Usable reports whether the secret can be consumed at now.
func (s Secret) Usable(now time.Time) bool {
	return s.State == StateProvided && s.UsesLeft > 0 && s.ExpiresAt != nil && now.Before(*s.ExpiresAt)
}

// LinkLive reports whether the entry link still accepts a value at now.
func (s Secret) LinkLive(now time.Time) bool {
	return s.State == StatePending && now.Before(s.LinkExpiresAt)
}

func fromStore(r *store.Secret) Secret {
	s := Secret{
		ID: r.ID, OwnerUserID: r.OwnerUserID, HarnessID: r.HarnessID, Label: r.Label,
		Binding:   Binding{ServerID: r.ServerID, Tool: r.Tool},
		UsesTotal: r.UsesTotal, UsesLeft: r.UsesLeft, TTL: r.TTL,
		LinkExpiresAt: r.LinkExpiresAt, ExpiresAt: r.ExpiresAt, State: r.State, HasValue: r.Value != nil,
		ProvidedAt: r.ProvidedAt, EndedAt: r.EndedAt, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	}
	if r.Arg != nil {
		s.Binding.Arg = *r.Arg
	}
	return s
}

// Requested is a new request: the raw request id (the entry link is
// <base>/s/<RequestID>) and handle, which exist only here, and the record.
type Requested struct {
	RequestID string
	Handle    string
	Secret    Secret
}

// StatusResult is Status's answer. Secret is set unless Status is
// StatusUnavailable; RequestID (the same link again) only for StatusPending.
type StatusResult struct {
	Status    string
	Secret    *Secret
	RequestID string
}

// Consumed is one use of a secret: the plaintext value, which the caller
// substitutes and then wipes, and the record id and label for audit.
type Consumed struct {
	SecretID string
	Label    string
	Value    []byte
}

// ExpireResult is what one expiry sweep did.
type ExpireResult struct {
	Expired int64
	Deleted int64
}

// Options are the optional dependencies.
type Options struct {
	Log *slog.Logger
}

// Service is the ephemeral secrets module.
type Service struct {
	st   Store
	keys crypto.KeyProvider
	log  *slog.Logger
	now  func() time.Time
}

// New builds the service. keys encrypts the values; without one the
// feature cannot run.
func New(st Store, keys crypto.KeyProvider, opts Options) (*Service, error) {
	if st == nil {
		return nil, errors.New("secrets: store is required")
	}
	if keys == nil {
		return nil, errors.New("secrets: key provider is required")
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	return &Service{st: st, keys: keys, log: opts.Log, now: func() time.Time { return time.Now().UTC() }}, nil
}

// SetClock replaces the time source (tests).
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// Request stores a pending request of owner, made by the harness
// harnessID (token id or OAuth family id), for binding. ttl 0 means
// DefaultTTL and is held within MinTTL..MaxTTL; uses 0 means DefaultUses
// and is capped at MaxUses. ErrInvalid for a malformed request,
// ErrLimited beyond the per-owner limits.
func (s *Service) Request(ctx context.Context, owner, harnessID, label string, b Binding, ttl time.Duration, uses int) (Requested, error) {
	label = strings.TrimSpace(label)
	switch {
	case owner == "", harnessID == "", len(harnessID) > 200, label == "", utf8.RuneCountInString(label) > MaxLabelLen,
		!b.validate(), ttl < 0, uses < 0:
		return Requested{}, ErrInvalid
	}
	ttl = clampTTL(ttl)
	uses = clampUses(uses)
	handle, err := GenerateHandle()
	if err != nil {
		return Requested{}, err
	}
	if !ValidHandle(handle) {
		return Requested{}, errors.New("secrets: generated handle is malformed")
	}
	requestID := RequestIDForHandle(handle)
	now := s.now()
	rec := &store.Secret{
		OwnerUserID: owner, HarnessID: harnessID, Label: label,
		UsesTotal: uses, UsesLeft: uses, TTL: ttl, LinkExpiresAt: now.Add(LinkTTL),
		RequestHash: hashOf(requestID), HandleHash: hashOf(handle), CreatedAt: now,
	}
	sb := b.store()
	rec.ServerID, rec.Tool, rec.Arg = sb.ServerID, sb.Tool, sb.Arg
	err = s.st.AsUser(ctx, owner, func(tx Tx) error {
		if err := tx.LockRequests(ctx, owner); err != nil {
			return err
		}
		pending, recent, err := tx.CountRequests(ctx, owner, now.Add(-time.Hour), now)
		if err != nil {
			return err
		}
		if pending >= MaxPendingPerOwner || recent >= MaxRequestsPerHour {
			return ErrLimited
		}
		return tx.CreateSecret(ctx, rec)
	})
	if err != nil {
		return Requested{}, err
	}
	s.log.Info("secret requested", "event", "secrets.requested", "secret_id", rec.ID, "label", rec.Label)
	return Requested{RequestID: requestID, Handle: handle, Secret: fromStore(rec)}, nil
}

func clampTTL(ttl time.Duration) time.Duration {
	switch {
	case ttl == 0:
		return DefaultTTL
	case ttl < MinTTL:
		return MinTTL
	case ttl > MaxTTL:
		return MaxTTL
	}
	return ttl.Truncate(time.Second)
}

func clampUses(uses int) int {
	switch {
	case uses == 0:
		return DefaultUses
	case uses > MaxUses:
		return MaxUses
	}
	return uses
}

// pendingRequest reads owner's pending request with a live link; every
// other case is ErrNotFound.
func (s *Service) pendingRequest(ctx context.Context, tx Tx, owner, requestID string, now time.Time) (*store.Secret, error) {
	if !validRequestID(requestID) {
		return nil, ErrNotFound
	}
	rec, err := tx.GetSecretByRequestHash(ctx, hashOf(requestID))
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if !equalCT(rec.OwnerUserID, owner) || !fromStore(rec).LinkLive(now) {
		return nil, ErrNotFound
	}
	return rec, nil
}

// LookupRequest returns owner's pending request for the entry page.
// ErrNotFound when it does not exist, is someone else's, its link expired
// or it was already answered.
func (s *Service) LookupRequest(ctx context.Context, owner, requestID string) (Secret, error) {
	var out Secret
	err := s.st.AsUser(ctx, owner, func(tx Tx) error {
		rec, err := s.pendingRequest(ctx, tx, owner, requestID, s.now())
		if err != nil {
			return err
		}
		out = fromStore(rec)
		return nil
	})
	return out, err
}

// Provide stores value for owner's pending request (single use): it is
// encrypted with AAD {owner, "secret", id, server id} and usable for the
// request's TTL from now. ErrNotFound as for LookupRequest; ErrTooShort /
// ErrTooLong for a value outside MinValueLen..MaxValueLen bytes.
func (s *Service) Provide(ctx context.Context, owner, requestID string, value []byte) (Secret, error) {
	var out Secret
	err := s.st.AsUser(ctx, owner, func(tx Tx) error {
		now := s.now()
		rec, err := s.pendingRequest(ctx, tx, owner, requestID, now)
		if err != nil {
			return err
		}
		switch {
		case len(value) < MinValueLen:
			return ErrTooShort
		case len(value) > MaxValueLen:
			return ErrTooLong
		}
		env, err := crypto.Encrypt(ctx, s.keys, aad(rec), value)
		if err != nil {
			return fmt.Errorf("secrets: encrypt: %w", err)
		}
		got, err := tx.ProvideSecret(ctx, rec.ID, rec.RequestHash, store.Encrypted(env), now)
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		out = fromStore(got)
		return nil
	})
	if err != nil {
		return Secret{}, err
	}
	s.log.Info("secret provided", "event", "secrets.provided", "secret_id", out.ID, "label", out.Label)
	return out, nil
}

func aad(rec *store.Secret) crypto.AAD {
	return crypto.AAD{UserID: rec.OwnerUserID, Kind: valueKind, RecordID: rec.ID, App: rec.ServerID}
}

// Deny refuses owner's pending request. ErrNotFound as for LookupRequest.
func (s *Service) Deny(ctx context.Context, owner, requestID string) (Secret, error) {
	var out Secret
	err := s.st.AsUser(ctx, owner, func(tx Tx) error {
		now := s.now()
		rec, err := s.pendingRequest(ctx, tx, owner, requestID, now)
		if err != nil {
			return err
		}
		got, err := tx.DenySecret(ctx, rec.RequestHash, now)
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		out = fromStore(got)
		return nil
	})
	if err != nil {
		return Secret{}, err
	}
	s.log.Info("secret denied", "event", "secrets.denied", "secret_id", out.ID, "label", out.Label)
	return out, nil
}

// Revoke ends owner's pending or provided secret id at once and wipes the
// value. ErrNotFound when there is no such live secret.
func (s *Service) Revoke(ctx context.Context, owner, id string) (Secret, error) {
	if !isUUID(id) {
		return Secret{}, ErrNotFound
	}
	var out Secret
	err := s.st.AsUser(ctx, owner, func(tx Tx) error {
		got, err := tx.RevokeSecret(ctx, id, s.now())
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		out = fromStore(got)
		return nil
	})
	if err != nil {
		return Secret{}, err
	}
	s.log.Info("secret revoked", "event", "secrets.revoked", "secret_id", out.ID, "label", out.Label)
	return out, nil
}

// List returns owner's secrets and requests, newest first, metadata only.
func (s *Service) List(ctx context.Context, owner string) ([]Secret, error) {
	var out []Secret
	err := s.st.AsUser(ctx, owner, func(tx Tx) error {
		rows, err := tx.ListSecrets(ctx, owner)
		if err != nil {
			return err
		}
		out = make([]Secret, 0, len(rows))
		for i := range rows {
			out = append(out, fromStore(&rows[i]))
		}
		return nil
	})
	return out, err
}

// Status tells the harness harnessID of owner what its handle stands for
// now. A handle is valid from the request on, also while pending. It
// returns StatusUnavailable, with nothing else, for anything that is not
// the caller's live request or secret.
func (s *Service) Status(ctx context.Context, owner, harnessID, handle string) (StatusResult, error) {
	unavailable := StatusResult{Status: StatusUnavailable}
	if owner == "" || !ValidHandle(handle) {
		return unavailable, nil
	}
	var out StatusResult
	err := s.st.AsUser(ctx, owner, func(tx Tx) error {
		rec, err := tx.GetSecretByHandleHash(ctx, hashOf(handle))
		if errors.Is(err, store.ErrNotFound) {
			out = unavailable
			return nil
		}
		if err != nil {
			return err
		}
		sec := fromStore(rec)
		now := s.now()
		switch {
		case !equalCT(rec.OwnerUserID, owner) || !equalCT(rec.HarnessID, harnessID):
			out = unavailable
		case sec.LinkLive(now):
			out = StatusResult{Status: StatusPending, Secret: &sec, RequestID: RequestIDForHandle(handle)}
		case sec.State == StateDenied:
			out = StatusResult{Status: StatusDenied, Secret: &sec}
		case sec.Usable(now):
			out = StatusResult{Status: StatusProvided, Secret: &sec}
		default:
			out = unavailable
		}
		return nil
	})
	if err != nil {
		return StatusResult{}, err
	}
	return out, nil
}

// Consume takes one use of the secret behind handle for a call by the
// harness harnessID of owner to binding and returns the plaintext. One
// conditional UPDATE decides (handle, owner, harness, binding, provided,
// uses left, unexpired), so concurrent callers never take more uses than
// there are; the value is decrypted in the same transaction, so a
// decryption failure takes nothing. ErrPending / ErrDenied for the
// caller's own matching request; ErrUnavailable for everything else.
func (s *Service) Consume(ctx context.Context, owner, harnessID, handle string, b Binding) (Consumed, error) {
	if owner == "" || harnessID == "" || !ValidHandle(handle) || !b.validate() {
		return Consumed{}, ErrUnavailable
	}
	var out Consumed
	err := s.st.AsUser(ctx, owner, func(tx Tx) error {
		now := s.now()
		h := hashOf(handle)
		rec, err := tx.ConsumeSecret(ctx, h, owner, harnessID, b.store(), now)
		if errors.Is(err, store.ErrSecretNotConsumable) {
			return s.whyNotConsumable(ctx, tx, h, owner, harnessID, b, now)
		}
		if err != nil {
			return err
		}
		if rec.Value == nil {
			return ErrUnavailable
		}
		plain, err := crypto.Decrypt(ctx, s.keys, aad(rec), crypto.Envelope(*rec.Value))
		if err != nil {
			return fmt.Errorf("secrets: decrypt %s: %w", rec.ID, err)
		}
		out = Consumed{SecretID: rec.ID, Label: rec.Label, Value: plain}
		return nil
	})
	if err != nil {
		return Consumed{}, err
	}
	s.log.Info("secret used", "event", "secrets.used", "secret_id", out.SecretID, "label", out.Label)
	return out, nil
}

// whyNotConsumable tells the caller's own pending or denied request apart;
// everything else is ErrUnavailable.
func (s *Service) whyNotConsumable(ctx context.Context, tx Tx, h []byte, owner, harnessID string, b Binding, now time.Time) error {
	rec, err := tx.GetSecretByHandleHash(ctx, h)
	if errors.Is(err, store.ErrNotFound) {
		return ErrUnavailable
	}
	if err != nil {
		return err
	}
	sec := fromStore(rec)
	if !equalCT(rec.OwnerUserID, owner) || !equalCT(rec.HarnessID, harnessID) || !sec.Binding.equal(b) {
		return ErrUnavailable
	}
	switch {
	case sec.LinkLive(now):
		return ErrPending
	case sec.State == StateDenied:
		return ErrDenied
	}
	return ErrUnavailable
}

// Refund gives back one use of owner's secret id after a call that never
// reached its target (a gateway refusal, an offline tunnel). Never above
// the requested uses, and only while the secret is still provided and
// unexpired; ErrNotFound otherwise.
func (s *Service) Refund(ctx context.Context, owner, id string) error {
	if !isUUID(id) {
		return ErrNotFound
	}
	return s.st.AsUser(ctx, owner, func(tx Tx) error {
		err := tx.RefundSecret(ctx, id, s.now())
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotFound
		}
		return err
	})
}

// Expire is the sweep the ExpiryJob runs (jobs scope): requests whose link
// passed and secrets used up or past their TTL become expired with the
// value wiped; ended rows older than Retention are deleted.
func (s *Service) Expire(ctx context.Context) (ExpireResult, error) {
	var res store.SecretExpiry
	err := s.st.Bypass(ctx, func(tx Tx) error {
		var err error
		res, err = tx.ExpireSecrets(ctx, s.now(), Retention)
		return err
	})
	if err != nil {
		return ExpireResult{}, fmt.Errorf("secrets: expire: %w", err)
	}
	if res.Expired > 0 || res.Deleted > 0 {
		s.log.Info("secrets expired", "event", "secrets.expired", "expired", res.Expired, "deleted", res.Deleted)
	}
	return ExpireResult{Expired: res.Expired, Deleted: res.Deleted}, nil
}

// OnDisableUser revokes every pending or provided secret of userID and
// wipes the values. Its signature is identity.DisableHook: it runs inside
// the transaction that disables the user (tx, a jobs-scope transaction);
// with a nil tx (a non-PostgreSQL identity store) it opens its own.
func (s *Service) OnDisableUser(ctx context.Context, tx store.Tx, userID string) error {
	now := s.now()
	var n int64
	var err error
	if tx != nil {
		n, err = pgTx{tx}.RevokeUserSecrets(ctx, userID, now)
	} else {
		err = s.st.Bypass(ctx, func(t Tx) error {
			n, err = t.RevokeUserSecrets(ctx, userID, now)
			return err
		})
	}
	if err != nil {
		return fmt.Errorf("secrets: revoke on disable: %w", err)
	}
	if n > 0 {
		s.log.Info("secrets revoked on disable", "event", "secrets.revoked_on_disable", "revoked", n)
	}
	return nil
}
