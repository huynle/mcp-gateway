package tunnel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
	"unicode"

	"github.com/huynle/mcp-gateway/internal/store"
)

// Errors returned by Service.
var (
	// ErrUnauthorized: the token is malformed, unknown or revoked.
	ErrUnauthorized = errors.New("tunnel: unauthorized")
	// ErrForbidden: the tunnel does not exist, is revoked, or belongs to
	// someone else.
	ErrForbidden = errors.New("tunnel: forbidden")
	// ErrInvalidName: a tunnel name must be 1-100 printable characters.
	ErrInvalidName = errors.New("tunnel: invalid name")
	// ErrNameTaken: the owner already has a live (not revoked) tunnel of
	// that name, ignoring case and surrounding space.
	ErrNameTaken = errors.New("tunnel: name already used by one of your tunnels")
)

// MaxNameLen bounds a tunnel's display name.
const MaxNameLen = 100

// Store is what the tunnel service needs from persistence. NewStore
// adapts *store.Store: owner-scoped calls run under WithUser, token lookup,
// re-validation and last-seen updates under WithJobs (no user is known
// when a tunnel client connects; decision 17iv8p3b).
type Store interface {
	// CreateTunnel stores a tunnel for ownerUserID (WithUser).
	CreateTunnel(ctx context.Context, ownerUserID, name string, tokenHash []byte) (*store.MCPTunnel, error)
	// RevokeTunnel revokes ownerUserID's live tunnel (WithUser);
	// store.ErrNotFound when it is not theirs, unknown or already revoked.
	RevokeTunnel(ctx context.Context, ownerUserID, tunnelID string, at time.Time) error
	// TunnelByTokenHash finds a tunnel by token hash, revoked or not (WithJobs).
	TunnelByTokenHash(ctx context.Context, hash []byte) (*store.MCPTunnel, error)
	// Tunnel returns a tunnel by ID, revoked or not (WithJobs).
	Tunnel(ctx context.Context, tunnelID string) (*store.MCPTunnel, error)
	// TouchTunnel records last_seen_at (WithJobs).
	TouchTunnel(ctx context.Context, tunnelID string, at time.Time) error
}

// Options configure a Service.
type Options struct {
	// Store is required (NewStore(*store.Store) in production).
	Store Store
	// Limits bound the multiplexed connection; zero fields take defaults.
	Limits Limits
	// Log receives connection events (tunnel id, owner, reason; never the
	// token). Default: discard.
	Log *slog.Logger
	// Now is the clock (tests). Default time.Now.
	Now func() time.Time
	// Relay enables the cross-replica relay (docs/tunnel.md "Multiple
	// replicas"); nil keeps every tunnel local to the replica holding its
	// connection.
	Relay *RelayOptions
}

// Service manages tunnel tokens, the /tunnel/connect endpoint and the
// in-process registry of live tunnel connections. It is safe for
// concurrent use.
type Service struct {
	store  Store
	limits Limits
	log    *slog.Logger
	now    func() time.Time
	reg    *registry
	relay  *relay // nil: relay disabled
}

// NewService builds a Service.
func NewService(o Options) (*Service, error) {
	if o.Store == nil {
		return nil, errors.New("tunnel: Options.Store is required")
	}
	s := &Service{store: o.Store, limits: o.Limits.withDefaults(), log: o.Log, now: o.Now}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	if s.now == nil {
		s.now = time.Now
	}
	s.reg = newRegistry()
	if o.Relay != nil {
		r, err := newRelay(s, *o.Relay)
		if err != nil {
			return nil, err
		}
		s.relay = r
	}
	return s, nil
}

// CreateTunnel registers a tunnel for ownerUserID and returns it with the
// plaintext token, which is never stored or shown again.
func (s *Service) CreateTunnel(ctx context.Context, ownerUserID, name string) (*store.MCPTunnel, string, error) {
	if !validName(name) {
		return nil, "", ErrInvalidName
	}
	raw, hash, err := GenerateToken()
	if err != nil {
		return nil, "", err
	}
	t, err := s.store.CreateTunnel(ctx, ownerUserID, name, hash)
	if err != nil {
		return nil, "", fmt.Errorf("tunnel: create: %w", err)
	}
	return t, raw, nil
}

// Revoke revokes ownerUserID's tunnel and drops its live connection on
// this replica (other replicas drop theirs at the next heartbeat).
func (s *Service) Revoke(ctx context.Context, ownerUserID, tunnelID string) error {
	if err := s.store.RevokeTunnel(ctx, ownerUserID, tunnelID, s.now()); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrForbidden
		}
		return fmt.Errorf("tunnel: revoke: %w", err)
	}
	s.reg.drop(tunnelID, closeRevoked, "revoked")
	return nil
}

// Authenticate resolves a bearer token to its live (not revoked) tunnel.
// Every failure is ErrUnauthorized, except store errors.
func (s *Service) Authenticate(ctx context.Context, raw string) (*store.MCPTunnel, error) {
	if ParseToken(raw) != nil {
		return nil, ErrUnauthorized
	}
	t, err := s.store.TunnelByTokenHash(ctx, HashToken(raw))
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrUnauthorized
	}
	if err != nil {
		return nil, fmt.Errorf("tunnel: authenticate: %w", err)
	}
	if t.RevokedAt != nil {
		return nil, ErrUnauthorized
	}
	return t, nil
}

// Authorize reports whether a server owned by serverOwnerID may route
// through tunnelID: the tunnel must exist, be live and have the same
// owner. A server published to roles by an admin keeps its owner, so a
// published server works through its owner's tunnel; nobody else's
// server can use it. Returns ErrForbidden otherwise.
func (s *Service) Authorize(ctx context.Context, serverOwnerID, tunnelID string) error {
	t, err := s.store.Tunnel(ctx, tunnelID)
	if errors.Is(err, store.ErrNotFound) {
		return ErrForbidden
	}
	if err != nil {
		return fmt.Errorf("tunnel: authorize: %w", err)
	}
	if t.RevokedAt != nil || serverOwnerID == "" || t.OwnerUserID != serverOwnerID {
		return ErrForbidden
	}
	return nil
}

func validName(name string) bool {
	if name == "" || len(name) > MaxNameLen {
		return false
	}
	for _, r := range name {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}
