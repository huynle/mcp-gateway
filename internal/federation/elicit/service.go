package elicit

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/huynle/mcp-gateway/internal/store"
)

// Limits of the relay (design, plan 2 "Storage").
const (
	// LinkTTL is how long an interstitial link (/elicit/<id>) stays live.
	LinkTTL = 10 * time.Minute
	// Retention is how long after expiry the expiry job keeps a row.
	Retention = 24 * time.Hour
	// MaxLivePerOwner bounds one user's live elicitations (ErrLimited).
	MaxLivePerOwner = 20
	// MaxURLLen, MaxMessageLen (characters), MaxUpstreamIDLen and
	// MaxHarnessIDLen mirror the column checks of migration 00032.
	MaxURLLen        = 2048
	MaxMessageLen    = 500
	MaxUpstreamIDLen = 200
	MaxHarnessIDLen  = 200
	// ElicitationIDPrefix starts the elicitationId handed to harnesses.
	ElicitationIDPrefix = "gwe_"
)

// Errors.
var (
	// ErrInvalidRequest: a malformed request (owner or server not a uuid, a URL
	// that is not absolute https without userinfo and control characters,
	// a field over its limit).
	ErrInvalidRequest = errors.New("elicit: invalid elicitation")
	// ErrLimited: the owner already has MaxLivePerOwner live elicitations.
	ErrLimited = errors.New("elicit: too many open elicitations")
	// ErrNotFound: no live elicitation of this user behind the link
	// (unknown, malformed, someone else's, cancelled or expired), never
	// told apart.
	ErrNotFound = errors.New("elicit: not found")
)

// Elicitation is a stored upstream URL elicitation as the gateway sees it.
// The link id is not part of it: only its hash is stored.
type Elicitation struct {
	ID                    string
	OwnerUserID           string
	ServerID              string
	HarnessID             string
	URL                   string
	UpstreamElicitationID string
	// Message is the upstream's text, cleaned (no control characters but
	// newlines and tabs, valid UTF-8, at most MaxMessageLen characters). It
	// is shown on the interstitial as escaped plain text only and never
	// handed to a harness.
	Message     string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	OpenedAt    *time.Time
	CancelledAt *time.Time
}

func fromStore(r *store.UpstreamElicitation) Elicitation {
	return Elicitation{
		ID: r.ID, OwnerUserID: r.OwnerUserID, ServerID: r.ServerID, HarnessID: r.HarnessID, URL: r.URL,
		UpstreamElicitationID: r.UpstreamElicitationID, Message: r.Message,
		CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt, OpenedAt: r.OpenedAt, CancelledAt: r.CancelledAt,
	}
}

// Options are the optional dependencies.
type Options struct {
	// Log receives lifecycle events (record ids only). Default slog.Default().
	Log *slog.Logger
}

// Service stores relayed elicitations and answers the interstitial.
type Service struct {
	st  Store
	log *slog.Logger
	now func() time.Time
}

// New builds the service over st (NewPostgresStore in production).
func New(st Store, opts Options) (*Service, error) {
	if st == nil {
		return nil, errors.New("elicit: store is required")
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	return &Service{st: st, log: opts.Log, now: func() time.Time { return time.Now().UTC() }}, nil
}

// SetClock replaces the time source (tests).
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// Create stores an elicitation of owner (the user whose call the upstream
// answered), made through the harness harnessID (token id or OAuth family
// id; may be empty) on serverID, and returns the new link id (the
// interstitial is <base>/elicit/<link id>) with the record. The URL must
// already have passed the relay's origin rules (ValidateOrigin and the
// server's elicitation origins); Create only re-checks its shape. message
// is cleaned and cut to MaxMessageLen characters. ErrInvalidRequest for a
// malformed request, ErrLimited beyond MaxLivePerOwner live rows.
func (s *Service) Create(ctx context.Context, owner, harnessID, serverID, rawURL, upstreamID, message string) (string, Elicitation, error) {
	switch {
	case !isUUID(owner), !isUUID(serverID), len(harnessID) > MaxHarnessIDLen, len(upstreamID) > MaxUpstreamIDLen,
		hasCTL(harnessID), hasCTL(upstreamID), !validURL(rawURL):
		return "", Elicitation{}, ErrInvalidRequest
	}
	link, err := newLinkID()
	if err != nil {
		return "", Elicitation{}, err
	}
	now := s.now()
	rec := &store.UpstreamElicitation{
		LinkHash: hashOf(link), OwnerUserID: owner, ServerID: serverID, HarnessID: harnessID, URL: rawURL,
		UpstreamElicitationID: upstreamID, Message: CleanMessage(message), CreatedAt: now, ExpiresAt: now.Add(LinkTTL),
	}
	err = s.st.AsUser(ctx, owner, func(tx Tx) error {
		if err := tx.Lock(ctx, owner); err != nil {
			return err
		}
		n, err := tx.CountLive(ctx, owner, now)
		if err != nil {
			return err
		}
		if n >= MaxLivePerOwner {
			return ErrLimited
		}
		return tx.Create(ctx, rec)
	})
	if err != nil {
		return "", Elicitation{}, err
	}
	s.log.Info("upstream elicitation stored", "event", "elicit.created", "elicitation_id", rec.ID, "server_id", serverID)
	return link, fromStore(rec), nil
}

// Lookup returns owner's live elicitation behind linkID (the interstitial).
func (s *Service) Lookup(ctx context.Context, owner, linkID string) (Elicitation, error) {
	return s.live(ctx, owner, linkID, Tx.GetByLink)
}

// Open records that owner pressed Continue and returns the elicitation;
// its URL is where the interstitial redirects. The link stays live until
// it expires or is cancelled, so Continue may be pressed again (a closed
// tab, a failed sign-in at the upstream): the upstream page, not the
// gateway, decides whether its flow can be completed twice. OpenedAt keeps
// the first time.
func (s *Service) Open(ctx context.Context, owner, linkID string) (Elicitation, error) {
	return s.live(ctx, owner, linkID, Tx.MarkOpened)
}

// Cancel ends owner's live elicitation behind linkID.
func (s *Service) Cancel(ctx context.Context, owner, linkID string) (Elicitation, error) {
	return s.live(ctx, owner, linkID, Tx.MarkCancelled)
}

func (s *Service) live(ctx context.Context, owner, linkID string,
	op func(Tx, context.Context, string, []byte, time.Time) (*store.UpstreamElicitation, error)) (Elicitation, error) {
	if !isUUID(owner) || !validLinkID(linkID) {
		return Elicitation{}, ErrNotFound
	}
	var out Elicitation
	err := s.st.AsUser(ctx, owner, func(tx Tx) error {
		rec, err := op(tx, ctx, owner, hashOf(linkID), s.now())
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		out = fromStore(rec)
		return nil
	})
	return out, err
}

// Expire deletes elicitations that expired more than Retention ago and
// reports how many.
func (s *Service) Expire(ctx context.Context) (int64, error) {
	var n int64
	err := s.st.Bypass(ctx, func(tx Tx) error {
		var err error
		n, err = tx.PurgeExpired(ctx, s.now().Add(-Retention))
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("elicit: expire: %w", err)
	}
	if n > 0 {
		s.log.Info("upstream elicitations purged", "event", "elicit.purged", "count", n)
	}
	return n, nil
}

// elicitationIDDomain separates the elicitation id derivation from other
// hashes.
const elicitationIDDomain = "mcp-gateway/upstream-elicitation-id/v1\x00"

// ElicitationID is the elicitationId the gateway hands to the harness for
// rec: ElicitationIDPrefix + base62 of SHA-256 over a domain tag and the
// record id. It is stable for a record and does not reveal the record id;
// it is not a credential (the link id is).
func ElicitationID(rec Elicitation) string {
	h := sha256.Sum256([]byte(elicitationIDDomain + rec.ID))
	return ElicitationIDPrefix + base62(h[:])
}

// ValidElicitationID reports whether s looks like an ElicitationID.
func ValidElicitationID(s string) bool {
	body, ok := strings.CutPrefix(s, ElicitationIDPrefix)
	return ok && len(body) == tokenLen && isBase62(body)
}

// CleanMessage makes upstream text safe to store and show as plain text:
// valid UTF-8, no control or bidirectional-override characters (newlines
// and tabs stay), trimmed, at most MaxMessageLen characters.
func CleanMessage(m string) string {
	m = strings.ToValidUTF8(strings.ReplaceAll(m, "\r\n", "\n"), "\uFFFD")
	var b strings.Builder
	n := 0
	for _, r := range m {
		if n >= MaxMessageLen {
			break
		}
		if r != '\n' && r != '\t' && (unicode.IsControl(r) || isBidiControl(r)) {
			continue
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}

func isBidiControl(r rune) bool {
	return (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) || r == 0x200E || r == 0x200F || r == 0x061C
}

// validURL re-checks the shape of an elicitation URL: absolute https with a
// host, no userinfo, no control characters, at most MaxURLLen bytes.
func validURL(raw string) bool {
	if raw == "" || len(raw) > MaxURLLen || hasCTL(raw) || !utf8.ValidString(raw) {
		return false
	}
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Opaque == ""
}

func hasCTL(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

// --- link ids ----------------------------------------------------------------------

// tokenLen is the base62 length of 256 bits.
const tokenLen = 43

// newLinkID returns base62 of 256 random bits (no prefix: the id only
// appears in the /elicit/ path).
func newLinkID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("elicit: random link id: %w", err)
	}
	return base62(b), nil
}

// validLinkID is a lenient format check (charset, length range), so the
// generator can change.
func validLinkID(s string) bool { return len(s) >= 20 && len(s) <= 100 && isBase62(s) }

func isBase62(s string) bool {
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
