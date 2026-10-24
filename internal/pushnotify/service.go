package pushnotify

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/webpush"
)

// Audit actions (user events; resource->>'action').
const (
	ActionSubscribed   = "push.subscribed"
	ActionUnsubscribed = "push.unsubscribed"
	ActionTestSent     = "push.test_sent"
)

// Errors.
var (
	// ErrInvalidSubscription wraps every reason a browser subscription is
	// refused (malformed, bad keys, endpoint not on a known push service);
	// the portal answers with one generic message.
	ErrInvalidSubscription = errors.New("pushnotify: invalid push subscription")
	// ErrLimit means the user already has MaxSubscriptionsPerUser devices.
	ErrLimit = errors.New("pushnotify: too many devices")
	// ErrNotFound means no such device of the user's.
	ErrNotFound = errors.New("pushnotify: device not found")
	// ErrTestTooSoon is TestTooSoonError's sentinel.
	ErrTestTooSoon = errors.New("pushnotify: test notification rate limited")
)

// TestTooSoonError is ErrTestTooSoon with the wait.
type TestTooSoonError struct{ RetryAfter time.Duration }

func (e *TestTooSoonError) Error() string {
	return fmt.Sprintf("pushnotify: test notification rate limited; retry after %s", e.RetryAfter)
}

// Is makes errors.Is(err, ErrTestTooSoon) true.
func (e *TestTooSoonError) Is(target error) bool { return target == ErrTestTooSoon }

// Sender delivers one encrypted push message (*webpush.Sender; tests use
// a fake so they need no network).
type Sender interface {
	Send(ctx context.Context, sub webpush.Subscription, payload []byte, o webpush.SendOptions) error
}

// SenderFactory builds the Sender once the VAPID key is loaded.
type SenderFactory func(keys *webpush.Keys) (Sender, error)

// Options configures New.
type Options struct {
	// Subject is the VAPID subject (Subject); required.
	Subject string
	// NewSender defaults to webpush.New with Subject and the netguard
	// client.
	NewSender SenderFactory
	// Audit records subscribe, unsubscribe and test sends.
	Audit audit.Recorder
	Log   *slog.Logger
	// Timeout bounds one fan-out (DefaultNotifyTimeout when zero).
	Timeout time.Duration
	// Now defaults to time.Now (UTC).
	Now func() time.Time
}

// Device is what the portal shows of a subscription: never the endpoint.
type Device struct {
	ID            string     `json:"id"`
	Label         string     `json:"label"`
	Host          string     `json:"host"`
	CreatedAt     time.Time  `json:"created_at"`
	LastSuccessAt *time.Time `json:"last_success_at,omitempty"`
	LastFailureAt *time.Time `json:"last_failure_at,omitempty"`
	FailureCount  int        `json:"failure_count"`
}

// Service owns the VAPID key, the subscriptions and the notifications.
type Service struct {
	st        Store
	kp        crypto.KeyProvider
	newSender SenderFactory
	audit     audit.Recorder
	log       *slog.Logger
	timeout   time.Duration
	now       func() time.Time

	// mu guards the loaded key and sender: loaded once per process (the
	// key is never rotated automatically).
	mu     sync.Mutex
	public string
	sender Sender

	// testMu guards lastTest, the per-user test-send limiter.
	testMu   sync.Mutex
	lastTest map[string]time.Time
}

// New builds the service. kp encrypts the VAPID private key and the
// subscriptions.
func New(st Store, kp crypto.KeyProvider, opts Options) (*Service, error) {
	if st == nil {
		return nil, errors.New("pushnotify: store is required")
	}
	if kp == nil {
		return nil, errors.New("pushnotify: key provider is required")
	}
	if !strings.HasPrefix(opts.Subject, "mailto:") {
		if u, err := url.Parse(opts.Subject); err != nil || u.Scheme != "https" || u.Host == "" {
			return nil, errors.New("pushnotify: the VAPID subject must be an https URL or a mailto: address")
		}
	}
	if opts.NewSender == nil {
		subject := opts.Subject
		opts.NewSender = func(k *webpush.Keys) (Sender, error) {
			return webpush.New(webpush.Options{Keys: k, Subject: subject})
		}
	}
	if opts.Audit == nil {
		opts.Audit = audit.NopRecorder{}
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultNotifyTimeout
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	now := opts.Now
	return &Service{
		st: st, kp: kp, newSender: opts.NewSender, audit: opts.Audit, log: opts.Log, timeout: opts.Timeout,
		now:      func() time.Time { return now().UTC() },
		lastTest: map[string]time.Time{},
	}, nil
}

// --- VAPID key ---------------------------------------------------------------

// PublicKey returns the VAPID public key as the browser's base64url
// applicationServerKey, creating the key pair on first use.
func (s *Service) PublicKey(ctx context.Context) (string, error) {
	if err := s.load(ctx); err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.public, nil
}

// senderFor returns the Sender, loading the key first if needed.
func (s *Service) senderFor(ctx context.Context) (Sender, error) {
	if err := s.load(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sender, nil
}

// load reads the VAPID key (creating it when the table is empty), opens
// it and builds the Sender, once per process. Creation is race-safe
// across replicas: the insert is ON CONFLICT DO NOTHING on a singleton and
// the row is read back in the same transaction, so a replica that lost
// the race uses the winner's key. A stored key that does not open is an
// error, never replaced: replacing it would silently invalidate every
// subscription.
func (s *Service) load(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sender != nil {
		return nil
	}
	var row *store.WebPushKey
	err := s.st.Bypass(ctx, func(tx Tx) error {
		var err error
		row, err = tx.GetKey(ctx)
		return err
	})
	if errors.Is(err, store.ErrNotFound) {
		row, err = s.create(ctx)
	}
	if err != nil {
		return fmt.Errorf("pushnotify: load VAPID key: %w", err)
	}
	der, err := crypto.Decrypt(ctx, s.kp, crypto.AAD{Kind: KeyKind, RecordID: row.ID}, crypto.Envelope(row.PrivateKey))
	if err != nil {
		return fmt.Errorf("pushnotify: open VAPID key: %w", err)
	}
	keys, err := webpush.ParsePrivateKey(der)
	clear(der)
	if err != nil {
		return fmt.Errorf("pushnotify: open VAPID key: %w", err)
	}
	if keys.PublicKey() != row.PublicKey {
		return errors.New("pushnotify: VAPID private key does not match the stored public key")
	}
	sender, err := s.newSender(keys)
	if err != nil {
		return fmt.Errorf("pushnotify: sender: %w", err)
	}
	s.public, s.sender = row.PublicKey, sender
	return nil
}

// create generates and stores a key pair unless another replica stored
// one first, and returns the stored row either way.
func (s *Service) create(ctx context.Context) (*store.WebPushKey, error) {
	keys, err := webpush.GenerateKeys()
	if err != nil {
		return nil, err
	}
	der, err := keys.MarshalPrivateKey()
	if err != nil {
		return nil, err
	}
	id := newID()
	env, err := crypto.Encrypt(ctx, s.kp, crypto.AAD{Kind: KeyKind, RecordID: id}, der)
	clear(der)
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}
	var row *store.WebPushKey
	var inserted bool
	err = s.st.Bypass(ctx, func(tx Tx) error {
		inserted, err = tx.CreateKey(ctx, &store.WebPushKey{ID: id, PublicKey: keys.PublicKey(), PrivateKey: store.Encrypted(env)})
		if err != nil {
			return err
		}
		row, err = tx.GetKey(ctx)
		return err
	})
	if err != nil {
		return nil, err
	}
	if inserted {
		s.log.Info("web push key created", "event", "pushnotify.key_created", "key_id", id)
	}
	return row, nil
}

// --- subscriptions -----------------------------------------------------------

// sealedSubscription is the plaintext inside a subscription's envelope.
type sealedSubscription struct {
	Endpoint string `json:"endpoint"`
	P256dh   []byte `json:"p256dh"`
	Auth     []byte `json:"auth"`
}

func endpointHash(endpoint string) []byte {
	h := sha256.Sum256([]byte(endpoint))
	return h[:]
}

func (s *Service) aad(userID, id string) crypto.AAD {
	return crypto.AAD{UserID: userID, Kind: SubscriptionKind, RecordID: id}
}

// Subscribe stores the browser subscription raw (PushSubscription.toJSON;
// other fields are ignored) for userID under label (cleaned; "Browser"
// when empty). Re-subscribing an endpoint updates its keys and label in
// place. An endpoint another user holds is handed over to userID. Errors:
// ErrInvalidSubscription, ErrLimit.
func (s *Service) Subscribe(ctx context.Context, userID string, raw []byte, label string) (*Device, error) {
	sub, err := webpush.ParseSubscription(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidSubscription, err)
	}
	u, err := url.Parse(sub.Endpoint)
	if err != nil {
		return nil, ErrInvalidSubscription
	}
	plain, err := json.Marshal(sealedSubscription{Endpoint: sub.Endpoint, P256dh: sub.P256dh, Auth: sub.Auth})
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	row := store.PushSubscription{
		UserID: userID, EndpointSHA256: endpointHash(sub.Endpoint),
		EndpointHost: strings.ToLower(u.Hostname()), DeviceLabel: cleanLabel(label),
	}
	renewed, err := s.upsert(ctx, &row, plain)
	if errors.Is(err, store.ErrPushEndpointTaken) {
		// The browser presenting the endpoint is now signed in as userID:
		// the previous owner must stop getting notifications on it.
		var released int64
		err = s.st.Bypass(ctx, func(tx Tx) error {
			var rerr error
			released, rerr = tx.Release(ctx, row.EndpointSHA256, userID)
			return rerr
		})
		if err == nil {
			s.log.Info("push endpoint handed over", "event", "pushnotify.endpoint_handed_over", "user_id", userID, "released", released)
			renewed, err = s.upsert(ctx, &row, plain)
		}
	}
	if err != nil {
		if errors.Is(err, ErrLimit) {
			return nil, err
		}
		return nil, fmt.Errorf("pushnotify: subscribe: %w", err)
	}
	extra := map[string]string{}
	if renewed {
		extra["renewed"] = "true"
	}
	s.record(ctx, userID, ActionSubscribed, &row, extra)
	s.log.Info("push subscription stored", "event", "pushnotify.subscribed", "user_id", userID, "subscription_id", row.ID,
		"host", row.EndpointHost, "renewed", renewed, observability.RequestIDAttr(ctx))
	d := toDevice(row)
	return &d, nil
}

// upsert stores row (sealing plain under its id) in one user-scoped
// transaction: an update of the user's own row for the same endpoint, or
// a new row within the cap. It reports whether it was an update.
func (s *Service) upsert(ctx context.Context, row *store.PushSubscription, plain []byte) (bool, error) {
	var renewed bool
	err := s.st.AsUser(ctx, row.UserID, func(tx Tx) error {
		if err := tx.Lock(ctx, row.UserID); err != nil {
			return err
		}
		existing, err := tx.GetByHash(ctx, row.EndpointSHA256)
		switch {
		case err == nil:
			row.ID, renewed = existing.ID, true
		case errors.Is(err, store.ErrNotFound):
			n, err := tx.Count(ctx, row.UserID)
			if err != nil {
				return err
			}
			if n >= MaxSubscriptionsPerUser {
				return ErrLimit
			}
			row.ID, renewed = newID(), false
		default:
			return err
		}
		env, err := crypto.Encrypt(ctx, s.kp, s.aad(row.UserID, row.ID), plain)
		if err != nil {
			return fmt.Errorf("encrypt: %w", err)
		}
		row.Sealed = store.Encrypted(env)
		if renewed {
			return tx.Update(ctx, row)
		}
		return tx.Create(ctx, row)
	})
	return renewed, err
}

// Unsubscribe deletes userID's subscription of endpoint (the browser's
// "turn off"). Unknown endpoints are not an error.
func (s *Service) Unsubscribe(ctx context.Context, userID, endpoint string) error {
	if endpoint == "" || len(endpoint) > webpush.MaxEndpointLength {
		return nil
	}
	h := endpointHash(endpoint)
	var row *store.PushSubscription
	err := s.st.AsUser(ctx, userID, func(tx Tx) error {
		r, err := tx.GetByHash(ctx, h)
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if _, err := tx.Delete(ctx, r.ID); err != nil {
			return err
		}
		row = r
		return nil
	})
	if err != nil {
		return fmt.Errorf("pushnotify: unsubscribe: %w", err)
	}
	if row != nil {
		s.record(ctx, userID, ActionUnsubscribed, row, nil)
	}
	return nil
}

var uuidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// RemoveDevice deletes one of userID's devices by id (the device table's
// Remove button). ErrNotFound for an unknown or someone else's id.
func (s *Service) RemoveDevice(ctx context.Context, userID, id string) error {
	if !uuidRE.MatchString(id) {
		return ErrNotFound
	}
	var row *store.PushSubscription
	err := s.st.AsUser(ctx, userID, func(tx Tx) error {
		list, err := tx.List(ctx, userID)
		if err != nil {
			return err
		}
		for i := range list {
			if strings.EqualFold(list[i].ID, id) {
				row = &list[i]
			}
		}
		if row == nil {
			return ErrNotFound
		}
		_, err = tx.Delete(ctx, row.ID)
		return err
	})
	if errors.Is(err, ErrNotFound) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("pushnotify: remove device: %w", err)
	}
	s.record(ctx, userID, ActionUnsubscribed, row, nil)
	return nil
}

// Devices lists userID's devices, oldest first.
func (s *Service) Devices(ctx context.Context, userID string) ([]Device, error) {
	var out []Device
	err := s.st.AsUser(ctx, userID, func(tx Tx) error {
		list, err := tx.List(ctx, userID)
		if err != nil {
			return err
		}
		for _, r := range list {
			out = append(out, toDevice(r))
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("pushnotify: devices: %w", err)
	}
	return out, nil
}

func toDevice(r store.PushSubscription) Device {
	return Device{
		ID: r.ID, Label: r.DeviceLabel, Host: r.EndpointHost, CreatedAt: r.CreatedAt,
		LastSuccessAt: r.LastSuccessAt, LastFailureAt: r.LastFailureAt, FailureCount: r.FailureCount,
	}
}

// OnDisableUser deletes every subscription of userID: a disabled user
// gets no more notifications, and the devices are gone when the account
// is enabled again. Its signature is identity.DisableHook: it runs inside
// the transaction that disables the user (tx, a jobs-scope transaction);
// with a nil tx (a non-PostgreSQL identity store) it opens its own.
func (s *Service) OnDisableUser(ctx context.Context, tx store.Tx, userID string) error {
	var n int64
	var err error
	if tx != nil {
		n, err = pgTx{tx}.DeleteUser(ctx, userID)
	} else {
		err = s.st.Bypass(ctx, func(t Tx) error {
			n, err = t.DeleteUser(ctx, userID)
			return err
		})
	}
	if err != nil {
		return fmt.Errorf("pushnotify: delete on disable: %w", err)
	}
	if n > 0 {
		s.log.Info("push subscriptions deleted on disable", "event", "pushnotify.deleted_on_disable", "user_id", userID, "deleted", n)
	}
	return nil
}

// record appends a user audit event naming the subscription by id, label
// and push-service host, never the endpoint. Failures are logged.
func (s *Service) record(ctx context.Context, userID, action string, row *store.PushSubscription, extra map[string]string) {
	res := map[string]string{"action": action}
	if row != nil {
		res["subscription_id"], res["device"], res["host"] = row.ID, row.DeviceLabel, row.EndpointHost
	}
	for k, v := range extra {
		res[k] = v
	}
	ev := audit.Event{
		Time: s.now(), UserID: userID, ResourceIdentity: res, Decision: "allow", Outcome: "succeeded",
		RequestID: observability.RequestIDFromContext(ctx),
	}
	if err := s.audit.Record(ctx, ev); err != nil {
		s.log.Error("audit event not recorded", "event", "pushnotify.audit_failed", "action", action,
			"error", observability.RedactError(err), observability.RequestIDAttr(ctx))
	}
}

// newID returns a random (version 4) UUID: row ids are chosen before the
// insert because they are part of the encryption's AAD.
func newID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// topic derives the RFC 8030 Topic of an approval's message: a short
// base64url hash of its id, so a push service replaces an undelivered
// duplicate without learning the id.
func topic(id string) string {
	h := sha256.Sum256([]byte("mcp-gateway/push-topic/" + id))
	return base64.RawURLEncoding.EncodeToString(h[:16])
}
