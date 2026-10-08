package connections

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/store"
)

// AAD record kinds (crypto.AAD.Kind) this package encrypts under.
const (
	aadKindConnection = "connection"
	aadKindVendorApp  = "vendor_app"
)

// Config is what the service needs from the gateway configuration.
type Config struct {
	// BaseURL is GATEWAY_BASE_URL; the redirect URI registered at every
	// vendor is BaseURL + "/connect/<vendor>/callback".
	BaseURL string
	// FlowTTL bounds how long a started connect flow may take; 0 means
	// DefaultFlowTTL.
	FlowTTL time.Duration
	// RefreshSkew refreshes a token this long before its expiry; 0 means
	// DefaultRefreshSkew.
	RefreshSkew time.Duration
	// KeepAliveAfter is how long a token may go without a refresh before
	// the keep-alive job refreshes it; 0 means DefaultKeepAliveAfter.
	KeepAliveAfter time.Duration
	// VendorTimeout bounds every call to a vendor (token endpoint, user
	// info, revocation); 0 means DefaultVendorTimeout.
	VendorTimeout time.Duration
}

// Defaults for Config.
const (
	DefaultFlowTTL        = 10 * time.Minute
	DefaultRefreshSkew    = 2 * time.Minute
	DefaultKeepAliveAfter = 30 * 24 * time.Hour
	DefaultVendorTimeout  = 15 * time.Second
)

// PersonalAccountPolicy answers whether the user's roles allow personal
// accounts for an app (decision mh7c6z3v: admins can block personal
// accounts per app and role). PolicyAllowance adapts policy.Service; the
// zero default allows everything.
type PersonalAccountPolicy interface {
	PersonalAccountsAllowed(ctx context.Context, userID, app string) (bool, error)
}

// Notification tells a user something about one of their connections
// (today: it needs reconnecting).
type Notification struct {
	UserID       string
	ConnectionID string
	Vendor       string
	DisplayName  string
	Kind         string // NotifyNeedsReconnect
	Message      string
}

// NotifyNeedsReconnect is the Notification.Kind for an invalid grant.
const NotifyNeedsReconnect = "needs_reconnect"

// Notifier delivers notifications to users. LogNotifier is the default;
// the approvals task supplies the Slack/portal one.
type Notifier interface {
	Notify(ctx context.Context, n Notification) error
}

// LogNotifier logs notifications (the no-op default).
type LogNotifier struct{ Log *slog.Logger }

// Notify implements Notifier.
func (l LogNotifier) Notify(_ context.Context, n Notification) error {
	log := l.Log
	if log == nil {
		log = slog.Default()
	}
	log.Warn("user notification", "event", "connections.notify", "kind", n.Kind, "user_id", n.UserID,
		"connection_id", n.ConnectionID, "vendor", n.Vendor, "message", n.Message)
	return nil
}

// Metrics is the part of observability.Metrics the service uses.
type Metrics interface {
	ConnectionRefreshFailure(app string)
}

// Options configures New. Everything is optional.
type Options struct {
	Audit    audit.Recorder
	Policy   PersonalAccountPolicy
	Notifier Notifier
	Metrics  Metrics
	Log      *slog.Logger
	// HTTPClient is used for every vendor call (tests point it at
	// httptest servers); nil means http.DefaultClient with VendorTimeout.
	HTTPClient *http.Client
}

type allowAllPolicy struct{}

func (allowAllPolicy) PersonalAccountsAllowed(context.Context, string, string) (bool, error) {
	return true, nil
}

type nopMetrics struct{}

func (nopMetrics) ConnectionRefreshFailure(string) {}

// Service owns vendor apps, the connect flow, connections and their
// tokens.
type Service struct {
	cfg      Config
	store    Store
	keys     crypto.KeyProvider
	audit    audit.Recorder
	policy   PersonalAccountPolicy
	notifier Notifier
	metrics  Metrics
	log      *slog.Logger
	client   *http.Client
	now      func() time.Time

	mu      sync.RWMutex
	binders map[string]Binder   // by vendor
	apps    map[string][]string // vendor -> connector app names
}

// New builds the service. keys encrypts vendor app secrets and token
// bundles.
func New(cfg Config, st Store, keys crypto.KeyProvider, opts Options) (*Service, error) {
	if st == nil {
		return nil, errors.New("connections: store is required")
	}
	if keys == nil {
		return nil, errors.New("connections: key provider is required")
	}
	cfg.BaseURL = strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if cfg.BaseURL == "" {
		return nil, errors.New("connections: base URL is required")
	}
	if cfg.FlowTTL <= 0 {
		cfg.FlowTTL = DefaultFlowTTL
	}
	if cfg.RefreshSkew <= 0 {
		cfg.RefreshSkew = DefaultRefreshSkew
	}
	if cfg.KeepAliveAfter <= 0 {
		cfg.KeepAliveAfter = DefaultKeepAliveAfter
	}
	if cfg.VendorTimeout <= 0 {
		cfg.VendorTimeout = DefaultVendorTimeout
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.Audit == nil {
		opts.Audit = audit.NopRecorder{}
	}
	if opts.Policy == nil {
		opts.Policy = allowAllPolicy{}
	}
	if opts.Notifier == nil {
		opts.Notifier = LogNotifier{Log: opts.Log}
	}
	if opts.Metrics == nil {
		opts.Metrics = nopMetrics{}
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{Timeout: cfg.VendorTimeout}
	}
	return &Service{
		cfg: cfg, store: st, keys: keys, audit: opts.Audit, policy: opts.Policy, notifier: opts.Notifier,
		metrics: opts.Metrics, log: opts.Log, client: opts.HTTPClient, now: time.Now,
		binders: map[string]Binder{}, apps: map[string][]string{},
	}, nil
}

// SetClock replaces the time source (tests).
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// RedirectURL is the callback URI registered at the vendor.
func (s *Service) RedirectURL(vendor string) string {
	return s.cfg.BaseURL + "/connect/" + vendor + "/callback"
}

// --- vendor apps (admin) -----------------------------------------------------

// VendorApps lists every registered app (secrets never included).
func (s *Service) VendorApps(ctx context.Context) ([]VendorApp, error) {
	var out []VendorApp
	err := s.store.Bypass(ctx, func(tx Tx) error {
		rows, err := tx.ListVendorApps(ctx)
		if err != nil {
			return err
		}
		for i := range rows {
			a, err := fromRow(&rows[i])
			if err != nil {
				return err
			}
			out = append(out, a)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("connections: list vendor apps: %w", err)
	}
	return out, nil
}

// VendorApp returns one registered app (store.ErrNotFound when none);
// variant "" means the vendor's default variant.
func (s *Service) VendorApp(ctx context.Context, vendor, variant string) (VendorApp, error) {
	vendor, variant = normalizeKey(vendor, variant)
	var out VendorApp
	err := s.store.Bypass(ctx, func(tx Tx) error {
		row, err := tx.FindVendorApp(ctx, vendor, variant)
		if err != nil {
			return err
		}
		out, err = fromRow(row)
		return err
	})
	if err != nil {
		return VendorApp{}, err
	}
	return out, nil
}

func normalizeKey(vendor, variant string) (string, string) {
	vendor = strings.ToLower(strings.TrimSpace(vendor))
	variant = strings.ToLower(strings.TrimSpace(variant))
	if variant == "" && KnownVendor(vendor) {
		variant = Variants(vendor)[0]
	}
	return vendor, variant
}

// SaveVendorApp creates or updates the app for (Vendor, Variant) on
// behalf of admin actorID. A non-empty ClientSecret replaces the stored
// one (encrypted under AAD{Kind: vendor_app, RecordID: app id}); an empty
// one keeps it, which is only allowed when a secret already exists. The
// change is audited as a user event of the admin naming the vendor and
// variant, never the secret.
func (s *Service) SaveVendorApp(ctx context.Context, actorID string, in VendorApp) (VendorApp, error) {
	if err := in.normalize(); err != nil {
		return VendorApp{}, err
	}
	secret := in.ClientSecret
	in.ClientSecret = ""
	var out VendorApp
	err := s.store.Bypass(ctx, func(tx Tx) error {
		row, err := in.toRow()
		if err != nil {
			return err
		}
		existing, err := tx.FindVendorApp(ctx, in.Vendor, in.Variant)
		switch {
		case err == nil:
			row.ID = existing.ID
			row.ClientSecret = existing.ClientSecret
		case errors.Is(err, store.ErrNotFound):
			row.ID = connectors.NewAccountID()
		default:
			return err
		}
		if secret != "" {
			env, err := crypto.Encrypt(ctx, s.keys, crypto.AAD{Kind: aadKindVendorApp, RecordID: row.ID}, []byte(secret))
			if err != nil {
				return err
			}
			row.ClientSecret = store.Encrypted(env)
		} else if len(row.ClientSecret.Ciphertext) == 0 {
			return fmt.Errorf("%w: client secret is required", ErrInvalidVendorApp)
		}
		if err := tx.UpsertVendorApp(ctx, row); err != nil {
			return err
		}
		out, err = fromRow(row)
		return err
	})
	if err != nil {
		return VendorApp{}, err
	}
	s.record(ctx, actorID, "", "", map[string]string{"action": "vendor_app_saved", "vendor": out.Vendor, "variant": out.Variant}, "succeeded", "")
	s.log.Info("vendor app saved", "event", "connections.vendor_app_saved", "actor_user_id", actorID, "vendor", out.Vendor, "variant", out.Variant, "client_id", out.ClientID)
	return out, nil
}

// clientSecret decrypts the app's client secret.
func (s *Service) clientSecret(ctx context.Context, row *store.VendorApp) (string, error) {
	b, err := crypto.Decrypt(ctx, s.keys, crypto.AAD{Kind: aadKindVendorApp, RecordID: row.ID}, crypto.Envelope(row.ClientSecret))
	if err != nil {
		return "", fmt.Errorf("connections: vendor app %s/%s secret: %w", row.Vendor, row.Name, err)
	}
	return string(b), nil
}

// EnabledApps returns the enabled registered apps grouped by vendor, in
// Vendors order (fake and any other vendor last).
func (s *Service) EnabledApps(ctx context.Context) (map[string][]VendorApp, []string, error) {
	apps, err := s.VendorApps(ctx)
	if err != nil {
		return nil, nil, err
	}
	byVendor := map[string][]VendorApp{}
	for _, a := range apps {
		if a.Enabled {
			byVendor[a.Vendor] = append(byVendor[a.Vendor], a)
		}
	}
	var order []string
	for _, v := range Vendors {
		if len(byVendor[v]) > 0 {
			order = append(order, v)
		}
	}
	var rest []string
	for v := range byVendor {
		if !contains(Vendors, v) {
			rest = append(rest, v)
		}
	}
	sort.Strings(rest)
	return byVendor, append(order, rest...), nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// --- audit -------------------------------------------------------------------

// record writes a user audit event; failures are logged, never returned,
// because the action it describes has already been committed.
func (s *Service) record(ctx context.Context, userID, connectionID, label string, resource map[string]string, outcome, errorClass string) {
	ev := audit.Event{
		Time:             s.now(),
		UserID:           userID,
		AccountID:        connectionID,
		AccountLabel:     label,
		ResourceIdentity: resource,
		Decision:         "allow",
		Outcome:          outcome,
		ErrorClass:       errorClass,
		RequestID:        observability.RequestIDFromContext(ctx),
	}
	if outcome == "denied" {
		ev.Decision = "deny"
	}
	if err := s.audit.Record(ctx, ev); err != nil {
		s.log.Error("audit record failed", "event", "connections.audit_failed", "user_id", userID, "error", observability.RedactError(err))
	}
}
