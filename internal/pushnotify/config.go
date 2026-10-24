package pushnotify

import (
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// EnvEnabled turns the feature on (GATEWAY_WEBPUSH_ENABLED, default off).
// It also stays off without a key provider (the VAPID private key and the
// subscriptions are envelope-encrypted) and without a usable VAPID
// subject (Subject).
const EnvEnabled = "GATEWAY_WEBPUSH_ENABLED"

// AAD kinds of the two envelope-encrypted records (internal/crypto).
const (
	// KeyKind seals the VAPID private key (RecordID: the key row id).
	KeyKind = "webpush_key"
	// SubscriptionKind seals a subscription's endpoint and keys (UserID:
	// the owner, RecordID: the subscription id).
	SubscriptionKind = "push_subscription"
)

// Limits (constants by design, like the secrets feature's).
const (
	// MaxSubscriptionsPerUser caps a user's devices; one more is ErrLimit.
	MaxSubscriptionsPerUser = 10
	// MaxLabelLen bounds a device label in characters.
	MaxLabelLen = 100
	// MaxRequestBytes bounds the portal's JSON request bodies.
	MaxRequestBytes = 8 << 10
	// DefaultNotifyTimeout bounds one approval's whole fan-out: the
	// approval is created synchronously behind it.
	DefaultNotifyTimeout = 5 * time.Second
	// NotifyConcurrency is how many devices are sent to at once.
	NotifyConcurrency = 4
	// MinTTL and MaxTTL bound how long a push service may hold an
	// approval message (it is useless once the approval has expired).
	MinTTL = time.Minute
	MaxTTL = time.Hour
	// TestInterval is how often a user may send a test notification.
	TestInterval = 30 * time.Second
	// testTTL is how long a push service may hold a test message.
	testTTL = 5 * time.Minute
	// recordTimeout bounds the delivery bookkeeping after a fan-out (it
	// runs even when the fan-out used up its own timeout).
	recordTimeout = time.Second
)

// Config is the feature configuration.
type Config struct {
	// Enabled is EnvEnabled.
	Enabled bool
}

// ConfigFromEnv reads EnvEnabled through getenv (typically os.Getenv).
func ConfigFromEnv(getenv func(string) string) (Config, error) {
	var cfg Config
	if v := strings.TrimSpace(getenv(EnvEnabled)); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return Config{}, fmt.Errorf("%s: %w", EnvEnabled, err)
		}
		cfg.Enabled = b
	}
	return cfg, nil
}

// ErrNoSubject means no VAPID subject can be derived: the base URL is not
// https and no contact email is configured.
var ErrNoSubject = errors.New("pushnotify: no VAPID subject: the base URL is not https and GATEWAY_LEGAL_CONTACT_EMAIL is unset")

// Subject derives the VAPID "sub" claim (RFC 8292: how a push service
// reaches the operator): the gateway's base URL when it is https (always
// the case in production), otherwise mailto:contact (a local or http
// deployment with GATEWAY_LEGAL_CONTACT_EMAIL set). Without either it is
// ErrNoSubject and the feature stays off.
func Subject(baseURL, contactEmail string) (string, error) {
	if u, err := url.Parse(baseURL); err == nil && u.Scheme == "https" && u.Host != "" {
		return strings.TrimRight(baseURL, "/"), nil
	}
	contact := strings.TrimSpace(contactEmail)
	if contact == "" {
		return "", ErrNoSubject
	}
	addr, err := mail.ParseAddress(contact)
	if err != nil || addr.Name != "" || addr.Address != contact {
		return "", fmt.Errorf("pushnotify: contact email %q is not a plain address: %w", contact, ErrNoSubject)
	}
	return "mailto:" + contact, nil
}
