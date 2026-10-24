package webpush

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/huynle/mcp-gateway/internal/netguard"
)

const (
	// DefaultTimeout bounds a whole push request when Options.Client is nil.
	DefaultTimeout = 10 * time.Second
	// DefaultTTL is the TTL used when SendOptions.TTL is zero.
	DefaultTTL = time.Hour
	// MaxTTL caps SendOptions.TTL.
	MaxTTL = 24 * time.Hour
	// maxTopicLen is the RFC 8030 Section 5.4 Topic limit.
	maxTopicLen = 32
	// maxDrain is how much of a response body is read before closing it.
	maxDrain = 4 << 10
)

var (
	// ErrGone means the push service answered 404 or 410: the
	// subscription has expired or been revoked and should be deleted.
	ErrGone = errors.New("webpush: subscription gone")
	// ErrRateLimited means the push service answered 429; see
	// StatusError.RetryAfter.
	ErrRateLimited = errors.New("webpush: rate limited")
)

// StatusError is returned by Send for a non-2xx response. It unwraps to
// ErrGone (404, 410), ErrPayloadTooLarge (413) or ErrRateLimited (429)
// where applicable. It names the endpoint's host only.
type StatusError struct {
	StatusCode int
	Host       string
	// RetryAfter is the parsed Retry-After header (seconds or HTTP date),
	// zero when absent or unparsable.
	RetryAfter time.Duration
	kind       error
}

func (e *StatusError) Error() string {
	msg := fmt.Sprintf("webpush: push service %s answered %d", e.Host, e.StatusCode)
	if e.kind != nil {
		msg += " (" + strings.TrimPrefix(e.kind.Error(), "webpush: ") + ")"
	}
	if e.RetryAfter > 0 {
		msg += fmt.Sprintf(", retry after %s", e.RetryAfter)
	}
	return msg
}

// Unwrap returns the sentinel error for the status, if any.
func (e *StatusError) Unwrap() error { return e.kind }

// Options configure a Sender.
type Options struct {
	// Keys is the VAPID key pair; required.
	Keys *Keys
	// Subject is the VAPID "sub" claim, an https: URL or mailto: address
	// the push service can use to contact the operator; required.
	Subject string
	// Client sends the requests. It should be the SSRF-safe netguard
	// client (see NewGuardedClient). When nil, NewGuardedClient() is used.
	// Redirects are never followed regardless of the client's policy; the
	// client itself is not modified.
	Client *http.Client
	// Now defaults to time.Now; used for the VAPID expiry and Retry-After.
	Now func() time.Time
}

// SendOptions are per-message RFC 8030 parameters.
type SendOptions struct {
	// TTL is how long the push service may hold the message: zero means
	// DefaultTTL, longer than MaxTTL is capped, negative is an error.
	TTL time.Duration
	// Urgency is "very-low", "low", "normal" or "high"; empty means "high".
	Urgency string
	// Topic optionally replaces an undelivered message with the same
	// topic: at most 32 characters of the base64url alphabet.
	Topic string
}

// Sender delivers encrypted, VAPID-signed push messages. It is safe for
// concurrent use.
type Sender struct {
	keys    *Keys
	subject string
	client  *http.Client
	now     func() time.Time
	// checkEndpoint is ValidateEndpoint; tests replace it to reach a local
	// server.
	checkEndpoint func(string) error
}

// NewGuardedClient returns an HTTP client built on netguard with
// DefaultTimeout and the netguard defaults (https only, internal
// addresses refused at dial time, nothing allow-listed). To share an
// existing netguard.Guard, pass guard.Client() as Options.Client instead.
func NewGuardedClient() *http.Client {
	return netguard.New(netguard.Options{Timeout: DefaultTimeout, MaxResponseBytes: maxDrain}).Client()
}

// New validates o and returns a Sender.
func New(o Options) (*Sender, error) {
	if o.Keys == nil || o.Keys.priv == nil {
		return nil, errors.New("webpush: VAPID keys required")
	}
	if err := validateSubject(o.Subject); err != nil {
		return nil, err
	}
	client := o.Client
	if client == nil {
		client = NewGuardedClient()
	}
	c := *client // never mutate the caller's client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	now := o.Now
	if now == nil {
		now = time.Now
	}
	return &Sender{keys: o.Keys, subject: o.Subject, client: &c, now: now, checkEndpoint: ValidateEndpoint}, nil
}

func validateSubject(subject string) error {
	if rest, ok := strings.CutPrefix(subject, "mailto:"); ok {
		if rest == "" {
			return errors.New("webpush: VAPID subject mailto: has no address")
		}
		return nil
	}
	u, err := url.Parse(subject)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return errors.New("webpush: VAPID subject must be an https URL or mailto: address")
	}
	return nil
}

// Send encrypts payload for sub and posts it to the subscription's push
// service. It returns nil for any 2xx response, a *StatusError otherwise
// (errors.Is ErrGone for 404/410: delete the subscription), and wraps
// ErrEndpointNotAllowed when the endpoint fails validation, in which case
// nothing is sent. Errors never include the endpoint's path or query.
// The payload must not contain sensitive data (see the package doc).
func (s *Sender) Send(ctx context.Context, sub Subscription, payload []byte, o SendOptions) error {
	if err := s.checkEndpoint(sub.Endpoint); err != nil {
		return err
	}
	host := endpointHost(sub.Endpoint)
	ttl, urgency, err := o.resolve()
	if err != nil {
		return err
	}
	body, err := Encrypt(sub.P256dh, sub.Auth, payload)
	if err != nil {
		return err
	}
	auth, err := s.keys.authorization(sub.Endpoint, s.subject, s.now())
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sub.Endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webpush: build request for %s: %w", host, unwrapURLError(err))
	}
	req.Header.Set("Content-Encoding", "aes128gcm")
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("TTL", strconv.FormatInt(int64(ttl/time.Second), 10))
	req.Header.Set("Urgency", urgency)
	if o.Topic != "" {
		req.Header.Set("Topic", o.Topic)
	}
	req.Header.Set("Authorization", auth)

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("webpush: send to %s: %w", host, unwrapURLError(err))
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.CopyN(io.Discard, resp.Body, maxDrain)

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	se := &StatusError{StatusCode: resp.StatusCode, Host: host}
	switch resp.StatusCode {
	case http.StatusNotFound, http.StatusGone:
		se.kind = ErrGone
	case http.StatusRequestEntityTooLarge:
		se.kind = ErrPayloadTooLarge
	case http.StatusTooManyRequests:
		se.kind = ErrRateLimited
		se.RetryAfter = parseRetryAfter(resp.Header.Get("Retry-After"), s.now())
	}
	return se
}

// resolve applies defaults and validates o.
func (o SendOptions) resolve() (ttl time.Duration, urgency string, err error) {
	ttl = o.TTL
	switch {
	case ttl < 0:
		return 0, "", errors.New("webpush: negative TTL")
	case ttl == 0:
		ttl = DefaultTTL
	case ttl > MaxTTL:
		ttl = MaxTTL
	}
	urgency = o.Urgency
	switch urgency {
	case "":
		urgency = "high"
	case "very-low", "low", "normal", "high":
	default:
		return 0, "", fmt.Errorf("webpush: invalid urgency %q", urgency)
	}
	if len(o.Topic) > maxTopicLen {
		return 0, "", fmt.Errorf("webpush: topic longer than %d characters", maxTopicLen)
	}
	for i := 0; i < len(o.Topic); i++ {
		c := o.Topic[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return 0, "", errors.New("webpush: topic must use the base64url alphabet")
		}
	}
	return ttl, urgency, nil
}

// unwrapURLError strips the *url.Error wrapper net/http adds, whose
// message contains the full request URL.
func unwrapURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

func parseRetryAfter(v string, now time.Time) time.Duration {
	if v == "" {
		return 0
	}
	if secs, err := strconv.ParseInt(v, 10, 64); err == nil {
		if secs <= 0 || secs > int64(MaxTTL/time.Second) {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil && t.After(now) {
		return t.Sub(now)
	}
	return 0
}
