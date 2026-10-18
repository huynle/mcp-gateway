package tunnel

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/huynle/mcp-gateway/internal/store"
)

// Cross-replica relay (Brain decision efq0ncag item 5, docs/tunnel.md
// "Multiple replicas").
//
// A tunnel's WebSocket lands on one replica (the holder), which records
// itself in mcp_tunnel_holders with a fresh connection epoch. A tunnel
// request on any other replica is forwarded to the holder over an
// internal, authenticated HTTP hop:
//
//	POST <holder>/tunnel-relay/v1/roundtrip
//	X-Mgw-Relay-Tunnel:    <tunnel id>
//	X-Mgw-Relay-Epoch:     <holder epoch read from the registry>
//	X-Mgw-Relay-Time:      <unix seconds>
//	X-Mgw-Relay-Nonce:     <random, single use>
//	X-Mgw-Relay-Request:   base64url(JSON {"m":method,"p":request URI,"h":headers})
//	X-Mgw-Relay-Signature: hex(HMAC-SHA256(secret, "mcp-gateway-relay.v1\n" id \n epoch \n time \n nonce \n request \n hex(sha256(body))))
//	<body: the request body, at most Limits.MaxRequestBytes>
//
// The holder checks the signature (constant time), the clock skew, that
// the nonce is new, and that it holds that tunnel with that epoch. It
// answers 200 with X-Mgw-Relay-Head: base64url(JSON {"s":status,"h":headers})
// and streams the tunnel response body, ending with the trailer
// X-Mgw-Relay-End: ok (or the error class if the stream failed). Refusals
// carry X-Mgw-Relay-Error: unauthorized | not_holder | bad_request | <tunnel class>.

// RelayPath is where the relay listener serves Service.RelayHandler. It is
// never mounted on the public mux.
const RelayPath = "/tunnel-relay/v1/roundtrip"

// MinRelaySecretBytes is the minimum length of the shared relay secret.
const MinRelaySecretBytes = 32

// Relay defaults.
const (
	// DefaultRelayMaxSkew bounds |holder clock - sender timestamp|.
	DefaultRelayMaxSkew = 30 * time.Second
	// relayHeaderGrace is added to ResponseHeaderTimeout on the sending
	// side so the holder's own timeout (a classified answer) wins.
	relayHeaderGrace = 5 * time.Second
	// maxRelayNonces bounds the replay cache.
	maxRelayNonces = 1 << 16
	// maxRelayHead bounds the encoded request head.
	maxRelayHead = 256 << 10
)

const (
	relaySigVersion      = "mcp-gateway-relay.v1"
	relayHeaderTunnel    = "X-Mgw-Relay-Tunnel"
	relayHeaderEpoch     = "X-Mgw-Relay-Epoch"
	relayHeaderTime      = "X-Mgw-Relay-Time"
	relayHeaderNonce     = "X-Mgw-Relay-Nonce"
	relayHeaderRequest   = "X-Mgw-Relay-Request"
	relayHeaderSignature = "X-Mgw-Relay-Signature"
	relayHeaderHead      = "X-Mgw-Relay-Head"
	relayHeaderError     = "X-Mgw-Relay-Error"
	relayHeaderReason    = "X-Mgw-Relay-Reason"
	relayTrailerEnd      = "X-Mgw-Relay-End"
	relayEndOK           = "ok"

	relayErrUnauthorized = "unauthorized"
	relayErrNotHolder    = "not_holder"
	relayErrBadRequest   = "bad_request"
)

// HolderStore is the tunnel holder registry (mcp_tunnel_holders, migration
// 00026). NewHolderStore adapts *store.Store (WithJobs).
type HolderStore interface {
	// ClaimHolder records holder as the tunnel's holder with a fresh,
	// globally unique epoch, touches last_seen_at and returns the epoch.
	ClaimHolder(ctx context.Context, tunnelID, holder string, at time.Time) (int64, error)
	// ReleaseHolder forgets the holder if it still has epoch.
	ReleaseHolder(ctx context.Context, tunnelID string, epoch int64) error
	// Holder returns the tunnel's holder with its liveness, or
	// store.ErrNotFound.
	Holder(ctx context.Context, tunnelID string) (*store.MCPTunnelHolder, error)
}

// RelayOptions enable the cross-replica relay. Leave Options.Relay nil for
// a single replica: nothing is recorded and requests for tunnels held
// elsewhere fail with ClassOffline, as before.
type RelayOptions struct {
	// Holders is the holder registry (required).
	Holders HolderStore
	// Advertise is this replica's relay base URL as peers reach it, e.g.
	// http://<pod IP>:18081 (GATEWAY_RELAY_ADVERTISE_ADDR). Scheme and
	// host only.
	Advertise string
	// Secret is the shared HMAC key (GATEWAY_RELAY_SECRET), at least
	// MinRelaySecretBytes. Never logged.
	Secret []byte
	// HTTPClient dials peers' relay listeners (required). The package
	// builds no HTTP stack of its own (netguard lint); cmd/gateway passes
	// a dedicated client without proxies. Redirects are never followed.
	HTTPClient *http.Client
	// Metrics registers tunnel_relay_requests_total; nil skips it.
	Metrics prometheus.Registerer
	// StaleAfter: a holder whose tunnel was not seen (last_seen_at) for
	// longer is ignored. Default 3 x Limits.HeartbeatInterval.
	StaleAfter time.Duration
	// MaxSkew bounds the accepted clock difference. Default
	// DefaultRelayMaxSkew.
	MaxSkew time.Duration
}

type relay struct {
	s          *Service
	holders    HolderStore
	self       string
	secret     []byte
	hc         *http.Client
	staleAfter time.Duration
	maxSkew    time.Duration
	nonces     nonceCache
	metrics    *relayMetrics
}

func newRelay(s *Service, o RelayOptions) (*relay, error) {
	switch {
	case o.Holders == nil:
		return nil, errors.New("tunnel: RelayOptions.Holders is required")
	case o.HTTPClient == nil:
		return nil, errors.New("tunnel: RelayOptions.HTTPClient is required")
	case len(o.Secret) < MinRelaySecretBytes:
		return nil, fmt.Errorf("tunnel: the relay secret must be at least %d bytes", MinRelaySecretBytes)
	}
	self, err := parseRelayBase(o.Advertise)
	if err != nil {
		return nil, errors.New("tunnel: RelayOptions.Advertise must be an http(s) URL with scheme and host only")
	}
	r := &relay{
		s: s, holders: o.Holders, self: self, secret: append([]byte(nil), o.Secret...),
		staleAfter: o.StaleAfter, maxSkew: o.MaxSkew, nonces: nonceCache{seen: map[string]time.Time{}},
	}
	if r.staleAfter <= 0 {
		r.staleAfter = 3 * s.limits.HeartbeatInterval
	}
	if r.maxSkew <= 0 {
		r.maxSkew = DefaultRelayMaxSkew
	}
	// A copy of the injected client: no cookies, no redirects.
	hc := *o.HTTPClient
	hc.Jar = nil
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	r.hc = &hc
	if o.Metrics != nil {
		m, err := newRelayMetrics(o.Metrics)
		if err != nil {
			return nil, err
		}
		r.metrics = m
	}
	return r, nil
}

// parseRelayBase validates a relay base URL and returns scheme://host.
func parseRelayBase(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", errors.New("tunnel: invalid relay address")
	}
	return u.Scheme + "://" + u.Host, nil
}

// RelayEnabled reports whether the cross-replica relay is configured.
func (s *Service) RelayEnabled() bool { return s.relay != nil }

// RelayHandler serves RelayPath for the internal relay listener
// (GATEWAY_RELAY_LISTEN_ADDR). Never mount it on the public mux. With the
// relay disabled it answers 404.
func (s *Service) RelayHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.relay == nil || r.URL.Path != RelayPath {
			http.NotFound(w, r)
			return
		}
		s.relay.serve(w, r)
	})
}

// --- signing -----------------------------------------------------------------

type relayHead struct {
	Method string      `json:"m,omitempty"`
	Path   string      `json:"p,omitempty"`
	Status int         `json:"s,omitempty"`
	Header http.Header `json:"h,omitempty"`
}

func encodeHead(h relayHead) string {
	b, _ := json.Marshal(h) // a struct of strings, ints and maps cannot fail
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeHead(raw string) (relayHead, error) {
	var h relayHead
	if raw == "" || len(raw) > maxRelayHead {
		return h, errors.New("tunnel: bad relay head")
	}
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return h, err
	}
	if err := json.Unmarshal(b, &h); err != nil {
		return h, err
	}
	return h, nil
}

func relayMAC(secret []byte, id string, epoch, ts int64, nonce, head string, body []byte) []byte {
	sum := sha256.Sum256(body)
	m := hmac.New(sha256.New, secret)
	_, _ = fmt.Fprintf(m, "%s\n%s\n%d\n%d\n%s\n%s\n%x", relaySigVersion, id, epoch, ts, nonce, head, sum)
	return m.Sum(nil)
}

// signedRelayRequest builds the relay request for one tunnel round trip.
func signedRelayRequest(ctx context.Context, base string, secret []byte, id string, epoch int64, method, uri string, h http.Header, body []byte, at time.Time, nonce string) (*http.Request, error) {
	head := encodeHead(relayHead{Method: method, Path: uri, Header: cleanHeader(h)})
	ts := at.Unix()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+RelayPath, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set(relayHeaderTunnel, id)
	req.Header.Set(relayHeaderEpoch, strconv.FormatInt(epoch, 10))
	req.Header.Set(relayHeaderTime, strconv.FormatInt(ts, 10))
	req.Header.Set(relayHeaderNonce, nonce)
	req.Header.Set(relayHeaderRequest, head)
	req.Header.Set(relayHeaderSignature, hex.EncodeToString(relayMAC(secret, id, epoch, ts, nonce, head, body)))
	return req, nil
}

func randomNonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b) // crypto/rand.Read never fails (Go 1.24+)
	return hex.EncodeToString(b)
}

var (
	nonceRE  = regexp.MustCompile(`^[0-9A-Za-z_-]{1,64}$`)
	reasonRE = regexp.MustCompile(`^[a-z_]{0,40}$`)
	methodRE = regexp.MustCompile(`^[A-Z]{1,16}$`)
)

// nonceCache remembers nonces until they could no longer pass the skew
// check.
type nonceCache struct {
	mu        sync.Mutex
	seen      map[string]time.Time
	lastPrune time.Time
}

// add records nonce until exp. It returns false when the nonce was seen
// (replay) and full=true when the cache is full.
func (c *nonceCache) add(nonce string, now, exp time.Time) (ok, full bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if now.Sub(c.lastPrune) > time.Second || len(c.seen) >= maxRelayNonces {
		for n, e := range c.seen {
			if !now.Before(e) {
				delete(c.seen, n)
			}
		}
		c.lastPrune = now
	}
	if e, dup := c.seen[nonce]; dup && now.Before(e) {
		return false, false
	}
	if len(c.seen) >= maxRelayNonces {
		return false, true
	}
	c.seen[nonce] = exp
	return true, false
}

// --- holder side ---------------------------------------------------------------

func relayRefuse(w http.ResponseWriter, status int, class, reason string) {
	w.Header().Set(relayHeaderError, class)
	if reason != "" {
		w.Header().Set(relayHeaderReason, reason)
	}
	w.WriteHeader(status)
}

func (r *relay) serve(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	unauthorized := func(why string) {
		r.metrics.inc("serve", why)
		r.s.log.Warn("tunnel relay: request refused", "reason", why)
		relayRefuse(w, http.StatusUnauthorized, relayErrUnauthorized, "")
	}
	id := req.Header.Get(relayHeaderTunnel)
	epoch, errE := strconv.ParseInt(req.Header.Get(relayHeaderEpoch), 10, 64)
	ts, errT := strconv.ParseInt(req.Header.Get(relayHeaderTime), 10, 64)
	nonce := req.Header.Get(relayHeaderNonce)
	head := req.Header.Get(relayHeaderRequest)
	sig, errS := hex.DecodeString(req.Header.Get(relayHeaderSignature))
	if !uuidRE.MatchString(id) || errE != nil || errT != nil || errS != nil || len(sig) != sha256.Size ||
		!nonceRE.MatchString(nonce) || head == "" || len(head) > maxRelayHead {
		unauthorized("malformed")
		return
	}
	max := r.s.limits.MaxRequestBytes
	if req.ContentLength > max {
		r.metrics.inc("serve", string(ClassTooLarge))
		relayRefuse(w, http.StatusRequestEntityTooLarge, string(ClassTooLarge), "request_body")
		return
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, max+1))
	if err != nil {
		r.metrics.inc("serve", relayErrBadRequest)
		relayRefuse(w, http.StatusBadRequest, relayErrBadRequest, "")
		return
	}
	if int64(len(body)) > max {
		r.metrics.inc("serve", string(ClassTooLarge))
		relayRefuse(w, http.StatusRequestEntityTooLarge, string(ClassTooLarge), "request_body")
		return
	}
	if !hmac.Equal(sig, relayMAC(r.secret, id, epoch, ts, nonce, head, body)) {
		unauthorized("bad_signature")
		return
	}
	now := r.s.now()
	at := time.Unix(ts, 0)
	if d := now.Sub(at); d > r.maxSkew || d < -r.maxSkew {
		unauthorized("clock_skew")
		return
	}
	ok, full := r.nonces.add(nonce, now, at.Add(r.maxSkew+time.Second))
	if full {
		r.metrics.inc("serve", string(ClassBusy))
		relayRefuse(w, http.StatusServiceUnavailable, string(ClassBusy), "replay_cache")
		return
	}
	if !ok {
		unauthorized("replay")
		return
	}
	h, err := decodeHead(head)
	if err != nil || !methodRE.MatchString(h.Method) || len(h.Path) == 0 || h.Path[0] != '/' {
		r.metrics.inc("serve", relayErrBadRequest)
		relayRefuse(w, http.StatusBadRequest, relayErrBadRequest, "")
		return
	}
	c := r.s.reg.get(id)
	if c == nil || c.epoch.Load() != epoch || c.isClosed() {
		r.metrics.inc("serve", relayErrNotHolder)
		relayRefuse(w, http.StatusConflict, relayErrNotHolder, "")
		return
	}
	treq, err := http.NewRequestWithContext(req.Context(), h.Method, URL(id, h.Path), nil)
	if err != nil {
		r.metrics.inc("serve", relayErrBadRequest)
		relayRefuse(w, http.StatusBadRequest, relayErrBadRequest, "")
		return
	}
	resp, err := r.s.roundTripConn(c, treq, h.Method, h.Path, h.Header, body)
	if err != nil {
		var te *Error
		if errors.As(err, &te) {
			r.metrics.inc("serve", string(te.Class))
			relayRefuse(w, http.StatusBadGateway, string(te.Class), te.Reason)
			return
		}
		// The sender went away (context cancelled): nothing to answer.
		r.metrics.inc("serve", "cancelled")
		relayRefuse(w, http.StatusBadGateway, string(ClassUnreachable), "")
		return
	}
	defer func() { _ = resp.Body.Close() }()
	r.metrics.inc("serve", relayEndOK)
	w.Header().Set(relayHeaderHead, encodeHead(relayHead{Status: resp.StatusCode, Header: resp.Header}))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Trailer", relayTrailerEnd)
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	if flusher != nil {
		flusher.Flush()
	}
	end := relayEndOK
	buf := make([]byte, maxChunk)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return // the sender went away
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if err == nil {
			continue
		}
		if !errors.Is(err, io.EOF) {
			end = string(ClassUnreachable)
			var te *Error
			if errors.As(err, &te) {
				end = string(te.Class)
			}
		}
		break
	}
	w.Header().Set(relayTrailerEnd, end)
}

// --- sending side --------------------------------------------------------------

var errRelayNotHolder = errors.New("tunnel: relay peer is not the holder")

// forward sends one round trip to the tunnel's holder on another replica.
// Every failure is a *Error (or the caller's context error).
func (r *relay) forward(req *http.Request, id, uri string, body []byte) (*http.Response, error) {
	for attempt := 0; ; attempt++ {
		base, epoch, err := r.lookup(req.Context(), id)
		if err != nil {
			return nil, err
		}
		resp, err := r.send(req, base, id, epoch, uri, body)
		if errors.Is(err, errRelayNotHolder) {
			// The holder changed between lookup and send (nothing was
			// delivered): look again once.
			if attempt == 0 {
				continue
			}
			return nil, newError(ClassOffline, "relay_not_holder", nil)
		}
		return resp, err
	}
}

// lookup returns the holder's base URL and epoch, or ClassOffline.
func (r *relay) lookup(ctx context.Context, id string) (string, int64, error) {
	miss := func(result, reason string) (string, int64, error) {
		r.metrics.inc("forward", result)
		return "", 0, newError(ClassOffline, reason, nil)
	}
	h, err := r.holders.Holder(ctx, id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return miss("miss", "")
	case err != nil:
		if ctx.Err() != nil {
			return "", 0, ctx.Err()
		}
		r.s.log.Warn("tunnel relay: holder lookup failed", "tunnel_id", id, "error", err)
		return miss("lookup_error", "relay_lookup")
	case h.Revoked:
		return miss("revoked", "")
	case h.LastSeenAt == nil || r.s.now().Sub(*h.LastSeenAt) > r.staleAfter:
		return miss("stale", "")
	}
	base, err := parseRelayBase(h.Holder)
	if err != nil {
		r.s.log.Warn("tunnel relay: unusable holder address", "tunnel_id", id, "epoch", h.Epoch)
		return miss("bad_holder", "")
	}
	if base == r.self {
		// Recorded as ours, but this replica has no live connection.
		return miss("self", "")
	}
	return base, h.Epoch, nil
}

func (r *relay) send(req *http.Request, base, id string, epoch int64, uri string, body []byte) (*http.Response, error) {
	parent := req.Context()
	ctx, cancel := context.WithCancel(parent)
	var timedOut atomic.Bool
	timer := time.AfterFunc(r.s.limits.ResponseHeaderTimeout+relayHeaderGrace, func() {
		timedOut.Store(true)
		cancel()
	})
	rq, err := signedRelayRequest(ctx, base, r.secret, id, epoch, req.Method, uri, req.Header, body, r.s.now(), randomNonce())
	if err != nil {
		timer.Stop()
		cancel()
		return nil, newError(ClassUnreachable, "relay_request", nil)
	}
	resp, err := r.hc.Do(rq)
	timer.Stop()
	if err != nil {
		cancel()
		switch {
		case timedOut.Load():
			r.metrics.inc("forward", string(ClassTimeout))
			return nil, newError(ClassTimeout, "response_header", nil)
		case parent.Err() != nil:
			return nil, parent.Err()
		}
		r.metrics.inc("forward", "unreachable_peer")
		r.s.log.Warn("tunnel relay: holder unreachable", "tunnel_id", id, "epoch", epoch)
		return nil, newError(ClassOffline, "relay_unreachable", nil)
	}
	if resp.StatusCode == http.StatusOK && resp.Header.Get(relayHeaderHead) != "" {
		h, err := decodeHead(resp.Header.Get(relayHeaderHead))
		if err != nil || h.Status < 100 || h.Status > 999 {
			_ = resp.Body.Close()
			cancel()
			r.metrics.inc("forward", "bad_head")
			return nil, newError(ClassUnreachable, "relay_bad_head", nil)
		}
		r.metrics.inc("forward", relayEndOK)
		rb := &relayBody{resp: resp, ctx: parent, cancel: cancel}
		hdr := cleanHeader(h.Header)
		if !isEventStream(hdr) {
			rb.max = r.s.limits.MaxResponseBytes
		}
		return &http.Response{
			Status: fmt.Sprintf("%d %s", h.Status, http.StatusText(h.Status)), StatusCode: h.Status,
			Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
			Header: hdr, Body: rb, ContentLength: -1, Request: req,
		}, nil
	}
	class, reason := resp.Header.Get(relayHeaderError), resp.Header.Get(relayHeaderReason)
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	_ = resp.Body.Close()
	cancel()
	if !reasonRE.MatchString(reason) {
		reason = ""
	}
	r.metrics.inc("forward", relayResult(class))
	switch class {
	case relayErrNotHolder:
		return nil, errRelayNotHolder
	case relayErrUnauthorized:
		r.s.log.Error("tunnel relay: the holder rejected this replica's request; check that every replica has the same GATEWAY_RELAY_SECRET and synchronised clocks",
			"tunnel_id", id, "epoch", epoch)
		return nil, newError(ClassOffline, "relay_rejected", nil)
	}
	if c, ok := knownClass(class); ok {
		return nil, newError(c, reason, nil)
	}
	return nil, newError(ClassUnreachable, "relay_status", nil)
}

func knownClass(s string) (Class, bool) {
	switch c := Class(s); c {
	case ClassOffline, ClassNotTunnel, ClassTooLarge, ClassTimeout, ClassBusy, ClassUnreachable:
		return c, true
	}
	return "", false
}

// relayResult bounds the metric label to known values.
func relayResult(class string) string {
	switch class {
	case relayErrNotHolder, relayErrUnauthorized, relayErrBadRequest:
		return class
	}
	if c, ok := knownClass(class); ok {
		return string(c)
	}
	return "bad_status"
}

// relayBody is the caller's view of a relayed response body: it enforces
// the response bound and turns the holder's end trailer into the stream's
// result.
type relayBody struct {
	resp   *http.Response
	ctx    context.Context
	cancel context.CancelFunc
	max    int64 // 0 = unbounded (event streams)
	total  int64
	err    error // sticky terminal error
	once   sync.Once
}

func (b *relayBody) Read(p []byte) (int, error) {
	if b.err != nil {
		return 0, b.err
	}
	n, err := b.resp.Body.Read(p)
	b.total += int64(n)
	if b.max > 0 && b.total > b.max {
		b.err = newError(ClassTooLarge, "response_body", nil)
		_ = b.Close()
		return 0, b.err
	}
	switch {
	case err == nil:
		return n, nil
	case errors.Is(err, io.EOF):
		switch end := b.resp.Trailer.Get(relayTrailerEnd); end {
		case relayEndOK:
			b.err = io.EOF
		case "":
			b.err = newError(ClassUnreachable, "relay_truncated", nil)
		default:
			c, ok := knownClass(end)
			if !ok {
				c = ClassUnreachable
			}
			b.err = newError(c, "", nil)
		}
	case b.ctx.Err() != nil:
		b.err = b.ctx.Err()
	default:
		b.err = newError(ClassUnreachable, "relay_stream", nil)
	}
	return n, b.err
}

func (b *relayBody) Close() error {
	b.once.Do(func() {
		_ = b.resp.Body.Close()
		b.cancel()
	})
	return nil
}

// --- metrics -------------------------------------------------------------------

// relayMetrics is tunnel_relay_requests_total{side,result}: side is
// "forward" (this replica sent to a holder) or "serve" (this replica, the
// holder, answered a peer); result is a fixed word, never an id or URL.
type relayMetrics struct{ c *prometheus.CounterVec }

func newRelayMetrics(reg prometheus.Registerer) (*relayMetrics, error) {
	c := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tunnel_relay_requests_total",
		Help: "Tunnel requests relayed between gateway replicas, by side (forward, serve) and result.",
	}, []string{"side", "result"})
	if err := reg.Register(c); err != nil {
		return nil, fmt.Errorf("tunnel: relay metrics: %w", err)
	}
	return &relayMetrics{c: c}, nil
}

func (m *relayMetrics) inc(side, result string) {
	if m != nil {
		m.c.WithLabelValues(side, result).Inc()
	}
}
