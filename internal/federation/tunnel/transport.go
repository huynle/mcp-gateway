package tunnel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"sync"
	"time"
)

// RoundTripper returns the gateway-side transport for tunnel URLs. It
// serves only tunnel URLs (tunnel://<id>/... or http://<id>.tunnel.invalid/...)
// by routing the request through the tunnel's live connection on this
// replica; any other URL fails with ClassNotTunnel. It never dials, so it
// needs no netguard: nothing leaves the gateway except frames on a
// connection the user's tunnel client opened.
//
// It does not check who may use the tunnel: callers must Authorize the
// server's owner against the tunnel ID before connecting.
func (s *Service) RoundTripper() http.RoundTripper { return &transport{s: s} }

// HTTPClient returns a copy of base (or a zero client when base is nil)
// whose transport is RoundTripper(), for internal/federation/client's
// Options.HTTPClient when the server's URL is a tunnel URL (use ClientURL
// for the Endpoint URL). Redirects may not leave the tunnel.
func (s *Service) HTTPClient(base *http.Client) *http.Client {
	// A copied or zero-value client is safe here: its only transport is
	// the tunnel transport, which cannot dial out (see RoundTripper).
	var hc http.Client
	if base != nil {
		hc = *base
	}
	hc.Transport = s.RoundTripper()
	hc.Jar = nil
	hc.CheckRedirect = sameTunnelRedirect
	return &hc
}

const maxRedirects = 5

func sameTunnelRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return newError(ClassUnreachable, "too_many_redirects", nil)
	}
	first, _, err1 := parseTunnelURL(via[0].URL)
	next, _, err2 := parseTunnelURL(req.URL)
	if err1 != nil || err2 != nil || first != next {
		return newError(ClassNotTunnel, "redirect_left_tunnel", nil)
	}
	return nil
}

// Online reports whether the tunnel has a live connection on this
// replica or, with the relay enabled, a fresh holder on another replica
// (one registry read, bounded to 2s).
func (s *Service) Online(tunnelID string) bool {
	if s.reg.get(tunnelID) != nil {
		return true
	}
	if s.relay == nil || !uuidRE.MatchString(tunnelID) {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, _, err := s.relay.lookup(ctx, tunnelID)
	return err == nil
}

type transport struct{ s *Service }

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	closeBody := func() {
		if req.Body != nil {
			_ = req.Body.Close()
		}
	}
	id, uri, err := parseTunnelURL(req.URL)
	if err != nil {
		closeBody()
		return nil, newError(ClassNotTunnel, "", nil)
	}
	c := t.s.reg.get(id)
	if c == nil && t.s.relay == nil {
		closeBody()
		return nil, newError(ClassOffline, "", nil)
	}
	var body []byte
	if req.Body != nil {
		body, err = io.ReadAll(io.LimitReader(req.Body, t.s.limits.MaxRequestBytes+1))
		closeBody()
		if err != nil {
			return nil, err
		}
		if int64(len(body)) > t.s.limits.MaxRequestBytes {
			return nil, newError(ClassTooLarge, "request_body", nil)
		}
	}
	if c == nil {
		// Held by another replica, perhaps: forward to the holder.
		return t.s.relay.forward(req, id, uri, body)
	}
	return t.s.roundTripConn(c, req, req.Method, uri, req.Header, body)
}

// roundTripConn sends one request on the local connection c and waits for
// the response head. req supplies the context and Response.Request.
func (s *Service) roundTripConn(c *conn, req *http.Request, method, uri string, header http.Header, body []byte) (*http.Response, error) {
	limits := c.limits
	ctx := req.Context()
	st, err := c.open(ctx)
	if err != nil {
		return nil, err
	}
	f := &frame{Type: frameRequest, ID: st.id, Method: method, Path: uri, Header: cleanHeader(header), Data: body}
	if c.l.machine != "" {
		f.Tunnel = c.tunnelID
	}
	if err := c.send(f); err != nil {
		st.abandon()
		return nil, newError(ClassOffline, "send", err)
	}
	timer := time.NewTimer(limits.ResponseHeaderTimeout)
	defer timer.Stop()
	select {
	case h := <-st.headc:
		if h.err != nil {
			st.abandon()
			return nil, h.err
		}
		return st.response(req, h.f), nil
	case <-ctx.Done():
		st.abandon()
		return nil, ctx.Err()
	case <-timer.C:
		st.abandon()
		return nil, newError(ClassTimeout, "response_header", nil)
	}
}

type headResult struct {
	f   *frame
	err error
}

// stream is one request/response exchange on a connection (gateway side).
// Its response body is a bounded buffer filled by the connection's read
// loop and drained by the caller.
type stream struct {
	c      *conn
	id     uint64
	ctx    context.Context
	headc  chan headResult // exactly one value
	notify chan struct{}

	mu       sync.Mutex
	headDone bool
	buf      bytes.Buffer
	total    int64
	maxTotal int64 // 0 = unbounded (event streams)
	done     bool
	err      error // terminal error once done (io.EOF on success)
	once     sync.Once
}

func newStream(c *conn, id uint64, ctx context.Context) *stream {
	return &stream{c: c, id: id, ctx: ctx, headc: make(chan headResult, 1), notify: make(chan struct{}, 1)}
}

func (s *stream) wake() {
	select {
	case s.notify <- struct{}{}:
	default:
	}
}

func (s *stream) deliverHead(f *frame) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.headDone || s.done {
		return
	}
	s.headDone = true
	if !isEventStream(f.Header) {
		s.maxTotal = s.c.limits.MaxResponseBytes
	}
	s.headc <- headResult{f: f}
}

// push appends a data chunk, enforcing the body and buffer bounds.
func (s *stream) push(p []byte) {
	s.mu.Lock()
	if s.done {
		s.mu.Unlock()
		return
	}
	if !s.headDone {
		s.mu.Unlock()
		s.fail(newError(ClassUnreachable, "data_before_head", nil))
		s.c.cancelStream(s.id)
		return
	}
	s.total += int64(len(p))
	overTotal := s.maxTotal > 0 && s.total > s.maxTotal
	overBuf := int64(s.buf.Len()+len(p)) > s.c.limits.MaxBufferedBytes
	if overTotal || overBuf {
		s.mu.Unlock()
		reason := "response_body"
		if !overTotal {
			reason = "buffer"
		}
		s.fail(newError(ClassTooLarge, reason, nil))
		s.c.cancelStream(s.id)
		return
	}
	s.buf.Write(p)
	s.mu.Unlock()
	s.wake()
}

func (s *stream) finish() { s.end(io.EOF) }

func (s *stream) fail(err error) { s.end(err) }

func (s *stream) end(err error) {
	s.mu.Lock()
	if s.done {
		s.mu.Unlock()
		return
	}
	s.done = true
	s.err = err
	if !s.headDone {
		s.headDone = true
		if errors.Is(err, io.EOF) {
			err = newError(ClassUnreachable, "no_response", nil)
		}
		s.headc <- headResult{err: err}
	}
	s.mu.Unlock()
	s.wake()
}

// abandon is called when the caller gives up (error before the response,
// or Body.Close): cancel on the client if still running, free the slot.
func (s *stream) abandon() {
	s.once.Do(func() {
		s.mu.Lock()
		running := !s.done
		s.done = true
		if s.err == nil {
			s.err = errors.New("tunnel: body closed")
		}
		s.mu.Unlock()
		if running {
			s.c.cancelStream(s.id)
		}
		s.c.forget(s)
	})
}

func (s *stream) response(req *http.Request, h *frame) *http.Response {
	hdr := cleanHeader(h.Header)
	return &http.Response{
		Status:        fmt.Sprintf("%d %s", h.Status, http.StatusText(h.Status)),
		StatusCode:    h.Status,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        hdr,
		Body:          &body{s: s},
		ContentLength: -1,
		Request:       req,
	}
}

// body is the response body handed to the caller.
type body struct{ s *stream }

func (b *body) Read(p []byte) (int, error) {
	s := b.s
	for {
		s.mu.Lock()
		if s.buf.Len() > 0 {
			n, _ := s.buf.Read(p)
			s.mu.Unlock()
			return n, nil
		}
		if s.done {
			err := s.err
			s.mu.Unlock()
			return 0, err
		}
		s.mu.Unlock()
		select {
		case <-s.notify:
		case <-s.ctx.Done():
			return 0, s.ctx.Err()
		}
	}
}

func (b *body) Close() error {
	b.s.abandon()
	return nil
}

func isEventStream(h http.Header) bool {
	mt, _, err := mime.ParseMediaType(h.Get("Content-Type"))
	return err == nil && mt == "text/event-stream"
}
