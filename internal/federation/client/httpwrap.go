package client

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// observer records what the HTTP layer saw during one operation (or, for
// the session context, on the long-lived legacy SSE stream), so SDK
// errors, which carry only text, are classified from facts instead of
// message matching.
type observer struct {
	mu           sync.Mutex
	status       int    // last non-2xx HTTP status
	challenge    string // WWW-Authenticate of the last 401/403
	transportErr error  // first error from the underlying transport
	refusal      *Error // first refusal by the round tripper itself
	tooLarge     bool   // a response body exceeded the bound
}

func (o *observer) recordTooLarge() {
	o.mu.Lock()
	o.tooLarge = true
	o.mu.Unlock()
}

func (o *observer) recordResponse(resp *http.Response) {
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.status = resp.StatusCode
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		o.challenge = truncateChallenge(resp.Header.Get("WWW-Authenticate"))
	}
}

func (o *observer) recordTransportErr(err error) {
	o.mu.Lock()
	if o.transportErr == nil {
		o.transportErr = err
	}
	o.mu.Unlock()
}

func (o *observer) recordRefusal(e *Error) {
	o.mu.Lock()
	if o.refusal == nil {
		o.refusal = e
	}
	o.mu.Unlock()
}

type observerKey struct{}

func withObserver(ctx context.Context, o *observer) context.Context {
	return context.WithValue(ctx, observerKey{}, o)
}

// observerFrom returns ctx's observer, or a throwaway one.
func observerFrom(ctx context.Context) *observer {
	if o, ok := ctx.Value(observerKey{}).(*observer); ok {
		return o
	}
	return &observer{}
}

// roundTripper wraps the injected (netguard) transport for one session.
// Every request:
//   - must stay on the endpoint's origin (scheme + host + port): a
//     redirect or a legacy SSE endpoint event pointing elsewhere is
//     refused, so credentials never leave the configured server;
//   - gets the endpoint's static headers, then whatever the Authorizer
//     adds. Nothing else is forwarded: the request is built by the MCP SDK
//     from scratch, so inbound gateway credentials cannot leak.
type roundTripper struct {
	base    http.RoundTripper
	origin  string
	headers http.Header
	auth    Authorizer
	maxBody int64
	// life is the session context: cancelling it (Close, or a failed
	// handshake) aborts every request of the session, including SDK
	// background requests made with detached contexts.
	life context.Context
}

func origin(u *url.URL) string {
	port := u.Port()
	scheme := strings.ToLower(u.Scheme)
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[scheme]
	}
	return scheme + "://" + strings.ToLower(u.Hostname()) + ":" + port
}

func (t *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	obs := observerFrom(req.Context())
	refuse := func(e *Error) (*http.Response, error) {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		obs.recordRefusal(e)
		return nil, e
	}
	if origin(req.URL) != t.origin {
		return refuse(refusal(ClassBlocked, ReasonCrossOrigin, nil))
	}
	ctx, cancel := context.WithCancel(req.Context())
	stop := context.AfterFunc(t.life, cancel)
	release := func() { stop(); cancel() }
	r := req.Clone(ctx)
	for k, vs := range t.headers {
		r.Header[k] = append([]string(nil), vs...)
	}
	if t.auth != nil {
		if err := t.auth.Authorize(r.Context(), r); err != nil {
			release()
			return refuse(refusal(ClassAuthRequired, ReasonAuthorizer, err))
		}
	}
	resp, err := t.base.RoundTrip(r)
	if err != nil {
		release()
		obs.recordTransportErr(err)
		return nil, err
	}
	obs.recordResponse(resp)
	limitBody(resp, t.maxBody, obs)
	resp.Body = &releaseBody{ReadCloser: resp.Body, release: release}
	return resp, nil
}

// releaseBody frees the request's session-cancellation hook on Close.
type releaseBody struct {
	io.ReadCloser
	once    sync.Once
	release func()
}

func (b *releaseBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(b.release)
	return err
}
