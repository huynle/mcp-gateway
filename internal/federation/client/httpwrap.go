package client

import (
	"context"
	"net/http"
	"sync"
)

// observer records what the HTTP layer saw during one operation (or for the
// session's long-lived streams), so SDK errors, which carry only text, can
// be classified from facts instead of message matching.
type observer struct {
	mu     sync.Mutex
	status int // last non-2xx HTTP status
}

func (o *observer) recordStatus(code int) {
	o.mu.Lock()
	o.status = code
	o.mu.Unlock()
}

func (o *observer) lastStatus() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.status
}

type observerKey struct{}

func withObserver(ctx context.Context, o *observer) context.Context {
	return context.WithValue(ctx, observerKey{}, o)
}

func observerFrom(ctx context.Context) *observer {
	o, _ := ctx.Value(observerKey{}).(*observer)
	return o
}

// roundTripper wraps the injected (netguard) transport for one session: it
// adds the endpoint's static headers and records responses in the
// request's observer.
type roundTripper struct {
	base    http.RoundTripper
	headers http.Header
}

func (t *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	for k, vs := range t.headers {
		r.Header[k] = append([]string(nil), vs...)
	}
	resp, err := t.base.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	if o := observerFrom(req.Context()); o != nil && (resp.StatusCode < 200 || resp.StatusCode > 299) {
		o.recordStatus(resp.StatusCode)
	}
	return resp, nil
}
