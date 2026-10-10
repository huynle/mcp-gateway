// Package graph is a thin, hand-written Microsoft Graph REST client scoped
// to what the microsoft connector needs (decision bt8ukyrd: no
// msgraph-sdk-go): bearer injection from an oauth2.TokenSource per
// request, JSON requests and answers, the Graph error envelope
// ({"error":{"code","message"}}) as *Error with the HTTP status and the
// Retry-After of a throttled answer (429, or 503 with Retry-After), and
// bounded collection paging over @odata.nextLink (Collect). It knows
// nothing about tools, tokens at rest or the connector's error classes.
package graph

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// DefaultBaseURL is the Graph v1.0 root.
const DefaultBaseURL = "https://graph.microsoft.com/v1.0/"

// MaxResponseBytes bounds how much of an answer is read; Graph answers
// over it fail to decode rather than grow memory.
const MaxResponseBytes = 8 << 20

// defaultUserAgent identifies the gateway to Graph.
const defaultUserAgent = "mcp-gateway"

// Options configures New. Token is required.
type Options struct {
	// HTTPClient sends the requests; http.DefaultClient when nil. The
	// client's transport is used as is: the bearer is set per request.
	HTTPClient *http.Client
	// BaseURL is the Graph root with a trailing slash; DefaultBaseURL
	// when empty. Tests point it at an httptest server.
	BaseURL string
	// Token supplies the bearer for every request (one Token() call per
	// request, so a refresh happens in the source when needed).
	Token oauth2.TokenSource
	// UserAgent overrides the User-Agent header.
	UserAgent string
}

// Client is one Graph client. Safe for concurrent use.
type Client struct {
	http      *http.Client
	base      *url.URL
	token     oauth2.TokenSource
	userAgent string
}

// New builds a client.
func New(opts Options) (*Client, error) {
	if opts.Token == nil {
		return nil, errors.New("graph: Options.Token is required")
	}
	base := opts.BaseURL
	if base == "" {
		base = DefaultBaseURL
	}
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("graph: BaseURL %q must be an absolute http(s) URL", opts.BaseURL)
	}
	if !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
	}
	u.RawQuery, u.Fragment = "", ""
	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	ua := opts.UserAgent
	if ua == "" {
		ua = defaultUserAgent
	}
	return &Client{http: httpClient, base: u, token: opts.Token, userAgent: ua}, nil
}

// BaseURL returns the root every relative path is joined under.
func (c *Client) BaseURL() string { return c.base.String() }

// Request is one Graph request: a relative path under the base (a
// leading slash is ignored; function segments such as
// "me/drive/root/search(q='x')" are sent as given) or an absolute URL on
// the base's host (a next link), optional query, extra headers and a
// JSON body.
type Request struct {
	Method string
	Path   string
	Query  url.Values
	Header http.Header
	Body   any
}

// Response is what Do reports besides the decoded body.
type Response struct {
	Status int
	Header http.Header
}

// Error is a Graph answer with a status of 400 or more: the status, the
// envelope's code and message (empty when the body was not the Graph
// envelope) and, for throttled answers, the Retry-After wait (zero when
// Graph gave none).
type Error struct {
	Status     int
	Code       string
	Message    string
	RetryAfter time.Duration
	// retryAfterSet says a Retry-After header was present (a 503 counts
	// as throttling only then).
	retryAfterSet bool
}

// Error implements error.
func (e *Error) Error() string {
	s := fmt.Sprintf("graph: http %d", e.Status)
	if e.Code != "" {
		s += " " + e.Code
	}
	if e.Message != "" {
		s += ": " + e.Message
	}
	return s
}

// Throttled reports whether Graph asked the caller to slow down: 429, or
// 503 carrying Retry-After.
func (e *Error) Throttled() bool {
	return e.Status == http.StatusTooManyRequests || (e.Status == http.StatusServiceUnavailable && e.retryAfterSet)
}

// Do sends req, decodes a JSON answer into out (when out is non-nil and
// the answer has a body) and returns the status and headers. A status of
// 400 or more is returned as *Error; transport failures and context
// errors are returned as they are (wrapped).
func (c *Client) Do(ctx context.Context, req Request, out any) (*Response, error) {
	u, err := c.resolve(req.Path, req.Query)
	if err != nil {
		return nil, err
	}
	tok, err := c.token.Token()
	if err != nil {
		return nil, fmt.Errorf("graph: token: %w", err)
	}
	var body io.Reader
	if req.Body != nil {
		b, err := json.Marshal(req.Body)
		if err != nil {
			return nil, fmt.Errorf("graph: encode body: %w", err)
		}
		body = bytes.NewReader(b)
	}
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	hreq, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, fmt.Errorf("graph: build request: %w", err)
	}
	for k, vs := range req.Header {
		for _, v := range vs {
			hreq.Header.Add(k, v)
		}
	}
	hreq.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	hreq.Header.Set("Accept", "application/json")
	hreq.Header.Set("User-Agent", c.userAgent)
	if body != nil {
		hreq.Header.Set("Content-Type", "application/json")
	}
	res, err := c.http.Do(hreq)
	if err != nil {
		return nil, fmt.Errorf("graph: %s %s: %w", method, req.Path, err)
	}
	defer func() { _ = res.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(res.Body, MaxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("graph: %s %s: read answer: %w", method, req.Path, err)
	}
	if len(raw) > MaxResponseBytes {
		return nil, fmt.Errorf("graph: %s %s: answer larger than %d bytes", method, req.Path, MaxResponseBytes)
	}
	resp := &Response{Status: res.StatusCode, Header: res.Header}
	if res.StatusCode >= 400 {
		return resp, newError(res, raw)
	}
	if out != nil && len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp, fmt.Errorf("graph: %s %s: decode answer: %w", method, req.Path, err)
		}
	}
	return resp, nil
}

// resolve turns a path into the request URL: an absolute URL must be on
// the base's host (next links); anything else is joined under the base.
func (c *Client) resolve(path string, query url.Values) (*url.URL, error) {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		u, err := url.Parse(path)
		if err != nil {
			return nil, fmt.Errorf("graph: bad next link: %w", err)
		}
		if u.Scheme != c.base.Scheme || u.Host != c.base.Host {
			return nil, fmt.Errorf("graph: next link %s://%s is not on %s://%s", u.Scheme, u.Host, c.base.Scheme, c.base.Host)
		}
		return u, nil
	}
	u := *c.base
	u.Path = c.base.Path + strings.TrimPrefix(path, "/")
	// Keep function-segment characters (parentheses, quotes) as given
	// while escaping anything a path cannot carry.
	u.RawPath = ""
	if len(query) > 0 {
		u.RawQuery = query.Encode()
	}
	return &u, nil
}

// Get is Do for a GET.
func (c *Client) Get(ctx context.Context, path string, query url.Values, out any) error {
	_, err := c.Do(ctx, Request{Method: http.MethodGet, Path: path, Query: query}, out)
	return err
}

// Post is Do for a JSON POST; it returns the status (201 Created, 202
// Accepted, ...).
func (c *Client) Post(ctx context.Context, path string, body, out any) (int, error) {
	res, err := c.Do(ctx, Request{Method: http.MethodPost, Path: path, Body: body}, out)
	if err != nil {
		return 0, err
	}
	return res.Status, nil
}

// envelope is the Graph error body.
type envelope struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// newError builds the *Error of a failed answer.
func newError(res *http.Response, raw []byte) *Error {
	e := &Error{Status: res.StatusCode}
	var env envelope
	if err := json.Unmarshal(raw, &env); err == nil {
		e.Code, e.Message = env.Error.Code, env.Error.Message
	}
	if ra := strings.TrimSpace(res.Header.Get("Retry-After")); ra != "" {
		e.retryAfterSet = true
		if secs, err := strconv.Atoi(ra); err == nil && secs >= 0 {
			e.RetryAfter = time.Duration(secs) * time.Second
		} else if at, err := http.ParseTime(ra); err == nil {
			if d := time.Until(at).Round(time.Second); d > 0 {
				e.RetryAfter = d
			}
		}
	}
	return e
}

// ListOptions bounds Collect: at most MaxItems items and MaxPages
// requests. Zero means one page / no item cap beyond that page.
type ListOptions struct {
	MaxItems int
	MaxPages int
}

// page is one collection answer.
type page struct {
	Value    []json.RawMessage `json:"value"`
	NextLink string            `json:"@odata.nextLink"`
}

// Collect walks a collection from path (with query on the first request;
// next links carry their own) and returns up to opts.MaxItems items of
// type T, reading at most opts.MaxPages pages. more reports that Graph
// had more (a next link was left unfollowed, or items were dropped to
// the cap). On an error after the first page the items read so far are
// returned with it.
func Collect[T any](ctx context.Context, c *Client, path string, query url.Values, opts ListOptions) (items []T, more bool, err error) {
	maxPages := opts.MaxPages
	if maxPages <= 0 {
		maxPages = 1
	}
	next, q := path, query
	for pages := 0; pages < maxPages; pages++ {
		var pg page
		if _, err := c.Do(ctx, Request{Method: http.MethodGet, Path: next, Query: q}, &pg); err != nil {
			return items, false, err
		}
		for _, raw := range pg.Value {
			if opts.MaxItems > 0 && len(items) >= opts.MaxItems {
				return items, true, nil
			}
			var it T
			if err := json.Unmarshal(raw, &it); err != nil {
				return items, false, fmt.Errorf("graph: decode item: %w", err)
			}
			items = append(items, it)
		}
		if pg.NextLink == "" {
			return items, false, nil
		}
		if opts.MaxItems > 0 && len(items) >= opts.MaxItems {
			return items, true, nil
		}
		next, q = pg.NextLink, nil
	}
	return items, true, nil
}

// Quote returns s as an OData string literal: single-quoted, with
// embedded single quotes doubled.
func Quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
