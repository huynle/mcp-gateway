package atlassian

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// DefaultAPIBase is Atlassian's OAuth 2.0 API gateway. Every product
// request goes to <base>/ex/jira/<cloud id>/... or
// <base>/ex/confluence/<cloud id>/wiki/...; the binder's identity calls
// go to <base>/me and <base>/oauth/token/accessible-resources.
const DefaultAPIBase = "https://api.atlassian.com"

// maxBodyBytes bounds how much of a reply the client reads (a page of
// 100 issues with descriptions stays far below it).
const maxBodyBytes = 8 << 20

// client is the thin REST client: one authenticated http.Client, the API
// base and the cloud id of the site every request targets. It knows the
// two products' URL prefixes and nothing else about them.
type client struct {
	http    *http.Client
	base    string
	cloudID string
}

// jiraURL builds <base>/ex/jira/<cloud id>/rest/api/3/<path>?query.
func (c *client) jiraURL(path string, q url.Values) string {
	return c.url("/ex/jira/"+c.cloudID+"/rest/api/3/"+strings.TrimPrefix(path, "/"), q)
}

// wikiURL builds <base>/ex/confluence/<cloud id>/wiki/<path>?query.
func (c *client) wikiURL(path string, q url.Values) string {
	return c.url("/ex/confluence/"+c.cloudID+"/wiki/"+strings.TrimPrefix(path, "/"), q)
}

func (c *client) url(path string, q url.Values) string {
	u := c.base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	return u
}

// getJSON performs GET rawURL and decodes the JSON reply into out (which
// may be nil). A non-2xx answer is an *httpError carrying the status,
// Retry-After and the vendor's message; a 2xx that does not decode is a
// *decodeError; transport failures come back as they are.
func (c *client) getJSON(ctx context.Context, rawURL string, out any) error {
	return c.do(ctx, http.MethodGet, rawURL, nil, out)
}

// postJSON performs POST rawURL with body as JSON; see getJSON for the
// errors. A 204 leaves out untouched.
func (c *client) postJSON(ctx context.Context, rawURL string, body, out any) error {
	return c.do(ctx, http.MethodPost, rawURL, body, out)
}

func (c *client) do(ctx context.Context, method, rawURL string, body, out any) error {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &httpError{status: resp.StatusCode, retryAfter: resp.Header.Get("Retry-After"), message: vendorMessage(data)}
	}
	if out == nil || resp.StatusCode == http.StatusNoContent || len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return &decodeError{status: resp.StatusCode, err: err}
	}
	return nil
}
