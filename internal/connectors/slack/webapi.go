package slack

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	goslack "github.com/slack-go/slack"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// maxWebResponseBytes bounds one Web API answer read by webAPI.call (a
// canvas's whole markdown comes back in one string; Slack caps a canvas
// edit at 1 MiB of markdown, so 16 MiB is generous and still bounded).
const maxWebResponseBytes = 16 << 20

// maxDownloadRedirects bounds the redirects a private file download
// follows (each one must stay on a Slack host).
const maxDownloadRedirects = 3

// webHandler runs one tool that needs Web API methods slack-go v0.29 does
// not wrap (canvases.getContent, slackLists.*, a canvas created in a
// channel, a canvas rename) or a private file download: both need the
// call's token, which the slack-go client keeps to itself.
type webHandler func(ctx context.Context, web *webAPI, call connectors.Call) (connectors.Result, error)

// webAPI is the connection's token, the slack-go client built from it
// and a JSON caller for the Web API methods slack-go lacks. Errors come
// back in slack-go's shapes (SlackErrorResponse for ok:false,
// StatusCodeError, RateLimitedError) so classify and ClassifyWrite treat
// them like every other Slack error.
type webAPI struct {
	api     *goslack.Client
	http    *http.Client
	base    string
	token   string
	allowed func(string) bool
}

// webFor builds the webAPI of one call.
func (c *Connector) webFor(api *goslack.Client, token string) *webAPI {
	w := &webAPI{api: api, base: c.baseURL, token: token, allowed: c.uploadURLAllowed}
	w.http = &http.Client{Transport: &userAgentTransport{base: c.transport}, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxDownloadRedirects || !w.allowed(req.URL.String()) {
			return errors.New("slack: redirect off Slack's hosts refused")
		}
		return nil
	}}
	return w
}

// call POSTs body as JSON to the Web API method and decodes the answer
// into out (nil to only check ok).
func (w *webAPI) call(ctx context.Context, method string, body, out any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return invalid("%s: arguments could not be encoded", method)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.base+method, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Authorization", "Bearer "+w.token)
	data, err := w.do(req, maxWebResponseBytes)
	if err != nil {
		return err
	}
	if len(data) > maxWebResponseBytes {
		return errors.New("slack answer exceeds the gateway's bound")
	}
	var head struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(data, &head); err != nil {
		return fmt.Errorf("slack answer could not be decoded: %w", err)
	}
	if !head.OK {
		code := strings.TrimSpace(head.Error)
		if code == "" {
			code = "unknown_error"
		}
		return goslack.SlackErrorResponse{Err: code}
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("slack answer could not be decoded: %w", err)
		}
	}
	return nil
}

// download GETs a private file URL (the caller checked it is on a Slack
// host) and returns at most max+1 bytes, so the caller can tell the file
// was longer than max.
func (w *webAPI) download(ctx context.Context, rawURL string, max int) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+w.token)
	return w.do(req, max)
}

// do sends req and reads at most max+1 bytes of a 200 answer; 429 is a
// RateLimitedError (with Slack's Retry-After), any other status a
// StatusCodeError.
func (w *webAPI) do(req *http.Request, max int) ([]byte, error) {
	resp, err := w.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		wait, _ := strconv.Atoi(strings.TrimSpace(resp.Header.Get("Retry-After")))
		return nil, &goslack.RateLimitedError{RetryAfter: time.Duration(wait) * time.Second}
	case resp.StatusCode != http.StatusOK:
		return nil, goslack.StatusCodeError{Code: resp.StatusCode, Status: resp.Status}
	}
	return io.ReadAll(io.LimitReader(resp.Body, int64(max)+1))
}
