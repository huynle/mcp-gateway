package client

import (
	"context"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// slowToolServer has a tool and a tools/list that each take delay: the
// tools/call one stands in for an image-generation tool that needs
// minutes (yoto-mcp generate_cover), scaled down.
func slowToolServer(delay time.Duration, slowList bool) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "slow", Version: "1"}, nil)
	mcp.AddTool(s, &mcp.Tool{Name: "slow", Description: "sleeps"},
		func(ctx context.Context, _ *mcp.CallToolRequest, in echoIn) (*mcp.CallToolResult, echoOut, error) {
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return nil, echoOut{}, ctx.Err()
			}
			return nil, echoOut{Echo: in.Text}, nil
		})
	if slowList {
		s.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
			return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
				if method == "tools/list" {
					select {
					case <-time.After(delay):
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				}
				return next(ctx, method, req)
			}
		})
	}
	return s
}

const (
	shortTimeout = 300 * time.Millisecond
	slowDelay    = 900 * time.Millisecond
	longCall     = 5 * time.Second
)

func TestCallTimeoutDefaultsToTimeout(t *testing.T) {
	for _, tr := range []Transport{TransportStreamableHTTP, TransportSSE} {
		t.Run(string(tr), func(t *testing.T) {
			ts, path := slowEndpoint(t, tr, slowToolServer(slowDelay, false))
			c := newTestClient(t, func(o *Options) { o.Timeout = shortTimeout })
			s := connect(t, c, Endpoint{URL: ts + path, Transport: tr})
			_, err := s.CallTool(ctxT(t), "slow", map[string]any{"text": "hi"})
			_ = wantClass(t, err, ClassTimeout)
		})
	}
}

func TestCallTimeoutAllowsSlowToolCall(t *testing.T) {
	for _, tr := range []Transport{TransportStreamableHTTP, TransportSSE} {
		t.Run(string(tr), func(t *testing.T) {
			ts, path := slowEndpoint(t, tr, slowToolServer(slowDelay, false))
			c := newTestClient(t, func(o *Options) { o.Timeout = shortTimeout; o.CallTimeout = longCall })
			s := connect(t, c, Endpoint{URL: ts + path, Transport: tr})
			res, err := s.CallTool(ctxT(t), "slow", map[string]any{"text": "hi"})
			if err != nil {
				t.Fatalf("CallTool past Timeout but within CallTimeout: %v", err)
			}
			if res == nil || res.IsError {
				t.Fatalf("result = %+v, want success", res)
			}
		})
	}
}

func TestCallTimeoutStillBoundsToolCall(t *testing.T) {
	ts, path := slowEndpoint(t, TransportStreamableHTTP, slowToolServer(3*slowDelay, false))
	c := newTestClient(t, func(o *Options) { o.Timeout = shortTimeout; o.CallTimeout = slowDelay })
	s := connect(t, c, Endpoint{URL: ts + path, Transport: TransportStreamableHTTP})
	start := time.Now()
	_, err := s.CallTool(ctxT(t), "slow", map[string]any{"text": "hi"})
	_ = wantClass(t, err, ClassTimeout)
	if d := time.Since(start); d < slowDelay || d > 2*slowDelay+slowDelay/2 {
		t.Errorf("call failed after %v, want about CallTimeout (%v)", d, slowDelay)
	}
}

func TestCallTimeoutDoesNotExtendList(t *testing.T) {
	ts, path := slowEndpoint(t, TransportStreamableHTTP, slowToolServer(slowDelay, true))
	c := newTestClient(t, func(o *Options) { o.Timeout = shortTimeout; o.CallTimeout = longCall })
	s := connect(t, c, Endpoint{URL: ts + path, Transport: TransportStreamableHTTP})
	_, err := s.ListTools(ctxT(t))
	_ = wantClass(t, err, ClassTimeout)
}

// slowEndpoint serves s over tr and returns the base URL and path.
func slowEndpoint(t *testing.T, tr Transport, s *mcp.Server) (string, string) {
	t.Helper()
	if tr == TransportSSE {
		return sseServer(t, s, nil).URL, "/sse"
	}
	return streamableServer(t, s, nil).URL, "/mcp"
}
