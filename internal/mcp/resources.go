package mcp

import (
	"cmp"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

// CodeUpstream: a resources/read or prompts/get reached the upstream
// server and failed there (unreachable, timeout, protocol, too large,
// tunnel offline, ...). The message is class-level, never upstream text.
// Tool calls report the same failures as tool results with isError;
// resources and prompts have no such result, so they get this code.
const CodeUpstream int64 = -32036

// DefaultListPageSize bounds a page of resources/list,
// resources/templates/list and prompts/list.
const DefaultListPageSize = 100

// Method names the endpoint serves from a ResourceProvider.
const (
	methodListResources         = "resources/list"
	methodListResourceTemplates = "resources/templates/list"
	methodReadResource          = "resources/read"
	methodListPrompts           = "prompts/list"
	methodGetPrompt             = "prompts/get"
)

// ResourceProvider serves the resources and prompts of /mcp for one
// principal (the federation connector: the approved snapshots of the
// upstream servers the caller may use). Lists return the caller's whole
// union; the endpoint sorts and pages it. ReadResource and GetPrompt
// must call admit once they have resolved and authorized the request and
// before anything goes upstream, and return admit's error as is: admit
// names the access for the audit row and applies the rate limit.
// Unknown and hidden items are ErrResourceNotFound / ErrPromptNotFound;
// other refusals are *ToolError; upstream failures are ClassedError
// (their message is shown, so it must be class-level).
type ResourceProvider interface {
	ListResources(ctx context.Context, p *tokens.Principal) ([]*sdk.Resource, error)
	ListResourceTemplates(ctx context.Context, p *tokens.Principal) ([]*sdk.ResourceTemplate, error)
	ListPrompts(ctx context.Context, p *tokens.Principal) ([]*sdk.Prompt, error)
	ReadResource(ctx context.Context, p *tokens.Principal, uri string, admit Admit) (*sdk.ReadResourceResult, error)
	GetPrompt(ctx context.Context, p *tokens.Principal, name string, args map[string]string, admit Admit) (*sdk.GetPromptResult, error)
}

// Admit is the endpoint's hook a ResourceProvider calls before going
// upstream (see ResourceProvider).
type Admit func(ctx context.Context, a Access) error

// Access names a resources/read or prompts/get for the audit row and the
// rate limiter: Name is tool-like ("<server>.resources/read"), its prefix
// up to the first "." the app the per-app bucket counts;
// ResourceIdentity is what was accessed (never content).
type Access struct {
	Name             string
	ResourceIdentity map[string]string
}

// ErrResourceNotFound is the one answer for a resource that does not
// exist or that the caller may not see: the go-sdk's own shape (code
// -32602, "Resource not found", data.uri).
func ErrResourceNotFound(uri string) *ToolError {
	te := NewToolError(CodeInvalidParams, "resource_not_found", "Resource not found")
	te.Data = map[string]any{"uri": uri}
	return te
}

// ErrPromptNotFound is the one answer for a prompt that does not exist
// or that the caller may not see (the go-sdk's own message).
func ErrPromptNotFound(name string) *ToolError {
	return NewToolError(CodeInvalidParams, "prompt_not_found", fmt.Sprintf("unknown prompt %q", name))
}

var errInvalidCursor = &jsonrpc.Error{Code: CodeInvalidParams, Message: "invalid cursor"}

// resourceMethod serves one resources/* or prompts/* method; handled is
// false for methods it does not own.
func (e *endpoint) resourceMethod(ctx context.Context, method string, req sdk.Request) (res sdk.Result, handled bool, err error) {
	switch method {
	case methodListResources, methodListResourceTemplates, methodReadResource, methodListPrompts, methodGetPrompt:
	default:
		return nil, false, nil
	}
	p := tokens.PrincipalFrom(ctx)
	if p == nil || p.UserID == "" {
		return nil, true, toRPCError(errUnauthenticated)
	}
	switch r := req.(type) {
	case *sdk.ListResourcesRequest:
		cursor := ""
		if r.Params != nil {
			cursor = r.Params.Cursor
		}
		res, err = e.listResources(ctx, p, cursor)
	case *sdk.ListResourceTemplatesRequest:
		cursor := ""
		if r.Params != nil {
			cursor = r.Params.Cursor
		}
		res, err = e.listResourceTemplates(ctx, p, cursor)
	case *sdk.ListPromptsRequest:
		cursor := ""
		if r.Params != nil {
			cursor = r.Params.Cursor
		}
		res, err = e.listPrompts(ctx, p, cursor)
	case *sdk.ReadResourceRequest:
		res, err = e.readResource(ctx, p, r)
	case *sdk.GetPromptRequest:
		res, err = e.getPrompt(ctx, p, r)
	default:
		return nil, false, nil
	}
	return res, true, err
}

func (e *endpoint) pageSize() int {
	if e.opts.ListPageSize > 0 {
		return e.opts.ListPageSize
	}
	return DefaultListPageSize
}

func (e *endpoint) listResources(ctx context.Context, p *tokens.Principal, cursor string) (sdk.Result, error) {
	all, err := e.opts.Resources.ListResources(ctx, p)
	if err != nil {
		return nil, e.listFailed(ctx, methodListResources, err)
	}
	items, next, err := page(all, func(r *sdk.Resource) string { return r.URI }, cursor, e.pageSize())
	if err != nil {
		return nil, err
	}
	return &sdk.ListResourcesResult{Resources: items, NextCursor: next, Cacheable: sdk.Cacheable{CacheScope: "private"}}, nil
}

func (e *endpoint) listResourceTemplates(ctx context.Context, p *tokens.Principal, cursor string) (sdk.Result, error) {
	all, err := e.opts.Resources.ListResourceTemplates(ctx, p)
	if err != nil {
		return nil, e.listFailed(ctx, methodListResourceTemplates, err)
	}
	items, next, err := page(all, func(t *sdk.ResourceTemplate) string { return t.URITemplate }, cursor, e.pageSize())
	if err != nil {
		return nil, err
	}
	return &sdk.ListResourceTemplatesResult{ResourceTemplates: items, NextCursor: next, Cacheable: sdk.Cacheable{CacheScope: "private"}}, nil
}

func (e *endpoint) listPrompts(ctx context.Context, p *tokens.Principal, cursor string) (sdk.Result, error) {
	all, err := e.opts.Resources.ListPrompts(ctx, p)
	if err != nil {
		return nil, e.listFailed(ctx, methodListPrompts, err)
	}
	items, next, err := page(all, func(p *sdk.Prompt) string { return p.Name }, cursor, e.pageSize())
	if err != nil {
		return nil, err
	}
	return &sdk.ListPromptsResult{Prompts: items, NextCursor: next, Cacheable: sdk.Cacheable{CacheScope: "private"}}, nil
}

// listFailed logs a provider failure and answers a bare internal error.
func (e *endpoint) listFailed(ctx context.Context, method string, err error) error {
	e.opts.Log.Error("list failed", "event", "mcp.list_failed", "method", method,
		"error", observability.RedactError(err), observability.RequestIDAttr(ctx))
	return &jsonrpc.Error{Code: CodeInternal, Message: method + " is unavailable"}
}

// page sorts items by key and returns the page after cursor (the
// base64url of the last key of the previous page; empty for the first)
// and the cursor of the next page (empty on the last). Keying the cursor
// on the item, not an offset, keeps paging stable when items come and go
// between pages.
func page[T any](items []T, key func(T) string, cursor string, size int) ([]T, string, error) {
	sorted := slices.Clone(items)
	slices.SortStableFunc(sorted, func(a, b T) int { return cmp.Compare(key(a), key(b)) })
	start := 0
	if cursor != "" {
		raw, err := base64.RawURLEncoding.DecodeString(cursor)
		if err != nil {
			return nil, "", errInvalidCursor
		}
		after := string(raw)
		start, _ = slices.BinarySearchFunc(sorted, after, func(t T, k string) int { return cmp.Compare(key(t), k) })
		for start < len(sorted) && key(sorted[start]) <= after {
			start++
		}
	}
	end := min(start+size, len(sorted))
	out := sorted[start:end]
	if out == nil {
		out = []T{}
	}
	next := ""
	if end < len(sorted) && end > start {
		next = base64.RawURLEncoding.EncodeToString([]byte(key(sorted[end-1])))
	}
	return out, next, nil
}

// access is the state of one resources/read or prompts/get for its audit
// row.
type access struct {
	method   string
	admitted *Access
	started  time.Time
}

// admit returns the Admit hook of one request: it records the access and
// asks the rate limiter.
func (e *endpoint) admit(p *tokens.Principal, a *access) Admit {
	return func(ctx context.Context, acc Access) error {
		a.admitted = &acc
		if e.opts.RateLimiter == nil {
			return nil
		}
		if ok, wait := e.opts.RateLimiter.Allow(ctx, p.UserID, acc.Name); !ok {
			te := NewToolError(CodeRateLimited, "rate_limited", fmt.Sprintf("rate limited; retry in %s", wait.Round(time.Second)))
			te.RetryAfter = wait
			return te
		}
		return nil
	}
}

func (e *endpoint) readResource(ctx context.Context, p *tokens.Principal, req *sdk.ReadResourceRequest) (sdk.Result, error) {
	a := &access{method: methodReadResource, started: time.Now()}
	uri := ""
	if req.Params != nil {
		uri = req.Params.URI
	}
	res, err := e.opts.Resources.ReadResource(ctx, p, uri, e.admit(p, a))
	if err == nil && res == nil {
		err = errors.New("mcp: resource provider returned no result")
	}
	e.auditAccess(ctx, p, a, err)
	if err != nil {
		return nil, e.accessError(ctx, a, err)
	}
	if res.Contents == nil {
		res.Contents = []*sdk.ResourceContents{}
	}
	// Read with the caller's credential: never cacheable for others.
	res.CacheScope = "private"
	return res, nil
}

func (e *endpoint) getPrompt(ctx context.Context, p *tokens.Principal, req *sdk.GetPromptRequest) (sdk.Result, error) {
	a := &access{method: methodGetPrompt, started: time.Now()}
	var name string
	var args map[string]string
	if req.Params != nil {
		name, args = req.Params.Name, req.Params.Arguments
	}
	res, err := e.opts.Resources.GetPrompt(ctx, p, name, args, e.admit(p, a))
	if err == nil && res == nil {
		err = errors.New("mcp: resource provider returned no result")
	}
	e.auditAccess(ctx, p, a, err)
	if err != nil {
		return nil, e.accessError(ctx, a, err)
	}
	if res.Messages == nil {
		res.Messages = []*sdk.PromptMessage{}
	}
	return res, nil
}

// accessError renders a read/get failure: a ToolError as itself, an
// upstream (classed) failure as CodeUpstream with its class-level
// message, anything else as a bare internal error (logged, never shown).
func (e *endpoint) accessError(ctx context.Context, a *access, err error) error {
	var te *ToolError
	if errors.As(err, &te) {
		return toRPCError(te)
	}
	var ce ClassedError
	if errors.As(err, &ce) && ce.ErrorClass() != "" {
		return &jsonrpc.Error{Code: CodeUpstream, Message: observability.RedactError(err)}
	}
	e.opts.Log.Error("request failed", "event", "mcp.access_failed", "method", a.method,
		"error", observability.RedactError(err), observability.RequestIDAttr(ctx))
	return &jsonrpc.Error{Code: CodeInternal, Message: a.method + " failed"}
}

// auditAccess records one event per resources/read or prompts/get, like a
// tool call: the access name (the bare method when the request never got
// that far, e.g. not found), user, token, resource identity, decision,
// outcome, latency and error class. Never content or arguments.
func (e *endpoint) auditAccess(ctx context.Context, p *tokens.Principal, a *access, err error) {
	ev := audit.Event{
		Time: time.Now(), UserID: p.UserID, TokenID: p.TokenID, Tool: a.method,
		Latency: time.Since(a.started), RequestID: observability.RequestIDFromContext(ctx),
	}
	if a.admitted != nil {
		ev.Tool = a.admitted.Name
		ev.ResourceIdentity = a.admitted.ResourceIdentity
		ev.Decision = "allow"
	}
	var te *ToolError
	switch {
	case err == nil:
		ev.Outcome = "succeeded"
	case errors.As(err, &te):
		ev.ErrorClass = te.Class()
		if te.Denial() {
			ev.Decision, ev.Outcome = "deny", "denied"
		} else {
			ev.Outcome = "failed"
		}
	default:
		ev.Outcome = "failed"
		ev.ErrorClass = errorClass(err, "upstream_error")
	}
	if e.opts.Audit != nil {
		if rerr := e.opts.Audit.Record(ctx, ev); rerr != nil {
			e.opts.Log.Error("audit event not recorded", "event", "mcp.audit_failed", "tool", ev.Tool,
				"error", observability.RedactError(rerr), observability.RequestIDAttr(ctx))
		}
	}
	e.opts.Log.Info("resource access", "event", "mcp.resource_access", "method", a.method, "tool", ev.Tool,
		"user_id", ev.UserID, "public_id", p.PublicID, "decision", ev.Decision, "outcome", ev.Outcome,
		"error_class", ev.ErrorClass, "latency_ms", ev.Latency.Milliseconds(), observability.RequestIDAttr(ctx))
}
