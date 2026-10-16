package microsoft

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/microsoft/graph"
)

// Shared plumbing of the tools added after the first ten (mail,
// calendar, drive, Teams chats, To Do, contacts and people): one
// declaration carries the tool and its handler, single-page listings
// return Page, and the stable-id checks GET the resource and decide from
// its state.

// MaxContentBytes caps every content download (mail_get_attachment,
// drive_get_file_content) and upload (drive_upload_file): 5 MiB of raw
// bytes. A larger item is refused with invalid_argument and its web
// link, never cut (a cut binary is useless).
const MaxContentBytes = 5 << 20

// contentResultBytes bounds the result of a content tool: the capped
// bytes in base64 plus room for the metadata.
const contentResultBytes = MaxContentBytes*4/3 + 64<<10

// toolDef is one tool with its handler.
type toolDef struct {
	connectors.Tool
	run handler
}

// extraDefs are the tools declared with their handler, in listing order.
func (c *Connector) extraDefs() []toolDef {
	var out []toolDef
	for _, area := range [][]toolDef{c.mailDefs(), c.calendarDefs(), c.driveDefs(), c.teamsDefs(), c.todoDefs(), c.peopleDefs()} {
		out = append(out, area...)
	}
	return out
}

// Page is the result of a single-page listing.
type Page[T any] struct {
	Top       int  `json:"top,omitempty"`
	HasMore   bool `json:"has_more"`
	Truncated bool `json:"truncated,omitempty"`
	Items     []T  `json:"items"`
}

// fetchPage reads one collection page (with headers such as Prefer or
// ConsistencyLevel) and reports whether Graph had a next link.
func fetchPage[T any](ctx context.Context, client *graph.Client, path string, query url.Values, header http.Header) ([]T, bool, error) {
	var pg struct {
		Value    []T    `json:"value"`
		NextLink string `json:"@odata.nextLink"`
	}
	_, err := client.Do(ctx, graph.Request{Method: http.MethodGet, Path: path, Query: query, Header: header}, &pg)
	return pg.Value, pg.NextLink != "", err
}

// pageResult converts items into a bounded Page result: Empty when there
// are none, Partial when top was clamped or items were dropped to fit
// the result bounds. At most top items are kept (top 0 keeps all).
func pageResult[G, T any](c *Connector, top int, clamped, more bool, items []G, conv func(G) T) connectors.Result {
	if top > 0 && len(items) > top {
		items, more = items[:top], true
	}
	out := Page[T]{Top: top, HasMore: more, Items: make([]T, 0, len(items))}
	for _, it := range items {
		out.Items = append(out.Items, conv(it))
	}
	res := connectors.Result{Partial: clamped, Empty: len(out.Items) == 0}
	if truncateItems(&out.Items, c.bounds.MaxResultBytes, func() any { return out }) {
		out.Truncated, res.Partial = true, true
	}
	res.Content = out
	return res
}

// listRead is the common shape of a single-page read: fetch, classify,
// convert.
func listRead[G, T any](ctx context.Context, c *Connector, client *graph.Client, action, path string, query url.Values, header http.Header, top int, clamped bool, conv func(G) T) (connectors.Result, error) {
	items, more, err := fetchPage[G](ctx, client, path, query, header)
	if err := classify(action, err); err != nil {
		return connectors.Result{}, err
	}
	return pageResult(c, top, clamped, more, items, conv), nil
}

// identity records the named arguments (pairs of argument name and
// identity key) when given; values are identifiers, never content.
func identity(pairs ...string) func(map[string]any) map[string]string {
	return func(args map[string]any) map[string]string {
		out := map[string]string{}
		for i := 0; i+1 < len(pairs); i += 2 {
			if v := strings.TrimSpace(stringArg(args, pairs[i])); v != "" {
				out[pairs[i+1]] = v
			}
		}
		return out
	}
}

// resultIDs returns a ResultIDs hook picking the named string fields of
// the result's JSON form; nil when none is set.
func resultIDs(keys ...string) func(connectors.Result) map[string]string {
	return func(res connectors.Result) map[string]string {
		if res.Content == nil {
			return nil
		}
		raw, err := json.Marshal(res.Content)
		if err != nil {
			return nil
		}
		var m map[string]any
		if json.Unmarshal(raw, &m) != nil {
			return nil
		}
		out := map[string]string{}
		for _, k := range keys {
			if s, ok := m[k].(string); ok && s != "" {
				out[k] = s
			}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	}
}

// boolArg reads an optional boolean argument.
func boolArg(args map[string]any, name string, def bool) (bool, error) {
	v, ok := args[name]
	if !ok || v == nil {
		return def, nil
	}
	b, ok := v.(bool)
	if !ok {
		return false, invalid("%s must be a boolean", name)
	}
	return b, nil
}

// boolIdentity records a boolean argument as "true" / "false" (def when
// absent or not a boolean).
func boolIdentity(name string, def bool) func(map[string]any) string {
	return func(args map[string]any) string {
		b, err := boolArg(args, name, def)
		if err != nil {
			b = def
		}
		return fmt.Sprint(b)
	}
}

// textArg reads a required string argument (kept as given) of at most
// maxBodyBytes.
func textArg(args map[string]any, name string, required bool) (string, error) {
	s, err := optionalString(args, name)
	if err != nil {
		return "", err
	}
	if required && strings.TrimSpace(s) == "" {
		return "", invalid("%s is required", name)
	}
	if len(s) > maxBodyBytes {
		return "", invalid("%s is too long", name)
	}
	return s, nil
}

// encodeContent returns downloaded bytes as text when they are valid
// UTF-8 of a textual type, else as base64.
func encodeContent(b []byte, contentType string) (encoding, content string) {
	ct := strings.ToLower(contentType)
	textual := ct == "" || strings.HasPrefix(ct, "text/") || strings.Contains(ct, "json") || strings.Contains(ct, "xml") ||
		strings.Contains(ct, "javascript") || strings.Contains(ct, "csv") || strings.Contains(ct, "yaml")
	if textual && utf8.Valid(b) {
		return "text", string(b)
	}
	return "base64", base64.StdEncoding.EncodeToString(b)
}

// tooLarge is the refusal of an item over MaxContentBytes.
func tooLarge(what string, size int64, link string) error {
	msg := fmt.Sprintf("%s is %d bytes, over the %d MiB cap", what, size, MaxContentBytes>>20)
	if link != "" {
		msg += "; open it at " + link
	}
	return invalid("%s", msg)
}

// stateCheck builds a stable-id Check: it GETs the resource whose id is
// the resource identity's idKey (path builds the Graph path, sel its
// $select) and lets
// decide answer from its JSON (nil and gone when Graph says not found).
// decide's ok false is "cannot tell yet"; any other Graph error is too.
func (c *Connector) stateCheck(idKey string, path func(id string, ident map[string]string) (string, error), sel string, decide func(ident map[string]string, body map[string]any, gone bool) (connectors.ReconcileResult, bool)) func(context.Context, connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	return func(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
		id := in.ResourceIdentity[idKey]
		if id == "" || len(id) > maxIDLength || !idRE.MatchString(id) {
			return connectors.ReconcileResult{}, fmt.Errorf("%w: resource identity has no valid %s", ErrNotReconcilable, idKey)
		}
		p, err := path(id, in.ResourceIdentity)
		if err != nil {
			return connectors.ReconcileResult{}, err
		}
		tg, err := c.target(ctx, in)
		if err != nil {
			return connectors.ReconcileResult{}, err
		}
		ctx, cancel := context.WithTimeout(ctx, c.timeout)
		defer cancel()
		var body map[string]any
		gone := false
		if _, err := tg.client.Do(ctx, graph.Request{Method: http.MethodGet, Path: p, Query: url.Values{"$select": {sel}}}, &body); err != nil {
			cerr := classify("reconcile: read "+idKey, err)
			if classOf(cerr) != ClassNotFound {
				return connectors.ReconcileResult{}, cerr
			}
			body, gone = nil, true
		}
		res, ok := decide(in.ResourceIdentity, body, gone)
		if !ok {
			return connectors.ReconcileResult{}, fmt.Errorf("microsoft: reconcile: the %s's state does not tell; cannot tell yet", idKey)
		}
		return res, nil
	}
}

// identityPath validates further identity values used in a path.
func identityPath(format string, keys ...string) func(id string, ident map[string]string) (string, error) {
	return func(id string, ident map[string]string) (string, error) {
		vals := []any{id}
		for _, k := range keys {
			v := ident[k]
			if v == "" || !idRE.MatchString(v) {
				return "", fmt.Errorf("%w: resource identity has no valid %s", ErrNotReconcilable, k)
			}
			vals = append(vals, v)
		}
		return fmt.Sprintf(format, vals...), nil
	}
}
