package google

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"google.golang.org/api/googleapi"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Bounds of the raw batch_update tools (increment 5).
const (
	// MaxBatchRequests bounds the requests of one batch_update call.
	MaxBatchRequests = 200
	// MaxBatchBytes bounds the serialised requests of one call.
	MaxBatchBytes = 1 << 20
)

// ToolBatchUpdate is the raw batch_update tool of Docs, Sheets, Slides
// and Forms.
const ToolBatchUpdate = "batch_update"

// requestKindRE is the shape of a request's kind (its one top-level key:
// insertText, addSheet, createSlide, createItem, ...).
var requestKindRE = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9]*$`)

// batchAPI describes one API's batchUpdate method: the app, the id
// argument, the default host and the path around the id, the write
// scope and whether the method takes a writeControl.
type batchAPI struct {
	app, idArg, noun string
	host, prefix     string
	scope            string
	writeControl     bool
	reference        string
}

var (
	docsBatch = batchAPI{app: AppDocs, idArg: "document_id", noun: "Google Doc", host: "https://docs.googleapis.com/", prefix: "v1/documents/",
		scope: ScopeDocuments, writeControl: true, reference: "https://developers.google.com/workspace/docs/api/reference/rest/v1/documents/request"}
	sheetsBatch = batchAPI{app: AppSheets, idArg: "spreadsheet_id", noun: "Google Sheet", host: "https://sheets.googleapis.com/", prefix: "v4/spreadsheets/",
		scope: ScopeSpreadsheets, reference: "https://developers.google.com/workspace/sheets/api/reference/rest/v4/spreadsheets/request"}
	slidesBatch = batchAPI{app: AppSlides, idArg: "presentation_id", noun: "Google Slides presentation", host: "https://slides.googleapis.com/", prefix: "v1/presentations/",
		scope: ScopePresentations, writeControl: true, reference: "https://developers.google.com/workspace/slides/api/reference/rest/v1/presentations/request"}
	formsBatch = batchAPI{app: AppForms, idArg: "form_id", noun: "Google Form", host: "https://forms.googleapis.com/", prefix: "v1/forms/",
		scope: ScopeFormsBody, writeControl: true, reference: "https://developers.google.com/workspace/forms/api/reference/rest/v1/forms/batchUpdate#request"}
)

// BatchUpdated is a batch_update's result: the target's id (one of the
// four), the requests sent, Google's replies (one per request, in order;
// trailing ones dropped to fit the bounds: truncated) and the revision
// the write produced (writeControl.requiredRevisionId), when Google
// gives one.
type BatchUpdated struct {
	DocumentID     string            `json:"document_id,omitempty"`
	SpreadsheetID  string            `json:"spreadsheet_id,omitempty"`
	PresentationID string            `json:"presentation_id,omitempty"`
	FormID         string            `json:"form_id,omitempty"`
	RequestCount   int               `json:"request_count"`
	RequestKinds   []string          `json:"request_kinds"`
	RevisionID     string            `json:"revision_id,omitempty"`
	Replies        []json.RawMessage `json:"replies"`
	Truncated      bool              `json:"truncated,omitempty"`
}

// targetID returns the result's id whatever the API.
func (b BatchUpdated) targetID() string {
	return b.DocumentID + b.SpreadsheetID + b.PresentationID + b.FormID
}

// setTarget sets the id field named by idArg.
func (b *BatchUpdated) setTarget(idArg, id string) {
	switch idArg {
	case "document_id":
		b.DocumentID = id
	case "spreadsheet_id":
		b.SpreadsheetID = id
	case "presentation_id":
		b.PresentationID = id
	case "form_id":
		b.FormID = id
	}
}

// batchTool declares api's raw batch_update tool.
func (c *Connector) batchTool(api batchAPI) connectors.Tool {
	props := []property{
		{api.idArg, "string", "The " + api.noun + "'s id (from drive.search, or the id in its URL).", nil},
		{"requests", "objects", fmt.Sprintf("The API's batchUpdate requests, sent as given (at most %d): each an object with one key naming the request "+
			"kind and its parameters (see %s).", MaxBatchRequests, api.reference), nil},
	}
	if api.writeControl {
		props = append(props, property{"required_revision_id", "string", "Apply only if the " + api.noun + " is still at this revision " +
			"(revision_id of a previous read or write); Google refuses the batch otherwise.", nil})
	}
	idArg := api.idArg
	return connectors.Tool{
		App: api.app, Name: ToolBatchUpdate, Kind: connectors.KindWrite,
		Description: fmt.Sprintf("Apply raw batchUpdate requests to a %s, atomically (all or none), as the API reference describes them (%s). "+
			"Returns Google's replies (one per request, in order) and the new revision_id. Cannot be verified after an unknown outcome: check the %s.",
			api.noun, api.reference, api.noun),
		InputSchema:    objectSchema(props, []string{api.idArg, "requests"}),
		RequiredScopes: []string{api.scope},
		ResourceIdentity: func(args map[string]any) map[string]string {
			out := map[string]string{}
			if id, _ := args[idArg].(string); strings.TrimSpace(id) != "" {
				out[idArg] = strings.TrimSpace(id)
			}
			if kinds := requestKinds(args["requests"]); len(kinds) > 0 {
				out["request_kinds"] = strings.Join(kinds, ",")
			}
			return out
		},
		Reconcile: connectors.Reconciliation{Kind: connectors.ReconcileNone},
		ResultIDs: func(res connectors.Result) map[string]string {
			if v, ok := res.Content.(BatchUpdated); ok && v.targetID() != "" {
				return map[string]string{idArg: v.targetID()}
			}
			return nil
		},
		Bounds: c.singleBounds(),
	}
}

// batchHandler runs api's raw batch_update.
func (c *Connector) batchHandler(api batchAPI) handler {
	return func(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
		id, err := idArg(call.Args, api.idArg)
		if err != nil {
			return connectors.Result{}, err
		}
		reqs, kinds, err := batchRequests(call.Args)
		if err != nil {
			return connectors.Result{}, err
		}
		body := map[string]any{"requests": reqs}
		if api.writeControl {
			rev, err := idArgDefault(call.Args, "required_revision_id", "")
			if err != nil {
				return connectors.Result{}, err
			}
			if rev != "" {
				body["writeControl"] = map[string]string{"requiredRevisionId": rev}
			}
		}
		out := BatchUpdated{RequestCount: len(reqs), RequestKinds: kinds}
		out.setTarget(api.idArg, id)
		return c.runBatch(ctx, cl, api, id, body, out)
	}
}

// runBatch posts a batchUpdate body and fits Google's replies into out.
func (c *Connector) runBatch(ctx context.Context, cl *client, api batchAPI, id string, body any, out BatchUpdated) (connectors.Result, error) {
	if err := cl.authenticate(ctx); err != nil {
		return connectors.Result{}, err
	}
	var resp struct {
		Replies      []json.RawMessage `json:"replies"`
		WriteControl *struct {
			RequiredRevisionID string `json:"requiredRevisionId"`
		} `json:"writeControl"`
	}
	answered, err := cl.postJSON(ctx, api.host, api.prefix+url.PathEscape(id)+":batchUpdate", body, &resp)
	if !answered {
		if err := classifyWrite("batch update", err); err != nil {
			return connectors.Result{}, err
		}
	}
	// A 200 whose body could not be read still applied the batch: the
	// result says so without replies.
	if err != nil {
		out.Truncated = true
	}
	if resp.WriteControl != nil {
		out.RevisionID = resp.WriteControl.RequiredRevisionID
	}
	out.Replies = resp.Replies
	if out.Replies == nil {
		out.Replies = []json.RawMessage{}
	}
	for encodedSize(out) > c.bounds.MaxResultBytes && len(out.Replies) > 0 {
		out.Replies = out.Replies[:len(out.Replies)-1]
		out.Truncated = true
	}
	return connectors.Result{Content: out}, nil
}

// batchRequests reads the requests argument: 1 to MaxBatchRequests
// objects, each with exactly one key (the request kind) whose value is an
// object, at most MaxBatchBytes serialised. It returns them as raw JSON
// (sent untouched: Google validates the parameters) and the sorted,
// unique kinds.
func batchRequests(args map[string]any) ([]json.RawMessage, []string, error) {
	var items []any
	switch v := args["requests"].(type) {
	case nil:
		return nil, nil, invalid("requests is required")
	case []any:
		items = v
	case []map[string]any:
		for _, m := range v {
			items = append(items, m)
		}
	default:
		return nil, nil, invalid("requests must be an array of request objects")
	}
	if len(items) == 0 {
		return nil, nil, invalid("requests must hold at least one request")
	}
	if len(items) > MaxBatchRequests {
		return nil, nil, invalid("requests holds %d requests; at most %d per call", len(items), MaxBatchRequests)
	}
	out := make([]json.RawMessage, 0, len(items))
	total := 0
	var kinds []string
	for i, item := range items {
		m, ok := item.(map[string]any)
		if !ok || len(m) != 1 {
			return nil, nil, invalid("requests[%d] must be an object with exactly one key, the request kind (insertText, addSheet, ...)", i)
		}
		for kind, params := range m {
			if !requestKindRE.MatchString(kind) {
				return nil, nil, invalid("requests[%d]: %q is not a request kind", i, kind)
			}
			if _, ok := params.(map[string]any); !ok {
				return nil, nil, invalid("requests[%d].%s must be an object", i, kind)
			}
			if !slices.Contains(kinds, kind) {
				kinds = append(kinds, kind)
			}
		}
		raw, err := json.Marshal(m)
		if err != nil {
			return nil, nil, invalid("requests[%d] cannot be encoded: %v", i, err)
		}
		if total += len(raw); total > MaxBatchBytes {
			return nil, nil, invalid("requests are larger than %d bytes", MaxBatchBytes)
		}
		out = append(out, raw)
	}
	slices.Sort(kinds)
	return out, kinds, nil
}

// requestKinds lists the sorted, unique request kinds of a requests
// argument, tolerating anything malformed (the resource identity is
// computed before validation).
func requestKinds(v any) []string {
	items, _ := v.([]any)
	if items == nil {
		if ms, ok := v.([]map[string]any); ok {
			for _, m := range ms {
				items = append(items, m)
			}
		}
	}
	var kinds []string
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok || len(m) != 1 {
			continue
		}
		for kind := range m {
			if requestKindRE.MatchString(kind) && !slices.Contains(kinds, kind) {
				kinds = append(kinds, kind)
			}
		}
	}
	slices.Sort(kinds)
	return kinds
}

// postJSON posts body as JSON to path on host (BaseURL instead, when
// set) with the call's authenticated client (authenticate first) and
// decodes the answer into out. answered reports that Google answered
// 2xx: the write was applied, and a non-nil err then only means the
// answer could not be read. Otherwise err is the request's error (a
// *googleapi.Error for a Google answer) for classifyWrite.
func (cl *client) postJSON(ctx context.Context, host, path string, body, out any) (answered bool, err error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return false, invalid("the request cannot be encoded: %v", err)
	}
	base := host
	if cl.base != "" {
		base = cl.base
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, bytes.NewReader(raw))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)
	res, err := cl.http.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = res.Body.Close() }()
	if err := googleapi.CheckResponse(res); err != nil {
		return false, err
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, MaxDownloadResultBytes))
	if err != nil {
		return true, err
	}
	return true, json.Unmarshal(b, out)
}

// Increment 5 write tools of Docs, Sheets, Slides and Forms; later
// helpers append to these lists.

func (c *Connector) docsFullWriteTools() []connectors.Tool {
	return []connectors.Tool{c.batchTool(docsBatch)}
}

func (c *Connector) docsFullWriteHandlers() map[string]handler {
	return map[string]handler{ToolBatchUpdate: c.batchHandler(docsBatch)}
}

func (c *Connector) sheetsFullWriteTools() []connectors.Tool {
	return []connectors.Tool{c.batchTool(sheetsBatch)}
}

func (c *Connector) sheetsFullWriteHandlers() map[string]handler {
	return map[string]handler{ToolBatchUpdate: c.batchHandler(sheetsBatch)}
}

func (c *Connector) slidesFullWriteTools() []connectors.Tool {
	return []connectors.Tool{c.batchTool(slidesBatch)}
}

func (c *Connector) slidesFullWriteHandlers() map[string]handler {
	return map[string]handler{ToolBatchUpdate: c.batchHandler(slidesBatch)}
}

func (c *Connector) formsWriteTools() []connectors.Tool {
	return []connectors.Tool{c.batchTool(formsBatch)}
}

func (c *Connector) formsWriteHandlers() map[string]handler {
	return map[string]handler{ToolBatchUpdate: c.batchHandler(formsBatch)}
}
