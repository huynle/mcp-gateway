package slack

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Canvas and Slack List tools. slack-go v0.29 wraps neither
// canvases.getContent, a canvas created in a channel, a canvas rename,
// nor any slackLists.* method, so they run through webAPI (JSON, the
// token as a bearer header).
const (
	ToolReadCanvas     = "read_canvas"
	ToolCreateCanvas   = "create_canvas"
	ToolUpdateCanvas   = "update_canvas"
	ToolReadList       = "read_list"
	ToolCreateList     = "create_list"
	ToolUpdateList     = "update_list"
	ToolAddListItem    = "add_list_item"
	ToolUpdateListItem = "update_list_item"
)

// Slack user-token scopes of canvases and lists.
const (
	ScopeCanvasesRead  = "canvases:read"
	ScopeCanvasesWrite = "canvases:write"
	ScopeListsRead     = "lists:read"
	ScopeListsWrite    = "lists:write"
)

// MaxCanvasMarkdown bounds the markdown of one canvas create or edit
// (Slack's own limit: 1 MiB).
const MaxCanvasMarkdown = 1 << 20

// MaxListFields bounds the fields of one add_list_item / update_list_item.
const MaxListFields = 50

// MaxListColumns bounds the columns create_list defines.
const MaxListColumns = 30

var (
	itemIDRE    = regexp.MustCompile(`^Rec[A-Za-z0-9]{4,}$`)
	sectionIDRE = regexp.MustCompile(`^[A-Za-z0-9:_-]{1,200}$`)
	dateRE      = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	slugRE      = regexp.MustCompile(`[^a-z0-9]+`)
)

// canvasOps are update_canvas's operations; the value says what it needs:
// markdown, a section, or both.
var canvasOps = map[string]struct{ markdown, section, sectionOptional bool }{
	"insert_at_start": {markdown: true},
	"insert_at_end":   {markdown: true},
	"insert_after":    {markdown: true, section: true},
	"insert_before":   {markdown: true, section: true},
	"replace":         {markdown: true, sectionOptional: true},
	"delete":          {section: true},
	"rename":          {markdown: true},
}

// listColumnTypes are the column types create_list defines.
var listColumnTypes = []string{"text", "rich_text", "number", "select", "multi_select", "date", "user", "channel", "checkbox", "email", "phone", "link", "rating", "vote", "attachment", "canvas", "message"}

// choiceColors are assigned to select choices in turn.
var choiceColors = []string{"blue", "green", "yellow", "red", "purple", "orange", "cyan", "pink", "indigo", "gray", "brown"}

// CanvasContent is read_canvas's result.
type CanvasContent struct {
	Canvas    string `json:"canvas"`
	Markdown  string `json:"markdown"`
	Truncated bool   `json:"truncated,omitempty"`
}

// CanvasChange is the result of create_canvas and update_canvas.
type CanvasChange struct {
	Canvas  string `json:"canvas"`
	Channel string `json:"channel,omitempty"`
	Action  string `json:"action"`
}

// ListColumn is one column of a Slack List. Choices are value=label.
type ListColumn struct {
	ID      string   `json:"id"`
	Key     string   `json:"key,omitempty"`
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	Primary bool     `json:"primary,omitempty"`
	Choices []string `json:"choices,omitempty"`
}

// ListField is one cell of an item: the column, its plain text and value.
type ListField struct {
	Column string `json:"column"`
	Key    string `json:"key,omitempty"`
	Text   string `json:"text,omitempty"`
	Value  any    `json:"value,omitempty"`
}

// ListItem is one row of a Slack List.
type ListItem struct {
	ID         string      `json:"id"`
	ParentItem string      `json:"parent_item,omitempty"`
	Created    string      `json:"created,omitempty"`
	CreatedBy  string      `json:"created_by,omitempty"`
	UpdatedBy  string      `json:"updated_by,omitempty"`
	Archived   bool        `json:"archived,omitempty"`
	Fields     []ListField `json:"fields"`
}

// ListPage is read_list's result.
type ListPage struct {
	List       ListInfo   `json:"list"`
	Items      []ListItem `json:"items"`
	NextCursor string     `json:"next_cursor,omitempty"`
	HasMore    bool       `json:"has_more"`
	Limit      int        `json:"limit"`
	Truncated  bool       `json:"truncated,omitempty"`
}

// ListInfo is a list's id, title and columns.
type ListInfo struct {
	ID      string       `json:"id"`
	Title   string       `json:"title,omitempty"`
	Columns []ListColumn `json:"columns,omitempty"`
}

// ListChange is the result of the list writes.
type ListChange struct {
	List   string `json:"list"`
	Item   string `json:"item,omitempty"`
	Action string `json:"action"`
}

// --- wire shapes -------------------------------------------------------------------

type wireColumn struct {
	ID        string `json:"id"`
	Key       string `json:"key"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	IsPrimary bool   `json:"is_primary_column"`
	Options   struct {
		Format  string `json:"format"`
		Choices []struct {
			Value string `json:"value"`
			Label string `json:"label"`
		} `json:"choices"`
	} `json:"options"`
}

type wireItems struct {
	List *struct {
		ID           string `json:"id"`
		Title        string `json:"title"`
		Name         string `json:"name"`
		ListMetadata struct {
			Schema []wireColumn `json:"schema"`
		} `json:"list_metadata"`
	} `json:"list"`
	Items []struct {
		ID             string `json:"id"`
		DateCreated    int64  `json:"date_created"`
		CreatedBy      string `json:"created_by"`
		UpdatedBy      string `json:"updated_by"`
		ParentRecordID string `json:"parent_record_id"`
		Archived       bool   `json:"archived"`
		Fields         []struct {
			Key      string          `json:"key"`
			ColumnID string          `json:"column_id"`
			Text     string          `json:"text"`
			Value    json.RawMessage `json:"value"`
		} `json:"fields"`
	} `json:"items"`
	ResponseMetadata struct {
		NextCursor string `json:"next_cursor"`
	} `json:"response_metadata"`
}

// --- declarations -------------------------------------------------------------------

func (c *Connector) docTools() []connectors.Tool {
	single := connectors.Bounds{MaxResultBytes: c.bounds.MaxResultBytes}
	paged := connectors.Bounds{MaxPageSize: c.bounds.MaxPageSize, MaxResultBytes: c.bounds.MaxResultBytes}
	none := connectors.Reconciliation{Kind: connectors.ReconcileNone}
	canvasProp := property{"canvas", "string", "The canvas id (F...), from search_files or a channel's canvas tab.", nil}
	listProp := property{"list", "string", "The list id (F...), from search_files or the list's link.", nil}
	fieldsProp := property{"fields", "object", "Cell values by column (its id Col..., key or display name): text, a number, true/false for a checkbox, " +
		"a YYYY-MM-DD date, user ids (U...) or channel ids, a select option's value or label; an array for several.", nil}
	return []connectors.Tool{
		{
			App: App, Name: ToolReadCanvas, Kind: connectors.KindRead,
			Description:    "Read a Slack canvas as markdown (the format create_canvas and update_canvas accept). Long canvases are cut to the result bound (truncated).",
			InputSchema:    objectSchema([]property{canvasProp}, []string{"canvas"}),
			RequiredScopes: []string{ScopeCanvasesRead}, ResourceIdentity: keyIdentity("canvas"), Bounds: single,
		},
		{
			App: App, Name: ToolCreateCanvas, Kind: connectors.KindWrite,
			Description: "Create a Slack canvas owned by the connected user, optionally with a title, markdown content and as a tab of a channel. " +
				"Returns the canvas id.",
			InputSchema: objectSchema([]property{
				{"title", "string", "Optional canvas title.", nil},
				{"markdown", "string", "Optional content in canvas markdown (headings, lists, checklists, tables, links, @mentions); at most 1 MiB.", nil},
				{"channel", "string", "Optional channel id or name to add the canvas to as a tab.", nil},
			}, nil),
			RequiredScopes: []string{ScopeCanvasesWrite}, ResourceIdentity: identity(), Reconcile: none, ResultIDs: canvasIDs, Bounds: single,
		},
		{
			App: App, Name: ToolUpdateCanvas, Kind: connectors.KindWrite,
			Description: "Edit a Slack canvas with one operation: insert_at_start / insert_at_end (markdown), insert_after / insert_before " +
				"(markdown and a section), replace (markdown; a section, or the whole canvas without one), delete (a section) or rename " +
				"(markdown is the new title). Name a section by section_id or by section_text (text it contains; exactly one section must match).",
			InputSchema: objectSchema([]property{
				canvasProp,
				{"operation", "string", "The edit to apply.", []string{"insert_at_start", "insert_at_end", "insert_after", "insert_before", "replace", "delete", "rename"}},
				{"markdown", "string", "The content to insert or replace with (canvas markdown, at most 1 MiB), or the new title for rename.", nil},
				{"section_id", "string", "The target section's id (from a previous lookup).", nil},
				{"section_text", "string", "Text the target section contains; looked up with canvases.sections.lookup.", nil},
			}, []string{"canvas", "operation"}),
			RequiredScopes: []string{ScopeCanvasesWrite}, ResourceIdentity: canvasEditIdentity, Reconcile: none, ResultIDs: canvasIDs, Bounds: single,
		},
		{
			App: App, Name: ToolReadList, Kind: connectors.KindRead,
			Description: "Read a Slack List: its title and columns (id, key, name, type, select choices as value=label) and a page of items " +
				"with their cells (column id, key, plain text, value). Cursor paginated (next_cursor).",
			InputSchema: objectSchema([]property{listProp, limitProperty, cursorProperty,
				{"archived", "boolean", "Return archived items instead of current ones. Default: false.", nil}}, []string{"list"}),
			RequiredScopes: []string{ScopeListsRead}, ResourceIdentity: keyIdentity("list"), Bounds: paged,
		},
		{
			App: App, Name: ToolCreateList, Kind: connectors.KindWrite,
			Description: fmt.Sprintf("Create a Slack List owned by the connected user: a name, an optional description, up to %d columns "+
				"(the first must be text: it is the primary column) and todo_mode (adds Completed, Assignee and Due date). Returns the list id.", MaxListColumns),
			InputSchema: patchSchema(objectSchema([]property{
				{"name", "string", "The list's name.", nil},
				{"description", "string", "Optional plain-text description.", nil},
				{"columns", "array", "Optional columns: objects with name, type and, for select / multi_select, choices (labels).", nil},
				{"todo_mode", "boolean", "Track tasks (Completed, Assignee, Due date columns). Default: false.", nil},
			}, []string{"name"}), "columns", map[string]any{
				"type": "array", "minItems": 1, "maxItems": MaxListColumns,
				"description": "Optional columns: objects with name, type and, for select / multi_select, choices (labels). The first column must be text.",
				"items": map[string]any{"type": "object", "additionalProperties": false, "required": []string{"name", "type"}, "properties": map[string]any{
					"name":    map[string]any{"type": "string", "description": "Column name."},
					"type":    map[string]any{"type": "string", "enum": listColumnTypes, "description": "Column type."},
					"key":     map[string]any{"type": "string", "description": "Optional column key (default: from the name)."},
					"choices": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "maxItems": 100, "description": "Option labels of a select column."},
				}},
			}),
			RequiredScopes: []string{ScopeListsWrite}, ResourceIdentity: func(map[string]any) map[string]string { return map[string]string{} },
			Reconcile: none, ResultIDs: listIDs, Bounds: single,
		},
		{
			App: App, Name: ToolUpdateList, Kind: connectors.KindWrite,
			Description: "Rename a Slack List, change its description or turn todo_mode on or off (at least one).",
			InputSchema: objectSchema([]property{listProp,
				{"name", "string", "The new name.", nil},
				{"description", "string", "The new plain-text description.", nil},
				{"todo_mode", "boolean", "Turn task tracking on or off.", nil}}, []string{"list"}),
			RequiredScopes: []string{ScopeListsWrite}, ResourceIdentity: keyIdentity("list"), Reconcile: none, ResultIDs: listIDs, Bounds: single,
		},
		{
			App: App, Name: ToolAddListItem, Kind: connectors.KindWrite,
			Description: fmt.Sprintf("Add an item (row) to a Slack List with cell values by column (at most %d); with parent_item, as a subtask. "+
				"The list's columns are read first to convert the values. Returns the item id.", MaxListFields),
			InputSchema: patchSchema(objectSchema([]property{listProp, fieldsProp,
				{"parent_item", "string", "Optional parent item id (Rec...) to add a subtask.", nil}}, []string{"list", "fields"}), "fields", fieldsSchema(fieldsProp.Description)),
			RequiredScopes: []string{ScopeListsRead, ScopeListsWrite}, ResourceIdentity: keyIdentity("list"), Reconcile: none, ResultIDs: listIDs, Bounds: single,
		},
		{
			App: App, Name: ToolUpdateListItem, Kind: connectors.KindWrite,
			Description: fmt.Sprintf("Update cells of one Slack List item (at most %d), by column id, key or name. The list's columns are read first to convert the values.", MaxListFields),
			InputSchema: patchSchema(objectSchema([]property{listProp,
				{"item", "string", "The item id (Rec...), from read_list.", nil}, fieldsProp}, []string{"list", "item", "fields"}), "fields", fieldsSchema(fieldsProp.Description)),
			RequiredScopes: []string{ScopeListsRead, ScopeListsWrite}, ResourceIdentity: keyIdentity("list", "item"), Reconcile: none, ResultIDs: listIDs, Bounds: single,
		},
	}
}

func fieldsSchema(desc string) map[string]any {
	return map[string]any{
		"type": "object", "description": desc, "minProperties": 1, "maxProperties": MaxListFields,
		"additionalProperties": map[string]any{"type": []string{"string", "number", "boolean", "array"}, "items": map[string]any{"type": "string"}},
	}
}

// patchSchema replaces one property's schema.
func patchSchema(raw json.RawMessage, name string, prop map[string]any) json.RawMessage {
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		panic(err)
	}
	schema["properties"].(map[string]any)[name] = prop
	out, err := json.Marshal(schema)
	if err != nil {
		panic(err)
	}
	return out
}

func (c *Connector) docReadHandlers() map[string]webHandler {
	return map[string]webHandler{ToolReadCanvas: c.readCanvas, ToolReadList: c.readList}
}

func (c *Connector) docWriteHandlers() map[string]webHandler {
	return map[string]webHandler{
		ToolCreateCanvas: c.createCanvas, ToolUpdateCanvas: c.updateCanvas,
		ToolCreateList: c.createList, ToolUpdateList: c.updateList, ToolAddListItem: c.addListItem, ToolUpdateListItem: c.updateListItem,
	}
}

// --- identity and ids --------------------------------------------------------------

// keyIdentity records the canvas / list / item ids among keys.
func keyIdentity(keys ...string) func(map[string]any) map[string]string {
	return func(args map[string]any) map[string]string {
		out := map[string]string{}
		for _, k := range keys {
			v, _ := args[k].(string)
			v = strings.TrimSpace(v)
			switch {
			case k == "item" && itemIDRE.MatchString(v):
				out[k] = v
			case k != "item" && fileIDRE.MatchString(strings.ToUpper(v)):
				out[k] = strings.ToUpper(v)
			}
		}
		return out
	}
}

func canvasEditIdentity(args map[string]any) map[string]string {
	out := keyIdentity("canvas")(args)
	if op, _ := args["operation"].(string); canvasOps[op] != (struct{ markdown, section, sectionOptional bool }{}) {
		out["operation"] = op
	}
	return out
}

func canvasIDs(res connectors.Result) map[string]string {
	v, ok := res.Content.(CanvasChange)
	if !ok || v.Canvas == "" {
		return nil
	}
	return map[string]string{"canvas": v.Canvas}
}

func listIDs(res connectors.Result) map[string]string {
	v, ok := res.Content.(ListChange)
	if !ok || v.List == "" {
		return nil
	}
	out := map[string]string{"list": v.List}
	if v.Item != "" {
		out["item"] = v.Item
	}
	return out
}

// --- helpers -------------------------------------------------------------------------

func markdownDoc(md string) map[string]string {
	return map[string]string{"type": "markdown", "markdown": md}
}

// richText is a Block Kit rich_text block holding plain text.
func richText(text string) []any {
	return []any{map[string]any{"type": "rich_text", "elements": []any{
		map[string]any{"type": "rich_text_section", "elements": []any{map[string]any{"type": "text", "text": text}}},
	}}}
}

func markdownArg(args map[string]any) (string, bool, error) {
	v, ok := args["markdown"]
	if !ok || v == nil {
		return "", false, nil
	}
	s, ok := v.(string)
	if !ok {
		return "", false, invalid("markdown must be a string")
	}
	if len(s) > MaxCanvasMarkdown {
		return "", false, invalid("markdown is larger than %d bytes (Slack's canvas limit)", MaxCanvasMarkdown)
	}
	return s, true, nil
}

func slug(s string) string {
	return strings.Trim(slugRE.ReplaceAllString(strings.ToLower(strings.TrimSpace(s)), "_"), "_")
}

// --- canvases ------------------------------------------------------------------------

func (c *Connector) readCanvas(ctx context.Context, web *webAPI, call connectors.Call) (connectors.Result, error) {
	id, err := fileArg(call.Args, "canvas")
	if err != nil {
		return connectors.Result{}, err
	}
	var resp struct {
		Content string `json:"content"`
	}
	if err := classify("read canvas", web.call(ctx, "canvases.getContent", map[string]string{"canvas_id": id, "content_type": "markdown"}, &resp)); err != nil {
		return connectors.Result{}, err
	}
	out := CanvasContent{Canvas: id, Markdown: resp.Content}
	if size := encodedSize(out); size > c.bounds.MaxResultBytes {
		out.Truncated = true
		cut := max(0, len(out.Markdown)-(size-c.bounds.MaxResultBytes)-64)
		for cut > 0 && !utf8.RuneStart(out.Markdown[cut]) {
			cut--
		}
		out.Markdown = out.Markdown[:cut]
		for encodedSize(out) > c.bounds.MaxResultBytes && out.Markdown != "" {
			_, n := utf8.DecodeLastRuneInString(out.Markdown)
			out.Markdown = out.Markdown[:len(out.Markdown)-n]
		}
	}
	return connectors.Result{Content: out, Partial: out.Truncated, Empty: resp.Content == ""}, nil
}

func (c *Connector) createCanvas(ctx context.Context, web *webAPI, call connectors.Call) (connectors.Result, error) {
	body := map[string]any{}
	title, err := optionalString(call.Args, "title")
	if err != nil {
		return connectors.Result{}, err
	}
	if title = strings.TrimSpace(title); title != "" {
		body["title"] = title
	}
	md, ok, err := markdownArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	if ok && md != "" {
		body["document_content"] = markdownDoc(md)
	}
	channel := ""
	if raw, _ := call.Args["channel"].(string); strings.TrimSpace(raw) != "" {
		if channel, err = c.channelTarget(ctx, web.api, call.Args); err != nil {
			return connectors.Result{}, err
		}
		body["channel_id"] = channel
	}
	var resp struct {
		CanvasID string `json:"canvas_id"`
	}
	if err := ClassifyWrite("create canvas", web.call(ctx, "canvases.create", body, &resp)); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: CanvasChange{Canvas: resp.CanvasID, Channel: channel, Action: "created"}}, nil
}

func (c *Connector) updateCanvas(ctx context.Context, web *webAPI, call connectors.Call) (connectors.Result, error) {
	id, err := fileArg(call.Args, "canvas")
	if err != nil {
		return connectors.Result{}, err
	}
	op, _ := call.Args["operation"].(string)
	need, known := canvasOps[op]
	if !known {
		return connectors.Result{}, invalid("operation must be one of insert_at_start, insert_at_end, insert_after, insert_before, replace, delete, rename")
	}
	md, hasMD, err := markdownArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	sectionID, err := optionalString(call.Args, "section_id")
	if err != nil {
		return connectors.Result{}, err
	}
	sectionText, err := optionalString(call.Args, "section_text")
	if err != nil {
		return connectors.Result{}, err
	}
	sectionID, sectionText = strings.TrimSpace(sectionID), strings.TrimSpace(sectionText)
	hasSection := sectionID != "" || sectionText != ""
	switch {
	case need.markdown && (!hasMD || strings.TrimSpace(md) == ""):
		return connectors.Result{}, invalid("%s needs markdown", op)
	case !need.markdown && hasMD:
		return connectors.Result{}, invalid("%s takes no markdown", op)
	case need.section && !hasSection:
		return connectors.Result{}, invalid("%s needs section_id or section_text", op)
	case !need.section && !need.sectionOptional && hasSection:
		return connectors.Result{}, invalid("%s takes no section", op)
	case sectionID != "" && sectionText != "":
		return connectors.Result{}, invalid("pass section_id or section_text, not both")
	case sectionID != "" && !sectionIDRE.MatchString(sectionID):
		return connectors.Result{}, invalid("section_id is not a canvas section id")
	}
	if sectionText != "" {
		var resp struct {
			Sections []struct {
				ID string `json:"id"`
			} `json:"sections"`
		}
		body := map[string]any{"canvas_id": id, "criteria": map[string]string{"contains_text": sectionText}}
		if err := classify("look up canvas section", web.call(ctx, "canvases.sections.lookup", body, &resp)); err != nil {
			return connectors.Result{}, err
		}
		switch len(resp.Sections) {
		case 0:
			return connectors.Result{}, &Error{Class: ClassNotFound, Message: "no canvas section contains section_text; nothing was changed"}
		case 1:
			sectionID = resp.Sections[0].ID
		default:
			return connectors.Result{}, invalid("%d canvas sections contain section_text; pass a more specific text or a section_id (nothing was changed)", len(resp.Sections))
		}
	}
	change := map[string]any{"operation": op}
	if sectionID != "" {
		change["section_id"] = sectionID
	}
	switch {
	case op == "rename":
		change["title_content"] = markdownDoc(md)
	case need.markdown:
		change["document_content"] = markdownDoc(md)
	}
	if err := ClassifyWrite("update canvas", web.call(ctx, "canvases.edit", map[string]any{"canvas_id": id, "changes": []any{change}}, nil)); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: CanvasChange{Canvas: id, Action: op}}, nil
}

// --- lists -----------------------------------------------------------------------------

func toListInfo(id string, w *wireItems) ListInfo {
	info := ListInfo{ID: id}
	if w.List == nil {
		return info
	}
	info.ID, info.Title = or(w.List.ID, id), or(w.List.Title, w.List.Name)
	for _, col := range w.List.ListMetadata.Schema {
		lc := ListColumn{ID: col.ID, Key: col.Key, Name: col.Name, Type: col.Type, Primary: col.IsPrimary}
		for _, ch := range col.Options.Choices {
			lc.Choices = append(lc.Choices, ch.Value+"="+ch.Label)
		}
		info.Columns = append(info.Columns, lc)
	}
	return info
}

func (c *Connector) readList(ctx context.Context, web *webAPI, call connectors.Call) (connectors.Result, error) {
	id, err := fileArg(call.Args, "list")
	if err != nil {
		return connectors.Result{}, err
	}
	limit, clamped, err := c.limitArg(call.Args, "limit", connectors.DefaultMaxPageSize)
	if err != nil {
		return connectors.Result{}, err
	}
	cursor, err := cursorArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	archived, err := boolArg(call.Args, "archived", false)
	if err != nil {
		return connectors.Result{}, err
	}
	body := map[string]any{"list_id": id, "limit": limit, "include_list": true}
	if cursor != "" {
		body["cursor"] = cursor
	}
	if archived {
		body["archived"] = true
	}
	var resp wireItems
	if err := classify("read list", web.call(ctx, "slackLists.items.list", body, &resp)); err != nil {
		return connectors.Result{}, err
	}
	next := resp.ResponseMetadata.NextCursor
	out := ListPage{List: toListInfo(id, &resp), Items: make([]ListItem, 0, len(resp.Items)), NextCursor: next, HasMore: next != "", Limit: limit}
	for _, it := range resp.Items {
		item := ListItem{ID: it.ID, ParentItem: it.ParentRecordID, Created: unixTime(it.DateCreated), CreatedBy: it.CreatedBy, UpdatedBy: it.UpdatedBy, Archived: it.Archived, Fields: []ListField{}}
		for _, f := range it.Fields {
			var v any
			if len(f.Value) > 0 {
				_ = json.Unmarshal(f.Value, &v)
			}
			item.Fields = append(item.Fields, ListField{Column: f.ColumnID, Key: f.Key, Text: f.Text, Value: v})
		}
		out.Items = append(out.Items, item)
	}
	out.Items, out.Truncated = fit(out.Items, c.bounds.MaxResultBytes, func(items []ListItem) any { out.Items = items; return out })
	return connectors.Result{Content: out, Partial: clamped || out.Truncated, Empty: len(out.Items) == 0}, nil
}

func (c *Connector) createList(ctx context.Context, web *webAPI, call connectors.Call) (connectors.Result, error) {
	name, err := requiredString(call.Args, "name")
	if err != nil {
		return connectors.Result{}, err
	}
	body := map[string]any{"name": name}
	if desc, err := optionalString(call.Args, "description"); err != nil {
		return connectors.Result{}, err
	} else if strings.TrimSpace(desc) != "" {
		body["description_blocks"] = richText(desc)
	}
	if v, ok := call.Args["todo_mode"]; ok && v != nil {
		b, ok := v.(bool)
		if !ok {
			return connectors.Result{}, invalid("todo_mode must be a boolean")
		}
		body["todo_mode"] = b
	}
	if v, ok := call.Args["columns"]; ok && v != nil {
		schema, err := columnsArg(v)
		if err != nil {
			return connectors.Result{}, err
		}
		body["schema"] = schema
	}
	var resp struct {
		ListID string `json:"list_id"`
	}
	if err := ClassifyWrite("create list", web.call(ctx, "slackLists.create", body, &resp)); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: ListChange{List: resp.ListID, Action: "created"}}, nil
}

// columnsArg turns create_list's columns into Slack's schema.
func columnsArg(v any) ([]any, error) {
	list, ok := v.([]any)
	if !ok || len(list) == 0 || len(list) > MaxListColumns {
		return nil, invalid("columns must be an array of 1-%d column objects", MaxListColumns)
	}
	var schema []any
	keys := map[string]bool{}
	for i, raw := range list {
		col, ok := raw.(map[string]any)
		if !ok {
			return nil, invalid("columns[%d] must be an object with name and type", i)
		}
		name, _ := col["name"].(string)
		typ, _ := col["type"].(string)
		if name = strings.TrimSpace(name); name == "" {
			return nil, invalid("columns[%d] needs a name", i)
		}
		known := false
		for _, t := range listColumnTypes {
			known = known || t == typ
		}
		if !known {
			return nil, invalid("columns[%d] type must be one of %s", i, strings.Join(listColumnTypes, ", "))
		}
		if i == 0 && typ != "text" {
			return nil, invalid("the first column is the primary column and must be text")
		}
		key, _ := col["key"].(string)
		if key = slug(key); key == "" {
			key = slug(name)
		}
		if key == "" || keys[key] {
			key = fmt.Sprintf("col_%d", i+1)
		}
		keys[key] = true
		out := map[string]any{"key": key, "name": name, "type": typ}
		if i == 0 {
			out["is_primary_column"] = true
		}
		if typ == "select" || typ == "multi_select" {
			out["type"] = "select"
			format := "single_select"
			if typ == "multi_select" {
				format = "multi_select"
			}
			choices, _ := col["choices"].([]any)
			if len(choices) == 0 || len(choices) > 100 {
				return nil, invalid("columns[%d] (%s) needs 1-100 choices", i, typ)
			}
			var opts []any
			for j, ch := range choices {
				label, _ := ch.(string)
				if strings.TrimSpace(label) == "" {
					return nil, invalid("columns[%d] choices must be non-empty labels", i)
				}
				opts = append(opts, map[string]any{"value": or(slug(label), fmt.Sprintf("opt_%d", j+1)), "label": strings.TrimSpace(label), "color": choiceColors[j%len(choiceColors)]})
			}
			out["options"] = map[string]any{"format": format, "choices": opts}
		} else if _, has := col["choices"]; has {
			return nil, invalid("columns[%d]: choices apply only to select and multi_select", i)
		}
		schema = append(schema, out)
	}
	return schema, nil
}

func (c *Connector) updateList(ctx context.Context, web *webAPI, call connectors.Call) (connectors.Result, error) {
	id, err := fileArg(call.Args, "list")
	if err != nil {
		return connectors.Result{}, err
	}
	body := map[string]any{"id": id}
	if name, err := optionalString(call.Args, "name"); err != nil {
		return connectors.Result{}, err
	} else if strings.TrimSpace(name) != "" {
		body["name"] = strings.TrimSpace(name)
	}
	if desc, err := optionalString(call.Args, "description"); err != nil {
		return connectors.Result{}, err
	} else if _, given := call.Args["description"]; given && call.Args["description"] != nil {
		body["description_blocks"] = richText(desc)
	}
	if v, ok := call.Args["todo_mode"]; ok && v != nil {
		b, ok := v.(bool)
		if !ok {
			return connectors.Result{}, invalid("todo_mode must be a boolean")
		}
		body["todo_mode"] = b
	}
	if len(body) == 1 {
		return connectors.Result{}, invalid("give at least one of name, description, todo_mode")
	}
	if err := ClassifyWrite("update list", web.call(ctx, "slackLists.update", body, nil)); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: ListChange{List: id, Action: "updated"}}, nil
}

// listColumns reads the list's schema (one item and the list).
func listColumns(ctx context.Context, web *webAPI, id string) ([]wireColumn, error) {
	var resp wireItems
	if err := classify("read list columns", web.call(ctx, "slackLists.items.list", map[string]any{"list_id": id, "limit": 1, "include_list": true}, &resp)); err != nil {
		return nil, err
	}
	if resp.List == nil || len(resp.List.ListMetadata.Schema) == 0 {
		return nil, &Error{Class: ClassVendorError, Message: "read list columns: Slack returned no column schema; nothing was changed"}
	}
	return resp.List.ListMetadata.Schema, nil
}

// cellsArg converts the fields argument to typed cells against the
// list's columns (column_id plus the type's value key).
func cellsArg(args map[string]any, cols []wireColumn) ([]map[string]any, error) {
	fields, ok := args["fields"].(map[string]any)
	if !ok || len(fields) == 0 {
		return nil, invalid("fields is required: an object of column -> value")
	}
	if len(fields) > MaxListFields {
		return nil, invalid("fields: at most %d per call", MaxListFields)
	}
	var cells []map[string]any
	for name, v := range fields {
		col := findColumn(cols, name)
		if col == nil {
			var names []string
			for _, c := range cols {
				names = append(names, c.Name)
			}
			return nil, invalid("column %q not found; the list's columns are %s", name, strings.Join(names, ", "))
		}
		cell, err := cellValue(col, v)
		if err != nil {
			return nil, err
		}
		cell["column_id"] = col.ID
		cells = append(cells, cell)
	}
	return cells, nil
}

func findColumn(cols []wireColumn, name string) *wireColumn {
	name = strings.TrimSpace(name)
	for _, match := range []func(wireColumn) bool{
		func(c wireColumn) bool { return c.ID == name },
		func(c wireColumn) bool { return strings.EqualFold(c.Key, name) },
		func(c wireColumn) bool { return strings.EqualFold(c.Name, name) },
	} {
		for i := range cols {
			if match(cols[i]) {
				return &cols[i]
			}
		}
	}
	return nil
}

// strings of a value: a string or an array of strings.
func valueStrings(v any) ([]string, bool) {
	switch x := v.(type) {
	case string:
		return []string{strings.TrimSpace(x)}, true
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			s, ok := e.(string)
			if !ok {
				return nil, false
			}
			out = append(out, strings.TrimSpace(s))
		}
		return out, len(out) > 0
	case []string:
		return x, len(x) > 0
	}
	return nil, false
}

func cellValue(col *wireColumn, v any) (map[string]any, error) {
	bad := func(want string) error { return invalid("column %q (%s) needs %s", col.Name, col.Type, want) }
	switch col.Type {
	case "text", "rich_text":
		s, ok := v.(string)
		if !ok {
			return nil, bad("text")
		}
		return map[string]any{"rich_text": richText(s)}, nil
	case "number":
		var n float64
		switch x := v.(type) {
		case float64:
			n = x
		case int:
			n = float64(x)
		case json.Number:
			f, err := x.Float64()
			if err != nil {
				return nil, bad("a number")
			}
			n = f
		default:
			return nil, bad("a number")
		}
		return map[string]any{"number": []float64{n}}, nil
	case "select", "multi_select":
		vals, ok := valueStrings(v)
		if !ok {
			return nil, bad("an option value or label")
		}
		var out []string
		for _, s := range vals {
			found := ""
			for _, ch := range col.Options.Choices {
				if strings.EqualFold(ch.Value, s) || strings.EqualFold(ch.Label, s) {
					found = ch.Value
				}
			}
			if found == "" {
				return nil, bad(fmt.Sprintf("one of its options (got %q)", s))
			}
			out = append(out, found)
		}
		if len(out) > 1 && col.Options.Format != "multi_select" {
			return nil, bad("a single option")
		}
		return map[string]any{"select": out}, nil
	case "date", "due_date", "todo_due_date":
		vals, ok := valueStrings(v)
		if !ok || len(vals) != 1 || !dateRE.MatchString(vals[0]) {
			return nil, bad("a YYYY-MM-DD date")
		}
		if _, err := time.Parse("2006-01-02", vals[0]); err != nil {
			return nil, bad("a YYYY-MM-DD date")
		}
		return map[string]any{"date": vals}, nil
	case "user", "assignee", "todo_assignee":
		vals, ok := valueStrings(v)
		if !ok {
			return nil, bad("user ids (U...)")
		}
		var ids []string
		for _, s := range vals {
			id := parseUserRef(s)
			if id == "" {
				return nil, bad("user ids (U...)")
			}
			ids = append(ids, id)
		}
		return map[string]any{"user": ids}, nil
	case "channel":
		vals, ok := valueStrings(v)
		if !ok {
			return nil, bad("channel ids (C...)")
		}
		var ids []string
		for _, s := range vals {
			id, _ := parseChannelRef(s)
			if id == "" {
				return nil, bad("channel ids (C...)")
			}
			ids = append(ids, id)
		}
		return map[string]any{"channel": ids}, nil
	case "checkbox", "completed", "todo_completed":
		b, ok := v.(bool)
		if !ok {
			return nil, bad("true or false")
		}
		return map[string]any{"checkbox": b}, nil
	case "email", "phone":
		vals, ok := valueStrings(v)
		if !ok || (col.Type == "email" && !strings.Contains(vals[0], "@")) {
			return nil, bad("an " + col.Type)
		}
		return map[string]any{col.Type: vals}, nil
	}
	return nil, invalid("column %q has type %s, which the gateway cannot set yet (text, number, select, date, user, channel, checkbox, email, phone)", col.Name, col.Type)
}

func (c *Connector) addListItem(ctx context.Context, web *webAPI, call connectors.Call) (connectors.Result, error) {
	id, err := fileArg(call.Args, "list")
	if err != nil {
		return connectors.Result{}, err
	}
	parent, err := optionalString(call.Args, "parent_item")
	if err != nil {
		return connectors.Result{}, err
	}
	if parent = strings.TrimSpace(parent); parent != "" && !itemIDRE.MatchString(parent) {
		return connectors.Result{}, invalid("parent_item must be an item id (Rec...)")
	}
	if f, ok := call.Args["fields"].(map[string]any); !ok || len(f) == 0 {
		return connectors.Result{}, invalid("fields is required: an object of column -> value")
	}
	cols, err := listColumns(ctx, web, id)
	if err != nil {
		return connectors.Result{}, err
	}
	cells, err := cellsArg(call.Args, cols)
	if err != nil {
		return connectors.Result{}, err
	}
	body := map[string]any{"list_id": id, "initial_fields": cells}
	if parent != "" {
		body["parent_item_id"] = parent
	}
	var resp struct {
		Item struct {
			ID string `json:"id"`
		} `json:"item"`
	}
	if err := ClassifyWrite("add list item", web.call(ctx, "slackLists.items.create", body, &resp)); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: ListChange{List: id, Item: resp.Item.ID, Action: "added"}}, nil
}

func (c *Connector) updateListItem(ctx context.Context, web *webAPI, call connectors.Call) (connectors.Result, error) {
	id, err := fileArg(call.Args, "list")
	if err != nil {
		return connectors.Result{}, err
	}
	item, _ := call.Args["item"].(string)
	if item = strings.TrimSpace(item); !itemIDRE.MatchString(item) {
		return connectors.Result{}, invalid("item is required: an item id (Rec...) from read_list")
	}
	if f, ok := call.Args["fields"].(map[string]any); !ok || len(f) == 0 {
		return connectors.Result{}, invalid("fields is required: an object of column -> value")
	}
	cols, err := listColumns(ctx, web, id)
	if err != nil {
		return connectors.Result{}, err
	}
	cells, err := cellsArg(call.Args, cols)
	if err != nil {
		return connectors.Result{}, err
	}
	for _, cell := range cells {
		cell["row_id"] = item
	}
	if err := ClassifyWrite("update list item", web.call(ctx, "slackLists.items.update", map[string]any{"list_id": id, "cells": cells}, nil)); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: ListChange{List: id, Item: item, Action: "updated"}}, nil
}
