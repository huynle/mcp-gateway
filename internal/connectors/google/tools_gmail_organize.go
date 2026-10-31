package google

import (
	"context"
	"fmt"
	"net/http"
	"net/mail"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"google.golang.org/api/gmail/v1"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Increment 5 (full Gmail): label management (gmail.labels) and filter
// management (gmail.settings.basic; get_filter reads with
// gmail.readonly like list_filters).

// Gmail label and filter tool names (increment 5).
const (
	ToolCreateLabel  = "create_label"
	ToolUpdateLabel  = "update_label"
	ToolDeleteLabel  = "delete_label"
	ToolGetFilter    = "get_filter"
	ToolCreateFilter = "create_filter"
	ToolDeleteFilter = "delete_filter"
)

// MaxLabelNameChars is Gmail's limit on a label name.
const MaxLabelNameChars = 225

// Values of a label's visibilities and a filter's size comparison.
var (
	labelListVisibilities   = []string{"labelShow", "labelShowIfUnread", "labelHide"}
	messageListVisibilities = []string{"show", "hide"}
	sizeComparisons         = []string{"larger", "smaller"}
)

// colorRE is the shape of a label color (Gmail accepts only its palette;
// Google answers 400 for other colors).
var colorRE = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

// ManagedLabel is the result of create_label and update_label.
type ManagedLabel struct {
	ID                    string `json:"id"`
	Name                  string `json:"name,omitempty"`
	Type                  string `json:"type,omitempty"`
	LabelListVisibility   string `json:"label_list_visibility,omitempty"`
	MessageListVisibility string `json:"message_list_visibility,omitempty"`
	BackgroundColor       string `json:"background_color,omitempty"`
	TextColor             string `json:"text_color,omitempty"`
}

// DeletedLabel is delete_label's result.
type DeletedLabel struct {
	LabelID string `json:"label_id"`
	Deleted bool   `json:"deleted"`
}

// DeletedFilter is delete_filter's result.
type DeletedFilter struct {
	FilterID string `json:"filter_id"`
	Deleted  bool   `json:"deleted"`
}

var (
	labelIDProperty  = property{"label_id", "string", "The user label's id (from list_labels); system labels cannot be changed.", nil}
	filterIDProperty = property{"filter_id", "string", "The filter's id (from list_filters).", nil}
	labelProps       = []property{
		{"label_list_visibility", "string", "Whether the label shows in the label list: labelShow, labelShowIfUnread or labelHide.", labelListVisibilities},
		{"message_list_visibility", "string", "Whether the label shows on messages in the message list: show or hide.", messageListVisibilities},
		{"background_color", "string", "Background color as #rrggbb from Gmail's label palette (with text_color).", nil},
		{"text_color", "string", "Text color as #rrggbb from Gmail's label palette (with background_color).", nil},
	}
)

func init() {
	str := func(d string) map[string]any { return map[string]any{"type": "string", "description": d} }
	strs := func(d string) map[string]any {
		return map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": d}
	}
	schemaTypes["filter_criteria"] = map[string]any{
		"type": "object",
		"properties": map[string]any{
			"from":            str("Sender address or name to match."),
			"to":              str("Recipient (To, Cc or Bcc) to match."),
			"subject":         str("Text the subject contains."),
			"query":           str("A Gmail search query the message matches (search syntax)."),
			"negated_query":   str("A Gmail search query the message does not match."),
			"has_attachment":  map[string]any{"type": "boolean", "description": "Only messages with an attachment."},
			"exclude_chats":   map[string]any{"type": "boolean", "description": "Leave chats out."},
			"size":            map[string]any{"type": "integer", "minimum": 0, "description": "Size in bytes (with size_comparison)."},
			"size_comparison": map[string]any{"type": "string", "enum": sizeComparisons, "description": "larger or smaller than size."},
		},
		"additionalProperties": false,
	}
	schemaTypes["filter_action"] = map[string]any{
		"type": "object",
		"properties": map[string]any{
			"add_label_ids":    strs("Label ids to add (STARRED, IMPORTANT, TRASH to delete, user labels from list_labels)."),
			"remove_label_ids": strs("Label ids to remove (INBOX to skip the inbox, UNREAD to mark read, SPAM never to send to spam)."),
			"forward":          str("Forward matching mail to this address; it must already be a verified forwarding address (list_forwarding_addresses)."),
		},
		"additionalProperties": false,
	}
}

func (c *Connector) gmailOrganizeReadTools() []connectors.Tool {
	return []connectors.Tool{{
		App: AppGmail, Name: ToolGetFilter, Kind: connectors.KindRead,
		Description:      "Get one Gmail filter by id: its criteria and action, as list_filters.",
		InputSchema:      objectSchema([]property{filterIDProperty}, []string{"filter_id"}),
		RequiredScopes:   []string{ScopeGmailReadonly},
		ResourceIdentity: idIdentity("filter_id"),
		Bounds:           c.singleBounds(),
	}}
}

func (c *Connector) gmailOrganizeReadHandlers() map[string]handler {
	return map[string]handler{ToolGetFilter: c.getFilter}
}

func (c *Connector) gmailOrganizeWriteTools() []connectors.Tool {
	labelIDs := func(res connectors.Result) map[string]string {
		switch v := res.Content.(type) {
		case ManagedLabel:
			if v.ID != "" {
				return map[string]string{"label_id": v.ID}
			}
		case DeletedLabel:
			return map[string]string{"label_id": v.LabelID}
		}
		return nil
	}
	filterIDs := func(res connectors.Result) map[string]string {
		switch v := res.Content.(type) {
		case Filter:
			if v.ID != "" {
				return map[string]string{"filter_id": v.ID}
			}
		case DeletedFilter:
			return map[string]string{"filter_id": v.FilterID}
		}
		return nil
	}
	return []connectors.Tool{
		{
			App: AppGmail, Name: ToolCreateLabel, Kind: connectors.KindWrite,
			Description: fmt.Sprintf("Create a Gmail label (at most %d characters; \"Parent/Child\" nests it), optionally with its visibility and color. ", MaxLabelNameChars) +
				"Returns the new label's id for modify_labels, search and filters.",
			InputSchema:      objectSchema(append([]property{{"name", "string", "The label's name.", nil}}, labelProps...), []string{"name"}),
			RequiredScopes:   []string{ScopeGmailLabels},
			ResourceIdentity: labelIdentity,
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileNone},
			ResultIDs:        labelIDs,
			Bounds:           c.singleBounds(),
		},
		{
			App: AppGmail, Name: ToolUpdateLabel, Kind: connectors.KindWrite,
			Description:      "Rename a Gmail user label or change its visibility or color; only what is given changes.",
			InputSchema:      objectSchema(append([]property{labelIDProperty, {"name", "string", "The new name.", nil}}, labelProps...), []string{"label_id"}),
			RequiredScopes:   []string{ScopeGmailLabels},
			ResourceIdentity: labelIdentity,
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: c.checkLabelUpdated},
			ResultIDs:        labelIDs,
			Bounds:           c.singleBounds(),
		},
		{
			App: AppGmail, Name: ToolDeleteLabel, Kind: connectors.KindWrite,
			Description:      "Delete a Gmail user label: it is removed from every message and thread (the messages stay).",
			InputSchema:      objectSchema([]property{labelIDProperty}, []string{"label_id"}),
			RequiredScopes:   []string{ScopeGmailLabels},
			ResourceIdentity: idIdentity("label_id"),
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: c.checkGoneByID("label_id", c.labelExists)},
			ResultIDs:        labelIDs,
			Bounds:           c.singleBounds(),
		},
		{
			App: AppGmail, Name: ToolCreateFilter, Kind: connectors.KindWrite,
			Description: "Create a Gmail filter applied to incoming mail: criteria (from, to, subject, query, negated_query, has_attachment, " +
				"exclude_chats, size with size_comparison) and action (add_label_ids, remove_label_ids, forward to an already verified " +
				"forwarding address). Remove INBOX to skip the inbox, add TRASH to delete on arrival.",
			InputSchema: objectSchema([]property{
				{"criteria", "filter_criteria", "What incoming mail the filter matches (at least one field).", nil},
				{"action", "filter_action", "What the filter does to matching mail (at least one field).", nil},
			}, []string{"criteria", "action"}),
			RequiredScopes:   []string{ScopeGmailSettingsBasic},
			ResourceIdentity: filterIdentity,
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileNone},
			ResultIDs:        filterIDs,
			Bounds:           c.singleBounds(),
		},
		{
			App: AppGmail, Name: ToolDeleteFilter, Kind: connectors.KindWrite,
			Description:      "Delete a Gmail filter (mail already filtered keeps its labels).",
			InputSchema:      objectSchema([]property{filterIDProperty}, []string{"filter_id"}),
			RequiredScopes:   []string{ScopeGmailSettingsBasic},
			ResourceIdentity: idIdentity("filter_id"),
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: c.checkGoneByID("filter_id", c.filterExists)},
			ResultIDs:        filterIDs,
			Bounds:           c.singleBounds(),
		},
	}
}

func (c *Connector) gmailOrganizeWriteHandlers() map[string]handler {
	return map[string]handler{
		ToolCreateLabel: c.createLabel, ToolUpdateLabel: c.updateLabel, ToolDeleteLabel: c.deleteLabel,
		ToolCreateFilter: c.createFilter, ToolDeleteFilter: c.deleteFilter,
	}
}

// idIdentity is the resource identity of a tool acting on one id.
func idIdentity(name string) func(map[string]any) map[string]string {
	return func(args map[string]any) map[string]string {
		out := map[string]string{}
		if v, _ := args[name].(string); strings.TrimSpace(v) != "" {
			out[name] = strings.TrimSpace(v)
		}
		return out
	}
}

// --- labels -----------------------------------------------------------------------

// labelSettings are create_label's and update_label's validated arguments;
// nil pointers are fields not given.
type labelSettings struct {
	name, labelVis, messageVis *string
	background, text           string // both or neither, lower-case
}

func parseLabelSettings(args map[string]any) (labelSettings, error) {
	var s labelSettings
	if _, given := args["name"]; given {
		name, err := requiredString(args, "name")
		if err != nil {
			return s, invalid("name must not be blank")
		}
		if strings.ContainsAny(name, "\r\n") || utf8.RuneCountInString(name) > MaxLabelNameChars {
			return s, invalid("name must be one line of at most %d characters", MaxLabelNameChars)
		}
		s.name = &name
	}
	for _, f := range []struct {
		arg    string
		values []string
		dst    **string
	}{{"label_list_visibility", labelListVisibilities, &s.labelVis}, {"message_list_visibility", messageListVisibilities, &s.messageVis}} {
		if _, given := args[f.arg]; !given {
			continue
		}
		v, err := optionalString(args, f.arg)
		if err != nil {
			return s, err
		}
		if !slices.Contains(f.values, v) {
			return s, invalid("%s must be one of %s", f.arg, strings.Join(f.values, ", "))
		}
		*f.dst = &v
	}
	bg, err := optionalString(args, "background_color")
	if err != nil {
		return s, err
	}
	fg, err := optionalString(args, "text_color")
	if err != nil {
		return s, err
	}
	if (bg == "") != (fg == "") {
		return s, invalid("give background_color and text_color together")
	}
	if bg != "" && (!colorRE.MatchString(bg) || !colorRE.MatchString(fg)) {
		return s, invalid("background_color and text_color must be #rrggbb colors from Gmail's label palette")
	}
	s.background, s.text = strings.ToLower(bg), strings.ToLower(fg)
	return s, nil
}

// empty reports whether no setting was given.
func (s labelSettings) empty() bool {
	return s.name == nil && s.labelVis == nil && s.messageVis == nil && s.background == ""
}

func (s labelSettings) label() *gmail.Label {
	l := &gmail.Label{}
	if s.name != nil {
		l.Name = *s.name
	}
	if s.labelVis != nil {
		l.LabelListVisibility = *s.labelVis
	}
	if s.messageVis != nil {
		l.MessageListVisibility = *s.messageVis
	}
	if s.background != "" {
		l.Color = &gmail.LabelColor{BackgroundColor: s.background, TextColor: s.text}
	}
	return l
}

// labelIdentity is the label id (update_label), the visibilities and
// colors given, and name = "true" when update_label renames; never the
// name.
func labelIdentity(args map[string]any) map[string]string {
	out := idIdentity("label_id")(args)
	s, err := parseLabelSettings(args)
	if err != nil {
		return out
	}
	if s.name != nil && out["label_id"] != "" {
		out["name"] = "true"
	}
	if s.labelVis != nil {
		out["label_list_visibility"] = *s.labelVis
	}
	if s.messageVis != nil {
		out["message_list_visibility"] = *s.messageVis
	}
	if s.background != "" {
		out["background_color"], out["text_color"] = s.background, s.text
	}
	return out
}

func toManagedLabel(l *gmail.Label) ManagedLabel {
	out := ManagedLabel{ID: l.Id, Name: l.Name, Type: l.Type, LabelListVisibility: l.LabelListVisibility, MessageListVisibility: l.MessageListVisibility}
	if l.Color != nil {
		out.BackgroundColor, out.TextColor = l.Color.BackgroundColor, l.Color.TextColor
	}
	return out
}

func (c *Connector) createLabel(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	if _, err := requiredString(call.Args, "name"); err != nil {
		return connectors.Result{}, err
	}
	s, err := parseLabelSettings(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.gmail(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	l, err := svc.Users.Labels.Create(gmailUser, s.label()).Context(ctx).Do()
	if err := classifyWrite("create label", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: toManagedLabel(l)}, nil
}

func (c *Connector) updateLabel(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	id, err := idArg(call.Args, "label_id")
	if err != nil {
		return connectors.Result{}, err
	}
	s, err := parseLabelSettings(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	if s.empty() {
		return connectors.Result{}, invalid("give name, label_list_visibility, message_list_visibility or the colors")
	}
	svc, err := cl.gmail(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	l, err := svc.Users.Labels.Patch(gmailUser, id, s.label()).Context(ctx).Do()
	if err := classifyWrite("update label", err); err != nil {
		return connectors.Result{}, err
	}
	out := toManagedLabel(l)
	if out.ID == "" {
		out.ID = id
	}
	return connectors.Result{Content: out}, nil
}

func (c *Connector) deleteLabel(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	id, err := idArg(call.Args, "label_id")
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.gmail(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	err = svc.Users.Labels.Delete(gmailUser, id).Context(ctx).Do()
	if err := classifyWrite("delete label", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: DeletedLabel{LabelID: id, Deleted: true}}, nil
}

// --- filters ----------------------------------------------------------------------

// objectArg reads a nested object argument, refusing unknown fields.
func objectArg(args map[string]any, name string, fields ...string) (map[string]any, error) {
	v, ok := args[name]
	if !ok || v == nil {
		return nil, invalid("%s is required", name)
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, invalid("%s must be an object", name)
	}
	for k := range obj {
		if !slices.Contains(fields, k) {
			return nil, invalid("%s: unknown field %q (known: %s)", name, k, strings.Join(fields, ", "))
		}
	}
	return obj, nil
}

// filterArgs reads and validates create_filter's criteria and action.
func filterArgs(args map[string]any) (*gmail.Filter, error) {
	cr, err := objectArg(args, "criteria", "from", "to", "subject", "query", "negated_query", "has_attachment", "exclude_chats", "size", "size_comparison")
	if err != nil {
		return nil, err
	}
	criteria := &gmail.FilterCriteria{}
	for name, dst := range map[string]*string{"from": &criteria.From, "to": &criteria.To, "subject": &criteria.Subject, "query": &criteria.Query, "negated_query": &criteria.NegatedQuery} {
		v, err := optionalString(cr, name)
		if err != nil {
			return nil, invalid("criteria.%s must be a string", name)
		}
		*dst = strings.TrimSpace(v)
	}
	for name, dst := range map[string]*bool{"has_attachment": &criteria.HasAttachment, "exclude_chats": &criteria.ExcludeChats} {
		v, err := optionalBool(cr, name, false)
		if err != nil {
			return nil, invalid("criteria.%s must be true or false", name)
		}
		*dst = v
	}
	_, hasSize := cr["size"]
	cmp, err := optionalString(cr, "size_comparison")
	if err != nil {
		return nil, invalid("criteria.size_comparison must be larger or smaller")
	}
	if hasSize != (cmp != "") {
		return nil, invalid("criteria.size and criteria.size_comparison go together")
	}
	if hasSize {
		size, err := toInt(cr["size"])
		if err != nil || size < 0 {
			return nil, invalid("criteria.size must be a number of bytes")
		}
		if !slices.Contains(sizeComparisons, cmp) {
			return nil, invalid("criteria.size_comparison must be larger or smaller")
		}
		criteria.Size, criteria.SizeComparison = int64(size), cmp
	}
	if criteria.From+criteria.To+criteria.Subject+criteria.Query+criteria.NegatedQuery == "" && !criteria.HasAttachment && !criteria.ExcludeChats && criteria.SizeComparison == "" {
		return nil, invalid("criteria needs at least one field")
	}
	ac, err := objectArg(args, "action", "add_label_ids", "remove_label_ids", "forward")
	if err != nil {
		return nil, err
	}
	action := &gmail.FilterAction{}
	if action.AddLabelIds, err = labelArgs(ac, "add_label_ids"); err != nil {
		return nil, invalid("action.add_label_ids must be Gmail label ids")
	}
	if action.RemoveLabelIds, err = labelArgs(ac, "remove_label_ids"); err != nil {
		return nil, invalid("action.remove_label_ids must be Gmail label ids")
	}
	fwd, err := optionalString(ac, "forward")
	if err != nil {
		return nil, invalid("action.forward must be an email address")
	}
	if fwd = strings.TrimSpace(fwd); fwd != "" {
		addr, err := mail.ParseAddress(fwd)
		if err != nil {
			return nil, invalid("action.forward must be an email address")
		}
		action.Forward = addr.Address
	}
	if len(action.AddLabelIds) == 0 && len(action.RemoveLabelIds) == 0 && action.Forward == "" {
		return nil, invalid("action needs at least one of add_label_ids, remove_label_ids, forward")
	}
	return &gmail.Filter{Criteria: criteria, Action: action}, nil
}

// filterIdentity is the labels a filter adds and removes (sorted) and the
// domain it forwards to; never the criteria or the address.
func filterIdentity(args map[string]any) map[string]string {
	ac, _ := args["action"].(map[string]any)
	out := gmailTargetIdentity(map[string]any{"add_label_ids": ac["add_label_ids"], "remove_label_ids": ac["remove_label_ids"]})
	if fwd, _ := ac["forward"].(string); fwd != "" {
		if addr, err := mail.ParseAddress(fwd); err == nil {
			if d := domainOf(addr.Address); d != "" {
				out["forward_domain"] = d
			}
		}
	}
	return out
}

func toFilter(f *gmail.Filter) Filter {
	item := Filter{ID: f.Id}
	if cr := f.Criteria; cr != nil {
		item.Criteria = FilterCriteria{From: cr.From, To: cr.To, Subject: cr.Subject, Query: cr.Query, NegatedQuery: cr.NegatedQuery,
			HasAttachment: cr.HasAttachment, ExcludeChats: cr.ExcludeChats, Size: cr.Size, SizeComparison: cr.SizeComparison}
	}
	if ac := f.Action; ac != nil {
		item.Action = FilterAction{AddLabelIDs: ac.AddLabelIds, RemoveLabelIDs: ac.RemoveLabelIds, Forward: ac.Forward}
	}
	return item
}

func (c *Connector) getFilter(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	id, err := idArg(call.Args, "filter_id")
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.gmail(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	f, err := svc.Users.Settings.Filters.Get(gmailUser, id).Context(ctx).Do()
	if err := classify("get filter", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: toFilter(f)}, nil
}

func (c *Connector) createFilter(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	f, err := filterArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.gmail(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	created, err := svc.Users.Settings.Filters.Create(gmailUser, f).Context(ctx).Do()
	if err := classifyWrite("create filter", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: toFilter(created)}, nil
}

func (c *Connector) deleteFilter(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	id, err := idArg(call.Args, "filter_id")
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.gmail(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	err = svc.Users.Settings.Filters.Delete(gmailUser, id).Context(ctx).Do()
	if err := classifyWrite("delete filter", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: DeletedFilter{FilterID: id, Deleted: true}}, nil
}

// --- reconciliation ---------------------------------------------------------------

// existsFunc reads one resource by id: nil when it exists, a classified
// error otherwise.
type existsFunc func(ctx context.Context, svc *gmail.Service, id string) error

func (c *Connector) labelExists(ctx context.Context, svc *gmail.Service, id string) error {
	_, err := svc.Users.Labels.Get(gmailUser, id).Context(ctx).Do()
	return classify("reconcile: get label", err)
}

func (c *Connector) filterExists(ctx context.Context, svc *gmail.Service, id string) error {
	_, err := svc.Users.Settings.Filters.Get(gmailUser, id).Context(ctx).Do()
	return classify("reconcile: get filter", err)
}

// checkGoneByID is the check of a delete by id: the resource answering
// 404 is found (deleted); still there is not_found; any other error is
// "cannot tell yet".
func (c *Connector) checkGoneByID(key string, exists existsFunc) func(context.Context, connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	return func(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
		tg, err := c.target(in)
		if err != nil {
			return connectors.ReconcileResult{}, err
		}
		id := in.ResourceIdentity[key]
		if id == "" || !idRE.MatchString(id) {
			return connectors.ReconcileResult{}, fmt.Errorf("%w: resource identity has no %s", ErrNotReconcilable, key)
		}
		ctx, cancel := context.WithTimeout(ctx, c.timeout)
		defer cancel()
		svc, err := tg.client.gmail(ctx)
		if err != nil {
			return connectors.ReconcileResult{}, err
		}
		switch err := exists(ctx, svc, id); {
		case err == nil:
			return notFound, nil
		case statusOf(err) == http.StatusNotFound:
			return found(id), nil
		default:
			return connectors.ReconcileResult{}, err
		}
	}
}

// checkLabelUpdated is update_label's state check: the label is read
// back and compared with the visibilities and colors the identity
// recorded. A difference is not_found (a patch applies at once); a
// match is found, unless the update also renamed the label: the name is
// never stored, so the check cannot tell. A gone label (404) or any
// error is "cannot tell yet".
func (c *Connector) checkLabelUpdated(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	tg, err := c.target(in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	id := in.ResourceIdentity["label_id"]
	if id == "" || !idRE.MatchString(id) {
		return connectors.ReconcileResult{}, fmt.Errorf("%w: resource identity has no label", ErrNotReconcilable)
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	svc, err := tg.client.gmail(ctx)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	l, err := svc.Users.Labels.Get(gmailUser, id).Context(ctx).Do()
	if err := classify("reconcile: get label", err); err != nil {
		return connectors.ReconcileResult{}, err
	}
	got := toManagedLabel(l)
	for key, value := range map[string]string{
		"label_list_visibility": got.LabelListVisibility, "message_list_visibility": got.MessageListVisibility,
		"background_color": got.BackgroundColor, "text_color": got.TextColor,
	} {
		if want := in.ResourceIdentity[key]; want != "" && !strings.EqualFold(want, value) {
			return notFound, nil
		}
	}
	if in.ResourceIdentity["name"] == "true" {
		return connectors.ReconcileResult{}, fmt.Errorf("google: reconcile: the label's settings match but its name cannot be compared (never stored); cannot tell")
	}
	return found(id), nil
}
