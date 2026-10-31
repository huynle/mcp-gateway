package google

import (
	"context"
	"fmt"
	"strconv"
	"time"
	"unicode/utf8"

	"google.golang.org/api/gmail/v1"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Gmail settings tool names (increment 4).
const (
	ToolGetVacation = "get_vacation"
	ToolListFilters = "list_filters"
	ToolSetVacation = "set_vacation"
)

// MaxVacationBodyChars bounds set_vacation's body.
const MaxVacationBodyChars = 100_000

// vacationSetting is the resource identity's and the ResultIDs' "setting"
// value, and the id the check reports when found.
const vacationSetting = "vacation"

// VacationSettings is get_vacation's result. Times are RFC 3339 UTC;
// empty when the responder has no start or end.
type VacationSettings struct {
	Enabled            bool   `json:"enabled"`
	Subject            string `json:"subject,omitempty"`
	BodyText           string `json:"body_text,omitempty"`
	BodyHTML           string `json:"body_html,omitempty"`
	RestrictToContacts bool   `json:"restrict_to_contacts"`
	RestrictToDomain   bool   `json:"restrict_to_domain"`
	StartTime          string `json:"start_time,omitempty"`
	EndTime            string `json:"end_time,omitempty"`
	// Truncated says a body was cut to fit the result bounds.
	Truncated bool `json:"truncated,omitempty"`
}

// VacationUpdate is set_vacation's result: the state Gmail stored, never
// the subject or the body.
type VacationUpdate struct {
	Enabled            bool   `json:"enabled"`
	RestrictToContacts bool   `json:"restrict_to_contacts"`
	RestrictToDomain   bool   `json:"restrict_to_domain"`
	StartTime          string `json:"start_time,omitempty"`
	EndTime            string `json:"end_time,omitempty"`
}

// FilterCriteria is what a Gmail filter matches.
type FilterCriteria struct {
	From           string `json:"from,omitempty"`
	To             string `json:"to,omitempty"`
	Subject        string `json:"subject,omitempty"`
	Query          string `json:"query,omitempty"`
	NegatedQuery   string `json:"negated_query,omitempty"`
	HasAttachment  bool   `json:"has_attachment,omitempty"`
	ExcludeChats   bool   `json:"exclude_chats,omitempty"`
	Size           int64  `json:"size,omitempty"`
	SizeComparison string `json:"size_comparison,omitempty"`
}

// FilterAction is what a Gmail filter does to the mail it matches.
type FilterAction struct {
	AddLabelIDs    []string `json:"add_label_ids,omitempty"`
	RemoveLabelIDs []string `json:"remove_label_ids,omitempty"`
	Forward        string   `json:"forward,omitempty"`
}

// Filter is one list_filters item.
type Filter struct {
	ID       string         `json:"id"`
	Criteria FilterCriteria `json:"criteria"`
	Action   FilterAction   `json:"action"`
}

// FiltersPage is list_filters's result (Gmail returns every filter at
// once: no pages).
type FiltersPage struct {
	Truncated bool     `json:"truncated,omitempty"`
	Items     []Filter `json:"items"`
}

func (c *Connector) gmailSettingsReadTools() []connectors.Tool {
	return []connectors.Tool{
		{
			App: AppGmail, Name: ToolGetVacation, Kind: connectors.KindRead,
			Description: "Get the Gmail vacation responder (out-of-office auto-reply): enabled, subject, body_text / body_html, " +
				"restrict_to_contacts, restrict_to_domain, start_time and end_time (RFC 3339). Bodies are cut to the result bounds.",
			InputSchema:      objectSchema(nil, nil),
			RequiredScopes:   []string{ScopeGmailReadonly},
			ResourceIdentity: noIdentity,
			Bounds:           c.singleBounds(),
		},
		{
			App: AppGmail, Name: ToolListFilters, Kind: connectors.KindRead,
			Description: "List the account's Gmail filters: id, criteria (from, to, subject, query, negated_query, has_attachment, " +
				"exclude_chats, size, size_comparison) and action (add_label_ids, remove_label_ids, forward). Label ids come from list_labels.",
			InputSchema:      objectSchema(nil, nil),
			RequiredScopes:   []string{ScopeGmailReadonly},
			ResourceIdentity: noIdentity,
			Bounds:           c.singleBounds(),
		},
	}
}

func (c *Connector) gmailSettingsReadHandlers() map[string]handler {
	return map[string]handler{ToolGetVacation: c.getVacation, ToolListFilters: c.listFilters}
}

func (c *Connector) gmailSettingsWriteTools() []connectors.Tool {
	return []connectors.Tool{{
		App: AppGmail, Name: ToolSetVacation, Kind: connectors.KindWrite,
		Description: "Turn the Gmail vacation responder (out-of-office auto-reply) on or off. enabled is required; subject, body (plain text), " +
			"restrict_to_contacts, restrict_to_domain (Google Workspace: only people in the domain), start and end (RFC 3339) change only " +
			"what is given (an empty start or end clears it); the rest keeps its current value. Returns the stored state, never the message.",
		InputSchema: objectSchema([]property{
			{"enabled", "boolean", "Turn the auto-reply on (true) or off (false).", nil},
			{"subject", "string", "Subject of the auto-reply.", nil},
			{"body", "string", "Plain-text body of the auto-reply (replaces any HTML body).", nil},
			{"restrict_to_contacts", "boolean", "Reply only to people in the account's contacts.", nil},
			{"restrict_to_domain", "boolean", "Reply only to people in the account's Google Workspace domain.", nil},
			{"start", "string", "When replies start (RFC 3339); empty clears it.", nil},
			{"end", "string", "When replies end (RFC 3339); empty clears it.", nil},
		}, []string{"enabled"}),
		RequiredScopes:   []string{ScopeGmailSettingsBasic},
		ResourceIdentity: vacationIdentity,
		Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: c.checkVacation},
		ResultIDs: func(res connectors.Result) map[string]string {
			if v, ok := res.Content.(VacationUpdate); ok {
				return map[string]string{"setting": vacationSetting, "enabled": strconv.FormatBool(v.Enabled)}
			}
			return nil
		},
		Bounds: c.singleBounds(),
	}}
}

func (c *Connector) gmailSettingsWriteHandlers() map[string]handler {
	return map[string]handler{ToolSetVacation: c.setVacation}
}

// vacationArgs are set_vacation's validated arguments; nil pointers are
// settings left as they are.
type vacationArgs struct {
	enabled                    bool
	subject, body              *string
	restrictContacts, restrict *bool
	start, end                 *int64 // epoch milliseconds; 0 clears
}

func parseVacationArgs(args map[string]any) (vacationArgs, error) {
	var a vacationArgs
	v, ok := args["enabled"].(bool)
	if !ok {
		return a, invalid("enabled is required (true or false)")
	}
	a.enabled = v
	for name, dst := range map[string]**string{"subject": &a.subject, "body": &a.body} {
		if _, given := args[name]; !given {
			continue
		}
		s, err := optionalString(args, name)
		if err != nil {
			return a, err
		}
		*dst = &s
	}
	if a.body != nil && utf8.RuneCountInString(*a.body) > MaxVacationBodyChars {
		return a, invalid("body is longer than %d characters", MaxVacationBodyChars)
	}
	for name, dst := range map[string]**bool{"restrict_to_contacts": &a.restrictContacts, "restrict_to_domain": &a.restrict} {
		if _, given := args[name]; !given {
			continue
		}
		b, err := optionalBool(args, name, false)
		if err != nil {
			return a, err
		}
		*dst = &b
	}
	for name, dst := range map[string]**int64{"start": &a.start, "end": &a.end} {
		if _, given := args[name]; !given {
			continue
		}
		t, err := optionalTime(args, name)
		if err != nil {
			return a, err
		}
		ms := int64(0)
		if !t.IsZero() {
			ms = t.UnixMilli()
		}
		*dst = &ms
	}
	if a.start != nil && a.end != nil && *a.start != 0 && *a.end != 0 && *a.end <= *a.start {
		return a, invalid("end must be after start")
	}
	return a, nil
}

// vacationIdentity is set_vacation's resource identity: the state the
// write asks for (enabled, start / end in epoch milliseconds or "none",
// the restrictions given) and "message" = "true" when the subject or the
// body was given. Never the subject or the body.
func vacationIdentity(args map[string]any) map[string]string {
	a, err := parseVacationArgs(args)
	if err != nil {
		return map[string]string{"setting": vacationSetting}
	}
	out := map[string]string{"setting": vacationSetting, "enabled": strconv.FormatBool(a.enabled)}
	for key, v := range map[string]*int64{"start": a.start, "end": a.end} {
		switch {
		case v == nil:
		case *v == 0:
			out[key] = "none"
		default:
			out[key] = strconv.FormatInt(*v, 10)
		}
	}
	for key, v := range map[string]*bool{"restrict_to_contacts": a.restrictContacts, "restrict_to_domain": a.restrict} {
		if v != nil {
			out[key] = strconv.FormatBool(*v)
		}
	}
	if a.subject != nil || a.body != nil {
		out["message"] = "true"
	}
	return out
}

// msTime renders Gmail's epoch milliseconds as RFC 3339 UTC; "" for 0.
func msTime(ms int64) string {
	if ms == 0 {
		return ""
	}
	return time.UnixMilli(ms).UTC().Format(time.RFC3339)
}

// --- handlers -------------------------------------------------------------------

func (c *Connector) getVacation(ctx context.Context, cl *client, _ connectors.Call) (connectors.Result, error) {
	svc, err := cl.gmail(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	v, err := svc.Users.Settings.GetVacation(gmailUser).Context(ctx).Do()
	if err := classify("get vacation settings", err); err != nil {
		return connectors.Result{}, err
	}
	out := VacationSettings{
		Enabled: v.EnableAutoReply, Subject: v.ResponseSubject, BodyText: v.ResponseBodyPlainText, BodyHTML: v.ResponseBodyHtml,
		RestrictToContacts: v.RestrictToContacts, RestrictToDomain: v.RestrictToDomain, StartTime: msTime(v.StartTime), EndTime: msTime(v.EndTime),
	}
	obj := func() any { return out }
	fitBody(&out.BodyHTML, &out.Truncated, c.bounds.MaxResultBytes, obj)
	fitBody(&out.BodyText, &out.Truncated, c.bounds.MaxResultBytes, obj)
	return connectors.Result{Content: out, Partial: out.Truncated}, nil
}

func (c *Connector) listFilters(ctx context.Context, cl *client, _ connectors.Call) (connectors.Result, error) {
	svc, err := cl.gmail(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	resp, err := svc.Users.Settings.Filters.List(gmailUser).Context(ctx).Do()
	if err := classify("list filters", err); err != nil {
		return connectors.Result{}, err
	}
	out := FiltersPage{Items: []Filter{}}
	for _, f := range resp.Filter {
		if f == nil {
			continue
		}
		out.Items = append(out.Items, toFilter(f))
	}
	res := connectors.Result{Empty: len(out.Items) == 0}
	for encodedSize(out) > c.bounds.MaxResultBytes && len(out.Items) > 1 {
		out.Items = out.Items[:len(out.Items)-1]
		out.Truncated, res.Partial = true, true
	}
	res.Content = out
	return res, nil
}

// setVacation reads the current settings (updateVacation replaces them
// all), applies what was given and writes them back. The read failing is
// a known outcome: nothing was sent.
func (c *Connector) setVacation(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	a, err := parseVacationArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.gmail(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	cur, err := svc.Users.Settings.GetVacation(gmailUser).Context(ctx).Do()
	if err := classify("get vacation settings", err); err != nil {
		return connectors.Result{}, err
	}
	next := &gmail.VacationSettings{
		EnableAutoReply: a.enabled, ResponseSubject: cur.ResponseSubject, ResponseBodyPlainText: cur.ResponseBodyPlainText, ResponseBodyHtml: cur.ResponseBodyHtml,
		RestrictToContacts: cur.RestrictToContacts, RestrictToDomain: cur.RestrictToDomain, StartTime: cur.StartTime, EndTime: cur.EndTime,
		ForceSendFields: []string{"EnableAutoReply", "RestrictToContacts", "RestrictToDomain"},
	}
	if a.subject != nil {
		next.ResponseSubject = *a.subject
	}
	if a.body != nil {
		// Gmail prefers an HTML body over the plain-text one: a new body
		// replaces both.
		next.ResponseBodyPlainText, next.ResponseBodyHtml = *a.body, ""
	}
	if a.restrictContacts != nil {
		next.RestrictToContacts = *a.restrictContacts
	}
	if a.restrict != nil {
		next.RestrictToDomain = *a.restrict
	}
	if a.start != nil {
		next.StartTime = *a.start
	}
	if a.end != nil {
		next.EndTime = *a.end
	}
	got, err := svc.Users.Settings.UpdateVacation(gmailUser, next).Context(ctx).Do()
	if err := classifyWrite("update vacation settings", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: VacationUpdate{
		Enabled: got.EnableAutoReply, RestrictToContacts: got.RestrictToContacts, RestrictToDomain: got.RestrictToDomain,
		StartTime: msTime(got.StartTime), EndTime: msTime(got.EndTime),
	}}, nil
}

// checkVacation is set_vacation's state check: the vacation settings are
// read back and compared with the state the resource identity recorded
// (enabled, and start / end / restrictions when given). A difference is
// not_found (updateVacation replaces the settings at once, so the write
// did not apply); a match is found, unless the write also changed the
// subject or the body ("message"), which the ledger never stores: then
// it cannot tell and the operation ends unresolved. Any read error is
// "cannot tell yet".
func (c *Connector) checkVacation(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	tg, err := c.target(in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	enabled, err := strconv.ParseBool(in.ResourceIdentity["enabled"])
	if err != nil {
		return connectors.ReconcileResult{}, fmt.Errorf("%w: resource identity has no enabled state", ErrNotReconcilable)
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	svc, err := tg.client.gmail(ctx)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	v, err := svc.Users.Settings.GetVacation(gmailUser).Context(ctx).Do()
	if err := classify("reconcile: get vacation settings", err); err != nil {
		return connectors.ReconcileResult{}, err
	}
	matches := v.EnableAutoReply == enabled
	for key, got := range map[string]int64{"start": v.StartTime, "end": v.EndTime} {
		switch want := in.ResourceIdentity[key]; want {
		case "":
		case "none":
			matches = matches && got == 0
		default:
			matches = matches && strconv.FormatInt(got, 10) == want
		}
	}
	for key, got := range map[string]bool{"restrict_to_contacts": v.RestrictToContacts, "restrict_to_domain": v.RestrictToDomain} {
		if want := in.ResourceIdentity[key]; want != "" {
			matches = matches && strconv.FormatBool(got) == want
		}
	}
	if !matches {
		return notFound, nil
	}
	if in.ResourceIdentity["message"] == "true" {
		return connectors.ReconcileResult{}, fmt.Errorf("google: reconcile: the vacation state matches but the subject or body cannot be compared (never stored); cannot tell")
	}
	return found(vacationSetting), nil
}
