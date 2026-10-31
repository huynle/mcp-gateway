package google

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"google.golang.org/api/calendar/v3"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Increment 5 (Brain decision 9jfy0gb8): the rest of what a consumer
// Google account can do with the Calendar API: recurring instances,
// natural-language quick add, moving an event between calendars,
// secondary calendars (create, update, delete, clear the primary), the
// calendar list (subscribe, unsubscribe, colors, hidden, reminders),
// sharing (ACL rules), the color palette and the user's settings. Every
// new write defaults to Ask (migration 00037).

// Calendar tool names (increment 5).
const (
	ToolListInstances           = "list_instances"
	ToolListACL                 = "list_acl"
	ToolGetColors               = "get_colors"
	ToolGetSettings             = "get_settings"
	ToolQuickAdd                = "quick_add"
	ToolMoveEvent               = "move_event"
	ToolCreateCalendar          = "create_calendar"
	ToolUpdateCalendar          = "update_calendar"
	ToolDeleteCalendar          = "delete_calendar"
	ToolClearCalendar           = "clear_calendar"
	ToolSubscribeCalendar       = "subscribe_calendar"
	ToolUnsubscribeCalendar     = "unsubscribe_calendar"
	ToolUpdateCalendarListEntry = "update_calendar_list_entry"
	ToolShareCalendar           = "share_calendar"
	ToolUpdateACL               = "update_acl"
	ToolUnshareCalendar         = "unshare_calendar"
)

// Calendar API limits the connector checks before sending.
const (
	// MaxEventReminders is the Calendar API's ceiling of reminder
	// overrides per event (and default reminders per calendar).
	MaxEventReminders = 5
	// MaxReminderMinutes is the latest a reminder may fire: four weeks.
	MaxReminderMinutes = 40320
	// MaxEventAttachments is the Calendar API's ceiling of attachments.
	MaxEventAttachments = 25
	// MaxRecurrenceLines bounds recurrence (RRULE, EXRULE, RDATE, EXDATE
	// lines) per event.
	MaxRecurrenceLines = 20
	// maxSettingsPages bounds get_settings' paging (one page in practice).
	maxSettingsPages = 5
	// aclPerPage is the Calendar API's maximum ACL page.
	aclPerPage = 250
)

var (
	aclRoleValues      = []string{"freeBusyReader", "reader", "writer", "owner"}
	aclTypeValues      = []string{"user", "group", "domain", "default"}
	visibilityValues   = []string{"default", "public", "private", "confidential"}
	transparencyValues = []string{"opaque", "transparent"}
	reminderMethods    = []string{"popup", "email"}
	// recurrenceRE is one iCalendar recurrence line (RFC 5545) as the
	// Calendar API takes it.
	recurrenceRE = regexp.MustCompile(`^(RRULE|EXRULE|RDATE|EXDATE)[:;][^\r\n]+$`)
	// colorIDRE is a palette id ("1".."24"; see get_colors).
	colorIDRE = regexp.MustCompile(`^[1-9][0-9]?$`)
	// domainRE is a bare DNS domain.
	domainRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
)

// Calendar palettes: calendar colors go up to 24, event colors to 11.
const (
	maxCalendarColorID = 24
	maxEventColorID    = 11
)

// ACLRuleKey is the resource-identity key of a calendar ACL rule: the
// rule id ("user:<address>", "group:<address>", "domain:<domain>",
// "default") hashed like EventID, so the identity names the rule without
// carrying the grantee's address; the checks list the ACL and compare.
func ACLRuleKey(ruleID string) string {
	return EventID("acl:" + strings.ToLower(strings.TrimSpace(ruleID)))
}

// --- result types -------------------------------------------------------------------

// EventAttachment is one file attached to an event.
type EventAttachment struct {
	Title    string `json:"title,omitempty"`
	URL      string `json:"url"`
	MimeType string `json:"mime_type,omitempty"`
}

// InstancesPage is list_instances's result.
type InstancesPage struct {
	EventsPage
	EventID string `json:"event_id"`
}

// ACLRule is one list_acl item.
type ACLRule struct {
	RuleID     string `json:"rule_id"`
	Role       string `json:"role"`
	ScopeType  string `json:"scope_type"`
	ScopeValue string `json:"scope_value,omitempty"`
}

// ACLPage is list_acl's result.
type ACLPage struct {
	CalendarID    string    `json:"calendar_id"`
	MaxResults    int       `json:"max_results"`
	NextPageToken string    `json:"next_page_token,omitempty"`
	HasMore       bool      `json:"has_more"`
	Truncated     bool      `json:"truncated,omitempty"`
	Items         []ACLRule `json:"items"`
}

// Color is one palette entry.
type Color struct {
	ID         string `json:"id"`
	Background string `json:"background"`
	Foreground string `json:"foreground"`
}

// Colors is get_colors's result: the calendar and event palettes,
// ordered by id.
type Colors struct {
	Calendar []Color `json:"calendar"`
	Event    []Color `json:"event"`
}

// Setting is one user setting.
type Setting struct {
	ID    string `json:"id"`
	Value string `json:"value"`
}

// Settings is get_settings's result.
type Settings struct {
	Truncated bool      `json:"truncated,omitempty"`
	Items     []Setting `json:"items"`
}

// CalendarChange is the result of the calendar and calendar-list writes.
type CalendarChange struct {
	ID       string `json:"id"`
	TimeZone string `json:"time_zone,omitempty"`
	ColorID  string `json:"color_id,omitempty"`
	Hidden   *bool  `json:"hidden,omitempty"`
	Selected *bool  `json:"selected,omitempty"`
	Deleted  bool   `json:"deleted,omitempty"`
	Cleared  bool   `json:"cleared,omitempty"`
	Removed  bool   `json:"removed,omitempty"`
}

// ACLChange is the result of the sharing writes.
type ACLChange struct {
	CalendarID string `json:"calendar_id"`
	RuleID     string `json:"rule_id"`
	Role       string `json:"role,omitempty"`
	ScopeType  string `json:"scope_type,omitempty"`
	Deleted    bool   `json:"deleted,omitempty"`
}

func calendarChangeResultIDs(res connectors.Result) map[string]string {
	v, ok := res.Content.(CalendarChange)
	if !ok || v.ID == "" {
		return nil
	}
	return map[string]string{"id": v.ID}
}

func aclChangeResultIDs(res connectors.Result) map[string]string {
	v, ok := res.Content.(ACLChange)
	if !ok || v.RuleID == "" {
		return nil
	}
	return map[string]string{"calendar_id": v.CalendarID, "rule_id": v.RuleID}
}

// --- declarations -------------------------------------------------------------------

var (
	pageTokenProperty  = property{"page_token", "string", "Token of the page to fetch (next_page_token of the previous result).", nil}
	ruleIDProperty     = property{"rule_id", "string", "The sharing rule's id (rule_id from list_acl: user:<address>, group:<address>, domain:<domain> or default).", nil}
	remindersProperty  = property{"reminders", "array", "Reminders, each method:minutes with method popup or email (\"popup:10\", \"email:1440\"); at most 5, minutes 0-40320. Replaces the calendar's default reminders.", nil}
	ownCalendarIDProp  = property{"calendar_id", "string", "The calendar's id (from list_calendars or create_calendar).", nil}
	calendarColorIDDoc = "Color id of the calendar palette (get_colors calendar ids, 1-24)."
)

// eventExtraProperties are the event fields create_event and
// update_event take since increment 5.
var eventExtraProperties = []property{
	{"recurrence", "array", "Recurrence lines (RFC 5545): RRULE, EXRULE, RDATE, EXDATE, e.g. \"RRULE:FREQ=WEEKLY;BYDAY=MO;COUNT=10\" (a timed recurring event needs time_zone). On update an empty list makes the event single.", nil},
	remindersProperty,
	{"use_default_reminders", "boolean", "true: the calendar's default reminders; false: none unless reminders is given.", nil},
	{"color_id", "string", "Event color id (get_colors event ids, 1-11).", nil},
	{"visibility", "string", "default, public, private or confidential.", visibilityValues},
	{"transparency", "string", "opaque (busy, default) or transparent (free).", transparencyValues},
	{"attachments", "array", "Google Drive file URLs to attach (https://drive.google.com/... or https://docs.google.com/...; at most 25). On update the list replaces the current attachments.", nil},
	{"guests_can_modify", "boolean", "Whether attendees may change the event.", nil},
	{"guests_can_invite_others", "boolean", "Whether attendees may invite others.", nil},
	{"guests_can_see_other_guests", "boolean", "Whether attendees see the guest list.", nil},
}

func (c *Connector) calendarFullReadTools() []connectors.Tool {
	empty := func(map[string]any) map[string]string { return map[string]string{} }
	return []connectors.Tool{
		{
			App: AppCalendar, Name: ToolListInstances, Kind: connectors.KindRead,
			Description: "List the occurrences of a recurring event (event_id of the series, e.g. recurring_event_id from list_events) " +
				"between time_min and time_max (RFC 3339), with each occurrence's own id (use it with update_event or delete_event to " +
				"change or cancel one occurrence). has_more and next_page_token say whether another page exists.",
			InputSchema: objectSchema([]property{
				calendarIDProperty, eventIDProperty,
				{"time_min", "string", "Lower bound (inclusive) of an occurrence's end, RFC 3339.", nil},
				{"time_max", "string", "Upper bound (exclusive) of an occurrence's start, RFC 3339.", nil},
				{"max_results", "integer", "Occurrences per page (1-100; default 25); clamped to the tool's maximum.", nil},
				pageTokenProperty,
			}, []string{"event_id"}),
			RequiredScopes:   []string{ScopeCalendarEventsReadonly},
			ResourceIdentity: calendarIdentity(true),
			Bounds:           c.pagedBounds(),
		},
		{
			App: AppCalendar, Name: ToolListACL, Kind: connectors.KindRead,
			Description: "List who a calendar is shared with (its access control rules): rule_id, role (none, freeBusyReader, reader, " +
				"writer, owner), scope_type (user, group, domain, default = public) and scope_value (the address or domain). " +
				"Pass a rule_id to update_acl or unshare_calendar.",
			InputSchema: objectSchema([]property{
				calendarIDProperty,
				{"max_results", "integer", "Rules per page (1-100; default 50); clamped to the tool's maximum.", nil},
				pageTokenProperty,
			}, nil),
			RequiredScopes:   []string{ScopeCalendarAclsReadonly},
			ResourceIdentity: calendarIdentity(false),
			Bounds:           c.pagedBounds(),
		},
		{
			App: AppCalendar, Name: ToolGetColors, Kind: connectors.KindRead,
			Description: "Get Google Calendar's color palettes: calendar colors (ids for update_calendar_list_entry color_id) and event " +
				"colors (ids for create_event / update_event color_id), each with its background and foreground hex color.",
			InputSchema:      objectSchema(nil, nil),
			RequiredScopes:   []string{ScopeCalendarListReadonly},
			ResourceIdentity: empty,
			Bounds:           c.singleBounds(),
		},
		{
			App: AppCalendar, Name: ToolGetSettings, Kind: connectors.KindRead,
			Description: "Get the account's Google Calendar settings (id and value): timezone, locale, weekStart, format24HourTime, " +
				"defaultEventLength, hideWeekends, autoAddHangouts and the others Google reports.",
			InputSchema:      objectSchema(nil, nil),
			RequiredScopes:   []string{ScopeCalendarSettingsReadonly},
			ResourceIdentity: empty,
			Bounds:           c.singleBounds(),
		},
	}
}

func (c *Connector) calendarFullReadHandlers() map[string]handler {
	return map[string]handler{
		ToolListInstances: c.listInstances, ToolListACL: c.listACL, ToolGetColors: c.getColors, ToolGetSettings: c.getSettings,
	}
}

func (c *Connector) calendarFullWriteTools() []connectors.Tool {
	tool := func(name, description string, props []property, required []string, scope string, identity func(map[string]any) map[string]string,
		rec connectors.Reconciliation, ids func(connectors.Result) map[string]string) connectors.Tool {
		return connectors.Tool{
			App: AppCalendar, Name: name, Kind: connectors.KindWrite, Description: description,
			InputSchema: objectSchema(props, required), RequiredScopes: []string{scope}, ResourceIdentity: identity,
			Reconcile: rec, ResultIDs: ids, Bounds: c.singleBounds(),
		}
	}
	none := connectors.Reconciliation{Kind: connectors.ReconcileNone}
	stable := func(check func(context.Context, connectors.ReconcileInput) (connectors.ReconcileResult, error)) connectors.Reconciliation {
		return connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: check}
	}
	listEntryProps := []property{
		{"color_id", "string", calendarColorIDDoc, nil},
		{"hidden", "boolean", "Hide the calendar from the list.", nil},
		{"selected", "boolean", "Show the calendar's events in the calendar UI.", nil},
		{"summary_override", "string", "The account's own name for the calendar (empty clears it).", nil},
	}
	return []connectors.Tool{
		tool(ToolQuickAdd,
			"Create an event from a sentence, as Google Calendar's quick add parses it (\"Lunch with Bob tomorrow 12pm at Cafe\"). "+
				"send_updates says whether Google emails the attendees (default none). Returns the event's id and url. "+
				"Cannot be verified after an unknown outcome (Google picks the id): check the calendar.",
			[]property{
				{"calendar_id", "string", "Calendar to create the event in: \"primary\" (default) or a calendar id.", nil},
				{"text", "string", "The event in plain words: what, when, where.", nil},
				sendUpdatesProperty,
			}, []string{"text"}, ScopeCalendarEvents, calendarIdentity(false), none, eventResultIDs),
		tool(ToolMoveEvent,
			"Move an event to another calendar (changes its organizer to that calendar). Only default events can be moved, not "+
				"out-of-office, focus-time or working-location events. Returns the event's id and url in the destination.",
			[]property{
				calendarIDProperty, eventIDProperty,
				{"destination", "string", "Id of the calendar to move the event to (from list_calendars).", nil},
				sendUpdatesProperty,
			}, []string{"event_id", "destination"}, ScopeCalendarEvents, moveIdentity, stable(c.checkEventMoved), eventResultIDs),
		tool(ToolCreateCalendar,
			"Create a secondary calendar owned by the account, with a summary (title) and optionally a description, location and "+
				"time_zone. Returns its id (use it as calendar_id). Cannot be verified after an unknown outcome (Google picks the id): "+
				"check list_calendars before retrying.",
			[]property{
				{"summary", "string", "The calendar's title.", nil},
				{"description", "string", "Description.", nil},
				{"location", "string", "Geographic location, free text.", nil},
				{"time_zone", "string", "IANA time zone (Europe/Berlin); the account's when omitted.", nil},
			}, []string{"summary"}, ScopeCalendarCalendars, func(map[string]any) map[string]string { return map[string]string{} }, none,
			calendarChangeResultIDs),
		tool(ToolUpdateCalendar,
			"Change a calendar the account owns: only the fields given change (summary, description, location, time_zone; empty "+
				"description or location clears it). The primary calendar's summary and time zone can be changed too.",
			[]property{
				calendarIDProperty,
				{"summary", "string", "New title.", nil},
				{"description", "string", "New description (empty clears it).", nil},
				{"location", "string", "New location (empty clears it).", nil},
				{"time_zone", "string", "New IANA time zone.", nil},
			}, nil, ScopeCalendarCalendars, calendarIdentity(false), none, calendarChangeResultIDs),
		tool(ToolDeleteCalendar,
			"Delete a secondary calendar the account owns, with all its events, for every user it is shared with. The primary "+
				"calendar cannot be deleted (use clear_calendar). To only remove someone else's calendar from the list, use unsubscribe_calendar.",
			[]property{ownCalendarIDProp}, []string{"calendar_id"}, ScopeCalendarCalendars, calendarIdentity(false),
			stable(c.checkCalendarDeleted), calendarChangeResultIDs),
		tool(ToolClearCalendar,
			"Delete every event of the account's primary calendar (Google allows this on the primary calendar only). Irreversible.",
			[]property{{"calendar_id", "string", "Only \"primary\" (default).", nil}}, nil, ScopeCalendarCalendars, calendarIdentity(false),
			stable(c.checkCalendarCleared), calendarChangeResultIDs),
		tool(ToolSubscribeCalendar,
			"Add an existing calendar (one shared with the account, or a public one such as a holiday calendar) to the account's "+
				"calendar list, optionally with a color, hidden or selected.",
			append([]property{{"calendar_id", "string", "Id of the calendar to add (often an address, or ...@group.calendar.google.com).", nil}},
				listEntryProps...), []string{"calendar_id"}, ScopeCalendarList, calendarIdentity(false), stable(c.checkSubscribed), calendarChangeResultIDs),
		tool(ToolUnsubscribeCalendar,
			"Remove a calendar from the account's calendar list (the calendar itself and its events stay; the owner can still share it again). "+
				"The primary calendar cannot be removed.",
			[]property{ownCalendarIDProp}, []string{"calendar_id"}, ScopeCalendarList, calendarIdentity(false), stable(c.checkUnsubscribed),
			calendarChangeResultIDs),
		tool(ToolUpdateCalendarListEntry,
			"Change how a calendar appears in the account's list: color_id, hidden, selected, summary_override and default_reminders "+
				"(the reminders new events of this calendar get). Only the fields given change.",
			append(append([]property{calendarIDProperty}, listEntryProps...),
				property{"default_reminders", "array", "Default reminders, each method:minutes (\"popup:10\"); at most 5; an empty list removes them.", nil}),
			nil, ScopeCalendarList, calendarIdentity(false), none, calendarChangeResultIDs),
		tool(ToolShareCalendar,
			"Share a calendar: give a user or group (email), a whole domain (domain) or everyone (type default: public) a role: "+
				"freeBusyReader (sees only free/busy), reader, writer (edits events) or owner (also manages sharing). Google emails the "+
				"grantee unless send_notifications is false. Sharing an existing grantee again replaces its role.",
			[]property{
				calendarIDProperty,
				{"role", "string", "freeBusyReader, reader, writer or owner.", aclRoleValues},
				{"type", "string", "user (default), group, domain or default (public).", aclTypeValues},
				{"email", "string", "Address of the user or group (types user and group).", nil},
				{"domain", "string", "Domain to share with (type domain).", nil},
				{"send_notifications", "boolean", "Email the grantee. Default true.", nil},
			}, []string{"role"}, ScopeCalendarAcls, calendarShareIdentity, stable(c.checkACLRole), aclChangeResultIDs),
		tool(ToolUpdateACL,
			"Change the role of an existing sharing rule (rule_id from list_acl) to freeBusyReader, reader, writer or owner.",
			[]property{calendarIDProperty, ruleIDProperty, {"role", "string", "freeBusyReader, reader, writer or owner.", aclRoleValues}},
			[]string{"rule_id", "role"}, ScopeCalendarAcls, ruleIdentity(true), stable(c.checkACLRole), aclChangeResultIDs),
		tool(ToolUnshareCalendar,
			"Stop sharing a calendar with a grantee: delete the sharing rule (rule_id from list_acl). The default rule makes the calendar private again.",
			[]property{calendarIDProperty, ruleIDProperty}, []string{"rule_id"}, ScopeCalendarAcls, ruleIdentity(false),
			stable(c.checkACLRemoved), aclChangeResultIDs),
	}
}

func (c *Connector) calendarFullWriteHandlers() map[string]handler {
	return map[string]handler{
		ToolQuickAdd: c.quickAdd, ToolMoveEvent: c.moveEvent,
		ToolCreateCalendar: c.createCalendar, ToolUpdateCalendar: c.updateCalendar, ToolDeleteCalendar: c.deleteCalendar,
		ToolClearCalendar: c.clearCalendar, ToolSubscribeCalendar: c.subscribeCalendar, ToolUnsubscribeCalendar: c.unsubscribeCalendar,
		ToolUpdateCalendarListEntry: c.updateCalendarListEntry,
		ToolShareCalendar:           c.shareCalendar, ToolUpdateACL: c.updateACL, ToolUnshareCalendar: c.unshareCalendar,
	}
}

// --- resource identities --------------------------------------------------------------

// moveIdentity is calendarIdentity(true) plus the destination calendar
// (lower-cased) and its domain.
func moveIdentity(args map[string]any) map[string]string {
	out := calendarIdentity(true)(args)
	if d, _ := args["destination"].(string); strings.TrimSpace(d) != "" {
		d = strings.ToLower(strings.TrimSpace(d))
		out["destination"] = d
		if dom := domainOf(d); dom != "" {
			out["destination_domain"] = dom
		}
	}
	return out
}

// aclRuleID builds the rule id Google gives a grantee.
func aclRuleID(scopeType, value string) string {
	if scopeType == "default" {
		return "default"
	}
	return scopeType + ":" + strings.ToLower(strings.TrimSpace(value))
}

// aclGrantee reads the grantee of share_calendar: type (user default),
// and the address or domain it needs. Validates.
func aclGrantee(args map[string]any) (scopeType, value string, err error) {
	if scopeType, err = optionalString(args, "type"); err != nil {
		return "", "", err
	}
	if scopeType = strings.TrimSpace(scopeType); scopeType == "" {
		scopeType = "user"
	}
	email, err := optionalString(args, "email")
	if err != nil {
		return "", "", err
	}
	domain, err := optionalString(args, "domain")
	if err != nil {
		return "", "", err
	}
	email, domain = strings.TrimSpace(email), strings.ToLower(strings.TrimSpace(domain))
	switch scopeType {
	case "user", "group":
		if domain != "" {
			return "", "", invalid("domain goes with type domain; give email for type %s", scopeType)
		}
		if email == "" || domainOf(email) == "" || strings.ContainsAny(email, " <>,") {
			return "", "", invalid("email must be the address of the %s to share with", scopeType)
		}
		return scopeType, strings.ToLower(email), nil
	case "domain":
		if email != "" {
			return "", "", invalid("email goes with types user and group; give domain for type domain")
		}
		if !domainRE.MatchString(domain) {
			return "", "", invalid("domain must be a domain such as example.com")
		}
		return scopeType, domain, nil
	case "default":
		if email != "" || domain != "" {
			return "", "", invalid("type default (public) takes no email or domain")
		}
		return scopeType, "", nil
	}
	return "", "", invalid("type must be user, group, domain or default")
}

// granteeIdentity is what the identity says of a rule id: its type, the
// grantee's domain (an address's domain, or the domain shared with) and
// the hashed rule key; never the address.
func granteeIdentity(out map[string]string, ruleID string) {
	ruleID = strings.ToLower(strings.TrimSpace(ruleID))
	if ruleID == "" {
		return
	}
	out["rule_key"] = ACLRuleKey(ruleID)
	scopeType, value, _ := strings.Cut(ruleID, ":")
	out["type"] = scopeType
	switch scopeType {
	case "domain":
		out["grantee_domain"] = value
	case "user", "group":
		if d := domainOf(value); d != "" {
			out["grantee_domain"] = d
		}
	}
}

// calendarShareIdentity: calendar_id, domain, role, type, grantee_domain and
// rule_key (ACLRuleKey of the rule the share creates).
func calendarShareIdentity(args map[string]any) map[string]string {
	out := calendarIdentity(false)(args)
	if r, _ := args["role"].(string); slices.Contains(aclRoleValues, strings.TrimSpace(r)) {
		out["role"] = strings.TrimSpace(r)
	}
	if scopeType, value, err := aclGrantee(args); err == nil {
		granteeIdentity(out, aclRuleID(scopeType, value))
	}
	return out
}

// ruleIdentity: calendar_id, domain, the rule's type, grantee_domain
// and rule_key, plus role when withRole.
func ruleIdentity(withRole bool) func(map[string]any) map[string]string {
	return func(args map[string]any) map[string]string {
		out := calendarIdentity(false)(args)
		if id, _ := args["rule_id"].(string); idRE.MatchString(strings.TrimSpace(id)) {
			granteeIdentity(out, id)
		}
		if r, _ := args["role"].(string); withRole && slices.Contains(aclRoleValues, strings.TrimSpace(r)) {
			out["role"] = strings.TrimSpace(r)
		}
		return out
	}
}

// --- argument helpers --------------------------------------------------------------------

// reminderList reads a list of "method:minutes" reminders; given says
// whether the argument was present (an empty list is given).
func reminderList(args map[string]any, name string) (out []*calendar.EventReminder, given bool, err error) {
	if v, ok := args[name]; !ok || v == nil {
		return nil, false, nil
	}
	list, err := stringList(args, name)
	if err != nil {
		return nil, true, err
	}
	if len(list) > MaxEventReminders {
		return nil, true, invalid("%s has %d reminders; at most %d", name, len(list), MaxEventReminders)
	}
	for _, r := range list {
		method, minutes, ok := strings.Cut(r, ":")
		n, err := strconv.Atoi(strings.TrimSpace(minutes))
		if !ok || !slices.Contains(reminderMethods, strings.TrimSpace(method)) || err != nil || n < 0 || n > MaxReminderMinutes {
			return nil, true, invalid("%s must be method:minutes with method popup or email and minutes 0-%d (%q is not)", name, MaxReminderMinutes, r)
		}
		out = append(out, &calendar.EventReminder{Method: strings.TrimSpace(method), Minutes: int64(n), ForceSendFields: []string{"Minutes"}})
	}
	return out, true, nil
}

// colorIDArg reads an optional palette id up to max.
func colorIDArg(args map[string]any, max int) (string, bool, error) {
	v, ok := args["color_id"]
	if !ok || v == nil {
		return "", false, nil
	}
	s, _ := v.(string)
	s = strings.TrimSpace(s)
	n, err := strconv.Atoi(s)
	if !colorIDRE.MatchString(s) || err != nil || n > max {
		return "", true, invalid("color_id must be a palette id from 1 to %d (see get_colors)", max)
	}
	return s, true, nil
}

// enumArg reads an optional string argument restricted to values.
func enumArg(args map[string]any, name string, values []string) (string, bool, error) {
	v, ok := args[name]
	if !ok || v == nil {
		return "", false, nil
	}
	s, _ := v.(string)
	if s = strings.TrimSpace(s); !slices.Contains(values, s) {
		return "", true, invalid("%s must be one of %s", name, strings.Join(values, ", "))
	}
	return s, true, nil
}

// eventExtras applies the increment-5 event fields given in args to ev
// (create_event and update_event). changed says whether any was given;
// attachments whether the request must say supportsAttachments.
func eventExtras(args map[string]any, ev *calendar.Event) (changed, attachments bool, err error) {
	if _, ok := args["recurrence"]; ok {
		lines, err := stringList(args, "recurrence")
		if err != nil {
			return false, false, err
		}
		if len(lines) > MaxRecurrenceLines {
			return false, false, invalid("recurrence has %d lines; at most %d", len(lines), MaxRecurrenceLines)
		}
		for _, l := range lines {
			if !recurrenceRE.MatchString(l) {
				return false, false, invalid("recurrence lines must start with RRULE:, EXRULE:, RDATE or EXDATE (%q does not)", l)
			}
		}
		ev.Recurrence, changed = lines, true
		if len(lines) == 0 {
			ev.ForceSendFields = append(ev.ForceSendFields, "Recurrence")
		}
	}
	overrides, remGiven, err := reminderList(args, "reminders")
	if err != nil {
		return false, false, err
	}
	useDefault, defGiven := args["use_default_reminders"]
	if defGiven && useDefault != nil {
		b, ok := useDefault.(bool)
		if !ok {
			return false, false, invalid("use_default_reminders must be a boolean")
		}
		if b && len(overrides) > 0 {
			return false, false, invalid("use_default_reminders true and reminders exclude each other")
		}
		ev.Reminders = &calendar.EventReminders{UseDefault: b, ForceSendFields: []string{"UseDefault"}}
		changed = true
	}
	if remGiven {
		ev.Reminders = &calendar.EventReminders{Overrides: overrides, ForceSendFields: []string{"UseDefault"}}
		if len(overrides) == 0 {
			ev.Reminders.ForceSendFields = append(ev.Reminders.ForceSendFields, "Overrides")
		}
		changed = true
	}
	color, given, err := colorIDArg(args, maxEventColorID)
	if err != nil {
		return false, false, err
	}
	if given {
		ev.ColorId, changed = color, true
	}
	if ev.Visibility, given, err = enumArg(args, "visibility", visibilityValues); err != nil {
		return false, false, err
	} else if given {
		changed = true
	}
	if ev.Transparency, given, err = enumArg(args, "transparency", transparencyValues); err != nil {
		return false, false, err
	} else if given {
		changed = true
	}
	if _, ok := args["attachments"]; ok {
		urls, err := stringList(args, "attachments")
		if err != nil {
			return false, false, err
		}
		if len(urls) > MaxEventAttachments {
			return false, false, invalid("attachments has %d files; at most %d", len(urls), MaxEventAttachments)
		}
		for _, u := range urls {
			if !strings.HasPrefix(u, "https://drive.google.com/") && !strings.HasPrefix(u, "https://docs.google.com/") {
				return false, false, invalid("attachments must be Google Drive file URLs (%q is not)", u)
			}
			ev.Attachments = append(ev.Attachments, &calendar.EventAttachment{FileUrl: u})
		}
		if len(urls) == 0 {
			ev.ForceSendFields = append(ev.ForceSendFields, "Attachments")
		}
		changed, attachments = true, true
	}
	for _, g := range []struct {
		name  string
		field string
		set   func(bool)
	}{
		{"guests_can_modify", "GuestsCanModify", func(b bool) { ev.GuestsCanModify = b }},
		{"guests_can_invite_others", "GuestsCanInviteOthers", func(b bool) { ev.GuestsCanInviteOthers = &b }},
		{"guests_can_see_other_guests", "GuestsCanSeeOtherGuests", func(b bool) { ev.GuestsCanSeeOtherGuests = &b }},
	} {
		if v, ok := args[g.name]; ok && v != nil {
			b, ok := v.(bool)
			if !ok {
				return false, false, invalid("%s must be a boolean", g.name)
			}
			g.set(b)
			ev.ForceSendFields = append(ev.ForceSendFields, g.field)
			changed = true
		}
	}
	return changed, attachments, nil
}

// destinationArg reads move_event's destination (another calendar).
func destinationArg(args map[string]any, source string) (string, error) {
	d, err := idArg(args, "destination")
	if err != nil {
		return "", err
	}
	d = strings.ToLower(d)
	if d == source {
		return "", invalid("destination must be another calendar than calendar_id")
	}
	return d, nil
}

// ownCalendarArg reads a required calendar_id, refusing "primary" when
// noPrimary (what Google never allows for the operation).
func ownCalendarArg(args map[string]any, noPrimary bool, why string) (string, error) {
	id, err := idArg(args, "calendar_id")
	if err != nil {
		return "", err
	}
	id = strings.ToLower(id)
	if noPrimary && id == DefaultCalendar {
		return "", invalid("%s", why)
	}
	return id, nil
}

// --- reads ------------------------------------------------------------------------------

func (c *Connector) listInstances(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	calendarID, err := calendarArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	eventID, err := idArg(call.Args, "event_id")
	if err != nil {
		return connectors.Result{}, err
	}
	timeMin, err := optionalTime(call.Args, "time_min")
	if err != nil {
		return connectors.Result{}, err
	}
	timeMax, err := optionalTime(call.Args, "time_max")
	if err != nil {
		return connectors.Result{}, err
	}
	if !timeMin.IsZero() && !timeMax.IsZero() && !timeMax.After(timeMin) {
		return connectors.Result{}, invalid("time_max must be after time_min")
	}
	maxResults, pageToken, clamped, err := c.pageArgs(call.Args, defaultEventsPerPage)
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.calendar(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	req := svc.Events.Instances(calendarID, eventID).Context(ctx).MaxResults(int64(maxResults))
	if !timeMin.IsZero() {
		req = req.TimeMin(timeMin.Format(time.RFC3339))
	}
	if !timeMax.IsZero() {
		req = req.TimeMax(timeMax.Format(time.RFC3339))
	}
	if pageToken != "" {
		req = req.PageToken(pageToken)
	}
	events, err := req.Do()
	if err := classify("list event instances", err); err != nil {
		return connectors.Result{}, err
	}
	out := InstancesPage{EventID: eventID, EventsPage: EventsPage{
		CalendarID: calendarID, TimeZone: events.TimeZone, MaxResults: maxResults, NextPageToken: events.NextPageToken,
		HasMore: events.NextPageToken != "", Items: make([]Event, 0, len(events.Items)),
	}}
	if !timeMin.IsZero() {
		out.TimeMin = timeMin.Format(time.RFC3339)
	}
	if !timeMax.IsZero() {
		out.TimeMax = timeMax.Format(time.RFC3339)
	}
	for _, ev := range events.Items {
		if ev != nil {
			out.Items = append(out.Items, toEvent(ev, calendarID))
		}
	}
	res := connectors.Result{Partial: clamped, Empty: len(out.Items) == 0}
	for encodedSize(out) > c.bounds.MaxResultBytes && len(out.Items) > 1 {
		out.Items = out.Items[:len(out.Items)-1]
		out.Truncated, res.Partial = true, true
	}
	res.Content = out
	return res, nil
}

func (c *Connector) listACL(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	calendarID, err := calendarArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	maxResults, pageToken, clamped, err := c.pageArgs(call.Args, connectors.DefaultMaxPageSize)
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.calendar(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	req := svc.Acl.List(calendarID).Context(ctx).MaxResults(int64(maxResults))
	if pageToken != "" {
		req = req.PageToken(pageToken)
	}
	list, err := req.Do()
	if err := classify("list calendar sharing", err); err != nil {
		return connectors.Result{}, err
	}
	out := ACLPage{CalendarID: calendarID, MaxResults: maxResults, NextPageToken: list.NextPageToken, HasMore: list.NextPageToken != "", Items: make([]ACLRule, 0, len(list.Items))}
	for _, r := range list.Items {
		if r == nil {
			continue
		}
		item := ACLRule{RuleID: r.Id, Role: r.Role}
		if r.Scope != nil {
			item.ScopeType, item.ScopeValue = r.Scope.Type, r.Scope.Value
		}
		out.Items = append(out.Items, item)
	}
	res := connectors.Result{Partial: clamped, Empty: len(out.Items) == 0}
	for encodedSize(out) > c.bounds.MaxResultBytes && len(out.Items) > 1 {
		out.Items = out.Items[:len(out.Items)-1]
		out.Truncated, res.Partial = true, true
	}
	res.Content = out
	return res, nil
}

// palette flattens a colors map, ordered by numeric id.
func palette(m map[string]calendar.ColorDefinition) []Color {
	out := make([]Color, 0, len(m))
	for id, d := range m {
		out = append(out, Color{ID: id, Background: d.Background, Foreground: d.Foreground})
	}
	sort.Slice(out, func(i, j int) bool {
		a, errA := strconv.Atoi(out[i].ID)
		b, errB := strconv.Atoi(out[j].ID)
		if errA != nil || errB != nil {
			return out[i].ID < out[j].ID
		}
		return a < b
	})
	return out
}

func (c *Connector) getColors(ctx context.Context, cl *client, _ connectors.Call) (connectors.Result, error) {
	svc, err := cl.calendar(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	colors, err := svc.Colors.Get().Context(ctx).Do()
	if err := classify("get calendar colors", err); err != nil {
		return connectors.Result{}, err
	}
	out := Colors{Calendar: palette(colors.Calendar), Event: palette(colors.Event)}
	return connectors.Result{Content: out, Empty: len(out.Calendar)+len(out.Event) == 0}, nil
}

func (c *Connector) getSettings(ctx context.Context, cl *client, _ connectors.Call) (connectors.Result, error) {
	svc, err := cl.calendar(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	out := Settings{Items: []Setting{}}
	res := connectors.Result{}
	pageToken := ""
	for page := 1; ; page++ {
		req := svc.Settings.List().Context(ctx)
		if pageToken != "" {
			req = req.PageToken(pageToken)
		}
		list, err := req.Do()
		if err := classify("get calendar settings", err); err != nil {
			return connectors.Result{}, err
		}
		for _, s := range list.Items {
			if s != nil {
				out.Items = append(out.Items, Setting{ID: s.Id, Value: s.Value})
			}
		}
		if pageToken = list.NextPageToken; pageToken == "" {
			break
		}
		if page == maxSettingsPages {
			out.Truncated, res.Partial = true, true
			break
		}
	}
	for encodedSize(out) > c.bounds.MaxResultBytes && len(out.Items) > 1 {
		out.Items = out.Items[:len(out.Items)-1]
		out.Truncated, res.Partial = true, true
	}
	res.Content, res.Empty = out, len(out.Items) == 0
	return res, nil
}

// --- writes -------------------------------------------------------------------------------

func (c *Connector) quickAdd(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	calendarID, err := calendarArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	text, err := requiredString(call.Args, "text")
	if err != nil {
		return connectors.Result{}, err
	}
	sendUpdates, err := sendUpdatesArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.calendar(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	created, err := svc.Events.QuickAdd(calendarID, text).Context(ctx).SendUpdates(sendUpdates).Do()
	if err := classifyWrite("quick add event", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: toCreatedEvent(created, calendarID)}, nil
}

func (c *Connector) moveEvent(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	calendarID, err := calendarArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	eventID, err := idArg(call.Args, "event_id")
	if err != nil {
		return connectors.Result{}, err
	}
	destination, err := destinationArg(call.Args, calendarID)
	if err != nil {
		return connectors.Result{}, err
	}
	sendUpdates, err := sendUpdatesArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.calendar(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	moved, err := svc.Events.Move(calendarID, eventID, destination).Context(ctx).SendUpdates(sendUpdates).Do()
	if err := classifyWrite("move event", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: toCreatedEvent(moved, destination)}, nil
}

// calendarFields reads update_calendar's / create_calendar's fields into
// cal; changed says whether any was given.
func calendarFields(args map[string]any, cal *calendar.Calendar) (changed bool, err error) {
	for _, f := range []struct {
		name, field string
		set         func(string)
		clearable   bool
	}{
		{"summary", "Summary", func(v string) { cal.Summary = v }, false},
		{"description", "Description", func(v string) { cal.Description = v }, true},
		{"location", "Location", func(v string) { cal.Location = v }, true},
		{"time_zone", "TimeZone", func(v string) { cal.TimeZone = v }, false},
	} {
		if v, ok := args[f.name]; !ok || v == nil {
			continue
		}
		v, err := optionalString(args, f.name)
		if err != nil {
			return false, err
		}
		if !f.clearable {
			v = strings.TrimSpace(v)
			if v == "" {
				return false, invalid("%s must not be blank", f.name)
			}
		}
		f.set(v)
		if v == "" {
			cal.ForceSendFields = append(cal.ForceSendFields, f.field)
		}
		changed = true
	}
	return changed, nil
}

func (c *Connector) createCalendar(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	if _, err := requiredString(call.Args, "summary"); err != nil {
		return connectors.Result{}, err
	}
	cal := &calendar.Calendar{}
	if _, err := calendarFields(call.Args, cal); err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.calendar(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	created, err := svc.Calendars.Insert(cal).Context(ctx).Do()
	if err := classifyWrite("create calendar", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: CalendarChange{ID: created.Id, TimeZone: created.TimeZone}}, nil
}

func (c *Connector) updateCalendar(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	calendarID, err := calendarArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	patch := &calendar.Calendar{}
	changed, err := calendarFields(call.Args, patch)
	if err != nil {
		return connectors.Result{}, err
	}
	if !changed {
		return connectors.Result{}, invalid("nothing to change: give at least one of summary, description, location or time_zone")
	}
	svc, err := cl.calendar(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	updated, err := svc.Calendars.Patch(calendarID, patch).Context(ctx).Do()
	if err := classifyWrite("update calendar", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: CalendarChange{ID: calendarID, TimeZone: updated.TimeZone}}, nil
}

func (c *Connector) deleteCalendar(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	calendarID, err := ownCalendarArg(call.Args, true, "the primary calendar cannot be deleted; clear_calendar deletes its events")
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.calendar(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	if err := classifyWrite("delete calendar", svc.Calendars.Delete(calendarID).Context(ctx).Do()); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: CalendarChange{ID: calendarID, Deleted: true}}, nil
}

func (c *Connector) clearCalendar(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	calendarID, err := calendarArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	if calendarID != DefaultCalendar {
		return connectors.Result{}, invalid("Google clears the primary calendar only; delete_calendar deletes a secondary calendar")
	}
	svc, err := cl.calendar(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	if err := classifyWrite("clear calendar", svc.Calendars.Clear(calendarID).Context(ctx).Do()); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: CalendarChange{ID: calendarID, Cleared: true}}, nil
}

// listEntryFields reads the calendar-list fields into e; changed says
// whether any was given.
func listEntryFields(args map[string]any, e *calendar.CalendarListEntry) (changed bool, err error) {
	color, given, err := colorIDArg(args, maxCalendarColorID)
	if err != nil {
		return false, err
	}
	if given {
		e.ColorId, changed = color, true
	}
	for _, f := range []struct {
		name, field string
		set         func(bool)
	}{
		{"hidden", "Hidden", func(b bool) { e.Hidden = b }},
		{"selected", "Selected", func(b bool) { e.Selected = b }},
	} {
		if v, ok := args[f.name]; ok && v != nil {
			b, ok := v.(bool)
			if !ok {
				return false, invalid("%s must be a boolean", f.name)
			}
			f.set(b)
			e.ForceSendFields = append(e.ForceSendFields, f.field)
			changed = true
		}
	}
	if v, ok := args["summary_override"]; ok && v != nil {
		s, err := optionalString(args, "summary_override")
		if err != nil {
			return false, err
		}
		e.SummaryOverride = strings.TrimSpace(s)
		if e.SummaryOverride == "" {
			e.ForceSendFields = append(e.ForceSendFields, "SummaryOverride")
		}
		changed = true
	}
	reminders, given, err := reminderList(args, "default_reminders")
	if err != nil {
		return false, err
	}
	if given {
		e.DefaultReminders, changed = reminders, true
		if len(reminders) == 0 {
			e.ForceSendFields = append(e.ForceSendFields, "DefaultReminders")
		}
	}
	return changed, nil
}

func toCalendarChange(e *calendar.CalendarListEntry, id string) CalendarChange {
	hidden, selected := e.Hidden, e.Selected
	return CalendarChange{ID: id, TimeZone: e.TimeZone, ColorID: e.ColorId, Hidden: &hidden, Selected: &selected}
}

func (c *Connector) subscribeCalendar(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	calendarID, err := ownCalendarArg(call.Args, false, "")
	if err != nil {
		return connectors.Result{}, err
	}
	entry := &calendar.CalendarListEntry{Id: calendarID}
	if _, err := listEntryFields(call.Args, entry); err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.calendar(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	added, err := svc.CalendarList.Insert(entry).Context(ctx).Do()
	if err := classifyWrite("add calendar to the list", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: toCalendarChange(added, calendarID)}, nil
}

func (c *Connector) unsubscribeCalendar(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	calendarID, err := ownCalendarArg(call.Args, true, "the primary calendar cannot be removed from the calendar list")
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.calendar(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	if err := classifyWrite("remove calendar from the list", svc.CalendarList.Delete(calendarID).Context(ctx).Do()); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: CalendarChange{ID: calendarID, Removed: true}}, nil
}

func (c *Connector) updateCalendarListEntry(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	calendarID, err := calendarArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	patch := &calendar.CalendarListEntry{}
	changed, err := listEntryFields(call.Args, patch)
	if err != nil {
		return connectors.Result{}, err
	}
	if !changed {
		return connectors.Result{}, invalid("nothing to change: give at least one of color_id, hidden, selected, summary_override or default_reminders")
	}
	svc, err := cl.calendar(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	updated, err := svc.CalendarList.Patch(calendarID, patch).Context(ctx).Do()
	if err := classifyWrite("update calendar list entry", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: toCalendarChange(updated, calendarID)}, nil
}

// roleArg reads a required ACL role.
func roleArg(args map[string]any) (string, error) {
	role, err := requiredString(args, "role")
	if err != nil {
		return "", err
	}
	if !slices.Contains(aclRoleValues, role) {
		return "", invalid("role must be freeBusyReader, reader, writer or owner")
	}
	return role, nil
}

func toACLChange(r *calendar.AclRule, calendarID string) ACLChange {
	out := ACLChange{CalendarID: calendarID, RuleID: r.Id, Role: r.Role}
	if r.Scope != nil {
		out.ScopeType = r.Scope.Type
	}
	return out
}

func (c *Connector) shareCalendar(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	calendarID, err := calendarArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	role, err := roleArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	scopeType, value, err := aclGrantee(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	notify, err := optionalBool(call.Args, "send_notifications", true)
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.calendar(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	rule := &calendar.AclRule{Role: role, Scope: &calendar.AclRuleScope{Type: scopeType, Value: value}}
	created, err := svc.Acl.Insert(calendarID, rule).Context(ctx).SendNotifications(notify).Do()
	if err := classifyWrite("share calendar", err); err != nil {
		return connectors.Result{}, err
	}
	out := toACLChange(created, calendarID)
	if out.RuleID == "" {
		out.RuleID = aclRuleID(scopeType, value)
	}
	return connectors.Result{Content: out}, nil
}

func (c *Connector) updateACL(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	calendarID, err := calendarArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	ruleID, err := idArg(call.Args, "rule_id")
	if err != nil {
		return connectors.Result{}, err
	}
	role, err := roleArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.calendar(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	updated, err := svc.Acl.Patch(calendarID, ruleID, &calendar.AclRule{Role: role}).Context(ctx).Do()
	if err := classifyWrite("update calendar sharing", err); err != nil {
		return connectors.Result{}, err
	}
	out := toACLChange(updated, calendarID)
	if out.RuleID == "" {
		out.RuleID = ruleID
	}
	return connectors.Result{Content: out}, nil
}

func (c *Connector) unshareCalendar(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	calendarID, err := calendarArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	ruleID, err := idArg(call.Args, "rule_id")
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.calendar(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	if err := classifyWrite("unshare calendar", svc.Acl.Delete(calendarID, ruleID).Context(ctx).Do()); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: ACLChange{CalendarID: calendarID, RuleID: ruleID, Deleted: true}}, nil
}

// --- reconciliation ------------------------------------------------------------------------

// identityCalendar reads a calendar id the identity holds under key.
func identityCalendar(in connectors.ReconcileInput, key string) (string, error) {
	id := strings.ToLower(strings.TrimSpace(in.ResourceIdentity[key]))
	if id == "" || !idRE.MatchString(id) {
		return "", fmt.Errorf("%w: resource identity has no %s", ErrNotReconcilable, key)
	}
	return id, nil
}

// isGone reports a 404 or 410 from Google.
func isGone(err error) bool {
	s := statusOf(err)
	return s == http.StatusNotFound || s == http.StatusGone
}

// checkEventMoved is move_event's stable-id check (Calendar keeps the
// event id across calendars): the event present in the destination is
// found; absent there but still in the source is not_found; absent from
// both, cancelled, or any error is "cannot tell yet".
func (c *Connector) checkEventMoved(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	tg, err := c.target(in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	source, err := identityCalendar(in, "calendar_id")
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	destination, err := identityCalendar(in, "destination")
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	eventID := strings.TrimSpace(in.ResourceIdentity["event_id"])
	if eventID == "" || !idRE.MatchString(eventID) {
		return connectors.ReconcileResult{}, fmt.Errorf("%w: resource identity has no event", ErrNotReconcilable)
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	svc, err := tg.client.calendar(ctx)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	ev, err := svc.Events.Get(destination, eventID).Context(ctx).Do()
	if err := classify("reconcile: get moved event", err); err == nil {
		if ev.Status == "cancelled" {
			return connectors.ReconcileResult{}, fmt.Errorf("google: reconcile: the event is cancelled in the destination; cannot tell")
		}
		return found(eventID), nil
	} else if !isGone(err) {
		return connectors.ReconcileResult{}, err
	}
	ev, err = svc.Events.Get(source, eventID).Context(ctx).Do()
	if err := classify("reconcile: get event in the source calendar", err); err != nil {
		if isGone(err) {
			return connectors.ReconcileResult{}, fmt.Errorf("google: reconcile: the event is in neither calendar; cannot tell")
		}
		return connectors.ReconcileResult{}, err
	}
	if ev.Status == "cancelled" {
		return connectors.ReconcileResult{}, fmt.Errorf("google: reconcile: the event is cancelled in the source; cannot tell")
	}
	return notFound, nil
}

// checkCalendarDeleted: calendars.get 404/410 is found; present is
// not_found.
func (c *Connector) checkCalendarDeleted(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	tg, err := c.target(in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	calendarID, err := identityCalendar(in, "calendar_id")
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	svc, err := tg.client.calendar(ctx)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	_, err = svc.Calendars.Get(calendarID).Context(ctx).Do()
	if err := classify("reconcile: get calendar", err); err != nil {
		if isGone(err) {
			return found(calendarID), nil
		}
		return connectors.ReconcileResult{}, err
	}
	return notFound, nil
}

// checkCalendarCleared: the primary calendar without any event is found;
// an event left could be one created after the clear, so it is "cannot
// tell" (never not_found). The listing needs an events read scope.
func (c *Connector) checkCalendarCleared(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	tg, err := c.target(in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	calendarID, err := identityCalendar(in, "calendar_id")
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	svc, err := tg.client.calendar(ctx)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	list, err := svc.Events.List(calendarID).Context(ctx).MaxResults(1).Do()
	if err := classify("reconcile: list events", err); err != nil {
		return connectors.ReconcileResult{}, err
	}
	if len(list.Items) == 0 {
		return found(calendarID), nil
	}
	return connectors.ReconcileResult{}, fmt.Errorf("google: reconcile: the calendar has events (perhaps created since); cannot tell")
}

// calendarListEntry fetches the account's list entry of the identity's
// calendar; gone is a 404/410.
func (c *Connector) calendarListEntry(ctx context.Context, in connectors.ReconcileInput) (calendarID string, gone bool, err error) {
	tg, err := c.target(in)
	if err != nil {
		return "", false, err
	}
	if calendarID, err = identityCalendar(in, "calendar_id"); err != nil {
		return "", false, err
	}
	svc, err := tg.client.calendar(ctx)
	if err != nil {
		return "", false, err
	}
	_, err = svc.CalendarList.Get(calendarID).Context(ctx).Do()
	if err := classify("reconcile: get calendar list entry", err); err != nil {
		if isGone(err) {
			return calendarID, true, nil
		}
		return "", false, err
	}
	return calendarID, false, nil
}

func (c *Connector) checkSubscribed(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	id, gone, err := c.calendarListEntry(ctx, in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	if gone {
		return notFound, nil
	}
	return found(id), nil
}

func (c *Connector) checkUnsubscribed(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	id, gone, err := c.calendarListEntry(ctx, in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	if gone {
		return found(id), nil
	}
	return notFound, nil
}

// findACLRule lists the calendar's ACL (bounded by MaxReconcilePages)
// for the rule whose ACLRuleKey is the identity's rule_key: nil when
// the whole ACL was read without it; running out of pages is an error.
func (c *Connector) findACLRule(ctx context.Context, in connectors.ReconcileInput) (rule *calendar.AclRule, err error) {
	tg, err := c.target(in)
	if err != nil {
		return nil, err
	}
	calendarID, err := identityCalendar(in, "calendar_id")
	if err != nil {
		return nil, err
	}
	key := strings.TrimSpace(in.ResourceIdentity["rule_key"])
	if key == "" {
		return nil, fmt.Errorf("%w: resource identity has no rule_key", ErrNotReconcilable)
	}
	svc, err := tg.client.calendar(ctx)
	if err != nil {
		return nil, err
	}
	pageToken := ""
	for page := 1; page <= MaxReconcilePages; page++ {
		req := svc.Acl.List(calendarID).Context(ctx).MaxResults(aclPerPage)
		if pageToken != "" {
			req = req.PageToken(pageToken)
		}
		list, err := req.Do()
		if err := classify("reconcile: list calendar sharing", err); err != nil {
			return nil, err
		}
		for _, r := range list.Items {
			if r != nil && ACLRuleKey(r.Id) == key {
				return r, nil
			}
		}
		if pageToken = list.NextPageToken; pageToken == "" {
			return nil, nil
		}
	}
	return nil, fmt.Errorf("google: reconcile: more than %d pages of sharing rules; cannot tell yet", MaxReconcilePages)
}

// checkACLRole (share_calendar, update_acl): the rule with the
// identity's role is found; another role or no rule is not_found.
func (c *Connector) checkACLRole(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	want := in.ResourceIdentity["role"]
	if !slices.Contains(aclRoleValues, want) {
		return connectors.ReconcileResult{}, fmt.Errorf("%w: resource identity has no role", ErrNotReconcilable)
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	rule, err := c.findACLRule(ctx, in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	if rule != nil && rule.Role == want {
		return found(rule.Id), nil
	}
	return notFound, nil
}

// checkACLRemoved (unshare_calendar): no rule (or role none, as the
// default rule reads once removed) is found, named by the rule key (the
// identity never holds the address); a rule with a role is not_found.
func (c *Connector) checkACLRemoved(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	rule, err := c.findACLRule(ctx, in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	if rule == nil {
		return found(in.ResourceIdentity["rule_key"]), nil
	}
	if rule.Role == "none" {
		return found(rule.Id), nil
	}
	return notFound, nil
}
