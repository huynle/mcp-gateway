package google

import (
	"context"
	"fmt"
	"net/http"
	"net/mail"
	"slices"
	"sort"
	"strings"
	"time"

	"google.golang.org/api/calendar/v3"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Calendar management tool names.
const (
	ToolListCalendars  = "list_calendars"
	ToolFreeBusy       = "free_busy"
	ToolUpdateEvent    = "update_event"
	ToolDeleteEvent    = "delete_event"
	ToolRespondToEvent = "respond_to_event"
)

// MaxFreeBusyCalendars is the Calendar API's ceiling of calendars per
// freebusy.query.
const MaxFreeBusyCalendars = 50

// EventMarkerKey is the private extended property update_event sets on
// the event it patches; its value is the ledger operation id, so the
// reconciler can tell whether the patch took effect.
const EventMarkerKey = "mcp-gateway-op"

// Values of respond_to_event's response.
var responseValues = []string{"accepted", "declined", "tentative"}

// CalendarEntry is one list_calendars item.
type CalendarEntry struct {
	ID          string `json:"id"`
	Summary     string `json:"summary"`
	Description string `json:"description,omitempty"`
	TimeZone    string `json:"time_zone,omitempty"`
	AccessRole  string `json:"access_role,omitempty"`
	Primary     bool   `json:"primary,omitempty"`
	Selected    bool   `json:"selected,omitempty"`
	Hidden      bool   `json:"hidden,omitempty"`
}

// CalendarsPage is list_calendars's result.
type CalendarsPage struct {
	MaxResults    int             `json:"max_results"`
	NextPageToken string          `json:"next_page_token,omitempty"`
	HasMore       bool            `json:"has_more"`
	Truncated     bool            `json:"truncated,omitempty"`
	Items         []CalendarEntry `json:"items"`
}

// BusyPeriod is one busy interval (RFC 3339).
type BusyPeriod struct {
	Start string `json:"start"`
	End   string `json:"end"`
}

// CalendarBusy is one calendar of free_busy's result; Errors carries
// Google's reasons when it could not read the calendar.
type CalendarBusy struct {
	ID     string       `json:"id"`
	Busy   []BusyPeriod `json:"busy"`
	Errors []string     `json:"errors,omitempty"`
}

// FreeBusy is free_busy's result, calendars in the order asked.
type FreeBusy struct {
	TimeMin   string         `json:"time_min"`
	TimeMax   string         `json:"time_max"`
	Calendars []CalendarBusy `json:"calendars"`
	Truncated bool           `json:"truncated,omitempty"`
}

// DeletedEvent is delete_event's result.
type DeletedEvent struct {
	ID         string `json:"id"`
	CalendarID string `json:"calendar_id"`
	Deleted    bool   `json:"deleted"`
}

// EventResponse is respond_to_event's result.
type EventResponse struct {
	ID         string `json:"id"`
	CalendarID string `json:"calendar_id"`
	Response   string `json:"response"`
	URL        string `json:"url,omitempty"`
}

var (
	eventIDProperty     = property{"event_id", "string", "The event's id (from list_events).", nil}
	sendUpdatesProperty = property{"send_updates", "string", "Whether Google emails the attendees: all, externalOnly or none (default).", sendUpdatesValues}
)

func (c *Connector) calendarManageReadTools() []connectors.Tool {
	return []connectors.Tool{
		{
			App: AppCalendar, Name: ToolListCalendars, Kind: connectors.KindRead,
			Description: "List the calendars in the account's calendar list: id, summary, description, time_zone, access_role " +
				"(owner, writer, reader, freeBusyReader), primary, selected and hidden. Hidden calendars are left out unless show_hidden is true. " +
				"Use an id as calendar_id of the other calendar tools. has_more and next_page_token say whether another page exists.",
			InputSchema: objectSchema([]property{
				{"show_hidden", "boolean", "Include calendars hidden from the list. Default false.", nil},
				{"max_results", "integer", "Calendars per page (1-100; default 50); clamped to the tool's maximum.", nil},
				{"page_token", "string", "Token of the page to fetch (next_page_token of the previous result).", nil},
			}, nil),
			RequiredScopes:   []string{ScopeCalendarListReadonly},
			ResourceIdentity: func(map[string]any) map[string]string { return map[string]string{} },
			Bounds:           c.pagedBounds(),
		},
		{
			App: AppCalendar, Name: ToolFreeBusy, Kind: connectors.KindRead,
			Description: "Get the busy periods of one or more calendars (the primary calendar by default; at most 50, e.g. colleagues' " +
				"email addresses) between time_min and time_max (RFC 3339). Each calendar lists busy intervals; errors says Google could not " +
				"read that calendar (no access, not found). Use it to find a free slot before create_event.",
			InputSchema: objectSchema([]property{
				{"time_min", "string", "Start of the interval, RFC 3339 such as 2026-10-09T00:00:00Z.", nil},
				{"time_max", "string", "End of the interval, RFC 3339.", nil},
				{"calendar_ids", "array", "Calendar ids or email addresses to query; [\"primary\"] when omitted.", nil},
				{"time_zone", "string", "IANA time zone of the answer (UTC when omitted).", nil},
			}, []string{"time_min", "time_max"}),
			RequiredScopes:   []string{ScopeCalendarFreeBusy},
			ResourceIdentity: freeBusyIdentity,
			Bounds:           c.singleBounds(),
		},
	}
}

func (c *Connector) calendarManageReadHandlers() map[string]handler {
	return map[string]handler{ToolListCalendars: c.listCalendars, ToolFreeBusy: c.freeBusy}
}

func (c *Connector) calendarManageWriteTools() []connectors.Tool {
	return []connectors.Tool{
		{
			App: AppCalendar, Name: ToolUpdateEvent, Kind: connectors.KindWrite,
			Description: "Change an event of a Google Calendar: only the fields given are changed (summary, description, location, " +
				"start and end in the same form as create_event, time_zone, attendees: the new full list of addresses). " +
				"send_updates says whether Google emails the attendees (default none). add_meet_link adds a Google Meet video link " +
				"(an event that already has one keeps it); recurrence, reminders, use_default_reminders, color_id, visibility, transparency, " +
				"attachments and guests_can_* change those fields. Returns the event's id and url (and meet_url).",
			InputSchema: objectSchema(append([]property{
				calendarIDProperty, eventIDProperty,
				{"summary", "string", "New title.", nil},
				{"description", "string", "New description (empty clears it).", nil},
				{"location", "string", "New location (empty clears it).", nil},
				{"start", "string", "New start: RFC 3339 timestamp or date (all-day).", nil},
				{"end", "string", "New end (exclusive): same form as start.", nil},
				{"time_zone", "string", "IANA time zone of start and end.", nil},
				{"attendees", "array", "The new full list of attendee email addresses (replaces the current list).", nil},
				sendUpdatesProperty,
				addMeetLinkProperty,
			}, eventExtraProperties...), []string{"event_id"}),
			RequiredScopes:   []string{ScopeCalendarEvents},
			ResourceIdentity: calendarIdentity(true),
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileMarker, Check: c.checkEventMarker},
			ResultIDs:        eventResultIDs,
			Bounds:           c.singleBounds(),
		},
		{
			App: AppCalendar, Name: ToolDeleteEvent, Kind: connectors.KindWrite,
			Description: "Delete (cancel) an event of a Google Calendar. send_updates says whether Google emails the attendees the cancellation " +
				"(default none). For a recurring event, the id of one instance deletes that instance; the series id deletes the series.",
			InputSchema:      objectSchema([]property{calendarIDProperty, eventIDProperty, sendUpdatesProperty}, []string{"event_id"}),
			RequiredScopes:   []string{ScopeCalendarEvents},
			ResourceIdentity: calendarIdentity(true),
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: c.checkEventDeleted},
			ResultIDs:        deletedEventResultIDs,
			Bounds:           c.singleBounds(),
		},
		{
			App: AppCalendar, Name: ToolRespondToEvent, Kind: connectors.KindWrite,
			Description: "Answer an invitation: set the account's own attendee response of an event to accepted, declined or tentative, " +
				"optionally with a comment. send_updates says whether Google emails the organizer (default none). The account must be an attendee.",
			InputSchema: objectSchema([]property{
				calendarIDProperty, eventIDProperty,
				{"response", "string", "accepted, declined or tentative.", responseValues},
				{"comment", "string", "Optional note to the organizer.", nil},
				sendUpdatesProperty,
			}, []string{"event_id", "response"}),
			RequiredScopes:   []string{ScopeCalendarEvents},
			ResourceIdentity: respondIdentity,
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: c.checkEventResponse},
			ResultIDs:        eventResponseResultIDs,
			Bounds:           c.singleBounds(),
		},
	}
}

func (c *Connector) calendarManageWriteHandlers() map[string]handler {
	return map[string]handler{ToolUpdateEvent: c.updateEvent, ToolDeleteEvent: c.deleteEvent, ToolRespondToEvent: c.respondToEvent}
}

// freeBusyIdentity extracts calendar_ids (sorted, unique, lower-cased,
// comma separated; "primary" when omitted) and domains (their domains).
func freeBusyIdentity(args map[string]any) map[string]string {
	ids, _ := stringList(args, "calendar_ids")
	if len(ids) == 0 {
		ids = []string{DefaultCalendar}
	}
	seen, domainSeen := map[string]bool{}, map[string]bool{}
	var list, domains []string
	for _, id := range ids {
		id = strings.ToLower(id)
		if !seen[id] {
			seen[id] = true
			list = append(list, id)
		}
		if d := domainOf(id); d != "" && !domainSeen[d] {
			domainSeen[d] = true
			domains = append(domains, d)
		}
	}
	sort.Strings(list)
	sort.Strings(domains)
	out := map[string]string{"calendar_ids": strings.Join(list, ",")}
	if len(domains) > 0 {
		out["domains"] = strings.Join(domains, ",")
	}
	return out
}

// respondIdentity is calendarIdentity(true) plus the response.
func respondIdentity(args map[string]any) map[string]string {
	out := calendarIdentity(true)(args)
	if r, _ := args["response"].(string); slices.Contains(responseValues, strings.TrimSpace(r)) {
		out["response"] = strings.TrimSpace(r)
	}
	return out
}

func deletedEventResultIDs(res connectors.Result) map[string]string {
	v, ok := res.Content.(DeletedEvent)
	if !ok || v.ID == "" {
		return nil
	}
	return map[string]string{"id": v.ID}
}

func eventResponseResultIDs(res connectors.Result) map[string]string {
	v, ok := res.Content.(EventResponse)
	if !ok || v.ID == "" {
		return nil
	}
	return map[string]string{"id": v.ID, "response": v.Response}
}

// sendUpdatesArg reads send_updates ("none" when absent).
func sendUpdatesArg(args map[string]any) (string, error) {
	v, err := optionalString(args, "send_updates")
	if err != nil {
		return "", err
	}
	if v = strings.TrimSpace(v); v == "" {
		return "none", nil
	}
	if !slices.Contains(sendUpdatesValues, v) {
		return "", invalid("send_updates must be all, externalOnly or none")
	}
	return v, nil
}

// --- reads ------------------------------------------------------------------------

func (c *Connector) listCalendars(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	showHidden, err := optionalBool(call.Args, "show_hidden", false)
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
	req := svc.CalendarList.List().Context(ctx).MaxResults(int64(maxResults)).ShowHidden(showHidden)
	if pageToken != "" {
		req = req.PageToken(pageToken)
	}
	list, err := req.Do()
	if err := classify("list calendars", err); err != nil {
		return connectors.Result{}, err
	}
	out := CalendarsPage{MaxResults: maxResults, NextPageToken: list.NextPageToken, HasMore: list.NextPageToken != "", Items: make([]CalendarEntry, 0, len(list.Items))}
	for _, e := range list.Items {
		if e == nil {
			continue
		}
		summary := e.Summary
		if e.SummaryOverride != "" {
			summary = e.SummaryOverride
		}
		out.Items = append(out.Items, CalendarEntry{
			ID: e.Id, Summary: summary, Description: e.Description, TimeZone: e.TimeZone, AccessRole: e.AccessRole,
			Primary: e.Primary, Selected: e.Selected, Hidden: e.Hidden,
		})
	}
	res := connectors.Result{Partial: clamped, Empty: len(out.Items) == 0}
	for encodedSize(out) > c.bounds.MaxResultBytes && len(out.Items) > 1 {
		out.Items = out.Items[:len(out.Items)-1]
		out.Truncated, res.Partial = true, true
	}
	res.Content = out
	return res, nil
}

func (c *Connector) freeBusy(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	timeMin, err := optionalTime(call.Args, "time_min")
	if err != nil {
		return connectors.Result{}, err
	}
	timeMax, err := optionalTime(call.Args, "time_max")
	if err != nil {
		return connectors.Result{}, err
	}
	if timeMin.IsZero() || timeMax.IsZero() {
		return connectors.Result{}, invalid("time_min and time_max are required (RFC 3339)")
	}
	if !timeMax.After(timeMin) {
		return connectors.Result{}, invalid("time_max must be after time_min")
	}
	ids, err := stringList(call.Args, "calendar_ids")
	if err != nil {
		return connectors.Result{}, err
	}
	if len(ids) == 0 {
		ids = []string{DefaultCalendar}
	}
	if len(ids) > MaxFreeBusyCalendars {
		return connectors.Result{}, invalid("calendar_ids has %d calendars; at most %d per call", len(ids), MaxFreeBusyCalendars)
	}
	for _, id := range ids {
		if !idRE.MatchString(id) {
			return connectors.Result{}, invalid("calendar_ids must be calendar ids or email addresses (%q is not)", id)
		}
	}
	timeZone, err := optionalString(call.Args, "time_zone")
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.calendar(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	req := &calendar.FreeBusyRequest{TimeMin: timeMin.Format(time.RFC3339), TimeMax: timeMax.Format(time.RFC3339), TimeZone: strings.TrimSpace(timeZone)}
	for _, id := range ids {
		req.Items = append(req.Items, &calendar.FreeBusyRequestItem{Id: id})
	}
	resp, err := svc.Freebusy.Query(req).Context(ctx).Do()
	if err := classify("query free/busy", err); err != nil {
		return connectors.Result{}, err
	}
	out := FreeBusy{TimeMin: timeMin.UTC().Format(time.RFC3339), TimeMax: timeMax.UTC().Format(time.RFC3339), Calendars: make([]CalendarBusy, 0, len(ids))}
	res := connectors.Result{}
	for _, id := range ids {
		entry := CalendarBusy{ID: id, Busy: []BusyPeriod{}}
		fb, ok := resp.Calendars[id]
		if !ok {
			entry.Errors = []string{"notReturned"}
		}
		for _, p := range fb.Busy {
			if p != nil {
				entry.Busy = append(entry.Busy, BusyPeriod{Start: normalizeTimestamp(p.Start), End: normalizeTimestamp(p.End)})
			}
		}
		for _, e := range fb.Errors {
			if e != nil {
				entry.Errors = append(entry.Errors, e.Reason)
			}
		}
		if len(entry.Errors) > 0 {
			res.Partial = true
		}
		out.Calendars = append(out.Calendars, entry)
	}
	for encodedSize(out) > c.bounds.MaxResultBytes && len(out.Calendars) > 1 {
		out.Calendars = out.Calendars[:len(out.Calendars)-1]
		out.Truncated, res.Partial = true, true
	}
	res.Content = out
	return res, nil
}

// --- writes -----------------------------------------------------------------------

// optionalEventTime is eventTime for an optional argument.
func optionalEventTime(args map[string]any, name string) (value string, allDay bool, at time.Time, given bool, err error) {
	if v, _ := args[name].(string); strings.TrimSpace(v) == "" {
		return "", false, time.Time{}, false, nil
	}
	value, allDay, at, err = eventTime(args, name)
	return value, allDay, at, true, err
}

// updateEvent reads the event (a read: its failure is a known outcome),
// then patches the fields given plus the operation's marker in the
// private extended properties, merged with the ones the event has.
func (c *Connector) updateEvent(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	calendarID, err := calendarArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	eventID, err := idArg(call.Args, "event_id")
	if err != nil {
		return connectors.Result{}, err
	}
	patch := &calendar.Event{}
	changed := false
	for _, f := range []struct {
		name string
		set  func(string)
	}{
		{"summary", func(v string) { patch.Summary = v }},
		{"description", func(v string) {
			patch.Description = v
			if v == "" {
				patch.ForceSendFields = append(patch.ForceSendFields, "Description")
			}
		}},
		{"location", func(v string) {
			patch.Location = v
			if v == "" {
				patch.ForceSendFields = append(patch.ForceSendFields, "Location")
			}
		}},
	} {
		if _, ok := call.Args[f.name]; !ok {
			continue
		}
		v, err := optionalString(call.Args, f.name)
		if err != nil {
			return connectors.Result{}, err
		}
		f.set(v)
		changed = true
	}
	if _, ok := call.Args["summary"]; ok && strings.TrimSpace(patch.Summary) == "" {
		return connectors.Result{}, invalid("summary must not be blank")
	}
	start, startAllDay, startAt, hasStart, err := optionalEventTime(call.Args, "start")
	if err != nil {
		return connectors.Result{}, err
	}
	end, endAllDay, endAt, hasEnd, err := optionalEventTime(call.Args, "end")
	if err != nil {
		return connectors.Result{}, err
	}
	if hasStart && hasEnd {
		if startAllDay != endAllDay {
			return connectors.Result{}, invalid("start and end must both be dates (all-day) or both be timestamps")
		}
		if !endAt.After(startAt) {
			return connectors.Result{}, invalid("end must be after start")
		}
	}
	timeZone, err := optionalString(call.Args, "time_zone")
	if err != nil {
		return connectors.Result{}, err
	}
	timeZone = strings.TrimSpace(timeZone)
	when := func(value string, allDay bool) *calendar.EventDateTime {
		if allDay {
			return &calendar.EventDateTime{Date: value}
		}
		return &calendar.EventDateTime{DateTime: value, TimeZone: timeZone}
	}
	if hasStart {
		patch.Start, changed = when(start, startAllDay), true
	}
	if hasEnd {
		patch.End, changed = when(end, endAllDay), true
	}
	if _, ok := call.Args["attendees"]; ok {
		attendees, err := stringList(call.Args, "attendees")
		if err != nil {
			return connectors.Result{}, err
		}
		for _, a := range attendees {
			addr, err := mail.ParseAddress(a)
			if err != nil {
				return connectors.Result{}, invalid("attendees must be email addresses (%q is not)", a)
			}
			patch.Attendees = append(patch.Attendees, &calendar.EventAttendee{Email: addr.Address})
		}
		if len(patch.Attendees) == 0 {
			patch.ForceSendFields = append(patch.ForceSendFields, "Attendees")
		}
		changed = true
	}
	addMeet, err := optionalBool(call.Args, "add_meet_link", false)
	if err != nil {
		return connectors.Result{}, err
	}
	extras, withAttachments, err := eventExtras(call.Args, patch)
	if err != nil {
		return connectors.Result{}, err
	}
	if !changed && !addMeet && !extras {
		return connectors.Result{}, invalid("nothing to change: give at least one of summary, description, location, start, end, attendees, " +
			"add_meet_link, recurrence, reminders, use_default_reminders, color_id, visibility, transparency, attachments or guests_can_*")
	}
	sendUpdates, err := sendUpdatesArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.calendar(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	current, err := svc.Events.Get(calendarID, eventID).Context(ctx).Fields("id,extendedProperties,hangoutLink,conferenceData").Do()
	if err := classify("look up the event", err); err != nil {
		return connectors.Result{}, err
	}
	private := map[string]string{}
	if current.ExtendedProperties != nil {
		for k, v := range current.ExtendedProperties.Private {
			private[k] = v
		}
	}
	private[EventMarkerKey] = call.OperationID
	patch.ExtendedProperties = &calendar.EventExtendedProperties{Private: private}
	req := svc.Events.Patch(calendarID, eventID, patch).Context(ctx).SendUpdates(sendUpdates)
	if withAttachments {
		req = req.SupportsAttachments(true)
	}
	if addMeet && meetingURL(current) == "" {
		// A new conference only when the event has none: a createRequest
		// on an event with a Meet would replace the link attendees have.
		patch.ConferenceData = meetRequest(call.OperationID)
		req = req.ConferenceDataVersion(1)
	}
	updated, err := req.Do()
	if err := classifyWrite("update event", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: toCreatedEvent(updated, calendarID)}, nil
}

func (c *Connector) deleteEvent(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	calendarID, err := calendarArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	eventID, err := idArg(call.Args, "event_id")
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
	err = svc.Events.Delete(calendarID, eventID).Context(ctx).SendUpdates(sendUpdates).Do()
	if err := classifyWrite("delete event", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: DeletedEvent{ID: eventID, CalendarID: calendarID, Deleted: true}}, nil
}

// respondToEvent reads the event, sets the account's own attendee entry
// (self) to the response and patches the full attendee list (Calendar
// replaces arrays on patch).
func (c *Connector) respondToEvent(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	calendarID, err := calendarArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	eventID, err := idArg(call.Args, "event_id")
	if err != nil {
		return connectors.Result{}, err
	}
	response, err := requiredString(call.Args, "response")
	if err != nil {
		return connectors.Result{}, err
	}
	if !slices.Contains(responseValues, response) {
		return connectors.Result{}, invalid("response must be accepted, declined or tentative")
	}
	comment, err := optionalString(call.Args, "comment")
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
	ev, err := svc.Events.Get(calendarID, eventID).Context(ctx).Do()
	if err := classify("look up the event", err); err != nil {
		return connectors.Result{}, err
	}
	self := -1
	for i, a := range ev.Attendees {
		if a != nil && a.Self {
			self = i
			break
		}
	}
	if self < 0 {
		return connectors.Result{}, invalid("this account is not an attendee of the event, so there is no invitation to answer")
	}
	ev.Attendees[self].ResponseStatus = response
	if comment = strings.TrimSpace(comment); comment != "" {
		ev.Attendees[self].Comment = comment
	}
	updated, err := svc.Events.Patch(calendarID, eventID, &calendar.Event{Attendees: ev.Attendees}).Context(ctx).SendUpdates(sendUpdates).Do()
	if err := classifyWrite("respond to event", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: EventResponse{ID: eventID, CalendarID: calendarID, Response: response, URL: updated.HtmlLink}}, nil
}

// --- reconciliation ---------------------------------------------------------------

// eventTarget reads calendar_id and event_id from the resource identity
// and fetches the event; a 404 or 410 is returned as gone (no error).
func (c *Connector) eventTarget(ctx context.Context, in connectors.ReconcileInput) (ev *calendar.Event, gone bool, opID string, err error) {
	tg, err := c.target(in)
	if err != nil {
		return nil, false, "", err
	}
	calendarID := strings.ToLower(strings.TrimSpace(in.ResourceIdentity["calendar_id"]))
	eventID := strings.TrimSpace(in.ResourceIdentity["event_id"])
	if calendarID == "" || eventID == "" || !idRE.MatchString(calendarID) || !idRE.MatchString(eventID) {
		return nil, false, "", fmt.Errorf("%w: resource identity has no calendar or event", ErrNotReconcilable)
	}
	svc, err := tg.client.calendar(ctx)
	if err != nil {
		return nil, false, "", err
	}
	ev, err = svc.Events.Get(calendarID, eventID).Context(ctx).Do()
	if err := classify("reconcile: get event", err); err != nil {
		if s := statusOf(err); s == http.StatusNotFound || s == http.StatusGone {
			return nil, true, tg.operationID, nil
		}
		return nil, false, "", err
	}
	return ev, false, tg.operationID, nil
}

// checkEventMarker is update_event's marker reconciliation: the event's
// private property EventMarkerKey equal to the operation id is found; no
// marker is not_found (the patch sets it with every change); another
// operation's marker, or the event gone, cannot tell (a later write may
// have replaced ours).
func (c *Connector) checkEventMarker(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	ev, gone, opID, err := c.eventTarget(ctx, in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	if gone {
		return connectors.ReconcileResult{}, fmt.Errorf("google: reconcile: the event is gone; cannot tell whether the update ran")
	}
	marker := ""
	if ev.ExtendedProperties != nil {
		marker = ev.ExtendedProperties.Private[EventMarkerKey]
	}
	switch marker {
	case opID:
		return found(ev.Id), nil
	case "":
		return notFound, nil
	}
	return connectors.ReconcileResult{}, fmt.Errorf("google: reconcile: the event carries another operation's marker; cannot tell")
}

// checkEventDeleted is delete_event's stable-id reconciliation: the event
// gone (404, 410) or cancelled is found; present otherwise is not_found.
func (c *Connector) checkEventDeleted(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	ev, gone, _, err := c.eventTarget(ctx, in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	eventID := strings.TrimSpace(in.ResourceIdentity["event_id"])
	if gone || ev.Status == "cancelled" {
		return found(eventID), nil
	}
	return notFound, nil
}

// checkEventResponse is respond_to_event's stable-id reconciliation: the
// account's own attendee entry carrying the response of the identity is
// found; another response is not_found.
func (c *Connector) checkEventResponse(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	want := in.ResourceIdentity["response"]
	if !slices.Contains(responseValues, want) {
		return connectors.ReconcileResult{}, fmt.Errorf("%w: resource identity has no response", ErrNotReconcilable)
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	ev, gone, _, err := c.eventTarget(ctx, in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	if gone {
		return connectors.ReconcileResult{}, fmt.Errorf("google: reconcile: the event is gone; cannot tell whether the response was recorded")
	}
	for _, a := range ev.Attendees {
		if a != nil && a.Self {
			if a.ResponseStatus == want {
				return found(ev.Id), nil
			}
			return notFound, nil
		}
	}
	return notFound, nil
}
