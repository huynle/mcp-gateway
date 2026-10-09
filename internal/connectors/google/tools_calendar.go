package google

import (
	"context"
	"strings"
	"time"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Calendar tool names.
const (
	ToolListEvents  = "list_events"
	ToolGetEvent    = "get_event"
	ToolCreateEvent = "create_event"
)

// DefaultCalendar is the calendar_id when the harness gives none: the
// account's primary calendar.
const DefaultCalendar = "primary"

// defaultEventsPerPage is list_events's page size when the harness gives
// none, capped by the bounds.
const defaultEventsPerPage = 25

var calendarIDProperty = property{"calendar_id", "string", "Calendar to read: \"primary\" (default) for the account's own calendar, or a calendar's id (usually an email address).", nil}

// calendarReadTools declares the Calendar reads.
func (c *Connector) calendarReadTools() []connectors.Tool {
	return []connectors.Tool{
		{
			App: AppCalendar, Name: ToolListEvents, Kind: connectors.KindRead,
			Description: "List events of a Google Calendar between time_min and time_max (RFC 3339; from now on when neither is given), " +
				"optionally matching a free-text q, ordered by start time with recurring events expanded. " +
				"Each item has id, summary, start, end, all_day, status, location, organizer, attendees and url; " +
				"has_more and next_page_token say whether another page exists (pass page_token).",
			InputSchema: objectSchema([]property{
				calendarIDProperty,
				{"time_min", "string", "Lower bound (inclusive) for an event's end time, RFC 3339 such as 2026-10-09T00:00:00Z. Default: now, when time_max is also omitted.", nil},
				{"time_max", "string", "Upper bound (exclusive) for an event's start time, RFC 3339.", nil},
				{"q", "string", "Free-text search over summary, description, location and attendees.", nil},
				{"max_results", "integer", "Events per page (1-100; default 25); clamped to the tool's maximum.", nil},
				{"page_token", "string", "Token of the page to fetch (next_page_token of the previous result).", nil},
			}, nil),
			RequiredScopes:   []string{ScopeCalendarEventsReadonly},
			ResourceIdentity: calendarIdentity(false),
			Bounds:           c.pagedBounds(),
		},
		{
			App: AppCalendar, Name: ToolGetEvent, Kind: connectors.KindRead,
			Description: "Get one event of a Google Calendar by id: summary, description, location, start, end, status, organizer, " +
				"attendees with their response status, meeting link and timestamps.",
			InputSchema: objectSchema([]property{
				calendarIDProperty,
				{"event_id", "string", "The event's id (from list_events).", nil},
			}, []string{"event_id"}),
			RequiredScopes:   []string{ScopeCalendarEventsReadonly},
			ResourceIdentity: calendarIdentity(true),
			Bounds:           c.singleBounds(),
		},
	}
}

// calendarReadHandlers maps the Calendar reads' short names to their
// implementation.
func (c *Connector) calendarReadHandlers() map[string]handler {
	return map[string]handler{
		ToolListEvents: c.listEvents,
		ToolGetEvent:   c.getEvent,
	}
}

// calendarIdentity extracts calendar_id (lower-cased; "primary" when
// absent), domain (the calendar id's domain when it is an address) and,
// when withEvent, event_id from the arguments; never argument content.
func calendarIdentity(withEvent bool) func(map[string]any) map[string]string {
	return func(args map[string]any) map[string]string {
		id, _ := args["calendar_id"].(string)
		id = strings.ToLower(strings.TrimSpace(id))
		if id == "" {
			id = DefaultCalendar
		}
		out := map[string]string{"calendar_id": id}
		if d := domainOf(id); d != "" {
			out["domain"] = d
		}
		if withEvent {
			if v, _ := args["event_id"].(string); strings.TrimSpace(v) != "" {
				out["event_id"] = strings.TrimSpace(v)
			}
		}
		return out
	}
}

// calendarArg reads calendar_id (DefaultCalendar when absent), lower-cased.
func calendarArg(args map[string]any) (string, error) {
	id, err := idArgDefault(args, "calendar_id", DefaultCalendar)
	if err != nil {
		return "", err
	}
	return strings.ToLower(id), nil
}

// --- handlers -------------------------------------------------------------------

func (c *Connector) listEvents(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	calendarID, err := calendarArg(call.Args)
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
	if timeMin.IsZero() && timeMax.IsZero() {
		timeMin = time.Now().UTC().Truncate(time.Second)
	}
	if !timeMin.IsZero() && !timeMax.IsZero() && !timeMax.After(timeMin) {
		return connectors.Result{}, invalid("time_max must be after time_min")
	}
	q, err := optionalString(call.Args, "q")
	if err != nil {
		return connectors.Result{}, err
	}
	maxResults, pageToken, clamped, err := c.pageArgs(call.Args, defaultEventsPerPage)
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.calendar(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	req := svc.Events.List(calendarID).Context(ctx).SingleEvents(true).OrderBy("startTime").MaxResults(int64(maxResults))
	if !timeMin.IsZero() {
		req = req.TimeMin(timeMin.Format(time.RFC3339))
	}
	if !timeMax.IsZero() {
		req = req.TimeMax(timeMax.Format(time.RFC3339))
	}
	if q = strings.TrimSpace(q); q != "" {
		req = req.Q(q)
	}
	if pageToken != "" {
		req = req.PageToken(pageToken)
	}
	events, err := req.Do()
	if err := classify("list events", err); err != nil {
		return connectors.Result{}, err
	}
	out := EventsPage{CalendarID: calendarID, TimeZone: events.TimeZone, MaxResults: maxResults, NextPageToken: events.NextPageToken, HasMore: events.NextPageToken != "", Items: make([]Event, 0, len(events.Items))}
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

func (c *Connector) getEvent(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	calendarID, err := calendarArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	eventID, err := idArg(call.Args, "event_id")
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.calendar(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	ev, err := svc.Events.Get(calendarID, eventID).Context(ctx).Do()
	if err := classify("get event", err); err != nil {
		return connectors.Result{}, err
	}
	out := toEvent(ev, calendarID)
	fitBody(&out.Description, &out.Truncated, c.bounds.MaxResultBytes, func() any { return out })
	return connectors.Result{Content: out, Partial: out.Truncated}, nil
}

// --- writes (next increment) ---------------------------------------------------

func (c *Connector) calendarWriteTools() []connectors.Tool { return nil }

func (c *Connector) calendarWriteHandlers() map[string]handler { return map[string]handler{} }
