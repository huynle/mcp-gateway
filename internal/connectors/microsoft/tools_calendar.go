package microsoft

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/microsoft/graph"
)

// Calendar tools beyond list / create: calendars, one event, meeting
// time suggestions, update, delete and invitation responses.
const (
	ToolCalendarListCalendars   = "calendar_list_calendars"
	ToolCalendarGetEvent        = "calendar_get_event"
	ToolCalendarFindMeetingTime = "calendar_find_meeting_times"
	ToolCalendarUpdateEvent     = "calendar_update_event"
	ToolCalendarDeleteEvent     = "calendar_delete_event"
	ToolCalendarRespondEvent    = "calendar_respond_event"
)

const (
	calendarSelect    = "id,name,color,canEdit,isDefaultCalendar,owner"
	eventDetailSelect = "id,subject,start,end,isAllDay,isCancelled,location,organizer,webLink,body,attendees,responseStatus,onlineMeeting"
	maxMeetingMinutes = 24 * 60
	maxCandidates     = 20
)

// responseVerbs maps calendar_respond_event's response to the Graph
// action and the responseStatus it leaves.
var responseVerbs = map[string]struct{ action, status string }{
	"accept":    {"accept", "accepted"},
	"decline":   {"decline", "declined"},
	"tentative": {"tentativelyAccept", "tentativelyAccepted"},
}

// Calendar is one calendar_list_calendars item.
type Calendar struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Color     string `json:"color,omitempty"`
	IsDefault bool   `json:"is_default"`
	CanEdit   bool   `json:"can_edit"`
	Owner     string `json:"owner,omitempty"`
}

type graphCalendar struct {
	ID                string             `json:"id"`
	Name              string             `json:"name"`
	Color             string             `json:"color"`
	CanEdit           bool               `json:"canEdit"`
	IsDefaultCalendar bool               `json:"isDefaultCalendar"`
	Owner             *graphEmailAddress `json:"owner"`
}

// EventAttendee is one attendee of calendar_get_event.
type EventAttendee struct {
	Name     string `json:"name,omitempty"`
	Address  string `json:"address"`
	Type     string `json:"type,omitempty"`
	Response string `json:"response,omitempty"`
}

// EventDetail is calendar_get_event's result.
type EventDetail struct {
	Event
	Response        string          `json:"response,omitempty"`
	JoinURL         string          `json:"join_url,omitempty"`
	Attendees       []EventAttendee `json:"attendees"`
	BodyContentType string          `json:"body_content_type,omitempty"`
	Body            string          `json:"body"`
	Truncated       bool            `json:"truncated,omitempty"`
}

type graphEventDetail struct {
	graphEvent
	Body           *graphBody `json:"body"`
	ResponseStatus *struct {
		Response string `json:"response"`
	} `json:"responseStatus"`
	OnlineMeeting *struct {
		JoinURL string `json:"joinUrl"`
	} `json:"onlineMeeting"`
	Attendees []struct {
		EmailAddress graphEmailAddress `json:"emailAddress"`
		Type         string            `json:"type"`
		Status       *struct {
			Response string `json:"response"`
		} `json:"status"`
	} `json:"attendees"`
}

// MeetingSlot is one calendar_find_meeting_times suggestion.
type MeetingSlot struct {
	Start                 string                 `json:"start"`
	End                   string                 `json:"end"`
	TimeZone              string                 `json:"time_zone,omitempty"`
	Confidence            float64                `json:"confidence"`
	OrganizerAvailability string                 `json:"organizer_availability,omitempty"`
	SuggestionReason      string                 `json:"suggestion_reason,omitempty"`
	Attendees             []AttendeeAvailability `json:"attendees"`
}

// AttendeeAvailability is one attendee's availability in a suggestion.
type AttendeeAvailability struct {
	Address      string `json:"address"`
	Availability string `json:"availability"`
}

// MeetingTimes is calendar_find_meeting_times's result.
type MeetingTimes struct {
	EmptyReason string        `json:"empty_reason,omitempty"`
	Truncated   bool          `json:"truncated,omitempty"`
	Items       []MeetingSlot `json:"items"`
}

// UpdatedEvent is calendar_update_event's result.
type UpdatedEvent struct {
	ID      string `json:"id"`
	WebLink string `json:"web_link,omitempty"`
}

// EventChange is the result of calendar_delete_event and
// calendar_respond_event.
type EventChange struct {
	EventID  string `json:"event_id"`
	Action   string `json:"action"`
	Response string `json:"response,omitempty"`
}

func (c *Connector) calendarDefs() []toolDef {
	paged := connectors.Bounds{MaxPageSize: c.bounds.MaxPageSize, MaxResultBytes: c.bounds.MaxResultBytes}
	single := connectors.Bounds{MaxResultBytes: c.bounds.MaxResultBytes}
	eventID := property{"event_id", "string", "The event id (from calendar_list_events).", nil}
	evIdentity := identity("event_id", "event")
	r, w := connectors.KindRead, connectors.KindWrite
	return []toolDef{
		{Tool: connectors.Tool{
			App: App, Name: ToolCalendarListCalendars, Kind: r,
			Description:      "List the user's calendars (id, name, default flag, whether the user can edit, owner); use an id as calendar_id.",
			InputSchema:      objectSchema([]property{topProperty}, nil),
			RequiredScopes:   []string{ScopeCalendarsRead},
			ResourceIdentity: identity(),
			Bounds:           paged,
		}, run: c.calendarListCalendars},
		{Tool: connectors.Tool{
			App: App, Name: ToolCalendarGetEvent, Kind: r,
			Description: "Get one calendar event: subject, start and end (UTC), location, organizer, attendees with their responses, the user's " +
				"own response, the online meeting join url and the description as plain text (cut to the result bounds).",
			InputSchema:      objectSchema([]property{eventID}, []string{"event_id"}),
			RequiredScopes:   []string{ScopeCalendarsRead},
			ResourceIdentity: evIdentity,
			Bounds:           single,
		}, run: c.calendarGetEvent},
		{Tool: connectors.Tool{
			App: App, Name: ToolCalendarFindMeetingTime, Kind: r,
			Description: "Suggest meeting times when the user and the attendees are free, between start and end (ISO 8601), for duration_minutes " +
				"(default 30). Returns slots in UTC with each attendee's availability, or the reason there is none. Work accounts only " +
				"(Calendars.Read.Shared).",
			InputSchema: objectSchema([]property{
				{"attendees", "array", "Attendee addresses (\"Name <address>\" allowed).", nil},
				{"start", "string", "Search window start, ISO 8601.", nil},
				{"end", "string", "Search window end, ISO 8601, after start.", nil},
				{"duration_minutes", "integer", "Meeting length in minutes (default 30, at most 1440).", nil},
				{"max_candidates", "integer", "Maximum number of suggestions (default 5, at most 20).", nil},
				{"activity_domain", "string", "Hours to consider: work (default), personal or unrestricted.", []string{"work", "personal", "unrestricted"}},
			}, []string{"attendees", "start", "end"}),
			RequiredScopes:   []string{ScopeCalendarsReadShared},
			ResourceIdentity: func(map[string]any) map[string]string { return map[string]string{"calendar": calendarDefaultName} },
			Bounds:           single,
		}, run: c.calendarFindMeetingTimes},
		{Tool: connectors.Tool{
			App: App, Name: ToolCalendarUpdateEvent, Kind: w,
			Description: "Change a calendar event: any of subject, start and end (together; ISO 8601 local times in time_zone, UTC by default), " +
				"location, body (plain text) and attendees (replaces the list; invited as required). Attendees are notified by Outlook.",
			InputSchema: objectSchema([]property{eventID,
				{"subject", "string", "New subject.", nil},
				{"start", "string", "New start, ISO 8601 (with end).", nil},
				{"end", "string", "New end, ISO 8601 (with start).", nil},
				{"time_zone", "string", "IANA time zone of start and end (default UTC).", nil},
				{"location", "string", "New location name.", nil},
				{"body", "string", "New description in plain text.", nil},
				{"attendees", "array", "New attendee list (replaces the current one).", nil},
			}, []string{"event_id"}),
			RequiredScopes:   []string{ScopeCalendarsReadWrite},
			ResourceIdentity: evIdentity,
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileNone},
			ResultIDs:        resultIDs("id", "web_link"),
			Bounds:           single,
		}, run: c.calendarUpdateEvent},
		{Tool: connectors.Tool{
			App: App, Name: ToolCalendarDeleteEvent, Kind: w,
			Description:      "Delete a calendar event from the user's calendar (as organizer this cancels it for the attendees).",
			InputSchema:      objectSchema([]property{eventID}, []string{"event_id"}),
			RequiredScopes:   []string{ScopeCalendarsReadWrite},
			ResourceIdentity: evIdentity,
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: c.stateCheck("event", identityPath("me/events/%s"), "id", decideGone)},
			ResultIDs:        resultIDs("event_id"),
			Bounds:           single,
		}, run: c.calendarDeleteEvent},
		{Tool: connectors.Tool{
			App: App, Name: ToolCalendarRespondEvent, Kind: w,
			Description: "Answer a meeting invitation: accept, decline or tentative, with an optional comment; send_response false answers " +
				"without notifying the organizer.",
			InputSchema: objectSchema([]property{eventID,
				{"response", "string", "accept, decline or tentative.", []string{"accept", "decline", "tentative"}},
				{"comment", "string", "Message to the organizer.", nil},
				{"send_response", "boolean", "Notify the organizer (default true).", nil},
			}, []string{"event_id", "response"}),
			RequiredScopes:   []string{ScopeCalendarsReadWrite},
			ResourceIdentity: identity("event_id", "event", "response", "response"),
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: c.stateCheck("event", identityPath("me/events/%s"), "id,responseStatus", decideResponse)},
			ResultIDs:        resultIDs("event_id", "response"),
			Bounds:           single,
		}, run: c.calendarRespondEvent},
	}
}

// decideResponse: the event's responseStatus is the one the response
// leaves; a declined invitation may be removed from the calendar, so a
// vanished event is found for decline and cannot tell otherwise.
func decideResponse(ident map[string]string, body map[string]any, gone bool) (connectors.ReconcileResult, bool) {
	verb, ok := responseVerbs[ident["response"]]
	if !ok {
		return connectors.ReconcileResult{}, false
	}
	if gone {
		if ident["response"] == "decline" {
			return found(ident["event"]), true
		}
		return connectors.ReconcileResult{}, false
	}
	rs, _ := body["responseStatus"].(map[string]any)
	got, _ := rs["response"].(string)
	if strings.EqualFold(got, verb.status) {
		return found(ident["event"]), true
	}
	return notFound, true
}

func (c *Connector) calendarListCalendars(ctx context.Context, client *graph.Client, call connectors.Call) (connectors.Result, error) {
	top, clamped, err := c.topArg(call.Args, maxTop)
	if err != nil {
		return connectors.Result{}, err
	}
	q := url.Values{"$top": {strconv.Itoa(top)}, "$select": {calendarSelect}}
	return listRead(ctx, c, client, "list calendars", "me/calendars", q, nil, top, clamped, func(g graphCalendar) Calendar {
		out := Calendar{ID: g.ID, Name: g.Name, Color: g.Color, IsDefault: g.IsDefaultCalendar, CanEdit: g.CanEdit}
		if g.Owner != nil {
			out.Owner = g.Owner.Address
		}
		return out
	})
}

func (c *Connector) calendarGetEvent(ctx context.Context, client *graph.Client, call connectors.Call) (connectors.Result, error) {
	id, err := requiredID(call.Args, "event_id")
	if err != nil {
		return connectors.Result{}, err
	}
	var g graphEventDetail
	_, err = client.Do(ctx, graph.Request{
		Method: http.MethodGet, Path: "me/events/" + id, Query: url.Values{"$select": {eventDetailSelect}},
		Header: http.Header{"Prefer": {preferTextBody + ", " + preferUTC}},
	}, &g)
	if err := classify("get event", err); err != nil {
		return connectors.Result{}, err
	}
	out := EventDetail{Event: toEvent(g.graphEvent), Attendees: []EventAttendee{}}
	if g.Body != nil {
		out.BodyContentType, out.Body = strings.ToLower(g.Body.ContentType), g.Body.Content
	}
	if g.ResponseStatus != nil {
		out.Response = g.ResponseStatus.Response
	}
	if g.OnlineMeeting != nil {
		out.JoinURL = g.OnlineMeeting.JoinURL
	}
	for _, a := range g.Attendees {
		at := EventAttendee{Name: a.EmailAddress.Name, Address: a.EmailAddress.Address, Type: a.Type}
		if a.Status != nil {
			at.Response = a.Status.Response
		}
		out.Attendees = append(out.Attendees, at)
	}
	fitBody(&out.Body, &out.Truncated, c.bounds.MaxResultBytes, func() any { return out })
	return connectors.Result{Content: out, Partial: out.Truncated}, nil
}

// intArg reads an optional integer argument within [lo, hi].
func intArg(args map[string]any, name string, def, lo, hi int) (int, error) {
	v, ok := args[name]
	if !ok || v == nil {
		return def, nil
	}
	n, err := toInt(v)
	if err != nil || n < lo || n > hi {
		return 0, invalid("%s must be an integer from %d to %d", name, lo, hi)
	}
	return n, nil
}

func (c *Connector) calendarFindMeetingTimes(ctx context.Context, client *graph.Client, call connectors.Call) (connectors.Result, error) {
	attendees, err := addressList(call.Args, "attendees", true)
	if err != nil {
		return connectors.Result{}, err
	}
	start, err := timeArg(call.Args, "start")
	if err != nil {
		return connectors.Result{}, err
	}
	end, err := timeArg(call.Args, "end")
	if err != nil {
		return connectors.Result{}, err
	}
	if !end.After(start) || end.Sub(start) > maxCalendarWindow {
		return connectors.Result{}, invalid("end must be after start and at most a year later")
	}
	minutes, err := intArg(call.Args, "duration_minutes", 30, 1, maxMeetingMinutes)
	if err != nil {
		return connectors.Result{}, err
	}
	candidates, err := intArg(call.Args, "max_candidates", 5, 1, maxCandidates)
	if err != nil {
		return connectors.Result{}, err
	}
	domain, err := optionalString(call.Args, "activity_domain")
	if err != nil {
		return connectors.Result{}, err
	}
	switch domain = strings.ToLower(strings.TrimSpace(domain)); domain {
	case "":
		domain = "work"
	case "work", "personal", "unrestricted":
	default:
		return connectors.Result{}, invalid("activity_domain must be work, personal or unrestricted")
	}
	list := make([]map[string]any, 0, len(attendees))
	for _, a := range attendees {
		list = append(list, map[string]any{"emailAddress": a.EmailAddress, "type": "required"})
	}
	slot := func(t time.Time) eventTime {
		return eventTime{DateTime: t.UTC().Format("2006-01-02T15:04:05"), TimeZone: "UTC"}
	}
	req := map[string]any{
		"attendees": list,
		"timeConstraint": map[string]any{
			"activityDomain": domain,
			"timeSlots":      []map[string]any{{"start": slot(start), "end": slot(end)}},
		},
		"meetingDuration":           fmt.Sprintf("PT%dM", minutes),
		"maxCandidates":             candidates,
		"returnSuggestionReasons":   true,
		"isOrganizerOptional":       false,
		"minimumAttendeePercentage": 100,
	}
	var g struct {
		EmptySuggestionsReason string `json:"emptySuggestionsReason"`
		MeetingTimeSuggestions []struct {
			Confidence            float64 `json:"confidence"`
			OrganizerAvailability string  `json:"organizerAvailability"`
			SuggestionReason      string  `json:"suggestionReason"`
			MeetingTimeSlot       struct {
				Start graphDateTimeZone `json:"start"`
				End   graphDateTimeZone `json:"end"`
			} `json:"meetingTimeSlot"`
			AttendeeAvailability []struct {
				Attendee struct {
					EmailAddress graphEmailAddress `json:"emailAddress"`
				} `json:"attendee"`
				Availability string `json:"availability"`
			} `json:"attendeeAvailability"`
		} `json:"meetingTimeSuggestions"`
	}
	_, err = client.Do(ctx, graph.Request{Method: http.MethodPost, Path: "me/findMeetingTimes", Body: req, Header: http.Header{"Prefer": {preferUTC}}}, &g)
	if err := classify("find meeting times", err); err != nil {
		return connectors.Result{}, err
	}
	out := MeetingTimes{EmptyReason: g.EmptySuggestionsReason, Items: []MeetingSlot{}}
	for _, s := range g.MeetingTimeSuggestions {
		ms := MeetingSlot{Start: s.MeetingTimeSlot.Start.DateTime, End: s.MeetingTimeSlot.End.DateTime, TimeZone: s.MeetingTimeSlot.Start.TimeZone,
			Confidence: s.Confidence, OrganizerAvailability: s.OrganizerAvailability, SuggestionReason: s.SuggestionReason, Attendees: []AttendeeAvailability{}}
		for _, a := range s.AttendeeAvailability {
			ms.Attendees = append(ms.Attendees, AttendeeAvailability{Address: a.Attendee.EmailAddress.Address, Availability: a.Availability})
		}
		out.Items = append(out.Items, ms)
	}
	res := connectors.Result{Empty: len(out.Items) == 0}
	if truncateItems(&out.Items, c.bounds.MaxResultBytes, func() any { return out }) {
		out.Truncated, res.Partial = true, true
	}
	res.Content = out
	return res, nil
}

func (c *Connector) calendarUpdateEvent(ctx context.Context, client *graph.Client, call connectors.Call) (connectors.Result, error) {
	id, err := requiredID(call.Args, "event_id")
	if err != nil {
		return connectors.Result{}, err
	}
	patch := map[string]any{}
	if v, err := optionalString(call.Args, "subject"); err != nil {
		return connectors.Result{}, err
	} else if strings.TrimSpace(v) != "" {
		patch["subject"] = strings.TrimSpace(v)
	}
	_, hasStart := call.Args["start"]
	_, hasEnd := call.Args["end"]
	if hasStart != hasEnd {
		return connectors.Result{}, invalid("start and end must be changed together")
	}
	if hasStart {
		zone, err := optionalString(call.Args, "time_zone")
		if err != nil {
			return connectors.Result{}, err
		}
		if zone = strings.TrimSpace(zone); zone == "" {
			zone = "UTC"
		}
		loc, err := time.LoadLocation(zone)
		if err != nil {
			return connectors.Result{}, invalid("time_zone %q is not a known IANA time zone", zone)
		}
		start, startAt, err := localTimeArg(call.Args, "start", loc, zone)
		if err != nil {
			return connectors.Result{}, err
		}
		end, endAt, err := localTimeArg(call.Args, "end", loc, zone)
		if err != nil {
			return connectors.Result{}, err
		}
		if !endAt.After(startAt) {
			return connectors.Result{}, invalid("end must be after start")
		}
		patch["start"], patch["end"] = start, end
	}
	if v, err := optionalString(call.Args, "location"); err != nil {
		return connectors.Result{}, err
	} else if strings.TrimSpace(v) != "" {
		patch["location"] = map[string]string{"displayName": strings.TrimSpace(v)}
	}
	if v, err := textArg(call.Args, "body", false); err != nil {
		return connectors.Result{}, err
	} else if strings.TrimSpace(v) != "" {
		patch["body"] = map[string]string{"contentType": "Text", "content": v}
	}
	if _, ok := call.Args["attendees"]; ok {
		attendees, err := addressList(call.Args, "attendees", false)
		if err != nil {
			return connectors.Result{}, err
		}
		list := make([]map[string]any, 0, len(attendees))
		for _, a := range attendees {
			list = append(list, map[string]any{"emailAddress": a.EmailAddress, "type": "required"})
		}
		patch["attendees"] = list
	}
	if len(patch) == 0 {
		return connectors.Result{}, invalid("nothing to change: give subject, start and end, location, body or attendees")
	}
	var updated graphEvent
	if err := client.Patch(ctx, "me/events/"+id, patch, &updated); err != nil {
		return connectors.Result{}, classifyWrite("update event", err)
	}
	if updated.ID == "" {
		updated.ID = id
	}
	return connectors.Result{Content: UpdatedEvent{ID: updated.ID, WebLink: updated.WebLink}}, nil
}

func (c *Connector) calendarDeleteEvent(ctx context.Context, client *graph.Client, call connectors.Call) (connectors.Result, error) {
	id, err := requiredID(call.Args, "event_id")
	if err != nil {
		return connectors.Result{}, err
	}
	if err := client.Delete(ctx, "me/events/"+id); err != nil {
		return connectors.Result{}, classifyWrite("delete event", err)
	}
	return connectors.Result{Content: EventChange{EventID: id, Action: "deleted"}}, nil
}

func (c *Connector) calendarRespondEvent(ctx context.Context, client *graph.Client, call connectors.Call) (connectors.Result, error) {
	id, err := requiredID(call.Args, "event_id")
	if err != nil {
		return connectors.Result{}, err
	}
	resp, err := requiredString(call.Args, "response")
	if err != nil {
		return connectors.Result{}, err
	}
	verb, ok := responseVerbs[strings.ToLower(resp)]
	if !ok {
		return connectors.Result{}, invalid("response must be accept, decline or tentative")
	}
	comment, err := textArg(call.Args, "comment", false)
	if err != nil {
		return connectors.Result{}, err
	}
	send, err := boolArg(call.Args, "send_response", true)
	if err != nil {
		return connectors.Result{}, err
	}
	req := map[string]any{"sendResponse": send}
	if comment != "" {
		req["comment"] = comment
	}
	if _, err := client.Post(ctx, "me/events/"+id+"/"+verb.action, req, nil); err != nil {
		return connectors.Result{}, classifyWrite("respond to event", err)
	}
	return connectors.Result{Content: EventChange{EventID: id, Action: "responded", Response: strings.ToLower(resp)}}, nil
}
