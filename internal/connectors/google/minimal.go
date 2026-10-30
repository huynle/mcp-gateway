package google

import (
	"strings"
	"time"

	"google.golang.org/api/calendar/v3"
)

// Result shapes of the Calendar tools: flat, with page metadata and the
// truncation flags the bounds need. Designed after the Calendar API
// resource (not copied from any MCP server).

// Attendee is one attendee of an event.
type Attendee struct {
	Email          string `json:"email"`
	Name           string `json:"name,omitempty"`
	ResponseStatus string `json:"response_status,omitempty"`
	Optional       bool   `json:"optional,omitempty"`
	Organizer      bool   `json:"organizer,omitempty"`
	Self           bool   `json:"self,omitempty"`
}

// Event is get_event's result and one list_events item. Start and End
// are RFC 3339 timestamps, or dates (YYYY-MM-DD) when AllDay.
type Event struct {
	ID               string     `json:"id"`
	CalendarID       string     `json:"calendar_id"`
	Summary          string     `json:"summary"`
	Description      string     `json:"description,omitempty"`
	Location         string     `json:"location,omitempty"`
	Status           string     `json:"status,omitempty"`
	Start            string     `json:"start"`
	End              string     `json:"end"`
	AllDay           bool       `json:"all_day"`
	TimeZone         string     `json:"time_zone,omitempty"`
	URL              string     `json:"url,omitempty"`
	MeetingURL       string     `json:"meeting_url,omitempty"`
	Organizer        string     `json:"organizer,omitempty"`
	Creator          string     `json:"creator,omitempty"`
	Attendees        []Attendee `json:"attendees,omitempty"`
	RecurringEventID string     `json:"recurring_event_id,omitempty"`
	Created          string     `json:"created,omitempty"`
	Updated          string     `json:"updated,omitempty"`
	// Truncated says the description was cut to fit the result bounds.
	Truncated bool `json:"truncated,omitempty"`
}

// EventsPage is list_events's result.
type EventsPage struct {
	CalendarID    string  `json:"calendar_id"`
	TimeZone      string  `json:"time_zone,omitempty"`
	TimeMin       string  `json:"time_min,omitempty"`
	TimeMax       string  `json:"time_max,omitempty"`
	MaxResults    int     `json:"max_results"`
	NextPageToken string  `json:"next_page_token,omitempty"`
	HasMore       bool    `json:"has_more"`
	Truncated     bool    `json:"truncated,omitempty"`
	Items         []Event `json:"items"`
}

// CreatedEvent is create_event's result: the identifiers of the new
// event, never its content (the ledger keeps id and url).
type CreatedEvent struct {
	ID         string `json:"id"`
	CalendarID string `json:"calendar_id"`
	URL        string `json:"url,omitempty"`
	Status     string `json:"status,omitempty"`
	Start      string `json:"start,omitempty"`
	End        string `json:"end,omitempty"`
	// MeetURL is the event's Google Meet link (add_meet_link, or one the
	// event already had); MeetStatus is Google's status of the
	// conference request (pending, success, failure) when one was made.
	MeetURL    string `json:"meet_url,omitempty"`
	MeetStatus string `json:"meet_status,omitempty"`
}

func toEvent(ev *calendar.Event, calendarID string) Event {
	out := Event{
		ID: ev.Id, CalendarID: calendarID, Summary: ev.Summary, Description: ev.Description, Location: ev.Location, Status: ev.Status,
		URL: ev.HtmlLink, MeetingURL: meetingURL(ev), RecurringEventID: ev.RecurringEventId,
		Created: normalizeTimestamp(ev.Created), Updated: normalizeTimestamp(ev.Updated),
	}
	out.Start, out.End, out.AllDay, out.TimeZone = eventTimes(ev.Start, ev.End)
	if ev.Organizer != nil {
		out.Organizer = ev.Organizer.Email
	}
	if ev.Creator != nil {
		out.Creator = ev.Creator.Email
	}
	for _, a := range ev.Attendees {
		if a == nil || a.Email == "" {
			continue
		}
		out.Attendees = append(out.Attendees, Attendee{
			Email: a.Email, Name: a.DisplayName, ResponseStatus: a.ResponseStatus, Optional: a.Optional, Organizer: a.Organizer, Self: a.Self,
		})
	}
	return out
}

// eventTimes flattens start/end: dateTime (timed) or date (all-day).
func eventTimes(start, end *calendar.EventDateTime) (s, e string, allDay bool, tz string) {
	if start != nil {
		if start.Date != "" {
			s, allDay = start.Date, true
		} else {
			s = start.DateTime
		}
		tz = start.TimeZone
	}
	if end != nil {
		if end.Date != "" {
			e = end.Date
		} else {
			e = end.DateTime
		}
	}
	return s, e, allDay, tz
}

// meetingURL is the event's video link: hangoutLink, else the video
// entry point of its conference data.
func meetingURL(ev *calendar.Event) string {
	if ev.HangoutLink != "" {
		return ev.HangoutLink
	}
	if ev.ConferenceData != nil {
		for _, ep := range ev.ConferenceData.EntryPoints {
			if ep != nil && ep.EntryPointType == "video" && ep.Uri != "" {
				return ep.Uri
			}
		}
	}
	return ""
}

func toCreatedEvent(ev *calendar.Event, calendarID string) CreatedEvent {
	s, e, _, _ := eventTimes(ev.Start, ev.End)
	out := CreatedEvent{ID: ev.Id, CalendarID: calendarID, URL: ev.HtmlLink, Status: ev.Status, Start: s, End: e, MeetURL: meetingURL(ev)}
	if cd := ev.ConferenceData; cd != nil && cd.CreateRequest != nil && cd.CreateRequest.Status != nil {
		out.MeetStatus = cd.CreateRequest.Status.StatusCode
	}
	return out
}

// normalizeTimestamp renders Google's RFC 3339 timestamps (which carry
// milliseconds) in UTC without the fraction; other strings pass through.
func normalizeTimestamp(s string) string {
	if s == "" {
		return ""
	}
	t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(s))
	if err != nil {
		return s
	}
	return t.UTC().Format(time.RFC3339)
}
