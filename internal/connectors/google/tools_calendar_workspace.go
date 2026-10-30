package google

import (
	"context"
	"slices"
	"strings"
	"time"

	"google.golang.org/api/calendar/v3"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// The Workspace-only event types (increment 4): out of office, working
// location and focus time. Google accepts them only from Google Workspace
// accounts and only on the primary calendar; a personal account gets
// Google's 400 or 403, which classifyWrite reports as invalid_argument or
// forbidden. Each is an events.insert with the event id derived from the
// operation (EventID), exactly like create_event, so the same stable-id
// check (checkEvent) reconciles them.

// Workspace event tool names.
const (
	ToolSetOutOfOffice     = "set_out_of_office"
	ToolSetWorkingLocation = "set_working_location"
	ToolCreateFocusTime    = "create_focus_time"
)

// Default summaries of the out-of-office and focus-time events.
const (
	DefaultOutOfOfficeSummary = "Out of office"
	DefaultFocusTimeSummary   = "Focus time"
)

// declineModes maps decline_mode to Google's autoDeclineMode.
var declineModes = map[string]string{
	"none":                 "declineNone",
	"all_conflicting":      "declineAllConflictingInvitations",
	"only_new_conflicting": "declineOnlyNewConflictingInvitations",
}

var declineModeValues = []string{"none", "all_conflicting", "only_new_conflicting"}

// workingLocationTypes maps type to Google's workingLocationProperties.type.
var workingLocationTypes = map[string]string{"home": "homeOffice", "office": "officeLocation", "custom": "customLocation"}

var (
	workingLocationValues = []string{"home", "office", "custom"}
	chatStatusValues      = []string{"available", "doNotDisturb"}
)

const workspaceOnlyNote = " Google Workspace accounts only (a personal Google account gets Google's error); always on the primary calendar."

var (
	timedStartProperty   = property{"start", "string", "Start: RFC 3339 timestamp (2026-10-12T09:00:00-07:00).", nil}
	timedEndProperty     = property{"end", "string", "End (exclusive): RFC 3339 timestamp.", nil}
	eventTimeZoneProp    = property{"time_zone", "string", "IANA time zone of start and end (America/Los_Angeles); the calendar's zone when omitted.", nil}
	declineMessageProp   = property{"decline_message", "string", "Message Google sends with the invitations it declines (needs a decline_mode other than none).", nil}
	declineModeOOOProp   = property{"decline_mode", "string", "Which invitations Google declines during the event: none, all_conflicting (default: existing and new) or only_new_conflicting.", declineModeValues}
	declineModeFocusProp = property{"decline_mode", "string", "Which invitations Google declines during the event: none, all_conflicting (existing and new) or only_new_conflicting (default).", declineModeValues}
)

func (c *Connector) calendarWorkspaceWriteTools() []connectors.Tool {
	tool := func(name, description string, props []property, required []string) connectors.Tool {
		return connectors.Tool{
			App: AppCalendar, Name: name, Kind: connectors.KindWrite,
			Description:      description + workspaceOnlyNote,
			InputSchema:      objectSchema(props, required),
			RequiredScopes:   []string{ScopeCalendarEvents},
			ResourceIdentity: calendarIdentity(false),
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: c.checkEvent},
			ResultIDs:        eventResultIDs,
			Bounds:           c.singleBounds(),
		}
	}
	return []connectors.Tool{
		tool(ToolSetOutOfOffice,
			"Mark the account out of office from start to end (an outOfOffice event): Google declines conflicting invitations "+
				"(decline_mode; default all_conflicting) with decline_message. Returns the event's id and url.",
			[]property{
				timedStartProperty, timedEndProperty,
				{"summary", "string", "Event title (default \"Out of office\").", nil},
				declineModeOOOProp, declineMessageProp, eventTimeZoneProp,
			}, []string{"start", "end"}),
		tool(ToolSetWorkingLocation,
			"Set where the account works (a workingLocation event): type home, office or custom (label names the office or place), "+
				"for a whole day (date) or between start and end. Returns the event's id and url.",
			[]property{
				{"date", "string", "Day, YYYY-MM-DD (an all-day working location); or give start and end instead.", nil},
				{"start", "string", "Start: RFC 3339 timestamp (with end, instead of date).", nil},
				{"end", "string", "End (exclusive): RFC 3339 timestamp.", nil},
				{"type", "string", "home, office or custom.", workingLocationValues},
				{"label", "string", "Name of the office (type office; optional) or of the place (type custom; required).", nil},
				eventTimeZoneProp,
			}, []string{"type"}),
		tool(ToolCreateFocusTime,
			"Block focus time from start to end (a focusTime event): Google declines conflicting invitations "+
				"(decline_mode; default only_new_conflicting) with decline_message and can set the Chat status (chat_status). "+
				"Returns the event's id and url.",
			[]property{
				timedStartProperty, timedEndProperty,
				{"summary", "string", "Event title (default \"Focus time\").", nil},
				declineModeFocusProp, declineMessageProp,
				{"chat_status", "string", "Google Chat status during the event: available or doNotDisturb.", chatStatusValues},
				eventTimeZoneProp,
			}, []string{"start", "end"}),
	}
}

func (c *Connector) calendarWorkspaceWriteHandlers() map[string]handler {
	return map[string]handler{
		ToolSetOutOfOffice:     c.setOutOfOffice,
		ToolSetWorkingLocation: c.setWorkingLocation,
		ToolCreateFocusTime:    c.createFocusTime,
	}
}

// --- arguments ----------------------------------------------------------------------

// timedRange reads the required start and end RFC 3339 timestamps (end
// after start) and the optional time_zone, as event times.
func timedRange(args map[string]any) (start, end *calendar.EventDateTime, err error) {
	from, err := requiredTimestamp(args, "start")
	if err != nil {
		return nil, nil, err
	}
	to, err := requiredTimestamp(args, "end")
	if err != nil {
		return nil, nil, err
	}
	if !to.After(from) {
		return nil, nil, invalid("end must be after start")
	}
	tz, err := optionalString(args, "time_zone")
	if err != nil {
		return nil, nil, err
	}
	tz = strings.TrimSpace(tz)
	s, _ := args["start"].(string)
	e, _ := args["end"].(string)
	return &calendar.EventDateTime{DateTime: strings.TrimSpace(s), TimeZone: tz}, &calendar.EventDateTime{DateTime: strings.TrimSpace(e), TimeZone: tz}, nil
}

// requiredTimestamp reads a required RFC 3339 timestamp argument.
func requiredTimestamp(args map[string]any, name string) (time.Time, error) {
	if _, err := requiredString(args, name); err != nil {
		return time.Time{}, err
	}
	return optionalTime(args, name)
}

// summaryArg reads summary, def when absent or blank.
func summaryArg(args map[string]any, def string) (string, error) {
	v, err := optionalString(args, "summary")
	if err != nil {
		return "", err
	}
	if v = strings.TrimSpace(v); v == "" {
		return def, nil
	}
	return v, nil
}

// declineArgs reads decline_mode (def when absent) as Google's
// autoDeclineMode, and decline_message (refused with mode none: Google
// would have nothing to send it with).
func declineArgs(args map[string]any, def string) (mode, message string, err error) {
	v, err := optionalString(args, "decline_mode")
	if err != nil {
		return "", "", err
	}
	if v = strings.TrimSpace(v); v == "" {
		v = def
	}
	mode, ok := declineModes[v]
	if !ok {
		return "", "", invalid("decline_mode must be none, all_conflicting or only_new_conflicting")
	}
	if message, err = optionalString(args, "decline_message"); err != nil {
		return "", "", err
	}
	if message = strings.TrimSpace(message); message != "" && v == "none" {
		return "", "", invalid("decline_message needs a decline_mode other than none")
	}
	return mode, message, nil
}

// insertWorkspaceEvent inserts ev on the primary calendar under the
// operation's event id.
func (c *Connector) insertWorkspaceEvent(ctx context.Context, cl *client, call connectors.Call, action string, ev *calendar.Event) (connectors.Result, error) {
	ev.Id = EventID(call.OperationID)
	svc, err := cl.calendar(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	created, err := svc.Events.Insert(DefaultCalendar, ev).Context(ctx).Do()
	if err := classifyWrite(action, err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: toCreatedEvent(created, DefaultCalendar)}, nil
}

// --- handlers -----------------------------------------------------------------------

func (c *Connector) setOutOfOffice(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	start, end, err := timedRange(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	summary, err := summaryArg(call.Args, DefaultOutOfOfficeSummary)
	if err != nil {
		return connectors.Result{}, err
	}
	mode, message, err := declineArgs(call.Args, "all_conflicting")
	if err != nil {
		return connectors.Result{}, err
	}
	return c.insertWorkspaceEvent(ctx, cl, call, "set out of office", &calendar.Event{
		EventType: "outOfOffice", Summary: summary, Start: start, End: end,
		OutOfOfficeProperties: &calendar.EventOutOfOfficeProperties{AutoDeclineMode: mode, DeclineMessage: message},
	})
}

func (c *Connector) setWorkingLocation(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	kind, err := requiredString(call.Args, "type")
	if err != nil {
		return connectors.Result{}, err
	}
	googleType, ok := workingLocationTypes[kind]
	if !ok {
		return connectors.Result{}, invalid("type must be home, office or custom")
	}
	label, err := optionalString(call.Args, "label")
	if err != nil {
		return connectors.Result{}, err
	}
	label = strings.TrimSpace(label)
	props := &calendar.EventWorkingLocationProperties{Type: googleType}
	switch kind {
	case "home":
		if label != "" {
			return connectors.Result{}, invalid("label names an office or a custom place; type home takes none")
		}
		props.HomeOffice = map[string]any{}
	case "office":
		props.OfficeLocation = &calendar.EventWorkingLocationPropertiesOfficeLocation{Label: label}
	case "custom":
		if label == "" {
			return connectors.Result{}, invalid("label is required for type custom (the place)")
		}
		props.CustomLocation = &calendar.EventWorkingLocationPropertiesCustomLocation{Label: label}
	}
	date, err := optionalString(call.Args, "date")
	if err != nil {
		return connectors.Result{}, err
	}
	_, hasStart := call.Args["start"]
	_, hasEnd := call.Args["end"]
	ev := &calendar.Event{EventType: "workingLocation", Visibility: "public", Transparency: "transparent", WorkingLocationProperties: props}
	switch date = strings.TrimSpace(date); {
	case date != "" && (hasStart || hasEnd):
		return connectors.Result{}, invalid("give either date or start and end, not both")
	case date != "":
		day, err := time.Parse("2006-01-02", date)
		if err != nil {
			return connectors.Result{}, invalid("date must be YYYY-MM-DD")
		}
		ev.Start, ev.End = &calendar.EventDateTime{Date: date}, &calendar.EventDateTime{Date: day.AddDate(0, 0, 1).Format("2006-01-02")}
	case hasStart || hasEnd:
		if ev.Start, ev.End, err = timedRange(call.Args); err != nil {
			return connectors.Result{}, err
		}
	default:
		return connectors.Result{}, invalid("date (YYYY-MM-DD) or start and end are required")
	}
	return c.insertWorkspaceEvent(ctx, cl, call, "set working location", ev)
}

func (c *Connector) createFocusTime(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	start, end, err := timedRange(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	summary, err := summaryArg(call.Args, DefaultFocusTimeSummary)
	if err != nil {
		return connectors.Result{}, err
	}
	mode, message, err := declineArgs(call.Args, "only_new_conflicting")
	if err != nil {
		return connectors.Result{}, err
	}
	chat, err := optionalString(call.Args, "chat_status")
	if err != nil {
		return connectors.Result{}, err
	}
	if chat = strings.TrimSpace(chat); chat != "" && !slices.Contains(chatStatusValues, chat) {
		return connectors.Result{}, invalid("chat_status must be available or doNotDisturb")
	}
	return c.insertWorkspaceEvent(ctx, cl, call, "create focus time", &calendar.Event{
		EventType: "focusTime", Summary: summary, Start: start, End: end,
		FocusTimeProperties: &calendar.EventFocusTimeProperties{AutoDeclineMode: mode, DeclineMessage: message, ChatStatus: chat},
	})
}
