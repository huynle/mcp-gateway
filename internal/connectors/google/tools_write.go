package google

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"net/mail"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"google.golang.org/api/calendar/v3"
	"google.golang.org/api/gmail/v1"
	"google.golang.org/api/tasks/v1"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// The four writes. Each requires the ledger's Call.OperationID, derives
// its reconciliation key from it before the request (an event id, a
// marker in the notes, an RFC 5322 Message-ID), returns only the created
// resource's identifiers and reports an outcome that cannot be known as
// connectors.ErrOutcomeUnknown (classifyWrite). Lookups before a write
// (the message replied to) are reads: their failures are known outcomes.

// Values of create_event's send_updates.
var sendUpdatesValues = []string{"all", "externalOnly", "none"}

// --- reconciliation keys ------------------------------------------------------------

// EventID returns the client-chosen Calendar event id for a ledger
// operation: the lower-case base32hex (a-v0-9, the alphabet Calendar
// accepts) of sha256(operation id), truncated to 32 characters. The same
// operation always maps to the same id, so an event created under an
// unknown outcome can be looked up by it.
func EventID(operationID string) string {
	sum := sha256.Sum256([]byte(operationID))
	return strings.ToLower(base32.HexEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:]))[:32]
}

// MeetRequestID returns the conferenceData.createRequest.requestId
// add_meet_link sends: "mcpgw-" + EventID(operation id). Google
// dedupes conference creation by it, so a retry of the same operation
// never asks for a second Meet; it never carries the operation id itself.
func MeetRequestID(operationID string) string { return "mcpgw-" + EventID(operationID) }

// meetRequest is the conference data that asks Google for a new Meet.
func meetRequest(operationID string) *calendar.ConferenceData {
	return &calendar.ConferenceData{CreateRequest: &calendar.CreateConferenceRequest{
		RequestId:             MeetRequestID(operationID),
		ConferenceSolutionKey: &calendar.ConferenceSolutionKey{Type: "hangoutsMeet"},
	}}
}

// taskMarkerPhrase is the searchable text inside a task marker.
const taskMarkerPhrase = "mcp-gateway op:"

// TaskMarker returns the marker tasks.create appends to the task's
// notes: "[mcp-gateway op:<operation id>]". Google Tasks has no hidden
// field, so the marker is visible in the notes; it is short and names
// the gateway.
func TaskMarker(operationID string) string { return "[" + taskMarkerPhrase + operationID + "]" }

// withTaskMarker appends the operation's marker to notes (on its own
// paragraph; just the marker when notes are empty).
func withTaskMarker(notes, operationID string) string {
	notes = strings.TrimRight(notes, " \t\r\n")
	if notes == "" {
		return TaskMarker(operationID)
	}
	return notes + "\n\n" + TaskMarker(operationID)
}

// hasTaskMarker reports whether notes carry the operation's marker.
func hasTaskMarker(notes, operationID string) bool {
	return operationID != "" && strings.Contains(notes, TaskMarker(operationID))
}

// MessageID returns the RFC 5322 Message-ID gmail.send and
// gmail.create_draft put on the message they create:
// "<op-<operation id>@mcp-gateway>". Gmail keeps a client-supplied
// Message-ID, and its search operator rfc822msgid: finds the message
// by it.
func MessageID(operationID string) string { return "<op-" + operationID + "@mcp-gateway>" }

// messageIDQuery is the Gmail search for an operation's Message-ID.
func messageIDQuery(operationID string) string {
	return "rfc822msgid:" + strings.Trim(MessageID(operationID), "<>")
}

// --- tool declarations -------------------------------------------------------------

var (
	toProperty        = property{"to", "array", "Recipient addresses (\"Name <user@example.com>\" or bare addresses).", nil}
	ccProperty        = property{"cc", "array", "Cc addresses.", nil}
	bccProperty       = property{"bcc", "array", "Bcc addresses.", nil}
	subjectProperty   = property{"subject", "string", "Subject line.", nil}
	bodyProperty      = property{"body", "string", "Plain-text body.", nil}
	inReplyToProperty = property{"in_reply_to", "string", "Id of the Gmail message being replied to (from search or get_message): the reply joins its thread and references it.", nil}
	// addMeetLinkProperty is create_event's and update_event's add_meet_link.
	addMeetLinkProperty = property{"add_meet_link", "boolean", "Add a Google Meet video link to the event (meet_url in the result; meet_status pending means Google is still creating it). Default false.", nil}
)

// calendarWriteTools declares calendar.create_event.
func (c *Connector) calendarWriteTools() []connectors.Tool {
	return []connectors.Tool{{
		App: AppCalendar, Name: ToolCreateEvent, Kind: connectors.KindWrite,
		Description: "Create an event in a Google Calendar with a summary, start and end (RFC 3339 timestamps, or YYYY-MM-DD dates for an all-day event), " +
			"and optionally a description, location, attendees and whether to email them (send_updates; default none). " +
			"add_meet_link adds a Google Meet video link. Returns the new event's id and url (and meet_url).",
		InputSchema: objectSchema([]property{
			{"calendar_id", "string", "Calendar to create the event in: \"primary\" (default) or a calendar id.", nil},
			{"summary", "string", "Event title.", nil},
			{"start", "string", "Start: RFC 3339 timestamp (2026-10-10T10:00:00-07:00) or date (2026-10-10) for an all-day event.", nil},
			{"end", "string", "End (exclusive): same form as start.", nil},
			{"time_zone", "string", "IANA time zone of start and end (America/Los_Angeles); the calendar's zone when omitted.", nil},
			{"description", "string", "Event description.", nil},
			{"location", "string", "Where the event takes place.", nil},
			{"attendees", "array", "Attendee email addresses.", nil},
			{"send_updates", "string", "Whether Google emails the attendees: all, externalOnly or none (default).", sendUpdatesValues},
			addMeetLinkProperty,
		}, []string{"summary", "start", "end"}),
		RequiredScopes:   []string{ScopeCalendarEvents},
		ResourceIdentity: calendarIdentity(false),
		Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: c.checkEvent},
		ResultIDs:        eventResultIDs,
		Bounds:           c.singleBounds(),
	}}
}

func (c *Connector) calendarWriteHandlers() map[string]handler {
	return map[string]handler{ToolCreateEvent: c.createEvent}
}

// tasksWriteTools declares tasks.create.
func (c *Connector) tasksWriteTools() []connectors.Tool {
	return []connectors.Tool{{
		App: AppTasks, Name: ToolCreateTask, Kind: connectors.KindWrite,
		Description: "Create a task in a Google Tasks list (the default list unless tasklist is given) with a title and optionally notes " +
			"and a due date (YYYY-MM-DD; Google Tasks keeps no time of day). Returns the new task's id and url.",
		InputSchema: objectSchema([]property{
			tasklistProperty,
			{"title", "string", "Task title.", nil},
			{"notes", "string", "Task notes.", nil},
			{"due", "string", "Due date, YYYY-MM-DD (an RFC 3339 timestamp is reduced to its date).", nil},
		}, []string{"title"}),
		RequiredScopes:   []string{ScopeTasks},
		ResourceIdentity: tasksIdentity,
		Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileMarker, Check: c.checkTask},
		ResultIDs:        taskResultIDs,
		Bounds:           c.singleBounds(),
	}}
}

func (c *Connector) tasksWriteHandlers() map[string]handler {
	return map[string]handler{ToolCreateTask: c.createTask}
}

// gmailWriteTools declares gmail.send and gmail.create_draft.
func (c *Connector) gmailWriteTools() []connectors.Tool {
	return []connectors.Tool{
		{
			App: AppGmail, Name: ToolSend, Kind: connectors.KindWrite,
			Description: "Send a plain-text email from the Gmail account to one or more recipients, with optional cc, bcc and attachments; " +
				"in_reply_to makes it a reply in that message's thread. Returns the sent message's id, thread id and Message-ID.",
			InputSchema:      objectSchema([]property{toProperty, ccProperty, bccProperty, subjectProperty, bodyProperty, inReplyToProperty, attachmentsProperty}, []string{"to", "subject", "body"}),
			RequiredScopes:   []string{ScopeGmailSend},
			ResourceIdentity: recipientsIdentity,
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileMarker, Check: c.checkSent},
			ResultIDs:        sentResultIDs,
			Bounds:           c.singleBounds(),
		},
		{
			App: AppGmail, Name: ToolCreateDraft, Kind: connectors.KindWrite,
			Description: "Create a draft email in the Gmail account (not sent): recipients, optional cc, bcc and attachments, subject and plain-text body; " +
				"in_reply_to drafts a reply in that message's thread. Returns the draft's id and the draft message's id.",
			InputSchema:      objectSchema([]property{toProperty, ccProperty, bccProperty, subjectProperty, bodyProperty, inReplyToProperty, attachmentsProperty}, []string{"to", "subject", "body"}),
			RequiredScopes:   []string{ScopeGmailCompose},
			ResourceIdentity: recipientsIdentity,
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileMarker, Check: c.checkDraft},
			ResultIDs:        draftResultIDs,
			Bounds:           c.singleBounds(),
		},
	}
}

func (c *Connector) gmailWriteHandlers() map[string]handler {
	return map[string]handler{ToolSend: c.sendMessage, ToolCreateDraft: c.createDraft}
}

// recipientsIdentity extracts recipient_domains (the sorted, unique
// domains of to, cc and bcc, comma separated) from the arguments: where
// the mail goes, never who exactly or what it says.
func recipientsIdentity(args map[string]any) map[string]string {
	seen := map[string]bool{}
	var domains []string
	for _, name := range []string{"to", "cc", "bcc"} {
		list, err := stringList(args, name)
		if err != nil {
			continue
		}
		for _, raw := range list {
			addr, err := mail.ParseAddress(raw)
			if err != nil {
				continue
			}
			if d := domainOf(addr.Address); d != "" && !seen[d] {
				seen[d] = true
				domains = append(domains, d)
			}
		}
	}
	out := map[string]string{}
	if len(domains) > 0 {
		sort.Strings(domains)
		out["recipient_domains"] = strings.Join(domains, ",")
	}
	if n := attachmentCount(args); n > 0 {
		out["attachments"] = strconv.Itoa(n)
	}
	return out
}

// --- result ids ----------------------------------------------------------------------

func eventResultIDs(res connectors.Result) map[string]string {
	v, ok := res.Content.(CreatedEvent)
	if !ok || v.ID == "" {
		return nil
	}
	ids := map[string]string{"id": v.ID, "url": v.URL}
	if v.MeetURL != "" {
		ids["meet_url"] = v.MeetURL
	}
	return ids
}

func taskResultIDs(res connectors.Result) map[string]string {
	v, ok := res.Content.(CreatedTask)
	if !ok || v.ID == "" {
		return nil
	}
	return map[string]string{"id": v.ID, "url": v.URL}
}

func sentResultIDs(res connectors.Result) map[string]string {
	v, ok := res.Content.(SentMessage)
	if !ok || v.ID == "" {
		return nil
	}
	return map[string]string{"id": v.ID, "thread_id": v.ThreadID, "message_id": v.MessageID}
}

func draftResultIDs(res connectors.Result) map[string]string {
	v, ok := res.Content.(CreatedDraft)
	if !ok || v.ID == "" {
		return nil
	}
	return map[string]string{"id": v.ID, "message_id": v.MessageID, "thread_id": v.ThreadID, "rfc822_message_id": v.RFC822ID}
}

// --- calendar.create_event ---------------------------------------------------------

// eventTime parses start or end: a date (all-day) or an RFC 3339
// timestamp.
func eventTime(args map[string]any, name string) (value string, allDay bool, at time.Time, err error) {
	v, err := requiredString(args, name)
	if err != nil {
		return "", false, time.Time{}, err
	}
	if d, err := time.Parse("2006-01-02", v); err == nil {
		return v, true, d, nil
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return "", false, time.Time{}, invalid("%s must be an RFC 3339 timestamp (2026-10-10T10:00:00-07:00) or a date (2026-10-10)", name)
	}
	return v, false, t, nil
}

func (c *Connector) createEvent(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	calendarID, err := calendarArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	summary, err := requiredString(call.Args, "summary")
	if err != nil {
		return connectors.Result{}, err
	}
	start, startAllDay, startAt, err := eventTime(call.Args, "start")
	if err != nil {
		return connectors.Result{}, err
	}
	end, endAllDay, endAt, err := eventTime(call.Args, "end")
	if err != nil {
		return connectors.Result{}, err
	}
	if startAllDay != endAllDay {
		return connectors.Result{}, invalid("start and end must both be dates (all-day) or both be timestamps")
	}
	if !endAt.After(startAt) {
		return connectors.Result{}, invalid("end must be after start")
	}
	timeZone, err := optionalString(call.Args, "time_zone")
	if err != nil {
		return connectors.Result{}, err
	}
	description, err := optionalString(call.Args, "description")
	if err != nil {
		return connectors.Result{}, err
	}
	location, err := optionalString(call.Args, "location")
	if err != nil {
		return connectors.Result{}, err
	}
	attendees, err := stringList(call.Args, "attendees")
	if err != nil {
		return connectors.Result{}, err
	}
	sendUpdates, err := optionalString(call.Args, "send_updates")
	if err != nil {
		return connectors.Result{}, err
	}
	if sendUpdates = strings.TrimSpace(sendUpdates); sendUpdates == "" {
		sendUpdates = "none"
	}
	if !slices.Contains(sendUpdatesValues, sendUpdates) {
		return connectors.Result{}, invalid("send_updates must be all, externalOnly or none")
	}
	addMeet, err := optionalBool(call.Args, "add_meet_link", false)
	if err != nil {
		return connectors.Result{}, err
	}
	ev := &calendar.Event{Id: EventID(call.OperationID), Summary: summary, Description: description, Location: location}
	if startAllDay {
		ev.Start, ev.End = &calendar.EventDateTime{Date: start}, &calendar.EventDateTime{Date: end}
	} else {
		ev.Start, ev.End = &calendar.EventDateTime{DateTime: start, TimeZone: strings.TrimSpace(timeZone)}, &calendar.EventDateTime{DateTime: end, TimeZone: strings.TrimSpace(timeZone)}
	}
	for _, a := range attendees {
		addr, err := mail.ParseAddress(a)
		if err != nil {
			return connectors.Result{}, invalid("attendees must be email addresses (%q is not)", a)
		}
		ev.Attendees = append(ev.Attendees, &calendar.EventAttendee{Email: addr.Address})
	}
	svc, err := cl.calendar(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	req := svc.Events.Insert(calendarID, ev).Context(ctx).SendUpdates(sendUpdates)
	if addMeet {
		ev.ConferenceData = meetRequest(call.OperationID)
		req = req.ConferenceDataVersion(1)
	}
	created, err := req.Do()
	if err := classifyWrite("create event", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: toCreatedEvent(created, calendarID)}, nil
}

// --- tasks.create --------------------------------------------------------------------

func (c *Connector) createTask(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	tasklist, err := idArgDefault(call.Args, "tasklist", DefaultTasklist)
	if err != nil {
		return connectors.Result{}, err
	}
	title, err := requiredString(call.Args, "title")
	if err != nil {
		return connectors.Result{}, err
	}
	notes, err := optionalString(call.Args, "notes")
	if err != nil {
		return connectors.Result{}, err
	}
	due, err := optionalString(call.Args, "due")
	if err != nil {
		return connectors.Result{}, err
	}
	task := &tasks.Task{Title: title, Notes: withTaskMarker(notes, call.OperationID)}
	if due = strings.TrimSpace(due); due != "" {
		d, err := time.Parse("2006-01-02", due)
		if err != nil {
			if d, err = time.Parse(time.RFC3339, due); err != nil {
				return connectors.Result{}, invalid("due must be a date (2026-10-10) or an RFC 3339 timestamp")
			}
		}
		task.Due = d.Format("2006-01-02") + "T00:00:00Z"
	}
	svc, err := cl.tasks(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	created, err := svc.Tasks.Insert(tasklist, task).Context(ctx).Do()
	if err := classifyWrite("create task", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: CreatedTask{ID: created.Id, Tasklist: tasklist, URL: created.WebViewLink, Status: created.Status}}, nil
}

// --- gmail.send / gmail.create_draft -------------------------------------------------

// outgoing is a message to send or draft.
type outgoing struct {
	to, cc, bcc                []string
	subject, body              string
	html                       bool // the body is text/html (a forwarded HTML message)
	messageID, inReplyTo, refs string
	threadID                   string
	attachments                []attachment
}

// addressList reads and validates an address-list argument.
func addressList(args map[string]any, name string, required bool) ([]string, error) {
	list, err := stringList(args, name)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		if required {
			return nil, invalid("%s is required: at least one recipient address", name)
		}
		return nil, nil
	}
	for _, raw := range list {
		if strings.ContainsAny(raw, "\r\n") {
			return nil, invalid("%s must not contain line breaks", name)
		}
		if _, err := mail.ParseAddress(raw); err != nil {
			return nil, invalid("%s must be email addresses (%q is not)", name, raw)
		}
	}
	return list, nil
}

// outgoingArgs reads the shared arguments of send and create_draft and,
// for a reply, looks the parent message up (a read).
func (c *Connector) outgoingArgs(ctx context.Context, cl *client, call connectors.Call) (outgoing, error) {
	var m outgoing
	var err error
	if m.to, err = addressList(call.Args, "to", true); err != nil {
		return m, err
	}
	if m.cc, err = addressList(call.Args, "cc", false); err != nil {
		return m, err
	}
	if m.bcc, err = addressList(call.Args, "bcc", false); err != nil {
		return m, err
	}
	if m.subject, err = requiredString(call.Args, "subject"); err != nil {
		return m, err
	}
	if strings.ContainsAny(m.subject, "\r\n") {
		return m, invalid("subject must not contain line breaks")
	}
	if _, err = requiredString(call.Args, "body"); err != nil {
		return m, err
	}
	m.body, _ = optionalString(call.Args, "body") // validated above; keep the body's own whitespace
	if m.attachments, err = attachmentsArg(call.Args); err != nil {
		return m, err
	}
	parentID, err := optionalString(call.Args, "in_reply_to")
	if err != nil {
		return m, err
	}
	m.messageID = MessageID(call.OperationID)
	if parentID = strings.TrimSpace(parentID); parentID != "" {
		if !idRE.MatchString(parentID) {
			return m, invalid("in_reply_to must be a Gmail message id")
		}
		svc, err := cl.gmail(ctx)
		if err != nil {
			return m, err
		}
		parent, err := svc.Users.Messages.Get(gmailUser, parentID).Context(ctx).Format("metadata").MetadataHeaders("Message-ID", "References").Do()
		if err := classify("look up the message to reply to", err); err != nil {
			return m, err
		}
		m.threadID = parent.ThreadId
		m.inReplyTo = headerOf(parent.Payload, "Message-ID")
		m.refs = strings.TrimSpace(strings.TrimSpace(headerOf(parent.Payload, "References")) + " " + m.inReplyTo)
	}
	return m, nil
}

func (c *Connector) sendMessage(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	m, err := c.outgoingArgs(ctx, cl, call)
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.gmail(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	req := svc.Users.Messages.Send(gmailUser, m.message()).Context(ctx)
	if media, ct := m.media(); media != nil {
		req = req.Media(media, ct)
	}
	sent, err := req.Do()
	if err := classifyWrite("send message", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: SentMessage{ID: sent.Id, ThreadID: sent.ThreadId, MessageID: m.messageID}}, nil
}

func (c *Connector) createDraft(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	m, err := c.outgoingArgs(ctx, cl, call)
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.gmail(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	req := svc.Users.Drafts.Create(gmailUser, &gmail.Draft{Message: m.message()}).Context(ctx)
	if media, ct := m.media(); media != nil {
		req = req.Media(media, ct)
	}
	draft, err := req.Do()
	if err := classifyWrite("create draft", err); err != nil {
		return connectors.Result{}, err
	}
	out := CreatedDraft{ID: draft.Id, RFC822ID: m.messageID}
	if draft.Message != nil {
		out.MessageID, out.ThreadID = draft.Message.Id, draft.Message.ThreadId
	}
	return connectors.Result{Content: out}, nil
}
