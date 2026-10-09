package microsoft

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/microsoft/graph"
)

// Write tool names.
const (
	ToolMailSend                = "mail_send"
	ToolCalendarCreateEvent     = "calendar_create_event"
	ToolDriveCreateFolder       = "drive_create_folder"
	ToolTeamsPostChannelMessage = "teams_post_channel_message"
)

// Limits on write arguments.
const (
	maxRecipients  = 500
	maxBodyBytes   = 1 << 20
	maxNameLength  = 255
	maxSubjectSize = 1024
)

// MarkerHeader is the internet message header mail_send adds to every
// message it sends, carrying the ledger operation id.
const MarkerHeader = "x-mcp-gateway-op"

// ErrMissingOperation is returned by every write called without
// Call.OperationID: the ledger stage sets it before dispatch, and the
// marker and stable-id reconciliation derive from it, so a write without
// one could never be verified after an unknown outcome. It means a
// pipeline wiring bug (a write dispatched without the ledger), never a
// harness mistake.
var ErrMissingOperation = errors.New("microsoft: write called without a ledger operation id")

// InternetMessageID returns the deterministic RFC 5322 message id
// mail_send gives the message of a ledger operation:
// "<op-<operation id>@mcp-gateway>". The reconciler filters Sent Items
// by it.
func InternetMessageID(operationID string) string {
	return "<op-" + operationID + "@mcp-gateway>"
}

// writeTools declares the four write tools.
func (c *Connector) writeTools() []connectors.Tool {
	single := connectors.Bounds{MaxResultBytes: c.bounds.MaxResultBytes}
	return []connectors.Tool{
		{
			App: App, Name: ToolMailSend, Kind: connectors.KindWrite,
			Description: "Send an Outlook mail from the user's mailbox to one or more recipients (addresses, or \"Name <address>\"), with a subject " +
				"and a plain-text body (content_type html sends HTML). A copy is saved to Sent Items. Returns the message's internet message id.",
			InputSchema: objectSchema([]property{
				{"to", "array", "Recipient addresses (\"bob@example.com\" or \"Bob <bob@example.com>\").", nil},
				{"subject", "string", "Subject line.", nil},
				{"body", "string", "Message body: plain text, or HTML when content_type is html.", nil},
				{"cc", "array", "Cc addresses.", nil},
				{"content_type", "string", "Body type: text (default) or html.", []string{"text", "html"}},
			}, []string{"to", "subject", "body"}),
			RequiredScopes:   []string{ScopeMailSend},
			ResourceIdentity: func(map[string]any) map[string]string { return map[string]string{"mailbox": "me"} },
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileMarker, Check: c.checkMail},
			ResultIDs:        mailResultIDs,
			Bounds:           single,
		},
		{
			App: App, Name: ToolCalendarCreateEvent, Kind: connectors.KindWrite,
			Description: "Create an event in the user's calendar: subject, start and end (ISO 8601 local times, interpreted in time_zone, UTC by " +
				"default; a trailing Z or offset is converted), optional attendees (invited as required), body, location and calendar_id. " +
				"Returns the new event's id and web link.",
			InputSchema: objectSchema([]property{
				{"subject", "string", "Event subject.", nil},
				{"start", "string", "Start, ISO 8601 (2026-10-10T14:00:00).", nil},
				{"end", "string", "End, ISO 8601, after start.", nil},
				{"time_zone", "string", "IANA or Windows time zone name for start and end (default UTC).", nil},
				{"attendees", "array", "Attendee addresses (\"Name <address>\" allowed); invited as required attendees.", nil},
				{"body", "string", "Description in plain text.", nil},
				{"location", "string", "Location name.", nil},
				{"calendar_id", "string", "Calendar id; the default calendar when omitted.", nil},
			}, []string{"subject", "start", "end"}),
			RequiredScopes:   []string{ScopeCalendarsReadWrite},
			ResourceIdentity: calendarIdentity,
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: c.checkEvent},
			ResultIDs:        eventResultIDs,
			Bounds:           single,
		},
		{
			App: App, Name: ToolDriveCreateFolder, Kind: connectors.KindWrite,
			Description: "Create a folder in the user's OneDrive (or in drive_id) under parent_id (the drive's root when omitted). Fails when " +
				"an item of that name exists there. Returns the new folder's id and web url.",
			InputSchema: objectSchema([]property{
				{"name", "string", "Folder name.", nil},
				{"parent_id", "string", "Parent folder item id; the drive root when omitted.", nil},
				{"drive_id", "string", "Drive id; the user's OneDrive when omitted.", nil},
			}, []string{"name"}),
			RequiredScopes:   []string{ScopeFilesReadWrite},
			ResourceIdentity: folderCreateIdentity,
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileMarker, Check: c.checkFolder},
			ResultIDs:        folderResultIDs,
			Bounds:           single,
		},
		{
			App: App, Name: ToolTeamsPostChannelMessage, Kind: connectors.KindWrite,
			Description: "Post a new message to a Teams channel as the user (plain text, or HTML with content_type html). Returns the message id. " +
				"Not available on personal Microsoft accounts. The outcome of a lost reply cannot be verified afterwards.",
			InputSchema: objectSchema([]property{
				{"team_id", "string", "Team id.", nil},
				{"channel_id", "string", "Channel id.", nil},
				{"content", "string", "Message content.", nil},
				{"content_type", "string", "Content type: text (default) or html.", []string{"text", "html"}},
			}, []string{"team_id", "channel_id", "content"}),
			RequiredScopes:   []string{ScopeChannelMessageSend},
			ResourceIdentity: teamIdentity(true),
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileNone},
			ResultIDs:        postedResultIDs,
			Bounds:           single,
		},
	}
}

// writeHandlers maps the write tools' short names to their implementation.
func (c *Connector) writeHandlers() map[string]handler {
	return map[string]handler{
		ToolMailSend:                c.mailSend,
		ToolCalendarCreateEvent:     c.calendarCreateEvent,
		ToolDriveCreateFolder:       c.driveCreateFolder,
		ToolTeamsPostChannelMessage: c.teamsPostChannelMessage,
	}
}

// folderCreateIdentity records the drive, the parent ("root" when
// omitted) and the folder name; the name keeps its case (the check
// compares case-insensitively, as OneDrive does).
func folderCreateIdentity(args map[string]any) map[string]string {
	out := driveIdentity(args)
	parent := strings.TrimSpace(stringArg(args, "parent_id"))
	if parent == "" {
		parent = "root"
	}
	out["parent"] = parent
	if name := strings.TrimSpace(stringArg(args, "name")); name != "" {
		out["folder"] = name
	}
	return out
}

// --- result ids -------------------------------------------------------------------

func mailResultIDs(res connectors.Result) map[string]string {
	v, ok := res.Content.(SentMail)
	if !ok || v.InternetMessageID == "" {
		return nil
	}
	return map[string]string{"internet_message_id": v.InternetMessageID}
}

func eventResultIDs(res connectors.Result) map[string]string {
	v, ok := res.Content.(CreatedEvent)
	if !ok || v.ID == "" {
		return nil
	}
	return map[string]string{"id": v.ID, "web_link": v.WebLink, "transaction_id": v.TransactionID}
}

func folderResultIDs(res connectors.Result) map[string]string {
	v, ok := res.Content.(CreatedFolder)
	if !ok || v.ID == "" {
		return nil
	}
	return map[string]string{"id": v.ID, "web_url": v.WebURL}
}

func postedResultIDs(res connectors.Result) map[string]string {
	v, ok := res.Content.(PostedMessage)
	if !ok || v.ID == "" {
		return nil
	}
	return map[string]string{"id": v.ID, "web_url": v.WebURL}
}

// --- shared write helpers ----------------------------------------------------------

// classifyWrite maps the error of the request that performs a write:
// an answer from Graph (4xx, throttle) is a known outcome and is
// classified like a read's; anything that leaves the outcome open (5xx,
// a timeout, a cancelled context, a dropped connection: the request may
// have been applied) wraps connectors.ErrOutcomeUnknown so the ledger
// marks the operation unknown and the reconciler checks it.
func classifyWrite(action string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return fmt.Errorf("%w: %s: Microsoft Graph did not answer in time (%w)", connectors.ErrOutcomeUnknown, action, err)
	}
	classified := classify(action, err)
	if classOf(classified) == ClassUnavailable {
		return fmt.Errorf("%w: %w", connectors.ErrOutcomeUnknown, classified)
	}
	return classified
}

// recipient is Graph's recipient shape.
type recipient struct {
	EmailAddress emailAddress `json:"emailAddress"`
}

type emailAddress struct {
	Address string `json:"address"`
	Name    string `json:"name,omitempty"`
}

// addressList reads an array of addresses ("addr" or "Name <addr>"),
// validated with net/mail; nil when absent and not required.
func addressList(args map[string]any, name string, required bool) ([]recipient, error) {
	v, ok := args[name]
	if !ok || v == nil {
		if required {
			return nil, invalid("%s is required: one or more addresses", name)
		}
		return nil, nil
	}
	var raw []string
	switch list := v.(type) {
	case []string:
		raw = list
	case []any:
		for _, item := range list {
			s, ok := item.(string)
			if !ok {
				return nil, invalid("%s must be an array of addresses", name)
			}
			raw = append(raw, s)
		}
	default:
		return nil, invalid("%s must be an array of addresses", name)
	}
	if len(raw) > maxRecipients {
		return nil, invalid("%s lists more than %d addresses", name, maxRecipients)
	}
	var out []recipient
	for _, s := range raw {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		addr, err := mail.ParseAddress(s)
		if err != nil || addr.Address == "" || !strings.Contains(addr.Address, "@") {
			return nil, invalid("%s: %q is not an email address", name, s)
		}
		out = append(out, recipient{EmailAddress: emailAddress{Address: addr.Address, Name: addr.Name}})
	}
	if len(out) == 0 && required {
		return nil, invalid("%s is required: one or more addresses", name)
	}
	return out, nil
}

// contentTypeArg reads content_type (text or html) and returns Graph's
// spelling for mail bodies ("Text"/"HTML") or chat bodies
// ("text"/"html").
func contentTypeArg(args map[string]any, mailStyle bool) (string, error) {
	ct, err := optionalString(args, "content_type")
	if err != nil {
		return "", err
	}
	ct = strings.ToLower(strings.TrimSpace(ct))
	switch ct {
	case "", "text":
		if mailStyle {
			return "Text", nil
		}
		return "text", nil
	case "html":
		if mailStyle {
			return "HTML", nil
		}
		return "html", nil
	}
	return "", invalid("content_type must be text or html")
}

// --- handlers ----------------------------------------------------------------------------

func (c *Connector) mailSend(ctx context.Context, client *graph.Client, call connectors.Call) (connectors.Result, error) {
	to, err := addressList(call.Args, "to", true)
	if err != nil {
		return connectors.Result{}, err
	}
	cc, err := addressList(call.Args, "cc", false)
	if err != nil {
		return connectors.Result{}, err
	}
	subject, err := requiredString(call.Args, "subject")
	if err != nil {
		return connectors.Result{}, err
	}
	if len(subject) > maxSubjectSize {
		return connectors.Result{}, invalid("subject is too long")
	}
	body, ok := call.Args["body"].(string)
	if !ok {
		return connectors.Result{}, invalid("body is required")
	}
	if len(body) > maxBodyBytes {
		return connectors.Result{}, invalid("body is too long")
	}
	contentType, err := contentTypeArg(call.Args, true)
	if err != nil {
		return connectors.Result{}, err
	}
	imID := InternetMessageID(call.OperationID)
	message := map[string]any{
		"subject":                subject,
		"body":                   map[string]string{"contentType": contentType, "content": body},
		"toRecipients":           to,
		"internetMessageId":      imID,
		"internetMessageHeaders": []map[string]string{{"name": MarkerHeader, "value": call.OperationID}},
	}
	if len(cc) > 0 {
		message["ccRecipients"] = cc
	}
	req := map[string]any{"message": message, "saveToSentItems": true}
	if _, err := client.Post(ctx, "me/sendMail", req, nil); err != nil {
		if err := classifyWrite("send mail", err); err != nil {
			return connectors.Result{}, err
		}
	}
	return connectors.Result{Content: SentMail{InternetMessageID: imID}}, nil
}

// eventTime is Graph's dateTimeTimeZone.
type eventTime struct {
	DateTime string `json:"dateTime"`
	TimeZone string `json:"timeZone"`
}

// localTimeArg reads an ISO 8601 time argument for an event: a value
// with an offset or Z is converted to the zone; a bare local time is
// taken as is in the zone.
func localTimeArg(args map[string]any, name string, loc *time.Location, zone string) (eventTime, time.Time, error) {
	s, err := requiredString(args, name)
	if err != nil {
		return eventTime{}, time.Time{}, err
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			local := t.In(loc)
			return eventTime{DateTime: local.Format("2006-01-02T15:04:05"), TimeZone: zone}, t, nil
		}
	}
	for _, layout := range []string{"2006-01-02T15:04:05.999999999", "2006-01-02T15:04:05", "2006-01-02T15:04"} {
		if t, err := time.ParseInLocation(layout, s, loc); err == nil {
			return eventTime{DateTime: t.Format("2006-01-02T15:04:05"), TimeZone: zone}, t, nil
		}
	}
	return eventTime{}, time.Time{}, invalid("%s must be an ISO 8601 timestamp (2026-10-10T14:00:00)", name)
}

func (c *Connector) calendarCreateEvent(ctx context.Context, client *graph.Client, call connectors.Call) (connectors.Result, error) {
	subject, err := requiredString(call.Args, "subject")
	if err != nil {
		return connectors.Result{}, err
	}
	zone, err := optionalString(call.Args, "time_zone")
	if err != nil {
		return connectors.Result{}, err
	}
	zone = strings.TrimSpace(zone)
	if zone == "" {
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
	attendees, err := addressList(call.Args, "attendees", false)
	if err != nil {
		return connectors.Result{}, err
	}
	body, err := optionalString(call.Args, "body")
	if err != nil {
		return connectors.Result{}, err
	}
	location, err := optionalString(call.Args, "location")
	if err != nil {
		return connectors.Result{}, err
	}
	cal, err := idArg(call.Args, "calendar_id")
	if err != nil {
		return connectors.Result{}, err
	}
	event := map[string]any{"subject": subject, "start": start, "end": end, "transactionId": call.OperationID}
	if len(attendees) > 0 {
		list := make([]map[string]any, 0, len(attendees))
		for _, a := range attendees {
			list = append(list, map[string]any{"emailAddress": a.EmailAddress, "type": "required"})
		}
		event["attendees"] = list
	}
	if strings.TrimSpace(body) != "" {
		event["body"] = map[string]string{"contentType": "Text", "content": body}
	}
	if strings.TrimSpace(location) != "" {
		event["location"] = map[string]string{"displayName": strings.TrimSpace(location)}
	}
	path := "me/events"
	if cal != "" {
		path = "me/calendars/" + cal + "/events"
	}
	var created graphEvent
	if _, err := client.Post(ctx, path, event, &created); err != nil {
		if err := classifyWrite("create event", err); err != nil {
			return connectors.Result{}, err
		}
	}
	if created.ID == "" {
		return connectors.Result{}, fmt.Errorf("%w: create event: Microsoft Graph answered without an event id", connectors.ErrOutcomeUnknown)
	}
	return connectors.Result{Content: CreatedEvent{ID: created.ID, WebLink: created.WebLink, TransactionID: call.OperationID}}, nil
}

// folderNameArg reads and validates the folder name: no path
// separators or characters OneDrive refuses, not "." or "..".
func folderNameArg(args map[string]any) (string, error) {
	name, err := requiredString(args, "name")
	if err != nil {
		return "", err
	}
	if len(name) > maxNameLength || name == "." || name == ".." || strings.ContainsAny(name, "/\\:*?\"<>|#%") {
		return "", invalid("name is not a valid folder name")
	}
	return name, nil
}

// childrenPath returns the Graph path of the children collection of
// parent in drive (the user's OneDrive root when either is empty).
func childrenPath(drive, parent string) string {
	root := "me/drive"
	if drive != "" && drive != driveDefaultName {
		root = "drives/" + drive
	}
	if parent == "" || parent == "root" {
		return root + "/root/children"
	}
	return root + "/items/" + parent + "/children"
}

func (c *Connector) driveCreateFolder(ctx context.Context, client *graph.Client, call connectors.Call) (connectors.Result, error) {
	name, err := folderNameArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	parent, err := idArg(call.Args, "parent_id")
	if err != nil {
		return connectors.Result{}, err
	}
	drive, err := idArg(call.Args, "drive_id")
	if err != nil {
		return connectors.Result{}, err
	}
	req := map[string]any{"name": name, "folder": map[string]any{}, "@microsoft.graph.conflictBehavior": "fail"}
	var created graphDriveItem
	if _, err := client.Post(ctx, childrenPath(drive, parent), req, &created); err != nil {
		if err := classifyWrite("create folder", err); err != nil {
			if statusOf(err) == http.StatusConflict {
				return connectors.Result{}, &Error{Status: http.StatusConflict, Class: ClassInvalidArgument, Message: "create folder: an item named " + name + " already exists in that folder", Err: err}
			}
			return connectors.Result{}, err
		}
	}
	if created.ID == "" {
		return connectors.Result{}, fmt.Errorf("%w: create folder: Microsoft Graph answered without an item id", connectors.ErrOutcomeUnknown)
	}
	out := CreatedFolder{ID: created.ID, Name: created.Name, WebURL: created.WebURL}
	if created.ParentReference != nil {
		out.DriveID, out.ParentID = created.ParentReference.DriveID, created.ParentReference.ID
	}
	return connectors.Result{Content: out}, nil
}

func (c *Connector) teamsPostChannelMessage(ctx context.Context, client *graph.Client, call connectors.Call) (connectors.Result, error) {
	team, err := requiredID(call.Args, "team_id")
	if err != nil {
		return connectors.Result{}, err
	}
	channel, err := requiredID(call.Args, "channel_id")
	if err != nil {
		return connectors.Result{}, err
	}
	content, err := requiredString(call.Args, "content")
	if err != nil {
		return connectors.Result{}, err
	}
	if len(content) > maxBodyBytes {
		return connectors.Result{}, invalid("content is too long")
	}
	contentType, err := contentTypeArg(call.Args, false)
	if err != nil {
		return connectors.Result{}, err
	}
	req := map[string]any{"body": map[string]string{"contentType": contentType, "content": content}}
	var posted graphChatMessage
	if _, err := client.Post(ctx, "teams/"+team+"/channels/"+channel+"/messages", req, &posted); err != nil {
		if err := classifyWrite("post channel message", err); err != nil {
			return connectors.Result{}, err
		}
	}
	if posted.ID == "" {
		return connectors.Result{}, fmt.Errorf("%w: post channel message: Microsoft Graph answered without a message id", connectors.ErrOutcomeUnknown)
	}
	return connectors.Result{Content: PostedMessage{ID: posted.ID, WebURL: posted.WebURL, TeamID: team, ChannelID: channel}}, nil
}
