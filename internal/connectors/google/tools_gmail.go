package google

import (
	"context"
	"encoding/base64"
	"errors"
	"net/mail"
	"strings"
	"time"

	"google.golang.org/api/gmail/v1"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Gmail tool names.
const (
	ToolSearch      = "search"
	ToolGetMessage  = "get_message"
	ToolListLabels  = "list_labels"
	ToolSend        = "send"
	ToolCreateDraft = "create_draft"
)

// gmailUser is the Gmail API's alias for the authenticated account.
const gmailUser = "me"

// defaultMessagesPerPage is search's page size when the harness gives
// none: every hit costs one metadata request, so it stays small.
const defaultMessagesPerPage = 10

// metadataHeaders are the headers search asks for per hit.
var metadataHeaders = []string{"From", "To", "Cc", "Subject", "Date", "Message-ID"}

// labelUnread is Gmail's system label for unread messages.
const labelUnread = "UNREAD"

// Label is one list_labels item.
type Label struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type,omitempty"`
}

// Labels is list_labels's result.
type Labels struct {
	Items []Label `json:"items"`
}

// MessageSummary is one search hit: ids, snippet and the headers a
// harness needs to decide whether to open the message. Error, when set,
// says why the headers are missing (the metadata fetch failed; the
// result is partial).
type MessageSummary struct {
	ID       string   `json:"id"`
	ThreadID string   `json:"thread_id"`
	From     string   `json:"from,omitempty"`
	To       string   `json:"to,omitempty"`
	Subject  string   `json:"subject,omitempty"`
	Date     string   `json:"date,omitempty"`
	Snippet  string   `json:"snippet,omitempty"`
	Labels   []string `json:"labels,omitempty"`
	Unread   bool     `json:"unread,omitempty"`
	Error    string   `json:"error,omitempty"`
}

// MessagesPage is search's result.
type MessagesPage struct {
	Query              string           `json:"query"`
	MaxResults         int              `json:"max_results"`
	ResultSizeEstimate int64            `json:"result_size_estimate,omitempty"`
	NextPageToken      string           `json:"next_page_token,omitempty"`
	HasMore            bool             `json:"has_more"`
	Truncated          bool             `json:"truncated,omitempty"`
	Items              []MessageSummary `json:"items"`
}

// Attachment is one attachment of a message: listed, never fetched.
type Attachment struct {
	ID       string `json:"id"`
	Filename string `json:"filename"`
	MimeType string `json:"mime_type,omitempty"`
	Size     int64  `json:"size,omitempty"`
}

// Message is get_message's result. Body is the text/plain part when the
// message has one, else the text/html part (BodyType says which),
// decoded and cut to the result bounds (BodyTruncated).
type Message struct {
	ID            string       `json:"id"`
	ThreadID      string       `json:"thread_id"`
	From          string       `json:"from,omitempty"`
	To            string       `json:"to,omitempty"`
	Cc            string       `json:"cc,omitempty"`
	Bcc           string       `json:"bcc,omitempty"`
	ReplyTo       string       `json:"reply_to,omitempty"`
	Subject       string       `json:"subject,omitempty"`
	Date          string       `json:"date,omitempty"`
	MessageID     string       `json:"message_id,omitempty"`
	InReplyTo     string       `json:"in_reply_to,omitempty"`
	Snippet       string       `json:"snippet,omitempty"`
	Labels        []string     `json:"labels,omitempty"`
	Unread        bool         `json:"unread,omitempty"`
	Body          string       `json:"body,omitempty"`
	BodyType      string       `json:"body_type,omitempty"`
	BodyTruncated bool         `json:"body_truncated,omitempty"`
	Attachments   []Attachment `json:"attachments,omitempty"`
	SizeEstimate  int64        `json:"size_estimate,omitempty"`
}

// SentMessage is send's result: the identifiers of the sent message.
type SentMessage struct {
	ID        string `json:"id"`
	ThreadID  string `json:"thread_id"`
	MessageID string `json:"message_id"`
}

// CreatedDraft is create_draft's result: the identifiers of the draft
// and of the message inside it.
type CreatedDraft struct {
	ID        string `json:"id"`
	MessageID string `json:"message_id"`
	ThreadID  string `json:"thread_id,omitempty"`
	RFC822ID  string `json:"rfc822_message_id"`
}

// gmailReadTools declares the Gmail reads.
func (c *Connector) gmailReadTools() []connectors.Tool {
	return []connectors.Tool{
		{
			App: AppGmail, Name: ToolSearch, Kind: connectors.KindRead,
			Description: "Search the Gmail mailbox with Gmail's search syntax (from:, to:, subject:, label:, newer_than:7d, has:attachment, is:unread, ...). " +
				"Each hit has id, thread_id, from, to, subject, date, snippet, labels and unread; use get_message for the body. " +
				"has_more and next_page_token say whether another page exists (pass page_token).",
			InputSchema: objectSchema([]property{
				{"q", "string", "Search query in Gmail's search syntax.", nil},
				{"label_ids", "array", "Only messages with all of these label ids (from list_labels), e.g. [\"INBOX\"].", nil},
				{"include_spam_trash", "boolean", "Include messages in Spam and Trash. Default false.", nil},
				{"max_results", "integer", "Hits per page (1-100; default 10); clamped to the tool's maximum.", nil},
				{"page_token", "string", "Token of the page to fetch (next_page_token of the previous result).", nil},
			}, []string{"q"}),
			RequiredScopes:   []string{ScopeGmailReadonly},
			ResourceIdentity: searchIdentity,
			Bounds:           c.pagedBounds(),
		},
		{
			App: AppGmail, Name: ToolGetMessage, Kind: connectors.KindRead,
			Description: "Get one Gmail message by id: headers (from, to, cc, subject, date, message_id, in_reply_to), labels, the text body " +
				"(plain text when the message has it, else HTML; cut to the result bounds) and the list of attachments (name, type, size; " +
				"attachments are never downloaded).",
			InputSchema: objectSchema([]property{
				{"id", "string", "The message's id (from search).", nil},
			}, []string{"id"}),
			RequiredScopes:   []string{ScopeGmailReadonly},
			ResourceIdentity: messageIdentity,
			Bounds:           c.singleBounds(),
		},
		{
			App: AppGmail, Name: ToolListLabels, Kind: connectors.KindRead,
			Description: "List the labels of the Gmail mailbox: id, name and type (system labels such as INBOX, SENT, DRAFT, UNREAD; user labels). " +
				"Use the ids with search's label_ids.",
			InputSchema:      objectSchema(nil, nil),
			RequiredScopes:   []string{ScopeGmailLabels},
			ResourceIdentity: func(map[string]any) map[string]string { return map[string]string{} },
			Bounds:           c.singleBounds(),
		},
	}
}

// gmailReadHandlers maps the Gmail reads' short names to their
// implementation.
func (c *Connector) gmailReadHandlers() map[string]handler {
	return map[string]handler{
		ToolSearch:     c.searchMessages,
		ToolGetMessage: c.getMessage,
		ToolListLabels: c.listLabels,
	}
}

// searchIdentity extracts label (the label_ids joined by commas) from
// the arguments; never the query.
func searchIdentity(args map[string]any) map[string]string {
	out := map[string]string{}
	if labels, err := stringList(args, "label_ids"); err == nil && len(labels) > 0 {
		out["label"] = strings.Join(labels, ",")
	}
	return out
}

// messageIdentity extracts message_id from the arguments.
func messageIdentity(args map[string]any) map[string]string {
	out := map[string]string{}
	if v, _ := args["id"].(string); strings.TrimSpace(v) != "" {
		out["message_id"] = strings.TrimSpace(v)
	}
	return out
}

// --- handlers -------------------------------------------------------------------

func (c *Connector) listLabels(ctx context.Context, cl *client, _ connectors.Call) (connectors.Result, error) {
	svc, err := cl.gmail(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	list, err := svc.Users.Labels.List(gmailUser).Context(ctx).Do()
	if err := classify("list labels", err); err != nil {
		return connectors.Result{}, err
	}
	out := Labels{Items: make([]Label, 0, len(list.Labels))}
	for _, l := range list.Labels {
		if l != nil && l.Id != "" {
			out.Items = append(out.Items, Label{ID: l.Id, Name: l.Name, Type: l.Type})
		}
	}
	return connectors.Result{Content: out, Empty: len(out.Items) == 0}, nil
}

func (c *Connector) searchMessages(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	q, err := requiredString(call.Args, "q")
	if err != nil {
		return connectors.Result{}, invalid("q is required: a Gmail search query")
	}
	labelIDs, err := stringList(call.Args, "label_ids")
	if err != nil {
		return connectors.Result{}, err
	}
	for _, id := range labelIDs {
		if !idRE.MatchString(id) {
			return connectors.Result{}, invalid("label_ids must be Gmail label ids")
		}
	}
	spamTrash, err := optionalBool(call.Args, "include_spam_trash", false)
	if err != nil {
		return connectors.Result{}, err
	}
	maxResults, pageToken, clamped, err := c.pageArgs(call.Args, defaultMessagesPerPage)
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.gmail(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	req := svc.Users.Messages.List(gmailUser).Context(ctx).Q(q).MaxResults(int64(maxResults))
	if len(labelIDs) > 0 {
		req = req.LabelIds(labelIDs...)
	}
	if spamTrash {
		req = req.IncludeSpamTrash(true)
	}
	if pageToken != "" {
		req = req.PageToken(pageToken)
	}
	list, err := req.Do()
	if err := classify("search messages", err); err != nil {
		return connectors.Result{}, err
	}
	out := MessagesPage{Query: q, MaxResults: maxResults, ResultSizeEstimate: list.ResultSizeEstimate, NextPageToken: list.NextPageToken, HasMore: list.NextPageToken != "", Items: make([]MessageSummary, 0, len(list.Messages))}
	res := connectors.Result{Partial: clamped}
	for _, m := range list.Messages {
		if m == nil || m.Id == "" {
			continue
		}
		item := MessageSummary{ID: m.Id, ThreadID: m.ThreadId}
		msg, err := svc.Users.Messages.Get(gmailUser, m.Id).Context(ctx).Format("metadata").MetadataHeaders(metadataHeaders...).Do()
		if err := classify("get message headers", err); err != nil {
			if stopsSearch(err) {
				return connectors.Result{}, err
			}
			item.Error = errorClass(err)
			res.Partial = true
		} else {
			item = toSummary(msg)
		}
		out.Items = append(out.Items, item)
	}
	res.Empty = len(out.Items) == 0
	for encodedSize(out) > c.bounds.MaxResultBytes && len(out.Items) > 1 {
		out.Items = out.Items[:len(out.Items)-1]
		out.Truncated, res.Partial = true, true
	}
	res.Content = out
	return res, nil
}

// stopsSearch reports whether a per-hit failure would repeat for every
// hit (the token, the scope, a rate limit, a cancelled context) and so
// ends the search instead of marking it partial.
func stopsSearch(err error) bool {
	var rl *connectors.RateLimited
	if errors.As(err, &rl) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	switch errorClass(err) {
	case ClassReconnectRequired, ClassScopeRequired:
		return true
	}
	return false
}

// errorClass returns the Class of a classified error, "" for others.
func errorClass(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Class
	}
	return ""
}

func (c *Connector) getMessage(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	id, err := idArg(call.Args, "id")
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.gmail(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	msg, err := svc.Users.Messages.Get(gmailUser, id).Context(ctx).Format("full").Do()
	if err := classify("get message", err); err != nil {
		return connectors.Result{}, err
	}
	out := toMessage(msg)
	fitBody(&out.Body, &out.BodyTruncated, c.bounds.MaxResultBytes, func() any { return out })
	return connectors.Result{Content: out, Partial: out.BodyTruncated}, nil
}

// --- conversions ------------------------------------------------------------------

// headerOf returns the first header named name (case-insensitive).
func headerOf(p *gmail.MessagePart, name string) string {
	if p == nil {
		return ""
	}
	for _, h := range p.Headers {
		if h != nil && strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

func toSummary(m *gmail.Message) MessageSummary {
	return MessageSummary{
		ID: m.Id, ThreadID: m.ThreadId, From: headerOf(m.Payload, "From"), To: headerOf(m.Payload, "To"), Subject: headerOf(m.Payload, "Subject"),
		Date: messageDate(headerOf(m.Payload, "Date"), m.InternalDate), Snippet: m.Snippet, Labels: m.LabelIds, Unread: hasLabel(m.LabelIds, labelUnread),
	}
}

func toMessage(m *gmail.Message) Message {
	out := Message{
		ID: m.Id, ThreadID: m.ThreadId, From: headerOf(m.Payload, "From"), To: headerOf(m.Payload, "To"), Cc: headerOf(m.Payload, "Cc"), Bcc: headerOf(m.Payload, "Bcc"),
		ReplyTo: headerOf(m.Payload, "Reply-To"), Subject: headerOf(m.Payload, "Subject"), Date: messageDate(headerOf(m.Payload, "Date"), m.InternalDate),
		MessageID: headerOf(m.Payload, "Message-ID"), InReplyTo: headerOf(m.Payload, "In-Reply-To"), Snippet: m.Snippet, Labels: m.LabelIds,
		Unread: hasLabel(m.LabelIds, labelUnread), SizeEstimate: m.SizeEstimate,
	}
	var plain, html string
	var walk func(p *gmail.MessagePart)
	walk = func(p *gmail.MessagePart) {
		if p == nil {
			return
		}
		if p.Filename != "" && p.Body != nil && (p.Body.AttachmentId != "" || p.Body.Size > 0) {
			out.Attachments = append(out.Attachments, Attachment{ID: p.Body.AttachmentId, Filename: p.Filename, MimeType: p.MimeType, Size: p.Body.Size})
		} else if p.Body != nil && p.Body.Data != "" {
			switch mime := strings.ToLower(p.MimeType); {
			case mime == "text/plain" && plain == "":
				plain = decodeBody(p.Body.Data)
			case mime == "text/html" && html == "":
				html = decodeBody(p.Body.Data)
			}
		}
		for _, child := range p.Parts {
			walk(child)
		}
	}
	walk(m.Payload)
	switch {
	case plain != "":
		out.Body, out.BodyType = plain, "text/plain"
	case html != "":
		out.Body, out.BodyType = html, "text/html"
	}
	return out
}

// decodeBody decodes a Gmail body (base64url, with or without padding).
func decodeBody(data string) string {
	if b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(data, "=")); err == nil {
		return string(b)
	}
	if b, err := base64.URLEncoding.DecodeString(data); err == nil {
		return string(b)
	}
	return ""
}

// messageDate renders the Date header as RFC 3339 UTC, falling back to
// Gmail's internal date (milliseconds since the epoch), then the raw
// header.
func messageDate(header string, internal int64) string {
	if header != "" {
		if t, err := mail.ParseDate(header); err == nil {
			return t.UTC().Format(time.RFC3339)
		}
	}
	if internal > 0 {
		return time.UnixMilli(internal).UTC().Format(time.RFC3339)
	}
	return header
}

func hasLabel(labels []string, label string) bool {
	for _, l := range labels {
		if l == label {
			return true
		}
	}
	return false
}
