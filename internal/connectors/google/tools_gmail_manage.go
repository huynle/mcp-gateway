package google

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"google.golang.org/api/gmail/v1"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Gmail management tool names.
const (
	ToolGetThread     = "get_thread"
	ToolListDrafts    = "list_drafts"
	ToolGetAttachment = "get_attachment"
	ToolModifyLabels  = "modify_labels"
	ToolTrash         = "trash"
	ToolSendDraft     = "send_draft"
)

// Download bounds shared by gmail.get_attachment and drive.get_content:
// at most MaxDownloadBytes of content per call (larger files are refused,
// never cut), and a result bound that holds that much in base64.
const (
	MaxDownloadBytes       = 5 << 20
	MaxDownloadResultBytes = 8 << 20
)

// Content encodings of a download result.
const (
	EncodingText   = "text"
	EncodingBase64 = "base64"
)

// labelTrash is Gmail's system label of trashed messages.
const labelTrash = "TRASH"

// Thread is get_thread's result: every message of the thread, oldest
// first, bodies cut (oldest first) to fit the bounds.
type Thread struct {
	ID        string    `json:"id"`
	Messages  []Message `json:"messages"`
	Truncated bool      `json:"truncated,omitempty"`
}

// DraftSummary is one list_drafts item.
type DraftSummary struct {
	DraftID   string `json:"draft_id"`
	MessageID string `json:"message_id,omitempty"`
	ThreadID  string `json:"thread_id,omitempty"`
	To        string `json:"to,omitempty"`
	Subject   string `json:"subject,omitempty"`
	Date      string `json:"date,omitempty"`
	Snippet   string `json:"snippet,omitempty"`
	Error     string `json:"error,omitempty"`
}

// DraftsPage is list_drafts's result.
type DraftsPage struct {
	MaxResults    int            `json:"max_results"`
	NextPageToken string         `json:"next_page_token,omitempty"`
	HasMore       bool           `json:"has_more"`
	Truncated     bool           `json:"truncated,omitempty"`
	Items         []DraftSummary `json:"items"`
}

// AttachmentContent is get_attachment's result: the content as text when
// it is valid UTF-8 without NUL bytes, else base64 (standard alphabet).
type AttachmentContent struct {
	MessageID    string `json:"message_id"`
	AttachmentID string `json:"attachment_id"`
	Size         int    `json:"size"`
	Encoding     string `json:"encoding"`
	Content      string `json:"content"`
}

// LabelChange is the result of modify_labels and trash.
type LabelChange struct {
	ID     string   `json:"id"`
	Target string   `json:"target"`
	Labels []string `json:"labels,omitempty"`
}

var (
	messageIDProperty = property{"message_id", "string", "Id of one message (from search). Give message_id or thread_id.", nil}
	threadIDProperty  = property{"thread_id", "string", "Id of a whole thread (a search hit's thread_id). Give message_id or thread_id.", nil}
)

func (c *Connector) gmailManageReadTools() []connectors.Tool {
	return []connectors.Tool{
		{
			App: AppGmail, Name: ToolGetThread, Kind: connectors.KindRead,
			Description: "Get a whole Gmail conversation by thread id: every message oldest first, each with headers, labels, text body " +
				"and attachment list (as get_message). Bodies are cut to the result bounds, oldest first (body_truncated says so).",
			InputSchema:      objectSchema([]property{{"thread_id", "string", "The thread's id (thread_id of a search hit).", nil}}, []string{"thread_id"}),
			RequiredScopes:   []string{ScopeGmailReadonly},
			ResourceIdentity: gmailTargetIdentity,
			Bounds:           c.singleBounds(),
		},
		{
			App: AppGmail, Name: ToolListDrafts, Kind: connectors.KindRead,
			Description: "List the Gmail drafts, newest first, optionally matching a Gmail search query: draft_id, message_id, to, subject, date, snippet. " +
				"Pass a draft_id to send_draft. has_more and next_page_token say whether another page exists.",
			InputSchema: objectSchema([]property{
				{"q", "string", "Optional Gmail search query over the drafts.", nil},
				{"max_results", "integer", "Drafts per page (1-100; default 10); clamped to the tool's maximum.", nil},
				{"page_token", "string", "Token of the page to fetch (next_page_token of the previous result).", nil},
			}, nil),
			RequiredScopes:   []string{ScopeGmailReadonly},
			ResourceIdentity: func(map[string]any) map[string]string { return map[string]string{} },
			Bounds:           c.pagedBounds(),
		},
		{
			App: AppGmail, Name: ToolGetAttachment, Kind: connectors.KindRead,
			Description: fmt.Sprintf("Download one attachment of a Gmail message (ids from get_message's attachments), at most %d MiB: "+
				"encoding text gives the content as text, encoding base64 its bytes in base64. Larger attachments are refused.", MaxDownloadBytes>>20),
			InputSchema: objectSchema([]property{
				{"message_id", "string", "The message's id.", nil},
				{"attachment_id", "string", "The attachment's id (from get_message).", nil},
			}, []string{"message_id", "attachment_id"}),
			RequiredScopes:   []string{ScopeGmailReadonly},
			ResourceIdentity: gmailTargetIdentity,
			Bounds:           connectors.Bounds{MaxResultBytes: MaxDownloadResultBytes},
		},
	}
}

func (c *Connector) gmailManageReadHandlers() map[string]handler {
	return map[string]handler{ToolGetThread: c.getThread, ToolListDrafts: c.listDrafts, ToolGetAttachment: c.getAttachment}
}

func (c *Connector) gmailManageWriteTools() []connectors.Tool {
	return []connectors.Tool{
		{
			App: AppGmail, Name: ToolModifyLabels, Kind: connectors.KindWrite,
			Description: "Add and remove labels on one message or a whole thread. System labels do the common actions: remove INBOX to archive, " +
				"remove UNREAD to mark read (add it to mark unread), add STARRED to star, add IMPORTANT; user label ids come from list_labels.",
			InputSchema: objectSchema([]property{
				messageIDProperty, threadIDProperty,
				{"add_label_ids", "array", "Label ids to add.", nil},
				{"remove_label_ids", "array", "Label ids to remove.", nil},
			}, nil),
			RequiredScopes:   []string{ScopeGmailModify},
			ResourceIdentity: gmailTargetIdentity,
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: c.checkLabels},
			ResultIDs:        labelChangeResultIDs,
			Bounds:           c.singleBounds(),
		},
		{
			App: AppGmail, Name: ToolTrash, Kind: connectors.KindWrite,
			Description:      "Move one message or a whole thread to the Trash (Gmail deletes it for good after 30 days).",
			InputSchema:      objectSchema([]property{messageIDProperty, threadIDProperty}, nil),
			RequiredScopes:   []string{ScopeGmailModify},
			ResourceIdentity: gmailTargetIdentity,
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: c.checkTrashed},
			ResultIDs:        labelChangeResultIDs,
			Bounds:           c.singleBounds(),
		},
		{
			App: AppGmail, Name: ToolSendDraft, Kind: connectors.KindWrite,
			Description:      "Send an existing Gmail draft as it is (draft_id from list_drafts or create_draft). Returns the sent message's id and thread id.",
			InputSchema:      objectSchema([]property{{"draft_id", "string", "The draft's id.", nil}}, []string{"draft_id"}),
			RequiredScopes:   []string{ScopeGmailCompose},
			ResourceIdentity: gmailTargetIdentity,
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: c.checkDraftSent},
			ResultIDs:        sentResultIDs,
			Bounds:           c.singleBounds(),
		},
	}
}

func (c *Connector) gmailManageWriteHandlers() map[string]handler {
	return map[string]handler{ToolModifyLabels: c.modifyLabels, ToolTrash: c.trash, ToolSendDraft: c.sendDraft}
}

// gmailTargetIdentity extracts the ids a Gmail management tool acts on
// (message_id, thread_id, attachment_id, draft_id) and the label ids
// added and removed (sorted, comma separated); never content.
func gmailTargetIdentity(args map[string]any) map[string]string {
	out := map[string]string{}
	for _, name := range []string{"message_id", "thread_id", "attachment_id", "draft_id"} {
		if v, _ := args[name].(string); strings.TrimSpace(v) != "" {
			out[name] = strings.TrimSpace(v)
		}
	}
	for arg, key := range map[string]string{"add_label_ids": "add_labels", "remove_label_ids": "remove_labels"} {
		if list, err := stringList(args, arg); err == nil && len(list) > 0 {
			list = slices.Clone(list)
			sort.Strings(list)
			out[key] = strings.Join(list, ",")
		}
	}
	return out
}

func labelChangeResultIDs(res connectors.Result) map[string]string {
	v, ok := res.Content.(LabelChange)
	if !ok || v.ID == "" {
		return nil
	}
	return map[string]string{"id": v.ID, "target": v.Target}
}

// targetArgs reads exactly one of message_id and thread_id.
func targetArgs(args map[string]any) (id string, thread bool, err error) {
	msg, err := idArgDefault(args, "message_id", "")
	if err != nil {
		return "", false, err
	}
	thr, err := idArgDefault(args, "thread_id", "")
	if err != nil {
		return "", false, err
	}
	switch {
	case msg != "" && thr != "":
		return "", false, invalid("give message_id or thread_id, not both")
	case msg != "":
		return msg, false, nil
	case thr != "":
		return thr, true, nil
	}
	return "", false, invalid("message_id or thread_id is required")
}

func targetName(thread bool) string {
	if thread {
		return "thread"
	}
	return "message"
}

// labelArgs reads a list of label ids.
func labelArgs(args map[string]any, name string) ([]string, error) {
	list, err := stringList(args, name)
	if err != nil {
		return nil, err
	}
	for _, id := range list {
		if !idRE.MatchString(id) {
			return nil, invalid("%s must be Gmail label ids", name)
		}
	}
	return list, nil
}

// --- reads ------------------------------------------------------------------------

func (c *Connector) getThread(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	id, err := idArg(call.Args, "thread_id")
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.gmail(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	th, err := svc.Users.Threads.Get(gmailUser, id).Context(ctx).Format("full").Do()
	if err := classify("get thread", err); err != nil {
		return connectors.Result{}, err
	}
	out := Thread{ID: th.Id, Messages: make([]Message, 0, len(th.Messages))}
	if out.ID == "" {
		out.ID = id
	}
	for _, m := range th.Messages {
		if m != nil {
			out.Messages = append(out.Messages, toMessage(m))
		}
	}
	partial := false
	for i := range out.Messages {
		if encodedSize(out) <= c.bounds.MaxResultBytes {
			break
		}
		fitBody(&out.Messages[i].Body, &out.Messages[i].BodyTruncated, c.bounds.MaxResultBytes, func() any { return out })
		partial = true
	}
	for encodedSize(out) > c.bounds.MaxResultBytes && len(out.Messages) > 1 {
		out.Messages = out.Messages[:len(out.Messages)-1]
		out.Truncated, partial = true, true
	}
	return connectors.Result{Content: out, Partial: partial, Empty: len(out.Messages) == 0}, nil
}

func (c *Connector) listDrafts(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	q, err := optionalString(call.Args, "q")
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
	req := svc.Users.Drafts.List(gmailUser).Context(ctx).MaxResults(int64(maxResults))
	if q = strings.TrimSpace(q); q != "" {
		req = req.Q(q)
	}
	if pageToken != "" {
		req = req.PageToken(pageToken)
	}
	list, err := req.Do()
	if err := classify("list drafts", err); err != nil {
		return connectors.Result{}, err
	}
	out := DraftsPage{MaxResults: maxResults, NextPageToken: list.NextPageToken, HasMore: list.NextPageToken != "", Items: make([]DraftSummary, 0, len(list.Drafts))}
	res := connectors.Result{Partial: clamped}
	for _, d := range list.Drafts {
		if d == nil || d.Id == "" {
			continue
		}
		item := DraftSummary{DraftID: d.Id}
		if d.Message != nil {
			item.MessageID, item.ThreadID = d.Message.Id, d.Message.ThreadId
		}
		full, err := svc.Users.Drafts.Get(gmailUser, d.Id).Context(ctx).Format("metadata").Do()
		if err := classify("get draft headers", err); err != nil {
			if stopsSearch(err) {
				return connectors.Result{}, err
			}
			item.Error, res.Partial = errorClass(err), true
		} else if m := full.Message; m != nil {
			item.MessageID, item.ThreadID, item.Snippet = m.Id, m.ThreadId, m.Snippet
			item.To, item.Subject = headerOf(m.Payload, "To"), headerOf(m.Payload, "Subject")
			item.Date = messageDate(headerOf(m.Payload, "Date"), m.InternalDate)
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

// downloadContent renders downloaded bytes as text (valid UTF-8 without
// NUL bytes) or base64.
func downloadContent(b []byte) (encoding, content string) {
	if utf8.Valid(b) && !bytes.Contains(b, []byte{0}) {
		return EncodingText, string(b)
	}
	return EncodingBase64, base64.StdEncoding.EncodeToString(b)
}

func tooLarge(size int64) error {
	return invalid("the content is %d bytes; at most %d bytes (%d MiB) can be downloaded", size, MaxDownloadBytes, MaxDownloadBytes>>20)
}

func (c *Connector) getAttachment(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	msgID, err := idArg(call.Args, "message_id")
	if err != nil {
		return connectors.Result{}, err
	}
	attID, err := idArg(call.Args, "attachment_id")
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.gmail(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	a, err := svc.Users.Messages.Attachments.Get(gmailUser, msgID, attID).Context(ctx).Do()
	if err := classify("get attachment", err); err != nil {
		return connectors.Result{}, err
	}
	if a.Size > MaxDownloadBytes || int64(len(a.Data)) > int64(MaxDownloadBytes)*4/3+4 {
		return connectors.Result{}, tooLarge(max(a.Size, int64(len(a.Data))*3/4))
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(a.Data, "="))
	if err != nil {
		return connectors.Result{}, &Error{Class: ClassVendorError, Message: "get attachment: Google returned undecodable data", Err: err}
	}
	out := AttachmentContent{MessageID: msgID, AttachmentID: attID, Size: len(raw)}
	out.Encoding, out.Content = downloadContent(raw)
	return connectors.Result{Content: out, Empty: len(raw) == 0}, nil
}

// --- writes -----------------------------------------------------------------------

func (c *Connector) modifyLabels(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	id, thread, err := targetArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	add, err := labelArgs(call.Args, "add_label_ids")
	if err != nil {
		return connectors.Result{}, err
	}
	remove, err := labelArgs(call.Args, "remove_label_ids")
	if err != nil {
		return connectors.Result{}, err
	}
	if len(add) == 0 && len(remove) == 0 {
		return connectors.Result{}, invalid("give add_label_ids or remove_label_ids")
	}
	for _, l := range add {
		if slices.Contains(remove, l) {
			return connectors.Result{}, invalid("label %s is both added and removed", l)
		}
	}
	svc, err := cl.gmail(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	out := LabelChange{ID: id, Target: targetName(thread)}
	if thread {
		_, err = svc.Users.Threads.Modify(gmailUser, id, &gmail.ModifyThreadRequest{AddLabelIds: add, RemoveLabelIds: remove}).Context(ctx).Do()
	} else {
		var m *gmail.Message
		if m, err = svc.Users.Messages.Modify(gmailUser, id, &gmail.ModifyMessageRequest{AddLabelIds: add, RemoveLabelIds: remove}).Context(ctx).Do(); err == nil {
			out.Labels = m.LabelIds
		}
	}
	if err := classifyWrite("modify labels", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: out}, nil
}

func (c *Connector) trash(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	id, thread, err := targetArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.gmail(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	out := LabelChange{ID: id, Target: targetName(thread)}
	if thread {
		_, err = svc.Users.Threads.Trash(gmailUser, id).Context(ctx).Do()
	} else {
		var m *gmail.Message
		if m, err = svc.Users.Messages.Trash(gmailUser, id).Context(ctx).Do(); err == nil {
			out.Labels = m.LabelIds
		}
	}
	if err := classifyWrite("move to trash", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: out}, nil
}

func (c *Connector) sendDraft(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	draftID, err := idArg(call.Args, "draft_id")
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.gmail(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	sent, err := svc.Users.Drafts.Send(gmailUser, &gmail.Draft{Id: draftID}).Context(ctx).Do()
	if err := classifyWrite("send draft", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: SentMessage{ID: sent.Id, ThreadID: sent.ThreadId}}, nil
}

// --- reconciliation ---------------------------------------------------------------

// labelSets returns the label ids of every message the identity names
// (one message, or each message of the thread); id is the target's id.
func (c *Connector) labelSets(ctx context.Context, in connectors.ReconcileInput) (id string, sets [][]string, err error) {
	tg, err := c.target(in)
	if err != nil {
		return "", nil, err
	}
	msg, thr := in.ResourceIdentity["message_id"], in.ResourceIdentity["thread_id"]
	if (msg == "") == (thr == "") || !idRE.MatchString(msg+thr) {
		return "", nil, fmt.Errorf("%w: resource identity names no message or thread", ErrNotReconcilable)
	}
	svc, err := tg.client.gmail(ctx)
	if err != nil {
		return "", nil, err
	}
	if msg != "" {
		m, err := svc.Users.Messages.Get(gmailUser, msg).Context(ctx).Format("minimal").Do()
		if err := classify("reconcile: get message labels", err); err != nil {
			return "", nil, err
		}
		return msg, [][]string{m.LabelIds}, nil
	}
	th, err := svc.Users.Threads.Get(gmailUser, thr).Context(ctx).Format("minimal").Do()
	if err := classify("reconcile: get thread labels", err); err != nil {
		return "", nil, err
	}
	for _, m := range th.Messages {
		if m != nil {
			sets = append(sets, m.LabelIds)
		}
	}
	if len(sets) == 0 {
		return "", nil, fmt.Errorf("google: reconcile: thread %s has no messages; cannot tell", thr)
	}
	return thr, sets, nil
}

// checkLabels: every message carries every added label and none of the
// removed ones is found; otherwise not_found. Any error (including 404:
// the message may since have been deleted) is "cannot tell yet".
func (c *Connector) checkLabels(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	split := func(key string) []string {
		if v := in.ResourceIdentity[key]; v != "" {
			return strings.Split(v, ",")
		}
		return nil
	}
	add, remove := split("add_labels"), split("remove_labels")
	if len(add) == 0 && len(remove) == 0 {
		return connectors.ReconcileResult{}, fmt.Errorf("%w: resource identity has no labels", ErrNotReconcilable)
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	id, sets, err := c.labelSets(ctx, in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	for _, labels := range sets {
		for _, l := range add {
			if !slices.Contains(labels, l) {
				return notFound, nil
			}
		}
		for _, l := range remove {
			if slices.Contains(labels, l) {
				return notFound, nil
			}
		}
	}
	return found(id), nil
}

// checkTrashed: every message labelled TRASH is found; otherwise not_found.
func (c *Connector) checkTrashed(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	id, sets, err := c.labelSets(ctx, in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	for _, labels := range sets {
		if !slices.Contains(labels, labelTrash) {
			return notFound, nil
		}
	}
	return found(id), nil
}

// checkDraftSent: the draft still there is not_found (it was not sent);
// gone cannot tell (sent, or deleted by the user): the operation ends
// unresolved and the user checks Sent.
func (c *Connector) checkDraftSent(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	tg, err := c.target(in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	draftID := in.ResourceIdentity["draft_id"]
	if draftID == "" || !idRE.MatchString(draftID) {
		return connectors.ReconcileResult{}, fmt.Errorf("%w: resource identity has no draft", ErrNotReconcilable)
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	svc, err := tg.client.gmail(ctx)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	_, err = svc.Users.Drafts.Get(gmailUser, draftID).Context(ctx).Format("minimal").Do()
	if err := classify("reconcile: get draft", err); err != nil {
		return connectors.ReconcileResult{}, fmt.Errorf("google: reconcile: the draft is gone or unreadable (sent, or deleted); cannot tell: %w", err)
	}
	return notFound, nil
}
