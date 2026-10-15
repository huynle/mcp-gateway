package microsoft

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/microsoft/graph"
)

// Mail tools beyond search / get / send: folders, attachments, drafts,
// reply / forward, move, read state and delete.
const (
	ToolMailListFolders     = "mail_list_folders"
	ToolMailListAttachments = "mail_list_attachments"
	ToolMailGetAttachment   = "mail_get_attachment"
	ToolMailCreateDraft     = "mail_create_draft"
	ToolMailSendDraft       = "mail_send_draft"
	ToolMailReply           = "mail_reply"
	ToolMailForward         = "mail_forward"
	ToolMailMove            = "mail_move"
	ToolMailMarkRead        = "mail_mark_read"
	ToolMailDelete          = "mail_delete"
)

const (
	mailFolderSelect = "id,displayName,parentFolderId,childFolderCount,totalItemCount,unreadItemCount"
	attachmentSelect = "id,name,contentType,size,isInline"
)

// MailFolder is one mail_list_folders item.
type MailFolder struct {
	ID               string `json:"id"`
	DisplayName      string `json:"display_name"`
	ParentFolderID   string `json:"parent_folder_id,omitempty"`
	ChildFolderCount int    `json:"child_folder_count"`
	TotalCount       int    `json:"total_count"`
	UnreadCount      int    `json:"unread_count"`
}

type graphMailFolder struct {
	ID               string `json:"id"`
	DisplayName      string `json:"displayName"`
	ParentFolderID   string `json:"parentFolderId"`
	ChildFolderCount int    `json:"childFolderCount"`
	TotalItemCount   int    `json:"totalItemCount"`
	UnreadItemCount  int    `json:"unreadItemCount"`
}

// AttachmentInfo is one mail_list_attachments item.
type AttachmentInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	ContentType string `json:"content_type,omitempty"`
	Size        int64  `json:"size"`
	IsInline    bool   `json:"is_inline"`
}

type graphAttachment struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	ContentType string `json:"contentType"`
	Size        int64  `json:"size"`
	IsInline    bool   `json:"isInline"`
}

func toAttachmentInfo(a graphAttachment) AttachmentInfo { return AttachmentInfo(a) }

// Attachment is mail_get_attachment's result: the metadata and the
// content as text or base64 (Encoding).
type Attachment struct {
	AttachmentInfo
	Encoding string `json:"encoding"`
	Content  string `json:"content"`
}

// Draft is mail_create_draft's result.
type Draft struct {
	ID                string `json:"id"`
	WebLink           string `json:"web_link,omitempty"`
	InternetMessageID string `json:"internet_message_id"`
}

// MessageChange is the result of the writes acting on one message.
type MessageChange struct {
	MessageID string `json:"message_id"`
	// ID is the message's id after a move (Outlook ids change with the
	// folder).
	ID       string `json:"id,omitempty"`
	Folder   string `json:"folder,omitempty"`
	IsRead   *bool  `json:"is_read,omitempty"`
	Action   string `json:"action"`
	ReplyAll bool   `json:"reply_all,omitempty"`
}

func (c *Connector) mailDefs() []toolDef {
	paged := connectors.Bounds{MaxPageSize: c.bounds.MaxPageSize, MaxResultBytes: c.bounds.MaxResultBytes}
	single := connectors.Bounds{MaxResultBytes: c.bounds.MaxResultBytes}
	messageID := property{"message_id", "string", "The message id (from mail_search).", nil}
	msgIdentity := identity("message_id", "message")
	r, w := connectors.KindRead, connectors.KindWrite
	stable := func(check func(context.Context, connectors.ReconcileInput) (connectors.ReconcileResult, error)) connectors.Reconciliation {
		return connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: check}
	}
	none := connectors.Reconciliation{Kind: connectors.ReconcileNone}
	changeIDs := resultIDs("message_id", "id")
	return []toolDef{
		{Tool: connectors.Tool{
			App: App, Name: ToolMailListFolders, Kind: r,
			Description:      "List the user's top-level Outlook mail folders with their ids, item and unread counts (use an id as mail_search's folder or mail_move's destination).",
			InputSchema:      objectSchema([]property{topProperty}, nil),
			RequiredScopes:   []string{ScopeMailRead},
			ResourceIdentity: identity(),
			Bounds:           paged,
		}, run: c.mailListFolders},
		{Tool: connectors.Tool{
			App: App, Name: ToolMailListAttachments, Kind: r,
			Description:      "List the attachments of an Outlook message: id, name, content type, size, inline flag (no content; use mail_get_attachment).",
			InputSchema:      objectSchema([]property{messageID, topProperty}, []string{"message_id"}),
			RequiredScopes:   []string{ScopeMailRead},
			ResourceIdentity: msgIdentity,
			Bounds:           paged,
		}, run: c.mailListAttachments},
		{Tool: connectors.Tool{
			App: App, Name: ToolMailGetAttachment, Kind: r,
			Description: "Download one attachment of an Outlook message (at most 5 MiB): text attachments come back as text, others as base64 " +
				"(encoding says which). Larger attachments are refused.",
			InputSchema: objectSchema([]property{messageID, {"attachment_id", "string", "The attachment id (from mail_list_attachments).", nil}},
				[]string{"message_id", "attachment_id"}),
			RequiredScopes:   []string{ScopeMailRead},
			ResourceIdentity: identity("message_id", "message", "attachment_id", "attachment"),
			Bounds:           connectors.Bounds{MaxResultBytes: contentResultBytes},
		}, run: c.mailGetAttachment},
		{Tool: connectors.Tool{
			App: App, Name: ToolMailCreateDraft, Kind: w,
			Description: "Save a new Outlook draft in Drafts (not sent): subject, body (text, or html with content_type), optional to and cc. " +
				"Returns the draft id; send it with mail_send_draft.",
			InputSchema: objectSchema([]property{
				{"subject", "string", "Subject line.", nil},
				{"body", "string", "Message body: plain text, or HTML when content_type is html.", nil},
				{"to", "array", "Recipient addresses (\"Name <address>\" allowed).", nil},
				{"cc", "array", "Cc addresses.", nil},
				{"content_type", "string", "Body type: text (default) or html.", []string{"text", "html"}},
			}, []string{"subject", "body"}),
			RequiredScopes:   []string{ScopeMailReadWrite},
			ResourceIdentity: func(map[string]any) map[string]string { return map[string]string{"mailbox": "me"} },
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileMarker, Check: c.checkMail},
			ResultIDs:        resultIDs("id", "internet_message_id"),
			Bounds:           single,
		}, run: c.mailCreateDraft},
		{Tool: connectors.Tool{
			App: App, Name: ToolMailSendDraft, Kind: w,
			Description:      "Send an existing Outlook draft (from mail_create_draft or Drafts) as it is; a copy goes to Sent Items.",
			InputSchema:      objectSchema([]property{{"message_id", "string", "The draft's message id.", nil}}, []string{"message_id"}),
			RequiredScopes:   []string{ScopeMailSend},
			ResourceIdentity: msgIdentity,
			Reconcile:        stable(c.stateCheck("message", identityPath("me/messages/%s"), "id,isDraft", decideDraftSent)),
			ResultIDs:        changeIDs,
			Bounds:           single,
		}, run: c.mailSendDraft},
		{Tool: connectors.Tool{
			App: App, Name: ToolMailReply, Kind: w,
			Description: "Reply to an Outlook message with a plain-text comment above the quoted original (reply_all answers every recipient). " +
				"Sent at once; the outcome of a lost reply cannot be verified afterwards.",
			InputSchema: objectSchema([]property{messageID,
				{"comment", "string", "The reply text.", nil},
				{"reply_all", "boolean", "Reply to all recipients (default false).", nil},
			}, []string{"message_id", "comment"}),
			RequiredScopes:   []string{ScopeMailSend},
			ResourceIdentity: msgIdentity,
			Reconcile:        none,
			ResultIDs:        changeIDs,
			Bounds:           single,
		}, run: c.mailReply},
		{Tool: connectors.Tool{
			App: App, Name: ToolMailForward, Kind: w,
			Description: "Forward an Outlook message to one or more recipients with an optional comment. Sent at once; the outcome of a lost " +
				"forward cannot be verified afterwards.",
			InputSchema: objectSchema([]property{messageID,
				{"to", "array", "Recipient addresses (\"Name <address>\" allowed).", nil},
				{"comment", "string", "Text above the forwarded message.", nil},
			}, []string{"message_id", "to"}),
			RequiredScopes:   []string{ScopeMailSend},
			ResourceIdentity: msgIdentity,
			Reconcile:        none,
			ResultIDs:        changeIDs,
			Bounds:           single,
		}, run: c.mailForward},
		{Tool: connectors.Tool{
			App: App, Name: ToolMailMove, Kind: w,
			Description: "Move an Outlook message to another folder (inbox, archive, deleteditems, junkemail, drafts, sentitems, or a folder id " +
				"from mail_list_folders). Returns the message's new id.",
			InputSchema: objectSchema([]property{messageID,
				{"destination", "string", "Destination folder: a well-known name or a folder id.", nil},
			}, []string{"message_id", "destination"}),
			RequiredScopes: []string{ScopeMailReadWrite},
			ResourceIdentity: func(args map[string]any) map[string]string {
				out := msgIdentity(args)
				if d := strings.TrimSpace(stringArg(args, "destination")); d != "" {
					out["folder"] = folderName(d)
				}
				return out
			},
			Reconcile: none,
			ResultIDs: changeIDs,
			Bounds:    single,
		}, run: c.mailMove},
		{Tool: connectors.Tool{
			App: App, Name: ToolMailMarkRead, Kind: w,
			Description:    "Mark an Outlook message read (is_read true, the default) or unread (false).",
			InputSchema:    objectSchema([]property{messageID, {"is_read", "boolean", "true marks read (default), false unread.", nil}}, []string{"message_id"}),
			RequiredScopes: []string{ScopeMailReadWrite},
			ResourceIdentity: func(args map[string]any) map[string]string {
				out := msgIdentity(args)
				out["is_read"] = boolIdentity("is_read", true)(args)
				return out
			},
			Reconcile: stable(c.stateCheck("message", identityPath("me/messages/%s"), "id,isRead", decideIsRead)),
			ResultIDs: changeIDs,
			Bounds:    single,
		}, run: c.mailMarkRead},
		{Tool: connectors.Tool{
			App: App, Name: ToolMailDelete, Kind: w,
			Description:      "Delete an Outlook message: it moves to Deleted Items (recoverable there).",
			InputSchema:      objectSchema([]property{messageID}, []string{"message_id"}),
			RequiredScopes:   []string{ScopeMailReadWrite},
			ResourceIdentity: msgIdentity,
			Reconcile:        stable(c.stateCheck("message", identityPath("me/messages/%s"), "id", decideGone)),
			ResultIDs:        changeIDs,
			Bounds:           single,
		}, run: c.mailDelete},
	}
}

// --- checks -----------------------------------------------------------------------

// decideDraftSent: a message that is no longer a draft was sent; a
// vanished draft cannot tell (sent and moved, or deleted).
func decideDraftSent(ident map[string]string, body map[string]any, gone bool) (connectors.ReconcileResult, bool) {
	if gone {
		return connectors.ReconcileResult{}, false
	}
	draft, ok := body["isDraft"].(bool)
	if !ok {
		return connectors.ReconcileResult{}, false
	}
	if !draft {
		return found(ident["message"]), true
	}
	return notFound, true
}

// decideIsRead: the message's isRead equals the requested state.
func decideIsRead(ident map[string]string, body map[string]any, gone bool) (connectors.ReconcileResult, bool) {
	read, ok := body["isRead"].(bool)
	if gone || !ok {
		return connectors.ReconcileResult{}, false
	}
	if strconv.FormatBool(read) == ident["is_read"] {
		return found(ident["message"]), true
	}
	return notFound, true
}

// decideGone: a deleted resource no longer resolves; one still there was
// not deleted.
func decideGone(ident map[string]string, _ map[string]any, gone bool) (connectors.ReconcileResult, bool) {
	for _, k := range []string{"message", "event", "item"} {
		if id := ident[k]; id != "" {
			if gone {
				return found(id), true
			}
			return notFound, true
		}
	}
	return connectors.ReconcileResult{}, false
}

// --- handlers ---------------------------------------------------------------------

func (c *Connector) mailListFolders(ctx context.Context, client *graph.Client, call connectors.Call) (connectors.Result, error) {
	top, clamped, err := c.topArg(call.Args, maxTop)
	if err != nil {
		return connectors.Result{}, err
	}
	q := url.Values{"$top": {strconv.Itoa(top)}, "$select": {mailFolderSelect}}
	return listRead(ctx, c, client, "list mail folders", "me/mailFolders", q, nil, top, clamped, func(f graphMailFolder) MailFolder {
		return MailFolder{ID: f.ID, DisplayName: f.DisplayName, ParentFolderID: f.ParentFolderID, ChildFolderCount: f.ChildFolderCount, TotalCount: f.TotalItemCount, UnreadCount: f.UnreadItemCount}
	})
}

func (c *Connector) mailListAttachments(ctx context.Context, client *graph.Client, call connectors.Call) (connectors.Result, error) {
	id, err := requiredID(call.Args, "message_id")
	if err != nil {
		return connectors.Result{}, err
	}
	top, clamped, err := c.topArg(call.Args, maxTop)
	if err != nil {
		return connectors.Result{}, err
	}
	q := url.Values{"$top": {strconv.Itoa(top)}, "$select": {attachmentSelect}}
	return listRead(ctx, c, client, "list attachments", messagesPath+"/"+id+"/attachments", q, nil, top, clamped, toAttachmentInfo)
}

func (c *Connector) mailGetAttachment(ctx context.Context, client *graph.Client, call connectors.Call) (connectors.Result, error) {
	msg, err := requiredID(call.Args, "message_id")
	if err != nil {
		return connectors.Result{}, err
	}
	att, err := requiredID(call.Args, "attachment_id")
	if err != nil {
		return connectors.Result{}, err
	}
	path := messagesPath + "/" + msg + "/attachments/" + att
	var meta graphAttachment
	if err := classify("get attachment", client.Get(ctx, path, url.Values{"$select": {attachmentSelect}}, &meta)); err != nil {
		return connectors.Result{}, err
	}
	if meta.Size > MaxContentBytes {
		return connectors.Result{}, tooLarge("the attachment", meta.Size, "")
	}
	raw, _, err := client.Download(ctx, path+"/$value", nil, MaxContentBytes)
	if errors.Is(err, graph.ErrTooLarge) {
		return connectors.Result{}, tooLarge("the attachment", MaxContentBytes+1, "")
	}
	if err := classify("download attachment", err); err != nil {
		return connectors.Result{}, err
	}
	out := Attachment{AttachmentInfo: toAttachmentInfo(meta)}
	out.Encoding, out.Content = encodeContent(raw, meta.ContentType)
	return connectors.Result{Content: out}, nil
}

func (c *Connector) mailCreateDraft(ctx context.Context, client *graph.Client, call connectors.Call) (connectors.Result, error) {
	subject, err := requiredString(call.Args, "subject")
	if err != nil {
		return connectors.Result{}, err
	}
	if len(subject) > maxSubjectSize {
		return connectors.Result{}, invalid("subject is too long")
	}
	body, err := textArg(call.Args, "body", true)
	if err != nil {
		return connectors.Result{}, err
	}
	to, err := addressList(call.Args, "to", false)
	if err != nil {
		return connectors.Result{}, err
	}
	cc, err := addressList(call.Args, "cc", false)
	if err != nil {
		return connectors.Result{}, err
	}
	contentType, err := contentTypeArg(call.Args, true)
	if err != nil {
		return connectors.Result{}, err
	}
	imID := InternetMessageID(call.OperationID)
	message := map[string]any{
		"subject":                subject,
		"body":                   map[string]string{"contentType": contentType, "content": body},
		"internetMessageId":      imID,
		"internetMessageHeaders": []map[string]string{{"name": MarkerHeader, "value": call.OperationID}},
	}
	if len(to) > 0 {
		message["toRecipients"] = to
	}
	if len(cc) > 0 {
		message["ccRecipients"] = cc
	}
	var created graphMessage
	if _, err := client.Post(ctx, messagesPath, message, &created); err != nil {
		return connectors.Result{}, classifyWrite("create draft", err)
	}
	if created.ID == "" {
		return connectors.Result{}, errNoID("create draft", "message")
	}
	return connectors.Result{Content: Draft{ID: created.ID, WebLink: created.WebLink, InternetMessageID: imID}}, nil
}

func (c *Connector) mailSendDraft(ctx context.Context, client *graph.Client, call connectors.Call) (connectors.Result, error) {
	id, err := requiredID(call.Args, "message_id")
	if err != nil {
		return connectors.Result{}, err
	}
	if _, err := client.Post(ctx, messagesPath+"/"+id+"/send", nil, nil); err != nil {
		return connectors.Result{}, classifyWrite("send draft", err)
	}
	return connectors.Result{Content: MessageChange{MessageID: id, Action: "sent"}}, nil
}

func (c *Connector) mailReply(ctx context.Context, client *graph.Client, call connectors.Call) (connectors.Result, error) {
	id, err := requiredID(call.Args, "message_id")
	if err != nil {
		return connectors.Result{}, err
	}
	comment, err := textArg(call.Args, "comment", true)
	if err != nil {
		return connectors.Result{}, err
	}
	all, err := boolArg(call.Args, "reply_all", false)
	if err != nil {
		return connectors.Result{}, err
	}
	verb := "reply"
	if all {
		verb = "replyAll"
	}
	if _, err := client.Post(ctx, messagesPath+"/"+id+"/"+verb, map[string]any{"comment": comment}, nil); err != nil {
		return connectors.Result{}, classifyWrite("reply", err)
	}
	return connectors.Result{Content: MessageChange{MessageID: id, Action: "replied", ReplyAll: all}}, nil
}

func (c *Connector) mailForward(ctx context.Context, client *graph.Client, call connectors.Call) (connectors.Result, error) {
	id, err := requiredID(call.Args, "message_id")
	if err != nil {
		return connectors.Result{}, err
	}
	to, err := addressList(call.Args, "to", true)
	if err != nil {
		return connectors.Result{}, err
	}
	comment, err := textArg(call.Args, "comment", false)
	if err != nil {
		return connectors.Result{}, err
	}
	req := map[string]any{"toRecipients": to}
	if comment != "" {
		req["comment"] = comment
	}
	if _, err := client.Post(ctx, messagesPath+"/"+id+"/forward", req, nil); err != nil {
		return connectors.Result{}, classifyWrite("forward", err)
	}
	return connectors.Result{Content: MessageChange{MessageID: id, Action: "forwarded"}}, nil
}

func (c *Connector) mailMove(ctx context.Context, client *graph.Client, call connectors.Call) (connectors.Result, error) {
	id, err := requiredID(call.Args, "message_id")
	if err != nil {
		return connectors.Result{}, err
	}
	dest, err := requiredID(call.Args, "destination")
	if err != nil {
		return connectors.Result{}, err
	}
	dest = folderName(dest)
	var moved graphMessage
	if _, err := client.Post(ctx, messagesPath+"/"+id+"/move", map[string]any{"destinationId": dest}, &moved); err != nil {
		return connectors.Result{}, classifyWrite("move message", err)
	}
	return connectors.Result{Content: MessageChange{MessageID: id, ID: moved.ID, Folder: dest, Action: "moved"}}, nil
}

func (c *Connector) mailMarkRead(ctx context.Context, client *graph.Client, call connectors.Call) (connectors.Result, error) {
	id, err := requiredID(call.Args, "message_id")
	if err != nil {
		return connectors.Result{}, err
	}
	read, err := boolArg(call.Args, "is_read", true)
	if err != nil {
		return connectors.Result{}, err
	}
	if err := client.Patch(ctx, messagesPath+"/"+id, map[string]any{"isRead": read}, nil); err != nil {
		return connectors.Result{}, classifyWrite("mark message", err)
	}
	return connectors.Result{Content: MessageChange{MessageID: id, IsRead: &read, Action: "marked"}}, nil
}

func (c *Connector) mailDelete(ctx context.Context, client *graph.Client, call connectors.Call) (connectors.Result, error) {
	id, err := requiredID(call.Args, "message_id")
	if err != nil {
		return connectors.Result{}, err
	}
	if err := client.Delete(ctx, messagesPath+"/"+id); err != nil {
		return connectors.Result{}, classifyWrite("delete message", err)
	}
	return connectors.Result{Content: MessageChange{MessageID: id, Action: "deleted"}}, nil
}

// errNoID is the unknown outcome of a create Graph answered without an id.
func errNoID(action, what string) error {
	return fmt.Errorf("%w: %s: Microsoft Graph answered without a %s id", connectors.ErrOutcomeUnknown, action, what)
}
