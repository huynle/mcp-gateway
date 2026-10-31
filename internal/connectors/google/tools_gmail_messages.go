package google

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"google.golang.org/api/gmail/v1"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Increment 5 (full Gmail): message management. forward re-sends a
// message (with its attachments) to new recipients; untrash restores
// from the Trash; delete removes for good (mail.google.com only);
// batch_modify_labels labels up to MaxBatchMessages messages at once.

// Gmail message management tool names (increment 5).
const (
	ToolForward           = "forward"
	ToolUntrash           = "untrash"
	ToolDelete            = "delete"
	ToolBatchModifyLabels = "batch_modify_labels"
)

// MaxBatchMessages is batchModify's limit: at most 1000 ids per request.
const MaxBatchMessages = 1000

// forwardedSeparator opens the forwarded message in a forward's body (the
// line Gmail itself writes).
const forwardedSeparator = "---------- Forwarded message ---------"

// DeletedMessage is delete's result.
type DeletedMessage struct {
	ID      string `json:"id"`
	Target  string `json:"target"`
	Deleted bool   `json:"deleted"`
}

// BatchLabelChange is batch_modify_labels's result.
type BatchLabelChange struct {
	MessageCount   int      `json:"message_count"`
	AddLabelIDs    []string `json:"add_label_ids,omitempty"`
	RemoveLabelIDs []string `json:"remove_label_ids,omitempty"`
}

func (c *Connector) gmailMessageWriteTools() []connectors.Tool {
	return []connectors.Tool{
		{
			App: AppGmail, Name: ToolForward, Kind: connectors.KindWrite,
			Description: "Forward a Gmail message to new recipients: the optional note first, then the original's headers and body " +
				fmt.Sprintf("(as Gmail's \"Forwarded message\"), with its attachments unless include_attachments is false (at most %d MiB together). ", MaxAttachmentBytes>>20) +
				"The forward joins the original's thread. Returns the sent message's id, thread id and Message-ID.",
			InputSchema: objectSchema([]property{
				{"message_id", "string", "Id of the message to forward (from search).", nil},
				toProperty, ccProperty, bccProperty,
				{"note", "string", "Plain-text note written above the forwarded message.", nil},
				{"include_attachments", "boolean", "Forward the original's attachments. Default true.", nil},
			}, []string{"message_id", "to"}),
			RequiredScopes:   []string{ScopeGmailReadonly, ScopeGmailSend},
			ResourceIdentity: forwardIdentity,
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileMarker, Check: c.checkSent},
			ResultIDs:        sentResultIDs,
			Bounds:           c.singleBounds(),
		},
		{
			App: AppGmail, Name: ToolUntrash, Kind: connectors.KindWrite,
			Description:      "Restore one message or a whole thread from the Trash.",
			InputSchema:      objectSchema([]property{messageIDProperty, threadIDProperty}, nil),
			RequiredScopes:   []string{ScopeGmailModify},
			ResourceIdentity: gmailTargetIdentity,
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: c.checkUntrashed},
			ResultIDs:        labelChangeResultIDs,
			Bounds:           c.singleBounds(),
		},
		{
			App: AppGmail, Name: ToolDelete, Kind: connectors.KindWrite,
			Description: "Delete one message or a whole thread permanently and immediately, skipping the Trash. This cannot be undone; " +
				"use trash to keep it recoverable for 30 days.",
			InputSchema:      objectSchema([]property{messageIDProperty, threadIDProperty}, nil),
			RequiredScopes:   []string{ScopeMail},
			ResourceIdentity: gmailTargetIdentity,
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: c.checkDeleted},
			ResultIDs: func(res connectors.Result) map[string]string {
				if v, ok := res.Content.(DeletedMessage); ok && v.ID != "" {
					return map[string]string{"id": v.ID, "target": v.Target}
				}
				return nil
			},
			Bounds: c.singleBounds(),
		},
		{
			App: AppGmail, Name: ToolBatchModifyLabels, Kind: connectors.KindWrite,
			Description: fmt.Sprintf("Add and remove labels on up to %d messages at once (ids from search): remove INBOX to archive, ", MaxBatchMessages) +
				"remove UNREAD to mark read, add STARRED to star, add or remove user label ids from list_labels.",
			InputSchema: objectSchema([]property{
				{"message_ids", "array", fmt.Sprintf("Ids of the messages (at most %d).", MaxBatchMessages), nil},
				{"add_label_ids", "array", "Label ids to add.", nil},
				{"remove_label_ids", "array", "Label ids to remove.", nil},
			}, []string{"message_ids"}),
			RequiredScopes:   []string{ScopeGmailModify},
			ResourceIdentity: batchLabelsIdentity,
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileNone},
			ResultIDs: func(res connectors.Result) map[string]string {
				if v, ok := res.Content.(BatchLabelChange); ok {
					return map[string]string{"message_count": strconv.Itoa(v.MessageCount)}
				}
				return nil
			},
			Bounds: c.singleBounds(),
		},
	}
}

func (c *Connector) gmailMessageWriteHandlers() map[string]handler {
	return map[string]handler{ToolForward: c.forward, ToolUntrash: c.untrash, ToolDelete: c.deleteMessage, ToolBatchModifyLabels: c.batchModifyLabels}
}

// forwardIdentity is the forwarded message's id and where the forward
// goes (recipient_domains); never the note or the addresses.
func forwardIdentity(args map[string]any) map[string]string {
	out := recipientsIdentity(args)
	delete(out, "attachments")
	if v, _ := args["message_id"].(string); strings.TrimSpace(v) != "" {
		out["message_id"] = strings.TrimSpace(v)
	}
	return out
}

// batchLabelsIdentity counts the unique message ids (a thousand ids do
// not fit the audit's resource bounds) and lists the label ids added and
// removed, sorted.
func batchLabelsIdentity(args map[string]any) map[string]string {
	out := gmailTargetIdentity(map[string]any{"add_label_ids": args["add_label_ids"], "remove_label_ids": args["remove_label_ids"]})
	if ids, err := stringList(args, "message_ids"); err == nil && len(ids) > 0 {
		out["message_count"] = strconv.Itoa(len(uniqueStrings(ids)))
	}
	return out
}

// uniqueStrings returns list without repeats, in first-seen order.
func uniqueStrings(list []string) []string {
	seen := make(map[string]bool, len(list))
	out := make([]string, 0, len(list))
	for _, s := range list {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// labelChangeArgs reads add_label_ids and remove_label_ids: at least one
// label, none both added and removed.
func labelChangeArgs(args map[string]any) (add, remove []string, err error) {
	if add, err = labelArgs(args, "add_label_ids"); err != nil {
		return nil, nil, err
	}
	if remove, err = labelArgs(args, "remove_label_ids"); err != nil {
		return nil, nil, err
	}
	if len(add) == 0 && len(remove) == 0 {
		return nil, nil, invalid("give add_label_ids or remove_label_ids")
	}
	for _, l := range add {
		if slices.Contains(remove, l) {
			return nil, nil, invalid("label %s is both added and removed", l)
		}
	}
	return add, remove, nil
}

// --- handlers -------------------------------------------------------------------

func (c *Connector) untrash(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
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
		_, err = svc.Users.Threads.Untrash(gmailUser, id).Context(ctx).Do()
	} else {
		var m *gmail.Message
		if m, err = svc.Users.Messages.Untrash(gmailUser, id).Context(ctx).Do(); err == nil {
			out.Labels = m.LabelIds
		}
	}
	if err := classifyWrite("restore from trash", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: out}, nil
}

func (c *Connector) deleteMessage(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	id, thread, err := targetArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.gmail(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	if thread {
		err = svc.Users.Threads.Delete(gmailUser, id).Context(ctx).Do()
	} else {
		err = svc.Users.Messages.Delete(gmailUser, id).Context(ctx).Do()
	}
	if err := classifyWrite("delete permanently", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: DeletedMessage{ID: id, Target: targetName(thread), Deleted: true}}, nil
}

func (c *Connector) batchModifyLabels(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	ids, err := stringList(call.Args, "message_ids")
	if err != nil {
		return connectors.Result{}, err
	}
	ids = uniqueStrings(ids)
	switch {
	case len(ids) == 0:
		return connectors.Result{}, invalid("message_ids is required: at least one message id")
	case len(ids) > MaxBatchMessages:
		return connectors.Result{}, invalid("at most %d message_ids per call", MaxBatchMessages)
	}
	for _, id := range ids {
		if !idRE.MatchString(id) {
			return connectors.Result{}, invalid("message_ids must be Gmail message ids")
		}
	}
	add, remove, err := labelChangeArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.gmail(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	err = svc.Users.Messages.BatchModify(gmailUser, &gmail.BatchModifyMessagesRequest{Ids: ids, AddLabelIds: add, RemoveLabelIds: remove}).Context(ctx).Do()
	if err := classifyWrite("modify labels of messages", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: BatchLabelChange{MessageCount: len(ids), AddLabelIDs: add, RemoveLabelIDs: remove}}, nil
}

// forward reads the original (format full: a read, its failure is a
// known outcome), downloads its attachments (reads too, after checking
// their sizes against MaxAttachmentBytes), then sends one message.
func (c *Connector) forward(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	msgID, err := idArg(call.Args, "message_id")
	if err != nil {
		return connectors.Result{}, err
	}
	var m outgoing
	if m.to, err = addressList(call.Args, "to", true); err != nil {
		return connectors.Result{}, err
	}
	if m.cc, err = addressList(call.Args, "cc", false); err != nil {
		return connectors.Result{}, err
	}
	if m.bcc, err = addressList(call.Args, "bcc", false); err != nil {
		return connectors.Result{}, err
	}
	note, err := optionalString(call.Args, "note")
	if err != nil {
		return connectors.Result{}, err
	}
	withAttachments, err := optionalBool(call.Args, "include_attachments", true)
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.gmail(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	orig, err := svc.Users.Messages.Get(gmailUser, msgID).Context(ctx).Format("full").Do()
	if err := classify("read the message to forward", err); err != nil {
		return connectors.Result{}, err
	}
	m.messageID, m.threadID = MessageID(call.OperationID), orig.ThreadId
	m.inReplyTo = headerOf(orig.Payload, "Message-ID")
	m.refs = strings.TrimSpace(strings.TrimSpace(headerOf(orig.Payload, "References")) + " " + m.inReplyTo)
	subject := headerOf(orig.Payload, "Subject")
	if !strings.HasPrefix(strings.ToLower(subject), "fwd:") && !strings.HasPrefix(strings.ToLower(subject), "fw:") {
		subject = "Fwd: " + subject
	}
	m.subject = strings.NewReplacer("\r", " ", "\n", " ").Replace(subject)
	m.body, m.html = forwardBody(orig, strings.TrimSpace(note))
	if withAttachments {
		if m.attachments, err = forwardAttachments(ctx, svc, orig); err != nil {
			return connectors.Result{}, err
		}
	}
	req := svc.Users.Messages.Send(gmailUser, m.message()).Context(ctx)
	if media, ct := m.media(); media != nil {
		req = req.Media(media, ct)
	}
	sent, err := req.Do()
	if err := classifyWrite("forward message", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: SentMessage{ID: sent.Id, ThreadID: sent.ThreadId, MessageID: m.messageID}}, nil
}

// forwardBody renders the note, the forwarded header block and the
// original body: plain text when the original has a text/plain part,
// else HTML (the note and headers escaped).
func forwardBody(orig *gmail.Message, note string) (string, bool) {
	o := toMessage(orig)
	var head strings.Builder
	head.WriteString(forwardedSeparator + "\n")
	for _, h := range []struct{ name, value string }{
		{"From", headerOf(orig.Payload, "From")}, {"Date", headerOf(orig.Payload, "Date")}, {"Subject", o.Subject},
		{"To", o.To}, {"Cc", o.Cc},
	} {
		if h.value != "" {
			head.WriteString(h.name + ": " + h.value + "\n")
		}
	}
	if o.BodyType == "text/html" {
		var b strings.Builder
		if note != "" {
			b.WriteString("<div>" + strings.ReplaceAll(html.EscapeString(note), "\n", "<br>") + "</div><br>")
		}
		b.WriteString("<div>" + strings.ReplaceAll(html.EscapeString(strings.TrimRight(head.String(), "\n")), "\n", "<br>") + "</div><br>")
		b.WriteString(o.Body)
		return b.String(), true
	}
	var b strings.Builder
	if note != "" {
		b.WriteString(note + "\n\n")
	}
	b.WriteString(head.String() + "\n" + o.Body)
	return b.String(), false
}

// forwardAttachments collects the original's attachments: their sizes
// are checked against MaxAttachmentBytes before any download, then each
// is fetched (attachments.get; inline data is used as it is).
func forwardAttachments(ctx context.Context, svc *gmail.Service, orig *gmail.Message) ([]attachment, error) {
	var parts []*gmail.MessagePart
	var walk func(p *gmail.MessagePart)
	walk = func(p *gmail.MessagePart) {
		if p == nil {
			return
		}
		if p.Filename != "" && p.Body != nil && (p.Body.AttachmentId != "" || p.Body.Data != "") {
			parts = append(parts, p)
		}
		for _, child := range p.Parts {
			walk(child)
		}
	}
	walk(orig.Payload)
	total := int64(0)
	for _, p := range parts {
		if total += p.Body.Size; total > MaxAttachmentBytes {
			return nil, invalid("the message's attachments are larger than %d MiB together; forward it with include_attachments false", MaxAttachmentBytes>>20)
		}
	}
	out := make([]attachment, 0, len(parts))
	got := 0
	for _, p := range parts {
		data := p.Body.Data
		if data == "" {
			a, err := svc.Users.Messages.Attachments.Get(gmailUser, orig.Id, p.Body.AttachmentId).Context(ctx).Do()
			if err := classify("download an attachment to forward", err); err != nil {
				return nil, err
			}
			data = a.Data
		}
		raw := []byte(decodeBody(data))
		if got += len(raw); got > MaxAttachmentBytes {
			return nil, invalid("the message's attachments are larger than %d MiB together; forward it with include_attachments false", MaxAttachmentBytes>>20)
		}
		mt := p.MimeType
		if mt == "" {
			mt = guessType(p.Filename)
		}
		name := p.Filename
		if !validFilename(name) {
			name = "attachment"
		}
		out = append(out, attachment{filename: name, mimeType: mt, data: raw})
	}
	return out, nil
}

// --- reconciliation ---------------------------------------------------------------

// checkUntrashed: no message labelled TRASH any more is found; otherwise
// not_found. Any error is "cannot tell yet".
func (c *Connector) checkUntrashed(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	id, sets, err := c.labelSets(ctx, in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	for _, labels := range sets {
		if slices.Contains(labels, labelTrash) {
			return notFound, nil
		}
	}
	return found(id), nil
}

// checkDeleted: the message or thread answering 404 is found (deleted);
// still there (in the Trash or not) is not_found; any other error is
// "cannot tell yet".
func (c *Connector) checkDeleted(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	_, _, err := c.labelSets(ctx, in)
	switch {
	case err == nil:
		return notFound, nil
	case statusOf(err) == http.StatusNotFound:
		return found(in.ResourceIdentity["message_id"] + in.ResourceIdentity["thread_id"]), nil
	}
	return connectors.ReconcileResult{}, err
}
