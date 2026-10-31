package google

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"google.golang.org/api/gmail/v1"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Increment 5 (full Gmail): drafts (get_draft, update_draft,
// delete_draft) and the mailbox profile.

// Gmail draft and profile tool names (increment 5).
const (
	ToolGetDraft    = "get_draft"
	ToolGetProfile  = "get_profile"
	ToolUpdateDraft = "update_draft"
	ToolDeleteDraft = "delete_draft"
)

// Draft is get_draft's result: the draft id and its message (as
// get_message: headers, body cut to the bounds, attachment list).
type Draft struct {
	DraftID string  `json:"draft_id"`
	Message Message `json:"message"`
}

// Profile is get_profile's result.
type Profile struct {
	EmailAddress  string `json:"email_address"`
	MessagesTotal int64  `json:"messages_total"`
	ThreadsTotal  int64  `json:"threads_total"`
	HistoryID     string `json:"history_id,omitempty"`
}

// DeletedDraft is delete_draft's result.
type DeletedDraft struct {
	DraftID string `json:"draft_id"`
	Deleted bool   `json:"deleted"`
}

var draftIDProperty = property{"draft_id", "string", "The draft's id (from list_drafts or create_draft).", nil}

func (c *Connector) gmailDraftReadTools() []connectors.Tool {
	return []connectors.Tool{
		{
			App: AppGmail, Name: ToolGetDraft, Kind: connectors.KindRead,
			Description: "Get one Gmail draft by id: its message's headers (to, cc, bcc, subject), text body (cut to the result bounds) " +
				"and attachment list, as get_message.",
			InputSchema:      objectSchema([]property{draftIDProperty}, []string{"draft_id"}),
			RequiredScopes:   []string{ScopeGmailReadonly},
			ResourceIdentity: gmailTargetIdentity,
			Bounds:           c.singleBounds(),
		},
		{
			App: AppGmail, Name: ToolGetProfile, Kind: connectors.KindRead,
			Description:      "Get the Gmail account's profile: its email address, the total number of messages and threads, and the current history id.",
			InputSchema:      objectSchema(nil, nil),
			RequiredScopes:   []string{ScopeGmailReadonly},
			ResourceIdentity: noIdentity,
			Bounds:           c.singleBounds(),
		},
	}
}

func (c *Connector) gmailDraftReadHandlers() map[string]handler {
	return map[string]handler{ToolGetDraft: c.getDraft, ToolGetProfile: c.getProfile}
}

func (c *Connector) gmailDraftWriteTools() []connectors.Tool {
	return []connectors.Tool{
		{
			App: AppGmail, Name: ToolUpdateDraft, Kind: connectors.KindWrite,
			Description: "Replace the content of an existing Gmail draft (not sent): recipients, optional cc, bcc and attachments, subject and " +
				"plain-text body, all as create_draft (what is not given is gone). in_reply_to keeps or makes it a reply in that message's thread.",
			InputSchema: objectSchema([]property{draftIDProperty, toProperty, ccProperty, bccProperty, subjectProperty, bodyProperty, inReplyToProperty, attachmentsProperty},
				[]string{"draft_id", "to", "subject", "body"}),
			RequiredScopes:   []string{ScopeGmailCompose},
			ResourceIdentity: updateDraftIdentity,
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileMarker, Check: c.checkDraftUpdated},
			ResultIDs:        draftResultIDs,
			Bounds:           c.singleBounds(),
		},
		{
			App: AppGmail, Name: ToolDeleteDraft, Kind: connectors.KindWrite,
			Description:      "Delete a Gmail draft permanently (it does not go to the Trash).",
			InputSchema:      objectSchema([]property{draftIDProperty}, []string{"draft_id"}),
			RequiredScopes:   []string{ScopeGmailCompose},
			ResourceIdentity: gmailTargetIdentity,
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: c.checkDraftDeleted},
			ResultIDs: func(res connectors.Result) map[string]string {
				if v, ok := res.Content.(DeletedDraft); ok && v.DraftID != "" {
					return map[string]string{"draft_id": v.DraftID}
				}
				return nil
			},
			Bounds: c.singleBounds(),
		},
	}
}

func (c *Connector) gmailDraftWriteHandlers() map[string]handler {
	return map[string]handler{ToolUpdateDraft: c.updateDraft, ToolDeleteDraft: c.deleteDraft}
}

// updateDraftIdentity is the draft id plus where the mail would go
// (recipient_domains) and the attachment count.
func updateDraftIdentity(args map[string]any) map[string]string {
	out := recipientsIdentity(args)
	if v, _ := args["draft_id"].(string); strings.TrimSpace(v) != "" {
		out["draft_id"] = strings.TrimSpace(v)
	}
	return out
}

// --- handlers -------------------------------------------------------------------

func (c *Connector) getDraft(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	id, err := idArg(call.Args, "draft_id")
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.gmail(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	d, err := svc.Users.Drafts.Get(gmailUser, id).Context(ctx).Format("full").Do()
	if err := classify("get draft", err); err != nil {
		return connectors.Result{}, err
	}
	out := Draft{DraftID: d.Id}
	if out.DraftID == "" {
		out.DraftID = id
	}
	if d.Message != nil {
		out.Message = toMessage(d.Message)
	}
	fitBody(&out.Message.Body, &out.Message.BodyTruncated, c.bounds.MaxResultBytes, func() any { return out })
	return connectors.Result{Content: out, Partial: out.Message.BodyTruncated}, nil
}

func (c *Connector) getProfile(ctx context.Context, cl *client, _ connectors.Call) (connectors.Result, error) {
	svc, err := cl.gmail(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	p, err := svc.Users.GetProfile(gmailUser).Context(ctx).Do()
	if err := classify("get profile", err); err != nil {
		return connectors.Result{}, err
	}
	out := Profile{EmailAddress: p.EmailAddress, MessagesTotal: p.MessagesTotal, ThreadsTotal: p.ThreadsTotal}
	if p.HistoryId != 0 {
		out.HistoryID = fmt.Sprint(p.HistoryId)
	}
	return connectors.Result{Content: out}, nil
}

// updateDraft replaces the draft's message (drafts.update) with one
// carrying the operation's Message-ID, as create_draft.
func (c *Connector) updateDraft(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	id, err := idArg(call.Args, "draft_id")
	if err != nil {
		return connectors.Result{}, err
	}
	m, err := c.outgoingArgs(ctx, cl, call)
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.gmail(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	req := svc.Users.Drafts.Update(gmailUser, id, &gmail.Draft{Id: id, Message: m.message()}).Context(ctx)
	if media, ct := m.media(); media != nil {
		req = req.Media(media, ct)
	}
	draft, err := req.Do()
	if err := classifyWrite("update draft", err); err != nil {
		return connectors.Result{}, err
	}
	out := CreatedDraft{ID: draft.Id, RFC822ID: m.messageID}
	if out.ID == "" {
		out.ID = id
	}
	if draft.Message != nil {
		out.MessageID, out.ThreadID = draft.Message.Id, draft.Message.ThreadId
	}
	return connectors.Result{Content: out}, nil
}

func (c *Connector) deleteDraft(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	id, err := idArg(call.Args, "draft_id")
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.gmail(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	err = svc.Users.Drafts.Delete(gmailUser, id).Context(ctx).Do()
	if err := classifyWrite("delete draft", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: DeletedDraft{DraftID: id, Deleted: true}}, nil
}

// --- reconciliation ---------------------------------------------------------------

// identityDraft returns the target and the draft id the identity names.
func (c *Connector) identityDraft(in connectors.ReconcileInput) (reconcileTarget, string, error) {
	tg, err := c.target(in)
	if err != nil {
		return reconcileTarget{}, "", err
	}
	id := in.ResourceIdentity["draft_id"]
	if id == "" || !idRE.MatchString(id) {
		return reconcileTarget{}, "", fmt.Errorf("%w: resource identity has no draft", ErrNotReconcilable)
	}
	return tg, id, nil
}

// checkDraftUpdated is update_draft's Message-ID check: the draft's
// message carrying the operation's Message-ID is found; another
// Message-ID is not_found (the update did not apply); the draft gone
// (sent or deleted since) or any error is "cannot tell yet".
func (c *Connector) checkDraftUpdated(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	tg, id, err := c.identityDraft(in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	svc, err := tg.client.gmail(ctx)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	d, err := svc.Users.Drafts.Get(gmailUser, id).Context(ctx).Format("metadata").Do()
	if err := classify("reconcile: get draft headers", err); err != nil {
		return connectors.ReconcileResult{}, err
	}
	if d.Message != nil && strings.TrimSpace(headerOf(d.Message.Payload, "Message-ID")) == MessageID(tg.operationID) {
		return found(id), nil
	}
	return notFound, nil
}

// checkDraftDeleted: the draft answering 404 is found (deleted); still
// there is not_found; any other error is "cannot tell yet".
func (c *Connector) checkDraftDeleted(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	tg, id, err := c.identityDraft(in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	svc, err := tg.client.gmail(ctx)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	_, err = svc.Users.Drafts.Get(gmailUser, id).Context(ctx).Format("minimal").Do()
	switch err := classify("reconcile: get draft", err); {
	case err == nil:
		return notFound, nil
	case statusOf(err) == http.StatusNotFound:
		return found(id), nil
	default:
		return connectors.ReconcileResult{}, err
	}
}
