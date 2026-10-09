package google

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// MaxReconcilePages bounds how many pages (of reconcilePerPage items) a
// listing reconciliation check walks before giving up with "cannot tell
// yet"; the reconciler retries later with backoff and, after its own
// limits, hands the operation to the user as unresolved.
const MaxReconcilePages = 5

// reconcilePerPage is the page size the listing checks use (the Tasks
// API's maximum).
const reconcilePerPage = 100

// MaxReconcileScan bounds how many recent sent messages or drafts the
// Gmail checks read (one metadata request each) when the rfc822msgid:
// search found nothing. The message would be among the newest; past
// this many the check answers not_found.
const MaxReconcileScan = 25

// ErrNotReconcilable says the ledger row lacks what the check needs (an
// operation id, the account, the calendar or the tasklist in the
// resource identity); the reconciler treats it as "cannot tell".
var ErrNotReconcilable = errors.New("google: operation cannot be reconciled")

// reconcileTarget is what every check starts from: the operation id and
// a client for the same account the write ran under (the token is
// fetched on first use).
type reconcileTarget struct {
	operationID string
	client      *client
}

// target validates the input and builds the client. Call.Args are empty
// when the reconciler runs from the ledger; everything comes from
// ResourceIdentity and OperationID (decision enlsy40f).
func (c *Connector) target(in connectors.ReconcileInput) (reconcileTarget, error) {
	opID := in.OperationID
	if opID == "" {
		opID = in.Call.OperationID
	}
	if opID == "" {
		return reconcileTarget{}, fmt.Errorf("%w: no operation id", ErrNotReconcilable)
	}
	if in.Call.Account == "" {
		return reconcileTarget{}, fmt.Errorf("%w: no account", ErrNotReconcilable)
	}
	call := in.Call
	call.OperationID = opID
	return reconcileTarget{operationID: opID, client: c.client(call)}, nil
}

// found builds a found result.
func found(id string) connectors.ReconcileResult {
	return connectors.ReconcileResult{Outcome: connectors.ReconcileFound, ResourceID: id}
}

// notFound is the definite negative.
var notFound = connectors.ReconcileResult{Outcome: connectors.ReconcileNotFound}

// --- calendar.create_event ---------------------------------------------------------

// checkEvent is create_event's stable-id reconciliation: the event id is
// derived from the operation id (EventID), so the event is looked up in
// the calendar the resource identity names. Present is found (whatever
// its status: a cancelled event with that id was created and then
// removed); 404 or 410 is not_found; anything else is "cannot tell yet".
func (c *Connector) checkEvent(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	tg, err := c.target(in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	calendarID := strings.ToLower(strings.TrimSpace(in.ResourceIdentity["calendar_id"]))
	if calendarID == "" || !idRE.MatchString(calendarID) {
		return connectors.ReconcileResult{}, fmt.Errorf("%w: resource identity has no calendar", ErrNotReconcilable)
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	svc, err := tg.client.calendar(ctx)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	id := EventID(tg.operationID)
	ev, err := svc.Events.Get(calendarID, id).Context(ctx).Do()
	if err := classify("reconcile: get event", err); err != nil {
		if s := statusOf(err); s == http.StatusNotFound || s == http.StatusGone {
			return notFound, nil
		}
		return connectors.ReconcileResult{}, err
	}
	if ev.Id != "" && ev.Id != id {
		return connectors.ReconcileResult{}, fmt.Errorf("google: reconcile: Google answered event %q for %q; cannot tell yet", ev.Id, id)
	}
	return found(id), nil
}

// --- tasks.create --------------------------------------------------------------------

// checkTask is tasks.create's marker reconciliation: the tasklist's
// tasks (completed and hidden ones included) are listed in pages of
// reconcilePerPage, bounded by MaxReconcilePages. The marker in a task's
// notes is found; the end of the list without it is not_found; running
// out of pages, or any listing error (including 404: the account may
// have lost the list rather than the task being absent), is "cannot
// tell yet".
func (c *Connector) checkTask(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	tg, err := c.target(in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	tasklist := strings.TrimSpace(in.ResourceIdentity["tasklist"])
	if tasklist == "" || !idRE.MatchString(tasklist) {
		return connectors.ReconcileResult{}, fmt.Errorf("%w: resource identity has no tasklist", ErrNotReconcilable)
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	svc, err := tg.client.tasks(ctx)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	pageToken := ""
	for page := 1; page <= MaxReconcilePages; page++ {
		req := svc.Tasks.List(tasklist).Context(ctx).ShowCompleted(true).ShowHidden(true).MaxResults(reconcilePerPage)
		if pageToken != "" {
			req = req.PageToken(pageToken)
		}
		list, err := req.Do()
		if err := classify("reconcile: list tasks", err); err != nil {
			return connectors.ReconcileResult{}, err
		}
		for _, t := range list.Items {
			if t != nil && hasTaskMarker(t.Notes, tg.operationID) {
				return found(t.Id), nil
			}
		}
		if pageToken = list.NextPageToken; pageToken == "" {
			return notFound, nil
		}
	}
	return connectors.ReconcileResult{}, fmt.Errorf("google: reconcile: more than %d pages of tasks in list %s; cannot tell yet", MaxReconcilePages, tasklist)
}

// --- gmail.send ------------------------------------------------------------------------

// checkSent is send's Message-ID reconciliation. The search
// rfc822msgid:<id> (Spam and Trash included) is exact: a hit is the
// message. The search index can lag, so a miss is confirmed by reading
// the Message-ID header of the newest MaxReconcileScan sent messages;
// none carrying it is not_found. Any search, listing or metadata error
// is "cannot tell yet".
func (c *Connector) checkSent(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	tg, err := c.target(in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	svc, err := tg.client.gmail(ctx)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	hits, err := svc.Users.Messages.List(gmailUser).Context(ctx).Q(messageIDQuery(tg.operationID)).IncludeSpamTrash(true).MaxResults(5).Do()
	if err := classify("reconcile: search sent message", err); err != nil {
		return connectors.ReconcileResult{}, err
	}
	for _, m := range hits.Messages {
		if m != nil && m.Id != "" {
			return found(m.Id), nil
		}
	}
	recent, err := svc.Users.Messages.List(gmailUser).Context(ctx).LabelIds("SENT").MaxResults(MaxReconcileScan).Do()
	if err := classify("reconcile: list sent messages", err); err != nil {
		return connectors.ReconcileResult{}, err
	}
	want := MessageID(tg.operationID)
	for _, m := range recent.Messages {
		if m == nil || m.Id == "" {
			continue
		}
		msg, err := svc.Users.Messages.Get(gmailUser, m.Id).Context(ctx).Format("metadata").MetadataHeaders("Message-ID").Do()
		if err := classify("reconcile: get sent message headers", err); err != nil {
			return connectors.ReconcileResult{}, err
		}
		if strings.TrimSpace(headerOf(msg.Payload, "Message-ID")) == want {
			return found(msg.Id), nil
		}
	}
	return notFound, nil
}

// --- gmail.create_draft -----------------------------------------------------------------

// checkDraft is create_draft's Message-ID reconciliation over drafts:
// drafts.list with the rfc822msgid: query first (a hit is the draft),
// then the newest MaxReconcileScan drafts read one by one for the
// header; none carrying it is not_found. The resource id is the draft
// id. Any error is "cannot tell yet".
func (c *Connector) checkDraft(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	tg, err := c.target(in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	svc, err := tg.client.gmail(ctx)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	hits, err := svc.Users.Drafts.List(gmailUser).Context(ctx).Q(messageIDQuery(tg.operationID)).MaxResults(5).Do()
	if err := classify("reconcile: search drafts", err); err != nil {
		return connectors.ReconcileResult{}, err
	}
	for _, d := range hits.Drafts {
		if d != nil && d.Id != "" {
			return found(d.Id), nil
		}
	}
	recent, err := svc.Users.Drafts.List(gmailUser).Context(ctx).MaxResults(MaxReconcileScan).Do()
	if err := classify("reconcile: list drafts", err); err != nil {
		return connectors.ReconcileResult{}, err
	}
	want := MessageID(tg.operationID)
	for _, d := range recent.Drafts {
		if d == nil || d.Id == "" {
			continue
		}
		draft, err := svc.Users.Drafts.Get(gmailUser, d.Id).Context(ctx).Format("metadata").Do()
		if err := classify("reconcile: get draft headers", err); err != nil {
			return connectors.ReconcileResult{}, err
		}
		if draft.Message != nil && strings.TrimSpace(headerOf(draft.Message.Payload, "Message-ID")) == want {
			return found(draft.Id), nil
		}
	}
	return notFound, nil
}
