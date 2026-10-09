package microsoft

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/microsoft/graph"
)

// MaxReconcilePages bounds how many pages (of reconcilePerPage items) a
// reconciliation check walks before giving up with "cannot tell yet";
// the reconciler retries later with backoff and, after its own limits,
// hands the operation to the user as unresolved.
const MaxReconcilePages = 5

// reconcilePerPage is the page size the checks list with.
const reconcilePerPage = 200

// ErrNotReconcilable says the ledger row lacks what the check needs (an
// operation id, the account, the folder name in the resource identity);
// the reconciler treats it as "cannot tell".
var ErrNotReconcilable = errors.New("microsoft: operation cannot be reconciled")

// reconcileTarget is what every check starts from: the operation id and
// an authenticated client for the same account the write ran under.
type reconcileTarget struct {
	operationID string
	client      *graph.Client
}

// target validates the input and builds the client. Call.Args are empty
// when the reconciler runs from the ledger; everything comes from
// ResourceIdentity and OperationID.
func (c *Connector) target(ctx context.Context, in connectors.ReconcileInput) (reconcileTarget, error) {
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
	client, err := c.client(ctx, in.Call)
	if err != nil {
		return reconcileTarget{}, err
	}
	return reconcileTarget{operationID: opID, client: client}, nil
}

// found builds a found result.
func found(id string) connectors.ReconcileResult {
	return connectors.ReconcileResult{Outcome: connectors.ReconcileFound, ResourceID: id}
}

// notFound is the definite negative.
var notFound = connectors.ReconcileResult{Outcome: connectors.ReconcileNotFound}

// --- mail_send -------------------------------------------------------------------

// checkMail is mail_send's marker reconciliation: the message was sent
// with the deterministic internet message id of the operation and a copy
// saved to Sent Items, so GET /me/messages?$filter=internetMessageId eq
// '<id>' (every folder) finds it. A hit whose id matches is found; an
// empty answer is not_found (the reconciler's first check runs at least
// a minute after the write, long after Sent Items is written); any
// error is "cannot tell yet".
func (c *Connector) checkMail(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	tg, err := c.target(ctx, in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	want := InternetMessageID(tg.operationID)
	query := url.Values{"$filter": {"internetMessageId eq " + graph.Quote(want)}, "$select": {"id,internetMessageId,webLink"}, "$top": {"10"}}
	items, _, err := graph.Collect[graphMessage](ctx, tg.client, messagesPath, query, graph.ListOptions{MaxItems: 10, MaxPages: 1})
	if err := classify("reconcile: find sent mail", err); err != nil {
		return connectors.ReconcileResult{}, err
	}
	for _, m := range items {
		if m.InternetMessageID == want && m.ID != "" {
			return found(m.ID), nil
		}
	}
	return notFound, nil
}

// --- calendar_create_event ----------------------------------------------------------

// checkEvent is calendar_create_event's stable-id reconciliation: the
// event was created with transactionId = the operation id, so
// GET /me/events?$filter=transactionId eq '<id>' (or the calendar's
// events) finds it. A hit whose transactionId matches is found; an
// empty answer is not_found; any error is "cannot tell yet".
func (c *Connector) checkEvent(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	tg, err := c.target(ctx, in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	path := "me/events"
	if cal := in.ResourceIdentity["calendar"]; cal != "" && cal != calendarDefaultName {
		if !idRE.MatchString(cal) {
			return connectors.ReconcileResult{}, fmt.Errorf("%w: resource identity has an invalid calendar", ErrNotReconcilable)
		}
		path = "me/calendars/" + cal + "/events"
	}
	query := url.Values{"$filter": {"transactionId eq " + graph.Quote(tg.operationID)}, "$select": {"id,transactionId,webLink"}, "$top": {"10"}}
	items, _, err := graph.Collect[graphEvent](ctx, tg.client, path, query, graph.ListOptions{MaxItems: 10, MaxPages: 1})
	if err := classify("reconcile: find event", err); err != nil {
		return connectors.ReconcileResult{}, err
	}
	for _, e := range items {
		if e.TransactionID == tg.operationID && e.ID != "" {
			return found(e.ID), nil
		}
	}
	return notFound, nil
}

// --- drive_create_folder -------------------------------------------------------------

// checkFolder is drive_create_folder's approximated marker
// reconciliation: a drive item carries no client-chosen id or header,
// so the parent's children (from the resource identity's drive and
// parent) are listed, bounded by MaxReconcilePages, and a folder whose
// name equals the recorded one (case-insensitively, as OneDrive compares
// names) is found. The end of the list without it is not_found; running
// out of pages or any listing error (including a 404: the account may
// have lost access rather than the parent being gone) is "cannot tell
// yet". A same-named folder created by other means in the meantime
// would be taken as this write's; the connector's "fail on conflict"
// request makes that the only way two such folders can exist.
func (c *Connector) checkFolder(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	tg, err := c.target(ctx, in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	name := in.ResourceIdentity["folder"]
	if name == "" {
		return connectors.ReconcileResult{}, fmt.Errorf("%w: resource identity has no folder name", ErrNotReconcilable)
	}
	drive, parent := in.ResourceIdentity["drive"], in.ResourceIdentity["parent"]
	if (drive != "" && !idRE.MatchString(drive)) || (parent != "" && !idRE.MatchString(parent)) {
		return connectors.ReconcileResult{}, fmt.Errorf("%w: resource identity has an invalid drive or parent", ErrNotReconcilable)
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	query := url.Values{"$select": {"id,name,folder"}, "$top": {fmt.Sprint(reconcilePerPage)}}
	next, q := childrenPath(drive, parent), query
	for page := 1; page <= MaxReconcilePages; page++ {
		var pg struct {
			Value    []graphDriveItem `json:"value"`
			NextLink string           `json:"@odata.nextLink"`
		}
		if _, err := tg.client.Do(ctx, graph.Request{Path: next, Query: q}, &pg); err != nil {
			if err := classify("reconcile: list folder children", err); err != nil {
				return connectors.ReconcileResult{}, err
			}
		}
		for _, item := range pg.Value {
			if item.Folder != nil && item.ID != "" && strings.EqualFold(item.Name, name) {
				return found(item.ID), nil
			}
		}
		if pg.NextLink == "" {
			return notFound, nil
		}
		next, q = pg.NextLink, nil
	}
	return connectors.ReconcileResult{}, fmt.Errorf("microsoft: reconcile: more than %d pages of items in the parent folder; cannot tell yet", MaxReconcilePages)
}
