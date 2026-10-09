package slack

import (
	"context"
	"errors"
	"fmt"

	goslack "github.com/slack-go/slack"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// MaxReconcilePages bounds how many pages (of reconcilePerPage messages)
// a marker check walks through a channel's history or a thread before
// giving up with "cannot tell yet"; the reconciler retries later with
// backoff and, after its own limits, hands the operation to the user as
// unresolved.
const MaxReconcilePages = 5

// reconcilePerPage is the page size the marker checks list with.
const reconcilePerPage = 200

// ErrNotReconcilable says the ledger row lacks what the check needs (an
// operation id, the channel, the message timestamp, the reaction name
// or the thread); the reconciler treats it as "cannot tell".
var ErrNotReconcilable = errors.New("slack: operation cannot be reconciled")

// reconcileTarget is what every check starts from: the channel the write
// targeted (from the resource identity the ledger stored; a name is
// resolved to its id), the operation id and an authenticated client for
// the same account the write ran under.
type reconcileTarget struct {
	channel, operationID string
	api                  *goslack.Client
}

// target validates the input, builds the client and resolves the
// channel. Call.Args are empty when the reconciler runs from the
// ledger; everything comes from ResourceIdentity and OperationID
// (decision enlsy40f).
func (c *Connector) target(ctx context.Context, in connectors.ReconcileInput) (reconcileTarget, error) {
	opID := in.OperationID
	if opID == "" {
		opID = in.Call.OperationID
	}
	if opID == "" {
		return reconcileTarget{}, fmt.Errorf("%w: no operation id", ErrNotReconcilable)
	}
	id, name := in.ResourceIdentity["channel_id"], in.ResourceIdentity["channel_name"]
	if id == "" && name == "" {
		id, name = parseChannelRef(in.ResourceIdentity["channel"])
	}
	if id == "" && name == "" {
		return reconcileTarget{}, fmt.Errorf("%w: resource identity has no channel", ErrNotReconcilable)
	}
	if in.Call.Account == "" {
		return reconcileTarget{}, fmt.Errorf("%w: no account", ErrNotReconcilable)
	}
	api, err := c.client(ctx, in.Call)
	if err != nil {
		return reconcileTarget{}, err
	}
	id, _, err = c.resolveChannel(ctx, api, id, name)
	if err != nil {
		return reconcileTarget{}, err
	}
	return reconcileTarget{channel: id, operationID: opID, api: api}, nil
}

// found builds a found result.
func found(id string) connectors.ReconcileResult {
	return connectors.ReconcileResult{Outcome: connectors.ReconcileFound, ResourceID: id}
}

// notFound is the definite negative.
var notFound = connectors.ReconcileResult{Outcome: connectors.ReconcileNotFound}

// --- add_reaction -----------------------------------------------------------------

// checkReaction is add_reaction's stable-id reconciliation: the message
// (channel + timestamp) and the emoji name are known before the call,
// so reactions.get (full user lists) says whether the account's own
// user (auth.test) is among the reactors. The reaction with this user
// is found (resource id: the message ts); the message without it, or a
// message that is gone (message_not_found), is not_found; anything
// else (channel_not_found: access may have been lost; 5xx; auth
// failure) is "cannot tell yet".
func (c *Connector) checkReaction(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	ts, name := in.ResourceIdentity["timestamp"], in.ResourceIdentity["reaction"]
	if !tsRE.MatchString(ts) {
		return connectors.ReconcileResult{}, fmt.Errorf("%w: resource identity has no message timestamp", ErrNotReconcilable)
	}
	if !reactionRE.MatchString(name) {
		return connectors.ReconcileResult{}, fmt.Errorf("%w: resource identity has no reaction name", ErrNotReconcilable)
	}
	tg, err := c.target(ctx, in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	me, err := tg.api.AuthTestContext(ctx)
	if err := classify("reconcile: identify account", err); err != nil {
		return connectors.ReconcileResult{}, err
	}
	item, err := tg.api.GetReactionsContext(ctx, goslack.ItemRef{Channel: tg.channel, Timestamp: ts}, goslack.GetReactionsParameters{Full: true})
	if err := classify("reconcile: get reactions", err); err != nil {
		var ser goslack.SlackErrorResponse
		if errors.As(err, &ser) && ser.Err == "message_not_found" {
			return notFound, nil
		}
		return connectors.ReconcileResult{}, err
	}
	for _, r := range item.Reactions {
		if r.Name != name {
			continue
		}
		for _, u := range r.Users {
			if u == me.UserID {
				return found(ts), nil
			}
		}
	}
	return notFound, nil
}

// --- post_message / reply_in_thread (marker, opt-in) ---------------------------------

// checkMessage is the marker reconciliation of post_message and
// reply_in_thread when Options.MarkerReconcile is on: the thread
// (conversations.replies, when the identity carries thread_ts) or the
// channel history (conversations.history, newest first) is read with
// include_all_metadata, bounded by MaxReconcilePages. The message whose
// metadata carries the operation id is found (resource id: its ts);
// the end of the listing without it is not_found; running out of pages
// or any listing error is "cannot tell yet".
//
// For reply_in_thread the thread is required; post_message without a
// thread_ts scans the channel.
func (c *Connector) checkMessage(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	threadTS := in.ResourceIdentity["thread_ts"]
	if threadTS != "" && !tsRE.MatchString(threadTS) {
		return connectors.ReconcileResult{}, fmt.Errorf("%w: resource identity has a malformed thread_ts", ErrNotReconcilable)
	}
	if shortName(in.Call.Tool) == ToolReplyInThread && threadTS == "" {
		return connectors.ReconcileResult{}, fmt.Errorf("%w: resource identity has no thread_ts", ErrNotReconcilable)
	}
	tg, err := c.target(ctx, in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	cursor := ""
	for page := 1; page <= MaxReconcilePages; page++ {
		var (
			msgs    []goslack.Message
			hasMore bool
			next    string
			err     error
		)
		if threadTS != "" {
			msgs, hasMore, next, err = tg.api.GetConversationRepliesContext(ctx, &goslack.GetConversationRepliesParameters{ChannelID: tg.channel, Timestamp: threadTS, Limit: reconcilePerPage, Cursor: cursor, IncludeAllMetadata: true})
			err = classify("reconcile: get thread", err)
		} else {
			var history *goslack.GetConversationHistoryResponse
			history, err = tg.api.GetConversationHistoryContext(ctx, &goslack.GetConversationHistoryParameters{ChannelID: tg.channel, Limit: reconcilePerPage, Cursor: cursor, IncludeAllMetadata: true})
			if err = classify("reconcile: read channel history", err); err == nil {
				msgs, hasMore, next = history.Messages, history.HasMore, history.ResponseMetaData.NextCursor
			}
		}
		if err != nil {
			return connectors.ReconcileResult{}, err
		}
		for _, m := range msgs {
			if hasMarker(m.Metadata, tg.operationID) {
				return found(m.Timestamp), nil
			}
		}
		if !hasMore || next == "" {
			return notFound, nil
		}
		cursor = next
	}
	return connectors.ReconcileResult{}, fmt.Errorf("slack: reconcile: more than %d pages of messages in %s without the marker; cannot tell yet", MaxReconcilePages, tg.channel)
}
