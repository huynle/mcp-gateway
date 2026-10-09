package microsoft

import (
	"context"
	"errors"

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

// ErrMissingOperation is returned by every write called without
// Call.OperationID: the ledger stage sets it before dispatch, and the
// marker and stable-id reconciliation derive from it, so a write without
// one could never be verified after an unknown outcome. It means a
// pipeline wiring bug (a write dispatched without the ledger), never a
// harness mistake.
var ErrMissingOperation = errors.New("microsoft: write called without a ledger operation id")

var errNotImplemented = errors.New("microsoft: not implemented")

// writeTools declares the four write tools.
func (c *Connector) writeTools() []connectors.Tool {
	single := connectors.Bounds{MaxResultBytes: c.bounds.MaxResultBytes}
	return []connectors.Tool{
		{
			App: App, Name: ToolMailSend, Kind: connectors.KindWrite,
			Description:      "Send an Outlook mail.",
			InputSchema:      objectSchema([]property{{"to", "array", "Recipient addresses.", nil}, {"subject", "string", "Subject.", nil}, {"body", "string", "Body.", nil}, {"cc", "array", "Cc addresses.", nil}}, []string{"to", "subject", "body"}),
			RequiredScopes:   []string{ScopeMailSend},
			ResourceIdentity: func(map[string]any) map[string]string { return map[string]string{} },
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileMarker, Check: c.checkMail},
			Bounds:           single,
		},
		{
			App: App, Name: ToolCalendarCreateEvent, Kind: connectors.KindWrite,
			Description:      "Create a calendar event.",
			InputSchema:      objectSchema([]property{{"subject", "string", "Subject.", nil}, {"start", "string", "Start.", nil}, {"end", "string", "End.", nil}}, []string{"subject", "start", "end"}),
			RequiredScopes:   []string{ScopeCalendarsReadWrite},
			ResourceIdentity: calendarIdentity,
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: c.checkEvent},
			Bounds:           single,
		},
		{
			App: App, Name: ToolDriveCreateFolder, Kind: connectors.KindWrite,
			Description:      "Create a folder.",
			InputSchema:      objectSchema([]property{{"name", "string", "Name.", nil}}, []string{"name"}),
			RequiredScopes:   []string{ScopeFilesReadWrite},
			ResourceIdentity: driveIdentity,
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileMarker, Check: c.checkFolder},
			Bounds:           single,
		},
		{
			App: App, Name: ToolTeamsPostChannelMessage, Kind: connectors.KindWrite,
			Description:      "Post a message to a Teams channel.",
			InputSchema:      objectSchema([]property{{"team_id", "string", "Team id.", nil}, {"channel_id", "string", "Channel id.", nil}, {"content", "string", "Content.", nil}}, []string{"team_id", "channel_id", "content"}),
			RequiredScopes:   []string{ScopeChannelMessageSend},
			ResourceIdentity: teamIdentity(true),
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileNone},
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

func (c *Connector) mailSend(context.Context, *graph.Client, connectors.Call) (connectors.Result, error) {
	return connectors.Result{}, errNotImplemented
}

func (c *Connector) calendarCreateEvent(context.Context, *graph.Client, connectors.Call) (connectors.Result, error) {
	return connectors.Result{}, errNotImplemented
}

func (c *Connector) driveCreateFolder(context.Context, *graph.Client, connectors.Call) (connectors.Result, error) {
	return connectors.Result{}, errNotImplemented
}

func (c *Connector) teamsPostChannelMessage(context.Context, *graph.Client, connectors.Call) (connectors.Result, error) {
	return connectors.Result{}, errNotImplemented
}

func (c *Connector) checkMail(context.Context, connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	return connectors.ReconcileResult{}, errNotImplemented
}

func (c *Connector) checkEvent(context.Context, connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	return connectors.ReconcileResult{}, errNotImplemented
}

func (c *Connector) checkFolder(context.Context, connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	return connectors.ReconcileResult{}, errNotImplemented
}
