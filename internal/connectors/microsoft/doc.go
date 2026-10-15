// Package microsoft is the Microsoft 365 connector (app "microsoft"):
// Outlook mail and calendar, OneDrive and Teams tools over the thin
// Graph REST client in the graph subpackage (decision bt8ukyrd: no
// msgraph-sdk-go), accepting work (Entra) and personal Microsoft
// accounts. It copies the GitHub reference connector's shape (decisions
// 89k5cln0, 8023b958): a connections.Binder (binder.go) that identifies
// the account by tenant and object id and labels it company or personal
// by tenant; read tools (tools_read.go) and write tools with their
// reconciliation (tools_write.go, reconcile.go); result shapes in
// minimal.go; tokens fetched per call through the injected
// TokenSourceFunc and never stored.
//
// Tool names are "microsoft.<area>_<verb>" (mail_search,
// calendar_create_event, ...): tool names cannot carry dots and one
// connector is one app, so the plan's "mail.search" is
// "microsoft.mail_search".
//
// Scopes: every tool declares the Graph delegated permissions it needs
// (RequiredScopes). The pipeline does not compare them with the
// account's granted scopes yet, so Call does (scopes.go) when an
// AccountSource is injected: a tool whose scopes the account has not
// granted is refused with ClassScopeRequired before any request.
// Personal Microsoft accounts cannot grant Teams permissions (decision
// mh7c6z3v); the binder strips them from such accounts, so the Teams
// tools are refused for them with a message that says why.
//
// Read results mark Empty (no items), Partial (clamped page size,
// result truncated to the bounds, or a team whose channels could not be
// listed) and Unavailable (5xx, network); throttling (429, or 503 with
// Retry-After) is *connectors.RateLimited; other failures are *Error
// with a Class (reconnect_required, not_found, forbidden,
// invalid_argument, scope_required, vendor_error).
//
// Writes require the ledger's Call.OperationID (ErrMissingOperation
// otherwise) and report an outcome that cannot be known (5xx, timeout,
// dropped connection after the request was sent) as
// connectors.ErrOutcomeUnknown. mail_send carries the operation id as a
// deterministic internetMessageId and an x-mcp-gateway-op header
// (marker); calendar_create_event as the event's transactionId (stable
// id); drive_create_folder is checked by the folder name in its parent
// (an approximated marker); teams_post_channel_message cannot be checked
// (none).
//
// Tools added to match the reference connectors (mail drafts, reply,
// forward, move, attachments; calendar get / update / delete / respond
// and meeting times; OneDrive listing, content, uploads and links; Teams
// chats; To Do; contacts, people and directory search) are declared
// with their handler as toolDef (tools_common.go and tools_<area>.go);
// content moves are capped at MaxContentBytes, and every new write
// defaults to Ask (migration 00023). WorkOnlyScope names the permissions
// personal accounts cannot grant.
//
// The tool set is designed after Softeria/ms-365-mcp-server (TypeScript,
// MIT) at the design level only; no code was copied (decision
// 0sod196t).
//
// Design: Brain plan 36bakiw8 section 5; decisions bt8ukyrd, mh7c6z3v,
// dovthftx, wcp2fmbz, rrmfnkqu, 0sod196t.
package microsoft

// App is the connector's name; every tool is "microsoft.<name>".
const App = "microsoft"

// PersonalTenant is the tenant id Microsoft issues for personal (MSA)
// accounts: outlook.com, hotmail.com, live.com and the like.
const PersonalTenant = "9188040d-6c67-4c5b-b112-36a304b66dad"
