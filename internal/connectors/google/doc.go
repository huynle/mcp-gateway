// Package google is the Google Workspace connector (decision bt8ukyrd):
// a connections.Binder for Google accounts (binder.go) and eight
// connector apps that share one Google account (vendor "google",
// connections.MapApp). Increment 1: "calendar" (list_events, get_event,
// create_event), "tasks" (list, create) and "gmail" (search,
// get_message, list_labels, send, create_draft). Increment 2 (decision
// 85k9b1ig): "drive" (search, get_file_metadata, create_folder), "docs"
// (get_text, create, append_text), "sheets" (read_range, append_rows)
// and "contacts" (search). Increment 3 (Brain plan 5soa9785) adds the
// management tools: calendar list_calendars, free_busy, update_event,
// delete_event, respond_to_event; tasks list_tasklists, get, update,
// complete, delete; gmail get_thread, list_drafts, get_attachment,
// modify_labels, trash, send_draft; drive get_content, list_folder,
// list_permissions, list_comments, create_file, update_file, share,
// add_comment; docs replace_text; sheets get_metadata, update_range,
// create; contacts get, list (docs/connectors/google.md). Increment 4
// (decision 94k2b0pp) adds the Google Workspace tools: contacts
// search_directory, list_directory, and the "chat" app (Google Chat API:
// list_spaces, get_space, list_messages, get_message, list_members).
// Each app is its own connectors.Connector so
// tool names read calendar.list_events, drive.search and docs.get_text,
// roles can grant or deny a whole app, and the restricted Gmail and
// Drive scopes stay separable from the rest.
//
// The connector follows the GitHub reference (internal/connectors/github,
// decisions 89k5cln0 and 8023b958): tokens come from the connection's
// oauth2.TokenSource per call and are never stored; reads mark Empty,
// Partial (clamped page size, truncated result, a metadata fetch that
// failed) and Unavailable (5xx, network); 429 and the 403 quota reasons
// (rateLimitExceeded, userRateLimitExceeded, quotaExceeded,
// dailyLimitExceeded) are *connectors.RateLimited; other failures are
// *Error with a Class (reconnect_required, scope_required, not_found,
// forbidden, invalid_argument, conflict, vendor_error).
//
// Google's granular consent lets a user decline some of the requested
// scopes. The pipeline does not yet compare Tool.RequiredScopes with
// Account.Scopes, so Call does it here when Options.Accounts is set: a
// tool whose scope the account did not grant answers *Error class
// scope_required ("grant more access") before any request is sent;
// Calendar tools keep working when only the Gmail scope was declined.
// Scope implication (calendar covers calendar.events covers
// calendar.events.readonly; mail.google.com covers every Gmail scope,
// gmail.modify covers readonly, labels, compose and send, gmail.compose
// covers send; tasks covers tasks.readonly; drive covers every Drive,
// Docs and Sheets scope, drive.readonly their read-only ones; contacts
// covers contacts.readonly) is applied, so an account that granted a
// broader scope than a tool asks for is not blocked; drive.file admits
// the Drive, Docs and Sheets tools on the files the gateway created or
// the user opened with it (GrantsOrPerFile).
//
// The directory and Chat scopes exist only for Google Workspace accounts
// (WorkspaceOnlyScope): personal accounts are never asked for them
// (ScopeGrantable, installed with connectors.Registry.SetScopeGrantable),
// the binder drops them from an account without a hosted domain (hd),
// and the scope gate's message says a personal account cannot grant
// them.
//
// Writes require the ledger's Call.OperationID (ErrMissingOperation) and
// reconcile from the resource identity and the operation id alone:
// calendar.create_event by a client-chosen event id derived from the
// operation id (stable_id), tasks.create by a marker in the task notes
// (marker), gmail.send and gmail.create_draft by a deterministic RFC 5322
// Message-ID "<op-<operation id>@mcp-gateway>" searched with
// rfc822msgid: (marker), drive.create_folder and docs.create by the
// Drive appProperties entry "mcp-gateway-op" set in the creating request
// and found with files.list (marker); docs.append_text and
// sheets.append_rows cannot be verified (none). An outcome that cannot
// be known (5xx, timeout, dropped connection after the request was sent)
// is reported as connectors.ErrOutcomeUnknown.
//
// The tool set is designed after taylorwilsdon/google_workspace_mcp
// (Python, MIT) without copying code (decision 0sod196t); the API is
// reached through google.golang.org/api (calendar/v3, tasks/v1, gmail/v1,
// drive/v3, docs/v1, sheets/v4, people/v1, chat/v1).
//
// Design: Brain plan 36bakiw8 section 5; decisions bt8ukyrd, mh7c6z3v,
// dovthftx, wcp2fmbz, rrmfnkqu, 0sod196t, 85k9b1ig, 94k2b0pp.
package google

// Vendor is the connections vendor every app of this package uses; the
// apps are mapped to it with connections.Service.MapApp.
const Vendor = "google"

// The connector apps; every tool is "<app>.<name>". Increment 1 is
// calendar, tasks and gmail; increment 2 adds drive, docs, sheets and
// contacts over the same account binding; increment 4 adds chat (Google
// Workspace accounts only).
const (
	AppCalendar = "calendar"
	AppTasks    = "tasks"
	AppGmail    = "gmail"
	AppDrive    = "drive"
	AppDocs     = "docs"
	AppSheets   = "sheets"
	AppContacts = "contacts"
	AppChat     = "chat"
)

// Apps lists the apps in registration order.
var Apps = []string{AppCalendar, AppTasks, AppGmail, AppDrive, AppDocs, AppSheets, AppContacts, AppChat}

// userAgent identifies the gateway to Google.
const userAgent = "mcp-gateway"
