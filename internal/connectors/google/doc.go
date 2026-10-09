// Package google is the Google Workspace connector, increment 1
// (decision bt8ukyrd): a connections.Binder for Google accounts
// (binder.go) and three connector apps that share one Google account
// (vendor "google", connections.MapApp): "calendar" (list_events,
// get_event, create_event), "tasks" (list, create) and "gmail" (search,
// get_message, list_labels, send, create_draft). Each app is its own
// connectors.Connector so tool names read calendar.list_events,
// tasks.list and gmail.search, roles can grant or deny a whole app, and
// the restricted Gmail scopes stay separable from Calendar and Tasks.
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
// covers send; tasks covers tasks.readonly) is applied, so an account
// that granted a broader scope than a tool asks for is not blocked.
//
// Writes require the ledger's Call.OperationID (ErrMissingOperation) and
// reconcile from the resource identity and the operation id alone:
// calendar.create_event by a client-chosen event id derived from the
// operation id (stable_id), tasks.create by a marker in the task notes
// (marker), gmail.send and gmail.create_draft by a deterministic RFC 5322
// Message-ID "<op-<operation id>@mcp-gateway>" searched with
// rfc822msgid: (marker). An outcome that cannot be known (5xx, timeout,
// dropped connection after the request was sent) is reported as
// connectors.ErrOutcomeUnknown.
//
// The tool set is designed after taylorwilsdon/google_workspace_mcp
// (Python, MIT) without copying code (decision 0sod196t); the API is
// reached through google.golang.org/api (calendar/v3, tasks/v1, gmail/v1).
//
// Design: Brain plan 36bakiw8 section 5; decisions bt8ukyrd, mh7c6z3v,
// dovthftx, wcp2fmbz, rrmfnkqu, 0sod196t.
package google

// Vendor is the connections vendor every app of this package uses; the
// three apps are mapped to it with connections.Service.MapApp.
const Vendor = "google"

// The connector apps; every tool is "<app>.<name>". Increment 1 is
// calendar, tasks and gmail; increment 2 adds drive, docs, sheets and
// contacts over the same account binding.
const (
	AppCalendar = "calendar"
	AppTasks    = "tasks"
	AppGmail    = "gmail"
	AppDrive    = "drive"
	AppDocs     = "docs"
	AppSheets   = "sheets"
	AppContacts = "contacts"
)

// Apps lists the apps in registration order.
var Apps = []string{AppCalendar, AppTasks, AppGmail}

// userAgent identifies the gateway to Google.
const userAgent = "mcp-gateway"
