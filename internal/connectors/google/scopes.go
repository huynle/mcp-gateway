package google

import (
	"strings"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Google OAuth scopes the tools declare as RequiredScopes (the minimal
// scope each tool works with; docs/vendor-apps.md section 4.3). The
// account may have granted a broader one: Grants applies the implication
// table below.
const (
	ScopeCalendarEventsReadonly = "https://www.googleapis.com/auth/calendar.events.readonly"
	ScopeCalendarEvents         = "https://www.googleapis.com/auth/calendar.events"
	ScopeCalendarReadonly       = "https://www.googleapis.com/auth/calendar.readonly"
	ScopeCalendar               = "https://www.googleapis.com/auth/calendar"
	// Calendar management (list_calendars, free_busy): the granular
	// calendar-list and free/busy scopes, both covered by
	// calendar.readonly.
	ScopeCalendarListReadonly   = "https://www.googleapis.com/auth/calendar.calendarlist.readonly"
	ScopeCalendarList           = "https://www.googleapis.com/auth/calendar.calendarlist"
	ScopeCalendarFreeBusy       = "https://www.googleapis.com/auth/calendar.freebusy"
	ScopeCalendarEventsFreeBusy = "https://www.googleapis.com/auth/calendar.events.freebusy"
	ScopeTasksReadonly          = "https://www.googleapis.com/auth/tasks.readonly"
	ScopeTasks                  = "https://www.googleapis.com/auth/tasks"
	ScopeGmailReadonly          = "https://www.googleapis.com/auth/gmail.readonly"
	ScopeGmailLabels            = "https://www.googleapis.com/auth/gmail.labels"
	ScopeGmailMetadata          = "https://www.googleapis.com/auth/gmail.metadata"
	ScopeGmailSend              = "https://www.googleapis.com/auth/gmail.send"
	ScopeGmailCompose           = "https://www.googleapis.com/auth/gmail.compose"
	ScopeGmailModify            = "https://www.googleapis.com/auth/gmail.modify"
	ScopeMail                   = "https://mail.google.com/"
	// gmail.settings.basic (restricted) is the only scope
	// users.settings.updateVacation accepts (not even mail.google.com);
	// getVacation and filters.list also accept gmail.readonly, which the
	// settings reads declare. No implication: nothing covers it.
	ScopeGmailSettingsBasic = "https://www.googleapis.com/auth/gmail.settings.basic"

	// Increment 2: Drive, Docs, Sheets, Contacts. drive, drive.readonly,
	// drive.metadata and drive.metadata.readonly are restricted scopes
	// (verification plus CASA for the External app); drive.file is
	// non-sensitive but per-file (only what the gateway created or the
	// user opened with it); the Docs, Sheets and Contacts scopes are
	// sensitive.
	ScopeDriveMetadataReadonly = "https://www.googleapis.com/auth/drive.metadata.readonly"
	ScopeDriveMetadata         = "https://www.googleapis.com/auth/drive.metadata"
	ScopeDriveReadonly         = "https://www.googleapis.com/auth/drive.readonly"
	ScopeDriveFile             = "https://www.googleapis.com/auth/drive.file"
	ScopeDrive                 = "https://www.googleapis.com/auth/drive"
	ScopeDocumentsReadonly     = "https://www.googleapis.com/auth/documents.readonly"
	ScopeDocuments             = "https://www.googleapis.com/auth/documents"
	ScopeSpreadsheetsReadonly  = "https://www.googleapis.com/auth/spreadsheets.readonly"
	ScopeSpreadsheets          = "https://www.googleapis.com/auth/spreadsheets"
	ScopeContactsReadonly      = "https://www.googleapis.com/auth/contacts.readonly"
	ScopeContacts              = "https://www.googleapis.com/auth/contacts"

	// Increment 4: Google Workspace only (WorkspaceOnlyScope). The
	// directory (People API searchDirectoryPeople, listDirectoryPeople)
	// and the Chat API exist only for Workspace accounts; personal
	// (gmail.com) accounts can never grant them. All are sensitive.
	ScopeDirectoryReadonly    = "https://www.googleapis.com/auth/directory.readonly"
	ScopeChatSpacesReadonly   = "https://www.googleapis.com/auth/chat.spaces.readonly"
	ScopeChatSpaces           = "https://www.googleapis.com/auth/chat.spaces"
	ScopeChatMessagesReadonly = "https://www.googleapis.com/auth/chat.messages.readonly"
	ScopeChatMessages         = "https://www.googleapis.com/auth/chat.messages"
	ScopeChatMessagesCreate   = "https://www.googleapis.com/auth/chat.messages.create"
	// spaces.members.list accepts chat.memberships.readonly or
	// chat.memberships with user authentication.
	ScopeChatMembershipsReadonly = "https://www.googleapis.com/auth/chat.memberships.readonly"
	ScopeChatMemberships         = "https://www.googleapis.com/auth/chat.memberships"

	// chatScopePrefix is the common prefix of every Chat API scope.
	chatScopePrefix = "https://www.googleapis.com/auth/chat."
)

// scopeImplies lists, per scope, the narrower scopes it covers (one
// level; Grants walks the closure). Taken from the methods' accepted
// scope lists in the Calendar, Tasks, Gmail, Drive, Docs, Sheets and
// People API references: the full drive scope is accepted by every Drive,
// Docs and Sheets method, drive.readonly by their read-only methods.
var scopeImplies = map[string][]string{
	ScopeCalendar:               {ScopeCalendarEvents, ScopeCalendarReadonly, ScopeCalendarList},
	ScopeCalendarEvents:         {ScopeCalendarEventsReadonly},
	ScopeCalendarReadonly:       {ScopeCalendarEventsReadonly, ScopeCalendarListReadonly, ScopeCalendarFreeBusy},
	ScopeCalendarList:           {ScopeCalendarListReadonly},
	ScopeCalendarEventsFreeBusy: {ScopeCalendarFreeBusy},
	ScopeTasks:                  {ScopeTasksReadonly},
	ScopeMail:                   {ScopeGmailModify},
	ScopeGmailModify:            {ScopeGmailReadonly, ScopeGmailCompose, ScopeGmailLabels},
	ScopeGmailCompose:           {ScopeGmailSend},
	ScopeGmailReadonly:          {ScopeGmailLabels, ScopeGmailMetadata},
	ScopeDrive:                  {ScopeDriveReadonly, ScopeDriveFile, ScopeDriveMetadata, ScopeDocuments, ScopeSpreadsheets},
	ScopeDriveReadonly:          {ScopeDriveMetadataReadonly, ScopeDocumentsReadonly, ScopeSpreadsheetsReadonly},
	ScopeDriveMetadata:          {ScopeDriveMetadataReadonly},
	ScopeDocuments:              {ScopeDocumentsReadonly},
	ScopeSpreadsheets:           {ScopeSpreadsheetsReadonly},
	ScopeContacts:               {ScopeContactsReadonly},
	ScopeChatSpaces:             {ScopeChatSpacesReadonly},
	ScopeChatMessages:           {ScopeChatMessagesReadonly, ScopeChatMessagesCreate},
	ScopeChatMemberships:        {ScopeChatMembershipsReadonly},
}

// perFileScopes are the required scopes drive.file stands in for: the
// Drive, Docs and Sheets methods accept drive.file, limited to the files
// the gateway created or the user opened with it, so an account that
// granted only drive.file may run those tools on that subset (Google
// decides per file: anything else answers not_found).
var perFileScopes = map[string]bool{
	ScopeDriveMetadataReadonly: true, ScopeDriveReadonly: true, ScopeDriveFile: true,
	ScopeDocumentsReadonly: true, ScopeDocuments: true,
	ScopeSpreadsheetsReadonly: true, ScopeSpreadsheets: true,
}

// PerFile reports whether drive.file admits a tool requiring scope, on
// the files the gateway created or the user opened with it.
func PerFile(scope string) bool { return perFileScopes[scope] }

// Grants reports whether the granted scopes cover required: one of them
// is required itself or implies it.
func Grants(granted []string, required string) bool {
	seen := map[string]bool{}
	var covers func(scope string) bool
	covers = func(scope string) bool {
		if scope == required {
			return true
		}
		if seen[scope] {
			return false
		}
		seen[scope] = true
		for _, narrower := range scopeImplies[scope] {
			if covers(narrower) {
				return true
			}
		}
		return false
	}
	for _, g := range granted {
		if covers(g) {
			return true
		}
	}
	return false
}

// GrantsOrPerFile is Grants, or the per-file admission: required is one
// of the Drive, Docs or Sheets scopes and the account granted drive.file
// (the scope gate uses it so such an account keeps the tools for the
// files it may see).
func GrantsOrPerFile(granted []string, required string) bool {
	return Grants(granted, required) || (PerFile(required) && Grants(granted, ScopeDriveFile))
}

// wholeDriveTools are the Drive tools whose method drive.file does not
// stand in for, although their scope is one it admits per file: the
// method lists no file (drives.list lists shared drives and accepts only
// drive and drive.readonly), so the per-file admission does not apply.
var wholeDriveTools = map[string]bool{AppDrive + "." + ToolListSharedDrives: true}

// toolGrants is the scope gate's test for one tool: GrantsOrPerFile,
// or Grants alone for a wholeDriveTools tool.
func toolGrants(tool connectors.Tool, granted []string, required string) bool {
	if wholeDriveTools[tool.App+"."+tool.Name] {
		return Grants(granted, required)
	}
	return GrantsOrPerFile(granted, required)
}

// WorkspaceOnlyScope reports whether only Google Workspace accounts can
// use scope: the directory (directory.readonly) and every Chat scope.
// Personal (gmail.com) accounts cannot grant them, so connect and grant
// more access never ask them (ScopeGrantable) and the binder strips them
// from accounts without a hosted domain.
func WorkspaceOnlyScope(scope string) bool {
	scope = strings.TrimSpace(scope)
	return scope == ScopeDirectoryReadonly || strings.HasPrefix(scope, chatScopePrefix)
}

// stripWorkspaceOnlyScopes returns scopes without the Workspace-only
// ones (WorkspaceOnlyScope), and whether any was removed.
func stripWorkspaceOnlyScopes(scopes []string) ([]string, bool) {
	out := make([]string, 0, len(scopes))
	for _, s := range scopes {
		if !WorkspaceOnlyScope(s) {
			out = append(out, s)
		}
	}
	return out, len(out) != len(scopes)
}

// ScopeGrantable is the connectors.ScopeGrantable of every Google app:
// personal accounts cannot grant the Workspace-only scopes
// (WorkspaceOnlyScope); company accounts can grant everything.
func ScopeGrantable(label connectors.AccountLabel, scope string) bool {
	return label != connectors.LabelPersonal || !WorkspaceOnlyScope(scope)
}
