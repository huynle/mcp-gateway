package google

// Google OAuth scopes the tools declare as RequiredScopes (the minimal
// scope each tool works with; docs/vendor-apps.md section 4.3). The
// account may have granted a broader one: Grants applies the implication
// table below.
const (
	ScopeCalendarEventsReadonly = "https://www.googleapis.com/auth/calendar.events.readonly"
	ScopeCalendarEvents         = "https://www.googleapis.com/auth/calendar.events"
	ScopeCalendarReadonly       = "https://www.googleapis.com/auth/calendar.readonly"
	ScopeCalendar               = "https://www.googleapis.com/auth/calendar"
	ScopeTasksReadonly          = "https://www.googleapis.com/auth/tasks.readonly"
	ScopeTasks                  = "https://www.googleapis.com/auth/tasks"
	ScopeGmailReadonly          = "https://www.googleapis.com/auth/gmail.readonly"
	ScopeGmailLabels            = "https://www.googleapis.com/auth/gmail.labels"
	ScopeGmailMetadata          = "https://www.googleapis.com/auth/gmail.metadata"
	ScopeGmailSend              = "https://www.googleapis.com/auth/gmail.send"
	ScopeGmailCompose           = "https://www.googleapis.com/auth/gmail.compose"
	ScopeGmailModify            = "https://www.googleapis.com/auth/gmail.modify"
	ScopeMail                   = "https://mail.google.com/"
)

// scopeImplies lists, per scope, the narrower scopes it covers (one
// level; Grants walks the closure). Taken from the methods' accepted
// scope lists in the Calendar, Tasks and Gmail API references.
var scopeImplies = map[string][]string{
	ScopeCalendar:         {ScopeCalendarEvents, ScopeCalendarReadonly},
	ScopeCalendarEvents:   {ScopeCalendarEventsReadonly},
	ScopeCalendarReadonly: {ScopeCalendarEventsReadonly},
	ScopeTasks:            {ScopeTasksReadonly},
	ScopeMail:             {ScopeGmailModify},
	ScopeGmailModify:      {ScopeGmailReadonly, ScopeGmailCompose, ScopeGmailLabels},
	ScopeGmailCompose:     {ScopeGmailSend},
	ScopeGmailReadonly:    {ScopeGmailLabels, ScopeGmailMetadata},
}

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
