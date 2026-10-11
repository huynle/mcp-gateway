package portal

import "errors"

// Helpers shared with the admin pages (internal/federation/admin), so both
// portals word failures and read credential forms the same way.

// SessionMessage is the user-facing, class-level text of a failure to open
// or use an upstream session (never upstream text).
func SessionMessage(err error) string { return sessionMessage(err) }

// ParseSecretHeaderLines reads "Name: value" lines of a shared or per-user
// header credential. A malformed line is an error whose message is safe
// to show (UserMessage; it never contains a header value).
func ParseSecretHeaderLines(s string) (map[string]string, error) { return parseHeaderLines(s, false) }

// UserMessage returns the display text of an error from this package's
// form validation (ParseSecretHeaderLines) and whether it is one.
func UserMessage(err error) (string, bool) {
	var ue *userError
	if errors.As(err, &ue) {
		return ue.msg, true
	}
	return "", false
}
