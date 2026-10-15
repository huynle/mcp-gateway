package connectors

import "context"

// AccessHint tells a harness, through "<app>.list_accounts", that an
// account cannot run some of the app's tools until the user grants more
// access on the portal: how many tools stay locked (never which scopes)
// and the page to grant them on. The zero value means nothing to say.
type AccessHint struct {
	// LockedTools counts the app's tools the user may see whose required
	// scopes the account has not granted.
	LockedTools int
	// GrantURL is the portal page where the user grants more access;
	// empty when the account lacks nothing.
	GrantURL string
}

// AccessHinter is the optional interface of an AccountSource that knows
// which tools an account's grant leaves locked (connections.Service).
// ListAccountsTool asks it per account; a failure leaves the account
// without a hint, because list_accounts must keep working.
type AccessHinter interface {
	AccessHint(ctx context.Context, userID string, acct Account) (AccessHint, error)
}
