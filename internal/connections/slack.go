package connections

import (
	"context"
	"errors"
	"strings"

	"github.com/huynle/mcp-gateway/internal/store"
)

// Slack connections are bound to the Slack user and the workspace (team)
// the token was issued for (decision mh7c6z3v: "Slack user + team"), as
// one external account ID "<team id>:<user id>". The Slack binder writes
// it; the approval notifier and /slack/interactions read it back through
// SlackIdentity.

// SlackAccountID formats the external account ID of a Slack connection.
func SlackAccountID(teamID, userID string) string { return teamID + ":" + userID }

// ParseSlackAccountID splits a Slack external account ID; ok is false
// when it is not of the form "<team id>:<user id>".
func ParseSlackAccountID(s string) (teamID, userID string, ok bool) {
	teamID, userID, ok = strings.Cut(s, ":")
	if !ok || teamID == "" || userID == "" || strings.Contains(userID, ":") {
		return "", "", false
	}
	return teamID, userID, true
}

// SlackIdentity is the Slack user and workspace a gateway user is
// connected as.
type SlackIdentity struct {
	UserID string
	TeamID string
}

// SlackIdentity returns the Slack user and team of userID's active,
// company-labelled Slack connection (decision s0p05diu: approval DMs only
// go to the company Slack the user connected). ok is false when there is
// none; err reports a store failure.
func (s *Service) SlackIdentity(ctx context.Context, userID string) (id SlackIdentity, ok bool, err error) {
	if userID == "" {
		return SlackIdentity{}, false, errors.New("connections: user is required")
	}
	list, err := s.Connections(ctx, userID)
	if err != nil {
		return SlackIdentity{}, false, err
	}
	for _, c := range list {
		if c.Vendor != VendorSlack || c.Label != store.AccountCompany || !c.Active() {
			continue
		}
		team, user, ok := ParseSlackAccountID(c.ExternalAccountID)
		if !ok {
			continue
		}
		return SlackIdentity{UserID: user, TeamID: team}, true, nil
	}
	return SlackIdentity{}, false, nil
}
