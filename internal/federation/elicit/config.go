// Package elicit holds the URL elicitation features of the federation
// (docs/plans/2026-10-23-credential-links-and-elicitation-relay-design.md):
// the flags of credential links (plan 1) and of the upstream URL
// elicitation relay (plan 2): the relay's storage (Service over
// upstream_elicitations, migration 00032), its URL rules and the /elicit
// interstitial page (Portal). It has no HTTP client, so the rawhttpcheck
// lint guarantees the gateway never pre-fetches an upstream URL. It imports
// only low-level gateway packages (store, audit, observability, the portal
// shell), so the connector, the account stage and the wiring can all use
// it.
package elicit

import (
	"fmt"
	"strconv"
	"strings"
)

// Environment variables, both default off.
const (
	// EnvCredentialLinks turns credential problems the caller can fix
	// (no connection, sign-in needed, rejected per-user credential; for
	// the owner, a missing shared credential) into -32042 answers with a
	// link to the connection page. Classes do not change.
	EnvCredentialLinks = "GATEWAY_CREDENTIAL_LINKS_ENABLED"
	// EnvUpstreamElicitation lets per-user upstream servers send the user
	// to their own page (MCP URL-mode elicitation) through the gateway's
	// /elicit interstitial.
	EnvUpstreamElicitation = "GATEWAY_UPSTREAM_ELICITATION_ENABLED"
)

// Config is the feature configuration.
type Config struct {
	// CredentialLinks is EnvCredentialLinks.
	CredentialLinks bool
	// UpstreamElicitation is EnvUpstreamElicitation.
	UpstreamElicitation bool
}

// ConfigFromEnv reads both variables through getenv (typically
// os.Getenv). An empty or blank value is off; anything strconv.ParseBool
// does not accept is an error naming the variable.
func ConfigFromEnv(getenv func(string) string) (Config, error) {
	var cfg Config
	for _, f := range []struct {
		name string
		dst  *bool
	}{
		{EnvCredentialLinks, &cfg.CredentialLinks},
		{EnvUpstreamElicitation, &cfg.UpstreamElicitation},
	} {
		v := strings.TrimSpace(getenv(f.name))
		if v == "" {
			continue
		}
		b, err := strconv.ParseBool(v)
		if err != nil {
			return Config{}, fmt.Errorf("%s: %w", f.name, err)
		}
		*f.dst = b
	}
	return cfg, nil
}
