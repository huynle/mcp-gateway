//go:build integration

package main

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/federation/connector"
	"github.com/huynle/mcp-gateway/internal/federation/elicit"
	"github.com/huynle/mcp-gateway/internal/observability"
)

// newFederation reads GATEWAY_CREDENTIAL_LINKS_ENABLED: a value that is
// not a boolean stops startup naming the variable; a valid one reaches
// the connector's WireOptions.
func TestIntegrationFederationCredentialLinksFlag(t *testing.T) {
	st := openFederationStore(t)
	log := slog.New(slog.DiscardHandler)
	cfg := config.Default()
	cfg.BaseURL = "http://gateway.test"
	keys, err := crypto.NewStaticProvider("k1", map[string][]byte{"k1": bytes.Repeat([]byte{5}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	saved := getenv
	t.Cleanup(func() { getenv = saved })
	env := map[string]string{}
	getenv = func(k string) string { return env[k] }

	env[elicit.EnvCredentialLinks] = "maybe"
	if _, err := newFederation(t.Context(), cfg, st, keys, connectors.NewRegistry(), nil, nil, observability.NewMetrics(), log); err == nil ||
		!strings.Contains(err.Error(), elicit.EnvCredentialLinks) {
		t.Fatalf("invalid flag = %v, want an error naming %s", err, elicit.EnvCredentialLinks)
	}
	for v, want := range map[string]bool{"": false, "true": true, "0": false} {
		env[elicit.EnvCredentialLinks] = v
		var got bool
		fed, err := newFederation(t.Context(), cfg, st, keys, connectors.NewRegistry(), nil, nil, observability.NewMetrics(), log,
			func(o *connector.WireOptions) { got = o.CredentialLinks })
		if err != nil || fed == nil {
			t.Fatalf("%q: newFederation = %v, %v", v, fed, err)
		}
		if got != want {
			t.Errorf("%q: WireOptions.CredentialLinks = %v, want %v", v, got, want)
		}
	}
}

// newFederation reads GATEWAY_UPSTREAM_ELICITATION_ENABLED: an invalid
// value stops startup; on, the federation has the elicitation service
// (the relay, the /elicit pages and the expiry job); off, none of them.
func TestIntegrationFederationUpstreamElicitationFlag(t *testing.T) {
	st := openFederationStore(t)
	log := slog.New(slog.DiscardHandler)
	cfg := config.Default()
	cfg.BaseURL = "http://gateway.test"
	keys, err := crypto.NewStaticProvider("k1", map[string][]byte{"k1": bytes.Repeat([]byte{5}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	saved := getenv
	t.Cleanup(func() { getenv = saved })
	env := map[string]string{}
	getenv = func(k string) string { return env[k] }

	env[elicit.EnvUpstreamElicitation] = "perhaps"
	if _, err := newFederation(t.Context(), cfg, st, keys, connectors.NewRegistry(), nil, nil, observability.NewMetrics(), log); err == nil ||
		!strings.Contains(err.Error(), elicit.EnvUpstreamElicitation) {
		t.Fatalf("invalid flag = %v, want an error naming %s", err, elicit.EnvUpstreamElicitation)
	}
	for v, want := range map[string]bool{"": false, "true": true, "false": false} {
		env[elicit.EnvUpstreamElicitation] = v
		var got bool
		fed, err := newFederation(t.Context(), cfg, st, keys, connectors.NewRegistry(), nil, nil, observability.NewMetrics(), log,
			func(o *connector.WireOptions) { got = o.UpstreamElicitation })
		if err != nil || fed == nil {
			t.Fatalf("%q: newFederation = %v, %v", v, fed, err)
		}
		if got != want || (fed.Elicit != nil) != want || (len(elicitJobs(fed)) == 1) != want {
			t.Errorf("%q: UpstreamElicitation = %v, service %v, jobs %d; want %v", v, got, fed.Elicit != nil, len(elicitJobs(fed)), want)
		}
	}
}
