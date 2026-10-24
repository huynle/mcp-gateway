package main

import (
	"log/slog"
	"net/http"
	"net/url"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/federation/connector"
	"github.com/huynle/mcp-gateway/internal/federation/elicit"
	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/jobs"
	"github.com/huynle/mcp-gateway/internal/secrets"
	"github.com/huynle/mcp-gateway/internal/store"
)

// The upstream URL elicitation relay (GATEWAY_UPSTREAM_ELICITATION_ENABLED,
// plan 2 of docs/plans/2026-10-23-credential-links-and-elicitation-relay-design.md;
// docs/elicitation.md): newFederation reads the flag and connector.Wire
// builds the elicitation service (fed.Elicit) the Manager relays through.
// This file mounts the /elicit interstitial and adds the expiry job.

// withElicitPages mounts GET/POST /elicit/{id} behind the portal's
// sign-in and CSRF checks, with the portal's own 404 for unknown or
// foreign links, the per-address limit on failed lookups (the secrets
// entry page's), the server and harness names as the owner sees them, the
// relay's URL rules for the domain shown, and audit rows through rec.
// Nothing is mounted without the relay.
func withElicitPages(fed *connector.Federation, st *store.Store, rec audit.Recorder) portalExtra {
	return func(_ *identity.Service, mount func(string, http.Handler), session func(*http.Request) (string, string), log *slog.Logger, notFound http.Handler) {
		if fed == nil || fed.Elicit == nil {
			return
		}
		elicit.NewPortal(fed.Elicit, session, elicit.PortalOptions{
			Log:            log,
			Servers:        elicit.ServerNamerFunc(serverNamer(st)),
			Harnesses:      elicit.HarnessNamerFunc(harnessNamer(st)),
			Domain:         elicitDomain,
			Audit:          rec,
			NotFound:       notFound,
			FailureLimiter: secrets.NewAddressLimiter(secrets.EntryFailureBurst, secrets.EntryFailureWindow, nil),
		}).Mount(mount)
	}
}

// elicitJobs is the relay's expiry job (deletes rows long expired).
func elicitJobs(fed *connector.Federation) []jobs.Job {
	if fed == nil || fed.Elicit == nil {
		return nil
	}
	return []jobs.Job{fed.Elicit.ExpiryJob(0)}
}

// elicitDomain describes a stored elicitation URL for the interstitial with
// the relay's own URL rules (elicit.Rules: ASCII host, eTLD+1 from the
// public suffix list, punycode labels). A stored URL already passed them;
// one that no longer parses shows its raw host as its own domain, flagged.
func elicitDomain(raw string) (host, registrable string, punycode bool) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", true
	}
	c, err := elicit.Rules{AllowedOrigins: []string{"https://" + u.Host}}.Check(raw)
	if err != nil {
		return u.Hostname(), u.Hostname(), true
	}
	return c.Host, c.RegistrableDomain, c.Punycode
}
