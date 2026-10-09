package oauthattack

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/oauthex"
)

// Resource indicators and audience confusion (RFC 8707, RFC 9728, RFC
// 9700 section 4.9 "audience restriction", MCP spec "Token Audience
// Binding and Validation"): the authorization server only issues tokens
// for its own MCP endpoint, and /mcp only accepts tokens issued for it.
// A decoy is a second gateway on another origin (another issuer and
// resource); with shared keys it models a second resource of the same
// authorization server, with its own keys a foreign authorization server.

// TestResourceParameter: resource is required at authorize and must name
// this gateway's MCP endpoint; the token request may repeat it but must
// not name anything else.
func TestResourceParameter(t *testing.T) {
	g := newGateway(t)
	d := g.newDecoy(t, true)
	br := g.browser(t, true)
	c := g.register(t, "https://app.example.com/cb")

	authorizeCases := map[string]string{
		"missing":         "",
		"decoy":           d.resource,
		"issuer_only":     g.base,
		"trailing_slash":  g.resource + "/",
		"other_path":      g.base + "/other-mcp",
		"path_prefix":     g.resource + "/sub",
		"with_query":      g.resource + "?x=1",
		"with_fragment":   g.resource + "#x",
		"with_userinfo":   strings.Replace(g.resource, "://", "://alice@", 1),
		"other_scheme":    strings.Replace(g.resource, "http://", "https://", 1),
		"no_scheme":       strings.TrimPrefix(g.resource, "http://"),
		"lookalike_host":  strings.Replace(g.resource, "127.0.0.1", "127.0.0.1.evil.example", 1),
		"two_values":      "", // set below
		"decoy_then_ours": "", // set below
	}
	for name, resource := range authorizeCases {
		t.Run("authorize_"+name, func(t *testing.T) {
			state := nonce(t)
			q := g.authorizeParams(c, newPKCE(t), state)
			switch name {
			case "missing":
				q.Del("resource")
			case "two_values":
				q["resource"] = []string{d.resource, g.resource}
			case "decoy_then_ours":
				q["resource"] = []string{g.resource, d.resource}
			default:
				q.Set("resource", resource)
			}
			loc := wantRedirectError(t, g.authorize(t, br, q), c.redirect, "invalid_target", state)
			if !strings.Contains(loc.Query().Get("error_description"), g.resource) {
				t.Errorf("description %q does not name the canonical resource", loc.Query().Get("error_description"))
			}
			rec := wantLogEvent(t, g, "authserver.authorize_rejected")
			if rec.Attrs["error"] != "invalid_target" {
				t.Errorf("log = %v", rec.Attrs)
			}
			wantRedirectError(t, g.consent(t, br, q, "approve"), c.redirect, "invalid_target", state)
			if len(g.astore.Codes()) != 0 {
				t.Fatal("a code was issued for a foreign resource")
			}
		})
	}
	t.Run("authorize_uppercase_scheme_and_host_accepted", func(t *testing.T) {
		// RFC 8707 section 2 / MCP spec: scheme and host compare
		// case-insensitively; the token is still bound to the canonical form.
		u, _ := url.Parse(g.resource)
		q := g.authorizeParams(c, newPKCE(t), "s")
		q.Set("resource", "HTTP://"+strings.ToUpper(u.Host)+u.Path)
		r := g.authorize(t, br, q)
		if r.status != http.StatusOK || !strings.Contains(string(r.body), g.resource) {
			t.Fatalf("authorize with upper-case scheme/host: %d %s", r.status, r.body)
		}
	})

	tokenCases := map[string]string{
		"decoy":          d.resource,
		"trailing_slash": g.resource + "/",
		"issuer_only":    g.base,
		"other_path":     g.base + "/other-mcp",
	}
	for name, resource := range tokenCases {
		t.Run("token_"+name, func(t *testing.T) {
			p := newPKCE(t)
			code := g.code(t, br, c, p, nonce(t))
			form := g.exchangeForm(c, code, p)
			form.Set("resource", resource)
			desc := wantOAuthError(t, g.token(t, form), http.StatusBadRequest, "invalid_target")
			if !strings.Contains(desc, g.resource) {
				t.Errorf("description = %q", desc)
			}
			// The mismatch burned the code (it was consumed before the check).
			wantOAuthError(t, g.token(t, g.exchangeForm(c, code, p)), http.StatusBadRequest, "invalid_grant")
		})
	}
	t.Run("token_resource_omitted_is_bound_anyway", func(t *testing.T) {
		p := newPKCE(t)
		code := g.code(t, br, c, p, nonce(t))
		form := g.exchangeForm(c, code, p)
		form.Del("resource")
		r := g.token(t, form)
		if r.status != http.StatusOK {
			t.Fatalf("exchange without resource: %d %s", r.status, r.body)
		}
		claims := decodeClaims(t, r.json()["access_token"].(string))
		if aud, _ := claims["aud"].(string); aud != g.resource {
			t.Errorf("aud = %v, want %s", claims["aud"], g.resource)
		}
	})
	t.Run("refresh_resource_mismatch", func(t *testing.T) {
		pair := g.issue(t, br, c)
		wantOAuthError(t, g.refresh(t, c, pair.refresh, "resource", d.resource), http.StatusBadRequest, "invalid_target")
		// Not a reuse: the refresh token was not rotated by the refused request.
		if r := g.refresh(t, c, pair.refresh, "resource", g.resource); r.status != http.StatusOK {
			t.Errorf("refresh after a refused resource: %d %s", r.status, r.body)
		}
	})
}

// TestAudienceConfusion: tokens that are valid somewhere else are not
// valid here. Each is signed correctly and rejected by /mcp with 401
// invalid_token, the resource metadata challenge and a logged reason.
func TestAudienceConfusion(t *testing.T) {
	g := newGateway(t)
	sameKeys := g.newDecoy(t, true)
	ownKeys := g.newDecoy(t, false)
	ctx := context.Background()

	t.Run("decoy_resource_same_issuer_same_keys", func(t *testing.T) {
		// The AS itself minting for another of its resources.
		cfg := g.cfg
		cfg.ResourcePath = "/other-mcp"
		grant := g.grant()
		grant.Resource = cfg.Resource()
		tok := g.mintWith(t, cfg, g.clock.Now(), grant)
		wantMCPUnauthorized(t, g, g.mcpCall(t, tok))
		wantAuthFailed(t, g, "wrong_audience")
	})
	t.Run("decoy_issuer_same_keys", func(t *testing.T) {
		// A sibling gateway sharing the signing keys (same signing_keys
		// table) mints for its own origin: both iss and aud differ.
		c := sameKeys.register(t, "https://app.example.com/cb")
		tok := sameKeys.mint(t, g, c)
		wantMCPUnauthorized(t, g, g.mcpCall(t, tok))
		rec := wantLogEvent(t, g, "authserver.auth_failed")
		if d := rec.Attrs["detail"]; d != "wrong_audience" && d != "wrong_issuer" {
			t.Errorf("detail = %q", d)
		}
		// And the decoy's own /mcp-side authenticator rejects ours.
		mine := g.mintWith(t, g.cfg, g.clock.Now(), g.grant())
		if _, err := sameKeys.svc.Authenticator().Authenticate(ctx, mine); err == nil {
			t.Error("the decoy accepted a token minted for this gateway")
		}
	})
	t.Run("decoy_issuer_same_keys_but_our_audience", func(t *testing.T) {
		// Same keys, aud = our resource, iss = the decoy: the issuer check
		// alone must refuse it.
		cfg := sameKeys.svc.Config()
		tok := g.mintWith(t, cfg, g.clock.Now(), g.grant())
		wantMCPUnauthorized(t, g, g.mcpCall(t, tok))
		wantAuthFailed(t, g, "wrong_issuer")
	})
	t.Run("foreign_issuer_own_keys", func(t *testing.T) {
		// A foreign authorization server with its own keys claims our
		// issuer and audience: unknown kid, never a signature check that
		// could pass.
		m := ownKeys.svc
		grant := g.grant()
		cfg := g.cfg // iss and aud = ours
		tok := mintOver(t, cfg, m, grant)
		wantMCPUnauthorized(t, g, g.mcpCall(t, tok))
		wantAuthFailed(t, g, "unknown_kid")
	})
	t.Run("decoy_metadata_not_accepted_for_our_resource", func(t *testing.T) {
		// A client that is pointed at the decoy's protected resource
		// metadata while intending to use our resource must notice: the
		// document names the decoy's resource (RFC 9728 section 3.3), and
		// the SDK refuses it. Our own document matches.
		if _, err := oauthex.GetProtectedResourceMetadata(ctx, sameKeys.base+"/.well-known/oauth-protected-resource", g.resource, http.DefaultClient); err == nil {
			t.Error("decoy PRM accepted for our resource")
		}
		prm, err := oauthex.GetProtectedResourceMetadata(ctx, g.base+"/.well-known/oauth-protected-resource", g.resource, http.DefaultClient)
		if err != nil || len(prm.AuthorizationServers) != 1 || prm.AuthorizationServers[0] != g.base {
			t.Fatalf("own PRM: %+v %v", prm, err)
		}
		// The decoy's AS metadata names the decoy as issuer, never us.
		meta := get(t, noRedirect, sameKeys.base+"/.well-known/oauth-authorization-server").json()
		if meta["issuer"] != sameKeys.base || meta["token_endpoint"] == g.base+"/oauth/token" {
			t.Errorf("decoy AS metadata = %v", meta)
		}
	})
	t.Run("code_from_decoy_at_our_token_endpoint", func(t *testing.T) {
		// A code issued by the decoy (same store, so the hash is findable)
		// is for the decoy's client row; our token endpoint does not know
		// that client id (separate registration) -> invalid_client; and
		// even a client registered at both cannot cross: the resource bound
		// to the code is the decoy's.
		c := sameKeys.register(t, "https://app.example.com/cb")
		p := newPKCE(t)
		code := sameKeys.code(t, g, c, p)
		form := g.exchangeForm(c, code, p)
		wantOAuthError(t, g.token(t, form), http.StatusBadRequest, "invalid_target")
		// Without the resource parameter the exchange goes through (the
		// code's own binding wins) but the token is for the decoy: /mcp
		// refuses it.
		code = sameKeys.code(t, g, c, p)
		form = g.exchangeForm(c, code, p)
		form.Del("resource")
		r := g.token(t, form)
		if r.status != http.StatusOK {
			t.Fatalf("exchange of a decoy code without resource: %d %s", r.status, r.body)
		}
		tok := r.json()["access_token"].(string)
		if aud, _ := decodeClaims(t, tok)["aud"].(string); aud != sameKeys.resource {
			t.Errorf("aud = %q, want the decoy's resource", aud)
		}
		wantMCPUnauthorized(t, g, g.mcpCall(t, tok))
		wantAuthFailed(t, g, "wrong_audience")
	})
	t.Run("token_for_us_presented_to_decoy_resource", func(t *testing.T) {
		mine := g.mintWith(t, g.cfg, g.clock.Now(), g.grant())
		if _, err := ownKeys.svc.Authenticator().Authenticate(ctx, mine); err == nil {
			t.Error("a foreign resource server with other keys accepted our token")
		}
	})
}

// decodeClaims returns the JWT body without verifying it (test only).
func decodeClaims(t *testing.T, raw string) map[string]any {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWS: %q", raw)
	}
	return decodeSegment(t, parts[1])
}
