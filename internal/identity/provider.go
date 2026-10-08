package identity

import (
	"context"
	"net/http"
	"sync"

	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/huynle/mcp-gateway/internal/config"
)

// provider is one configured OIDC provider and its lazily discovered
// relying party.
type provider struct {
	cfg         config.OIDCProvider
	redirectURI string
	httpClient  *http.Client

	mu sync.Mutex
	rp rp.RelyingParty
}

func newProvider(cfg config.OIDCProvider, redirectURI string, httpClient *http.Client) *provider {
	return &provider{cfg: cfg, redirectURI: redirectURI, httpClient: httpClient}
}

type nonceKey struct{}

// withNonce stores the expected ID token nonce in ctx; the relying party's
// verifier reads it back during the code exchange.
func withNonce(ctx context.Context, nonce string) context.Context {
	return context.WithValue(ctx, nonceKey{}, nonce)
}

func nonceFrom(ctx context.Context) string {
	n, _ := ctx.Value(nonceKey{}).(string)
	return n
}

// relyingParty runs OIDC discovery on first use and caches the result; a
// failed discovery is retried on the next call.
func (p *provider) relyingParty(ctx context.Context) (rp.RelyingParty, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.rp != nil {
		return p.rp, nil
	}
	r, err := rp.NewRelyingPartyOIDC(ctx, p.cfg.Issuer, p.cfg.ClientID, p.cfg.ClientSecret, p.redirectURI,
		[]string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail},
		rp.WithHTTPClient(p.httpClient),
		rp.WithVerifierOpts(rp.WithNonce(nonceFrom)),
	)
	if err != nil {
		return nil, err
	}
	p.rp = r
	return r, nil
}
