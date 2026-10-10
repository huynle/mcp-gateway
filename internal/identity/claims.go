package identity

import (
	"strings"

	"github.com/huynle/mcp-gateway/internal/config"
)

// Claims is what the gateway reads from a verified ID token. Identity is
// Issuer+Subject (decision uamxx6ba); everything else is advisory.
type Claims struct {
	Issuer        string
	Subject       string
	Name          string
	Email         string
	EmailVerified bool
	// Extra holds the remaining claims (hd, tid, custom domain claims).
	Extra map[string]any
}

// displayName picks a human label for the user: name, else the local part
// of the email, else the subject.
func (c Claims) displayName() string {
	if n := strings.TrimSpace(c.Name); n != "" {
		return n
	}
	if local, _, ok := strings.Cut(c.Email, "@"); ok && local != "" {
		return local
	}
	return c.Subject
}

func (c Claims) extraString(key string) string {
	v, _ := c.Extra[key].(string)
	return strings.TrimSpace(v)
}

// Rejection reasons, logged as the "reason" attribute of
// identity.signin_rejected events.
const (
	reasonIssuerMismatch   = "issuer_mismatch"
	reasonNoSubject        = "no_subject"
	reasonTenantNotAllowed = "tenant_not_allowed"
	reasonDomainNotAllowed = "domain_not_allowed"
	reasonNoDomain         = "no_domain_claim"
)

// allow decides whether claims from provider p may sign in. It returns the
// rejection reason, or "" when allowed.
//
// Tenants (Entra "tid") and hosted domains are alternatives: matching either
// configured list admits the user. The domain is read from DomainClaim when
// set ("email" meaning the email's domain regardless of verification),
// otherwise from "hd" (Google Workspace) and, failing that, from a verified
// email address.
func allow(p config.OIDCProvider, c Claims) string {
	if c.Issuer != p.Issuer {
		return reasonIssuerMismatch
	}
	if strings.TrimSpace(c.Subject) == "" {
		return reasonNoSubject
	}
	if len(p.AllowedTenants) > 0 {
		if tid := c.extraString("tid"); tid != "" && contains(p.AllowedTenants, tid) {
			return ""
		}
		if len(p.AllowedDomains) == 0 {
			return reasonTenantNotAllowed
		}
	}
	domain := domainOf(p, c)
	if domain == "" {
		return reasonNoDomain
	}
	if !contains(p.AllowedDomains, domain) {
		return reasonDomainNotAllowed
	}
	return ""
}

func domainOf(p config.OIDCProvider, c Claims) string {
	switch p.DomainClaim {
	case "":
		if hd := c.extraString("hd"); hd != "" {
			return strings.ToLower(hd)
		}
		if c.EmailVerified {
			return emailDomain(c.Email)
		}
		return ""
	case "email":
		return emailDomain(c.Email)
	default:
		return strings.ToLower(c.extraString(p.DomainClaim))
	}
}

func emailDomain(email string) string {
	_, domain, ok := strings.Cut(email, "@")
	if !ok {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(domain))
}

func contains(list []string, v string) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}
