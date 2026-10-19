package portal

import (
	"errors"
	"fmt"
	"github.com/huynle/mcp-gateway/internal/clientinstall"
	"net/http"
	"net/mail"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/huynle/mcp-gateway/internal/identity"
)

// The operator-configurable values of the public pages (homepage, privacy
// policy, terms of service, support). Every one has a safe placeholder, so
// the pages render on a fresh deployment; the draft marker is on until the
// operator turns it off after legal review (docs/public-launch.md).
const (
	EnvLegalOperatorName  = "GATEWAY_LEGAL_OPERATOR_NAME"
	EnvLegalContactEmail  = "GATEWAY_LEGAL_CONTACT_EMAIL"
	EnvLegalJurisdiction  = "GATEWAY_LEGAL_JURISDICTION"
	EnvLegalEffectiveDate = "GATEWAY_LEGAL_EFFECTIVE_DATE"
	EnvLegalDraft         = "GATEWAY_LEGAL_DRAFT"
)

// legalDateLayout is the GATEWAY_LEGAL_EFFECTIVE_DATE format (ISO 8601).
const legalDateLayout = "2006-01-02"

// maxLegalText bounds the free-text values (operator name, jurisdiction).
const maxLegalText = 200

// Legal is what the public pages show about the operator.
type Legal struct {
	// OperatorName is the person or organisation running this gateway (the
	// data controller in the privacy policy).
	OperatorName string
	// ContactEmail is the privacy and support address (a bare address).
	ContactEmail string
	// Jurisdiction is the governing law named in the terms.
	Jurisdiction string
	// EffectiveDate is when the current texts took effect (zero: unset).
	EffectiveDate time.Time
	// Draft shows the "Draft – pending review" marker on the legal texts.
	Draft bool
}

// DefaultLegal is the configuration without any GATEWAY_LEGAL_* variable:
// placeholders everywhere and the draft marker on.
func DefaultLegal() Legal { return Legal{Draft: true} }

// LegalFromEnv reads the GATEWAY_LEGAL_* variables through getenv (unset =
// ""). Invalid values are errors naming the variable, so startup fails
// instead of publishing a broken contact link or date.
func LegalFromEnv(getenv func(string) string) (Legal, error) {
	l := DefaultLegal()
	var errs []error
	var err error
	if l.OperatorName, err = legalText(EnvLegalOperatorName, getenv(EnvLegalOperatorName)); err != nil {
		errs = append(errs, err)
	}
	if l.Jurisdiction, err = legalText(EnvLegalJurisdiction, getenv(EnvLegalJurisdiction)); err != nil {
		errs = append(errs, err)
	}
	if v := strings.TrimSpace(getenv(EnvLegalContactEmail)); v != "" {
		a, perr := mail.ParseAddress(v)
		if perr != nil || a.Name != "" || a.Address != v || len(v) > 254 {
			errs = append(errs, fmt.Errorf("%s must be a bare email address such as privacy@example.com", EnvLegalContactEmail))
		} else {
			l.ContactEmail = v
		}
	}
	if v := strings.TrimSpace(getenv(EnvLegalEffectiveDate)); v != "" {
		d, perr := time.Parse(legalDateLayout, v)
		if perr != nil {
			errs = append(errs, fmt.Errorf("%s must be a date as YYYY-MM-DD, got %q", EnvLegalEffectiveDate, v))
		}
		l.EffectiveDate = d
	}
	if v := strings.TrimSpace(getenv(EnvLegalDraft)); v != "" {
		b, perr := strconv.ParseBool(v)
		if perr != nil {
			errs = append(errs, fmt.Errorf("%s must be true or false, got %q", EnvLegalDraft, v))
		}
		l.Draft = b
	}
	if len(errs) > 0 {
		return Legal{}, errors.Join(errs...)
	}
	return l, nil
}

// legalText trims a free-text value and rejects control characters and
// overlong values.
func legalText(name, v string) (string, error) {
	v = strings.TrimSpace(v)
	if len(v) > maxLegalText {
		return "", fmt.Errorf("%s must be at most %d characters", name, maxLegalText)
	}
	if strings.IndexFunc(v, unicode.IsControl) >= 0 {
		return "", fmt.Errorf("%s must not contain control characters", name)
	}
	return v, nil
}

// Placeholders lists the variables still unset, in display order; the
// gateway logs them at startup so a placeholder never goes live unnoticed.
func (l Legal) Placeholders() []string {
	var out []string
	if l.OperatorName == "" {
		out = append(out, EnvLegalOperatorName)
	}
	if l.ContactEmail == "" {
		out = append(out, EnvLegalContactEmail)
	}
	if l.Jurisdiction == "" {
		out = append(out, EnvLegalJurisdiction)
	}
	if l.EffectiveDate.IsZero() {
		out = append(out, EnvLegalEffectiveDate)
	}
	return out
}

// OperatorDisplay is the operator name or its placeholder.
func (l Legal) OperatorDisplay() string { return orPlaceholder(l.OperatorName, "[operator name]") }

// ContactDisplay is the contact address or its placeholder.
func (l Legal) ContactDisplay() string { return orPlaceholder(l.ContactEmail, "[contact email]") }

// ContactMailto is the mailto: URL of the contact address ("" when unset,
// so the templates render the placeholder as plain text).
func (l Legal) ContactMailto() string {
	if l.ContactEmail == "" {
		return ""
	}
	return "mailto:" + l.ContactEmail
}

// JurisdictionDisplay is the governing law or its placeholder.
func (l Legal) JurisdictionDisplay() string {
	return orPlaceholder(l.Jurisdiction, "[jurisdiction]")
}

// EffectiveDisplay is the effective date ("18 October 2026") or its
// placeholder.
func (l Legal) EffectiveDisplay() string {
	if l.EffectiveDate.IsZero() {
		return "[effective date]"
	}
	return l.EffectiveDate.Format("2 January 2006")
}

func orPlaceholder(v, placeholder string) string {
	if v == "" {
		return placeholder
	}
	return v
}

// SetLegal replaces the operator values the public pages show (default:
// DefaultLegal). Call before Handler.
func (p *Portal) SetLegal(l Legal) { p.legal = l }

// publicData is what the public pages render.
type publicData struct {
	Legal     Legal
	Providers []signInProvider
	// Install is the CLI install commands (homepage only).
	Install []clientinstall.Command
}

// installScript sends `curl -fsSL <gateway>/install | sh` to the install
// script of the latest GitHub release (curl -L follows the redirect). The
// script verifies each archive against the release's checksums.txt.
func installScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=300")
	http.Redirect(w, r, clientinstall.InstallScriptURL, http.StatusFound)
}

// publicPage serves one of the public pages (privacy, terms, support) to
// anyone, signed in or not.
func (p *Portal) publicPage(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		publicCaching(w, r)
		p.render(w, r, http.StatusOK, name, publicData{Legal: p.legal})
	}
}

// publicCaching: anonymous copies of the public pages may be cached for a
// few minutes (they are the same for every visitor); a signed-in copy
// carries the user's nav and CSRF token and is never stored. Vary: Cookie
// keeps a shared cache from serving one for the other.
func publicCaching(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Vary", "Cookie")
	if identity.PrincipalFrom(r.Context()) != nil {
		w.Header().Set("Cache-Control", "no-store")
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
}
