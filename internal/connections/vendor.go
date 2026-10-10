package connections

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/huynle/mcp-gateway/internal/store"
)

// Vendors the gateway connects to (decision mh7c6z3v). Fake is the
// httptest vendor the tests and the local fake connector use; the
// vendor_apps CHECK constraint allows the same six values.
const (
	VendorGitHub    = "github"
	VendorSlack     = "slack"
	VendorAtlassian = "atlassian"
	VendorGoogle    = "google"
	VendorMicrosoft = "microsoft"
	VendorFake      = "fake"
)

// Vendors lists the real vendors in the order the admin page shows them.
var Vendors = []string{VendorGitHub, VendorSlack, VendorAtlassian, VendorGoogle, VendorMicrosoft}

// DefaultVariant is the variant name of vendors that have one registered
// app. Google has two (decision mh7c6z3v): "internal" (the Workspace
// client for company accounts) and "external" (the published-unverified
// app for personal accounts).
const DefaultVariant = "default"

// Google's two variants.
const (
	GoogleInternal = "internal"
	GoogleExternal = "external"
)

// Variants returns the variant names a vendor supports.
func Variants(vendor string) []string {
	if vendor == VendorGoogle {
		return []string{GoogleInternal, GoogleExternal}
	}
	return []string{DefaultVariant}
}

// KnownVendor reports whether vendor is one of the six.
func KnownVendor(vendor string) bool {
	return vendor == VendorFake || slices.Contains(Vendors, vendor)
}

// VendorApp is one admin-registered OAuth app at a vendor (the vendor_apps
// row). ClientSecret is write-only: set it to replace the stored secret;
// reads leave it empty and report HasSecret. AuthURL and TokenURL are the
// vendor's OAuth 2.0 endpoints; UserInfoURL is what the GenericBinder
// fetches to identify the account; RevokeURL is optional (best-effort
// revocation on disconnect). Scopes are the base scopes every connection
// requests (identity scopes; tools add theirs incrementally). Extra holds
// additional authorization parameters (access_type=offline, prompt=consent,
// audience=...) and the binder hints below.
type VendorApp struct {
	ID           string
	Vendor       string
	Variant      string
	ClientID     string
	ClientSecret string
	HasSecret    bool
	// Secrets are the vendor's extra secrets (ExtraSecretKeys; for Slack
	// the bot token and the signing secret), write-only like ClientSecret:
	// a non-empty value replaces the stored one, an empty or absent key
	// keeps it. Reads leave it empty and list the stored keys in
	// SecretKeys. Service.VendorSecrets returns the values.
	Secrets     map[string]string
	SecretKeys  []string
	AuthURL     string
	TokenURL    string
	UserInfoURL string
	RevokeURL   string
	Scopes      []string
	Extra       map[string]string
	Enabled     bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Extra keys the flow and the GenericBinder understand. Anything else in
// Extra is sent as an authorization request parameter.
const (
	// ExtraScopeParam renames the scope query parameter (Slack user tokens
	// use user_scope).
	ExtraScopeParam = "scope_param"
	// ExtraCompanyDomains lists the email domains (comma separated) whose
	// accounts are company accounts; others are personal.
	ExtraCompanyDomains = "company_domains"
	// ExtraDefaultLabel is the label when no domain rule decides
	// (company|personal); unset means personal unless the variant is
	// Google internal.
	ExtraDefaultLabel = "default_label"
	// ExtraIDField, ExtraNameField and ExtraEmailField name the userinfo
	// JSON fields the GenericBinder reads (defaults: id|sub, name|login,
	// email).
	ExtraIDField    = "id_field"
	ExtraNameField  = "name_field"
	ExtraEmailField = "email_field"
	// ExtraCompanyOrgs lists the organizations (comma separated) whose
	// members get company accounts; read by the GitHub binder.
	ExtraCompanyOrgs = "company_orgs"
	// ExtraCompanySites lists the Atlassian sites (comma separated) whose
	// accounts are company accounts; read by the Atlassian binder.
	ExtraCompanySites = "company_sites"
	// ExtraCompanyTenants lists the Entra tenant ids (comma separated)
	// whose accounts are company accounts; read by the Microsoft binder.
	ExtraCompanyTenants = "company_tenants"
	// ExtraCompanyTeamID and ExtraCompanyTeamDomain name the company
	// Slack workspace (team id, or the "acme" of acme.slack.com); read by
	// the Slack binder.
	ExtraCompanyTeamID     = "company_team_id"
	ExtraCompanyTeamDomain = "company_team_domain"
	// ExtraMarkerReconcile ("true") opts the Slack message writes into
	// marker reconciliation; read by cmd/gateway at start-up.
	ExtraMarkerReconcile = "marker_reconcile"
)

// reservedExtra are the Extra keys the gateway consumes itself (flow
// settings and binder hints); they are never sent as authorization
// request parameters (quirk sxbr5or5). A binder that reads a new hint
// from Extra adds its key here; TestAuthParamsExcludeEveryReservedKey
// walks every connector's Extra constants against this map.
var reservedExtra = map[string]bool{
	ExtraScopeParam: true, ExtraCompanyDomains: true, ExtraDefaultLabel: true,
	ExtraIDField: true, ExtraNameField: true, ExtraEmailField: true,
	ExtraCompanyOrgs: true, ExtraCompanySites: true, ExtraCompanyTenants: true,
	ExtraCompanyTeamID: true, ExtraCompanyTeamDomain: true, ExtraMarkerReconcile: true,
}

// AuthParams returns the Extra entries that are sent as authorization
// request parameters, sorted by key.
func (a VendorApp) AuthParams() [][2]string {
	var out [][2]string
	for k, v := range a.Extra {
		if reservedExtra[k] || k == "" {
			continue
		}
		out = append(out, [2]string{k, v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i][0] < out[j][0] })
	return out
}

// Key is "vendor" or "vendor/variant" for Google: the path segment(s) the
// admin pages use.
func (a VendorApp) Key() string {
	if a.Vendor == VendorGoogle {
		return a.Vendor + "/" + a.Variant
	}
	return a.Vendor
}

// Defaults returns the vendor's documented endpoints and base scopes
// (docs/vendor-apps.md) so the admin editor starts filled in. Unknown
// vendors (and fake) have none.
func Defaults(vendor, variant string) VendorApp {
	a := VendorApp{Vendor: vendor, Variant: variant, Enabled: true, Extra: map[string]string{}}
	switch vendor {
	case VendorGitHub:
		a.AuthURL = "https://github.com/login/oauth/authorize"
		a.TokenURL = "https://github.com/login/oauth/access_token"
		a.UserInfoURL = "https://api.github.com/user"
		a.Extra[ExtraNameField] = "login"
	case VendorSlack:
		a.AuthURL = "https://slack.com/oauth/v2/authorize"
		a.TokenURL = "https://slack.com/api/oauth.v2.access"
		a.RevokeURL = "https://slack.com/api/auth.revoke"
		a.Extra[ExtraScopeParam] = "user_scope"
	case VendorAtlassian:
		a.AuthURL = "https://auth.atlassian.com/authorize"
		a.TokenURL = "https://auth.atlassian.com/oauth/token"
		a.UserInfoURL = "https://api.atlassian.com/me"
		a.Scopes = []string{"offline_access"}
		a.Extra["audience"] = "api.atlassian.com"
		a.Extra["prompt"] = "consent"
		a.Extra[ExtraIDField] = "account_id"
	case VendorGoogle:
		a.AuthURL = "https://accounts.google.com/o/oauth2/v2/auth"
		a.TokenURL = "https://oauth2.googleapis.com/token"
		a.UserInfoURL = "https://openidconnect.googleapis.com/v1/userinfo"
		a.RevokeURL = "https://oauth2.googleapis.com/revoke"
		a.Scopes = []string{"openid", "https://www.googleapis.com/auth/userinfo.email"}
		a.Extra["access_type"] = "offline"
		a.Extra["prompt"] = "consent"
		a.Extra["include_granted_scopes"] = "true"
		a.Extra[ExtraIDField] = "sub"
		a.Extra[ExtraNameField] = "email"
	case VendorMicrosoft:
		a.AuthURL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
		a.TokenURL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
		a.UserInfoURL = "https://graph.microsoft.com/v1.0/me"
		a.Scopes = []string{"User.Read", "offline_access"}
		a.Extra[ExtraNameField] = "userPrincipalName"
		a.Extra[ExtraEmailField] = "userPrincipalName"
	}
	return a
}

// ErrInvalidVendorApp marks a vendor app that fails validation; the
// message after the sentinel is safe to show an admin.
var ErrInvalidVendorApp = errors.New("connections: invalid vendor app")

// normalize trims, lower-cases and validates a vendor app; the variant is
// defaulted for single-app vendors.
func (a *VendorApp) normalize() error {
	a.Vendor = strings.ToLower(strings.TrimSpace(a.Vendor))
	a.Variant = strings.ToLower(strings.TrimSpace(a.Variant))
	if !KnownVendor(a.Vendor) {
		return fmt.Errorf("%w: unknown vendor %q", ErrInvalidVendorApp, a.Vendor)
	}
	if a.Variant == "" {
		a.Variant = Variants(a.Vendor)[0]
	}
	if !slices.Contains(Variants(a.Vendor), a.Variant) {
		return fmt.Errorf("%w: %s has no variant %q", ErrInvalidVendorApp, a.Vendor, a.Variant)
	}
	a.ClientID = strings.TrimSpace(a.ClientID)
	if a.ClientID == "" {
		return fmt.Errorf("%w: client ID is required", ErrInvalidVendorApp)
	}
	for name, u := range map[string]*string{"authorization URL": &a.AuthURL, "token URL": &a.TokenURL, "user info URL": &a.UserInfoURL, "revoke URL": &a.RevokeURL} {
		*u = strings.TrimSpace(*u)
		if *u == "" {
			if name == "authorization URL" || name == "token URL" {
				return fmt.Errorf("%w: %s is required", ErrInvalidVendorApp, name)
			}
			continue
		}
		p, err := url.Parse(*u)
		if err != nil || (p.Scheme != "https" && p.Scheme != "http") || p.Host == "" {
			return fmt.Errorf("%w: %s must be an absolute http(s) URL", ErrInvalidVendorApp, name)
		}
	}
	a.Scopes = SplitScopes(strings.Join(a.Scopes, " "))
	extra := map[string]string{}
	for k, v := range a.Extra {
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if k != "" {
			extra[k] = v
		}
	}
	a.Extra = extra
	secrets := map[string]string{}
	for k, v := range a.Secrets {
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if k == "" || k == SecretClientSecret {
			continue
		}
		if !slices.Contains(ExtraSecretKeys(a.Vendor), k) {
			return fmt.Errorf("%w: %s has no secret %q", ErrInvalidVendorApp, a.Vendor, k)
		}
		secrets[k] = v
	}
	a.Secrets = secrets
	return nil
}

// SplitScopes parses a scope list separated by spaces, commas or newlines
// into sorted, unique scopes.
func SplitScopes(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == ',' || r == '\n' || r == '\r' || r == '\t' })
	return unionScopes(nil, fields)
}

// unionScopes merges scope lists into one sorted, unique list.
func unionScopes(lists ...[]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range lists {
		for _, s := range l {
			s = strings.TrimSpace(s)
			if s == "" || seen[s] {
				continue
			}
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// appConfig is the vendor_apps.config JSON document.
type appConfig struct {
	AuthURL     string            `json:"auth_url"`
	TokenURL    string            `json:"token_url"`
	UserInfoURL string            `json:"userinfo_url,omitempty"`
	RevokeURL   string            `json:"revoke_url,omitempty"`
	Scopes      []string          `json:"scopes,omitempty"`
	Extra       map[string]string `json:"extra,omitempty"`
}

// toRow converts to the store row; the secret envelope is set by the caller.
func (a VendorApp) toRow() (*store.VendorApp, error) {
	cfg, err := json.Marshal(appConfig{AuthURL: a.AuthURL, TokenURL: a.TokenURL, UserInfoURL: a.UserInfoURL, RevokeURL: a.RevokeURL, Scopes: a.Scopes, Extra: a.Extra})
	if err != nil {
		return nil, err
	}
	return &store.VendorApp{ID: a.ID, Vendor: a.Vendor, Name: a.Variant, ClientID: a.ClientID, Config: cfg, Enabled: a.Enabled}, nil
}

// fromRow converts a store row; the secrets stay encrypted in the row
// (SecretKeys is filled by the admin reads, which open the bundle).
func fromRow(r *store.VendorApp) (VendorApp, error) {
	var cfg appConfig
	if len(r.Config) > 0 {
		if err := json.Unmarshal(r.Config, &cfg); err != nil {
			return VendorApp{}, fmt.Errorf("connections: vendor app %s config: %w", r.ID, err)
		}
	}
	if cfg.Extra == nil {
		cfg.Extra = map[string]string{}
	}
	return VendorApp{
		ID: r.ID, Vendor: r.Vendor, Variant: r.Name, ClientID: r.ClientID,
		HasSecret: len(r.ClientSecret.Ciphertext) > 0,
		AuthURL:   cfg.AuthURL, TokenURL: cfg.TokenURL, UserInfoURL: cfg.UserInfoURL, RevokeURL: cfg.RevokeURL,
		Scopes: cfg.Scopes, Extra: cfg.Extra, Enabled: r.Enabled, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
	}, nil
}
