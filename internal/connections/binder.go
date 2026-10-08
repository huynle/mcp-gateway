package connections

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/oauth2"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/store"
)

// Bound is what a Binder learned about the account a token belongs to:
// the vendor's permanent account ID (Google sub, Entra object ID +
// tenant, Atlassian account ID, GitHub user ID, Slack user + team), a name
// the user recognises, whether it is a company or a personal account, and
// the scopes the vendor says were granted (nil means "what was
// requested").
type Bound struct {
	ExternalAccountID string
	DisplayName       string
	Label             connectors.AccountLabel
	Scopes            []string
}

// BindInput is what a Binder gets after the code exchange.
type BindInput struct {
	// App is the vendor app the token was issued by.
	App VendorApp
	// Token is the freshly exchanged token (access token, refresh token,
	// expiry and the vendor's extra fields such as "scope").
	Token *oauth2.Token
	// Client sends requests authenticated with Token.
	Client *http.Client
	// RequestedScopes are the scopes the flow asked for.
	RequestedScopes []string
}

// Binder identifies the account behind a token for one vendor. Each
// connector task registers its vendor's binder with Service.RegisterBinder;
// GenericBinder (user info JSON + email domain rule) serves tests and
// vendors without special needs.
type Binder interface {
	Bind(ctx context.Context, in BindInput) (Bound, error)
}

// BinderFunc adapts a function to Binder.
type BinderFunc func(ctx context.Context, in BindInput) (Bound, error)

// Bind implements Binder.
func (f BinderFunc) Bind(ctx context.Context, in BindInput) (Bound, error) { return f(ctx, in) }

// RegisterBinder installs the binder for vendor, replacing any previous
// one. Vendors without a binder fall back to the GenericBinder.
func (s *Service) RegisterBinder(vendor string, b Binder) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.binders[vendor] = b
}

// MapApp declares that connector app (the first segment of its tool names,
// e.g. "gmail") uses accounts of vendor (e.g. "google"). Apps that are not
// mapped are assumed to be named after their vendor.
func (s *Service) MapApp(app, vendor string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.apps[vendor] {
		if a == app {
			return
		}
	}
	s.apps[vendor] = append(s.apps[vendor], app)
}

// binderFor returns the vendor's binder or the generic one.
func (s *Service) binderFor(vendor string) Binder {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if b, ok := s.binders[vendor]; ok {
		return b
	}
	return GenericBinder{}
}

// appsFor returns the connector apps that use vendor's accounts.
func (s *Service) appsFor(vendor string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if apps := s.apps[vendor]; len(apps) > 0 {
		return append([]string(nil), apps...)
	}
	return []string{vendor}
}

// vendorFor returns the vendor whose accounts app uses.
func (s *Service) vendorFor(app string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for vendor, apps := range s.apps {
		for _, a := range apps {
			if a == app {
				return vendor
			}
		}
	}
	return app
}

// GenericBinder identifies the account from the vendor app's UserInfoURL:
// a JSON document whose ID, name and email fields are named by the app's
// Extra (id_field, name_field, email_field; defaults id|sub, name|login,
// email). The label is company when the email's domain is in the app's
// company_domains, else personal; without domains it is the app's
// default_label, company for the Google internal variant, personal
// otherwise.
type GenericBinder struct{}

// Bind implements Binder.
func (GenericBinder) Bind(ctx context.Context, in BindInput) (Bound, error) {
	return bindFromUserInfo(ctx, in)
}

// bindFromUserInfo is the GenericBinder's implementation.
func bindFromUserInfo(ctx context.Context, in BindInput) (Bound, error) {
	if in.App.UserInfoURL == "" {
		return Bound{}, errors.New("connections: generic binder needs a user info URL")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, in.App.UserInfoURL, nil)
	if err != nil {
		return Bound{}, err
	}
	req.Header.Set("Accept", "application/json")
	res, err := in.Client.Do(req)
	if err != nil {
		return Bound{}, fmt.Errorf("connections: user info: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return Bound{}, fmt.Errorf("connections: user info: http %d", res.StatusCode)
	}
	dec := json.NewDecoder(io.LimitReader(res.Body, 1<<20))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return Bound{}, fmt.Errorf("connections: user info: %w", err)
	}
	id := field(doc, in.App.Extra[ExtraIDField], "id", "sub")
	if id == "" {
		return Bound{}, errors.New("connections: user info has no account ID")
	}
	email := field(doc, in.App.Extra[ExtraEmailField], "email")
	name := field(doc, in.App.Extra[ExtraNameField], "name", "login", "email")
	if name == "" {
		name = id
	}
	return Bound{ExternalAccountID: id, DisplayName: name, Label: labelFor(in.App, email)}, nil
}

// field returns the first non-empty of the named fields as a string
// (numbers are formatted, so GitHub's numeric id works).
func field(doc map[string]any, names ...string) string {
	for _, n := range names {
		if n == "" {
			continue
		}
		switch v := doc[n].(type) {
		case string:
			if v != "" {
				return v
			}
		case json.Number:
			return v.String()
		case bool:
			return strconv.FormatBool(v)
		}
	}
	return ""
}

// labelFor applies the app's company_domains rule to the account's
// email, then default_label, then the Google internal variant rule.
func labelFor(app VendorApp, email string) connectors.AccountLabel {
	if domains := SplitScopes(strings.ToLower(app.Extra[ExtraCompanyDomains])); len(domains) > 0 {
		_, domain, _ := strings.Cut(strings.ToLower(email), "@")
		if domain != "" && slices.Contains(domains, domain) {
			return connectors.LabelCompany
		}
		return connectors.LabelPersonal
	}
	switch strings.ToLower(app.Extra[ExtraDefaultLabel]) {
	case store.AccountCompany:
		return connectors.LabelCompany
	case store.AccountPersonal:
		return connectors.LabelPersonal
	}
	if app.Vendor == VendorGoogle && app.Variant == GoogleInternal {
		return connectors.LabelCompany
	}
	return connectors.LabelPersonal
}
