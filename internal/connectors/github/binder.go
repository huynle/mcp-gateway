package github

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	gh "github.com/google/go-github/v90/github"

	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/connectors"
)

// ExtraCompanyOrgs is the vendor app Extra key listing the company's
// GitHub organizations (comma separated, case-insensitive). An account
// that is an active member of any of them is a company account; every
// other account, and every account when the list is empty, is personal.
const ExtraCompanyOrgs = connections.ExtraCompanyOrgs

// DefaultAPIBase is api.github.com; GHES deployments point the vendor
// app's UserInfoURL at https://<host>/api/v3/user and the binder follows.
const DefaultAPIBase = "https://api.github.com/"

// Binder identifies the GitHub account behind a GitHub App user access
// token (connections.Binder for vendor "github"): GET /user gives the
// permanent numeric id ("github:<id>" is the external account id) and
// the login (the display name); the label is company when the user is
// an active member of one of the app's company_orgs, checked through
// GET /user/memberships/orgs/{org} and, when that endpoint is not
// permitted to the app, the public membership check
// GET /orgs/{org}/members/{login}; the scopes are the token response's
// scope field, else the X-OAuth-Scopes header (OAuth Apps), else nil
// (GitHub App tokens carry none; the connect flow then records the
// requested scopes).
type Binder struct {
	// BaseURL overrides the API root (with trailing slash). Empty derives
	// it from the vendor app's UserInfoURL, then DefaultAPIBase.
	BaseURL string
}

// Bind implements connections.Binder.
func (b Binder) Bind(ctx context.Context, in connections.BindInput) (connections.Bound, error) {
	httpClient := in.Client
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	client, err := newClient(httpClient, b.baseURL(in.App))
	if err != nil {
		return connections.Bound{}, err
	}
	user, resp, err := client.Users.Get(ctx, "")
	if err := classify("identify account", err); err != nil {
		return connections.Bound{}, err
	}
	if user.GetID() == 0 || user.GetLogin() == "" {
		return connections.Bound{}, &Error{Class: ClassVendorError, Message: "identify account: GitHub returned no user id or login"}
	}
	bound := connections.Bound{
		ExternalAccountID: "github:" + strconv.FormatInt(user.GetID(), 10),
		DisplayName:       user.GetLogin(),
		Label:             connectors.LabelPersonal,
		Scopes:            grantedScopes(in, resp),
	}
	member, err := b.isCompanyMember(ctx, client, user.GetLogin(), companyOrgs(in.App))
	if err != nil {
		return connections.Bound{}, err
	}
	if member {
		bound.Label = connectors.LabelCompany
	}
	return bound, nil
}

// baseURL picks the API root: the explicit override, else the vendor
// app's UserInfoURL with its trailing "user" segment removed, else
// api.github.com.
func (b Binder) baseURL(app connections.VendorApp) string {
	if b.BaseURL != "" {
		return b.BaseURL
	}
	if app.UserInfoURL != "" {
		if u, err := url.Parse(app.UserInfoURL); err == nil && u.Host != "" {
			u.Path = strings.TrimSuffix(strings.TrimSuffix(u.Path, "/"), "/user")
			u.RawQuery, u.Fragment = "", ""
			return strings.TrimSuffix(u.String(), "/") + "/"
		}
	}
	return DefaultAPIBase
}

// companyOrgs parses the app's company_orgs list, lower-cased.
func companyOrgs(app connections.VendorApp) []string {
	var out []string
	for _, o := range strings.FieldsFunc(app.Extra[ExtraCompanyOrgs], func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' }) {
		if o = strings.ToLower(strings.TrimSpace(o)); o != "" {
			out = append(out, o)
		}
	}
	return out
}

// isCompanyMember reports whether login is an active member of any org.
// A 404 or a pending membership means not a member; a 403 (the app lacks
// the Members permission) falls back to the public membership check.
// Any other failure is returned: binding must not guess the label.
func (b Binder) isCompanyMember(ctx context.Context, client *gh.Client, login string, orgs []string) (bool, error) {
	for _, org := range orgs {
		m, _, err := client.Organizations.GetOrgMembership(ctx, "", org)
		switch cerr := classify("check organization membership", err); {
		case cerr == nil:
			if strings.EqualFold(m.GetState(), "active") {
				return true, nil
			}
		case statusOf(cerr) == http.StatusNotFound:
		case statusOf(cerr) == http.StatusForbidden:
			ok, _, err := client.Organizations.IsMember(ctx, org, login)
			if cerr := classify("check organization membership", err); cerr != nil && statusOf(cerr) != http.StatusNotFound && statusOf(cerr) != http.StatusForbidden {
				return false, cerr
			}
			if ok {
				return true, nil
			}
		default:
			return false, cerr
		}
	}
	return false, nil
}

// grantedScopes reads the token response's scope field, else the
// X-OAuth-Scopes response header; nil when neither says anything.
func grantedScopes(in connections.BindInput, resp *gh.Response) []string {
	if in.Token != nil {
		if raw, ok := in.Token.Extra("scope").(string); ok && strings.TrimSpace(raw) != "" {
			return connections.SplitScopes(raw)
		}
	}
	if resp != nil {
		if raw := strings.TrimSpace(resp.Header.Get("X-OAuth-Scopes")); raw != "" {
			return connections.SplitScopes(raw)
		}
	}
	return nil
}

// newClient builds a go-github client over httpClient rooted at base
// (api.github.com when empty).
func newClient(httpClient *http.Client, base string) (*gh.Client, error) {
	opts := []gh.ClientOptionsFunc{gh.WithHTTPClient(httpClient), gh.WithUserAgent(userAgent)}
	if base != "" {
		u, err := url.Parse(base)
		if err != nil || u.Host == "" {
			return nil, fmt.Errorf("github: invalid API base URL %q", base)
		}
		if !strings.HasSuffix(u.Path, "/") {
			u.Path += "/"
		}
		s := u.String()
		opts = append(opts, gh.WithURLs(&s, nil))
	}
	client, err := gh.NewClient(opts...)
	if err != nil {
		return nil, fmt.Errorf("github: client: %w", err)
	}
	return client, nil
}
