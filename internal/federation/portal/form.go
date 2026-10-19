package portal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/huynle/mcp-gateway/internal/federation/connector"

	"github.com/huynle/mcp-gateway/internal/caps"
	"github.com/huynle/mcp-gateway/internal/federation/auth"
	"github.com/huynle/mcp-gateway/internal/federation/client"
	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/federation/tunnel"
	"github.com/huynle/mcp-gateway/internal/store"
)

// ReservedNames are the built-in app prefixes a user-added server may not
// take (decision 17iv8p3b leaves this to the app layer): v1 connectors and
// the products behind them, so <server>.<tool> never shadows a built-in
// tool family.
var ReservedNames = connector.ReservedNames()

var nameRE = regexp.MustCompile(`^[a-z0-9_-]{1,63}$`)

// ValidateName checks a server name (the tool prefix): the store's pattern
// and not a reserved built-in name. The error is safe to show.
func ValidateName(name string) error {
	if !nameRE.MatchString(name) {
		return bad("Use 1–63 lowercase letters, digits, '-' or '_' for the name.")
	}
	if slices.Contains(ReservedNames, name) {
		return bad("The name %q is reserved for a built-in app; choose another.", name)
	}
	return nil
}

// Limits on form input.
const (
	maxURL        = 2048
	maxLines      = 50
	maxFieldValue = 8 << 10
)

// serverForm is the add / edit form. Secret fields are unexported so they
// can never reach a template.
type serverForm struct {
	Name           string
	URLMode        string // https | tunnel
	URL            string
	TunnelID       string
	TunnelPath     string
	AuthKind       string
	CredentialMode string
	APIKeyIn       string // header | query
	APIKeyName     string
	Scopes         string
	StaticHeaders  string
	PerUserHeaders string
	ClientID       string
	ClientIssuer   string

	sharedAPIKey  string
	sharedBearer  string
	sharedHeaders string
	clientSecret  string
}

func parseServerForm(r *http.Request) serverForm {
	v := func(k string) string { return strings.TrimSpace(r.PostForm.Get(k)) }
	return serverForm{
		Name: v("name"), URLMode: v("url_mode"), URL: v("url"), TunnelID: v("tunnel_id"), TunnelPath: v("tunnel_path"),
		AuthKind: v("auth_kind"), CredentialMode: v("credential_mode"), APIKeyIn: v("api_key_in"), APIKeyName: v("api_key_name"),
		Scopes: v("scopes"), StaticHeaders: r.PostForm.Get("static_headers"), PerUserHeaders: r.PostForm.Get("per_user_headers"),
		ClientID: v("client_id"), ClientIssuer: v("client_issuer"),
		sharedAPIKey: v("shared_api_key"), sharedBearer: v("shared_bearer"), sharedHeaders: r.PostForm.Get("shared_headers"),
		clientSecret: v("client_secret"),
	}
}

// formFromServer fills the edit form from a stored server (no secrets).
func formFromServer(s *store.MCPServer, info CredentialInfo) serverForm {
	f := serverForm{Name: s.Name, URLMode: "https", URL: s.URL, AuthKind: s.AuthKind, CredentialMode: s.CredentialMode, ClientID: info.StaticClientID}
	if id, path, err := tunnel.ParseURL(s.URL); err == nil {
		f.URLMode, f.URL, f.TunnelID, f.TunnelPath = "tunnel", "", id, path
	}
	ac := parseAuthConfig(s.AuthConfig)
	f.Scopes = strings.Join(ac.Scopes, " ")
	if ac.APIKey != nil {
		if ac.APIKey.Header != "" {
			f.APIKeyIn, f.APIKeyName = "header", ac.APIKey.Header
		} else if ac.APIKey.Query != "" {
			f.APIKeyIn, f.APIKeyName = "query", ac.APIKey.Query
		}
	}
	hc := parseHeaderConfig(s.HeaderConfig)
	names := make([]string, 0, len(hc.Static))
	for k := range hc.Static {
		names = append(names, k)
	}
	slices.Sort(names)
	var lines []string
	for _, k := range names {
		lines = append(lines, k+": "+hc.Static[k])
	}
	f.StaticHeaders = strings.Join(lines, "\n")
	f.PerUserHeaders = strings.Join(hc.PerUser, "\n")
	return f
}

// userError is a validation message safe to show.
type userError struct{ msg string }

func (e *userError) Error() string { return e.msg }

func bad(format string, a ...any) error { return &userError{msg: fmt.Sprintf(format, a...)} }

// validated is a checked form, ready to store.
type validated struct {
	url          string
	authConfig   json.RawMessage
	headerConfig json.RawMessage
	shared       *auth.Credential // nil: keep / none
	client       bool             // set the static OAuth client
}

var allKinds = []string{store.MCPAuthOAuth, store.MCPAuthAPIKey, store.MCPAuthBearer, store.MCPAuthHeaders, store.MCPAuthNone}

func secretKind(kind string) bool {
	return kind == store.MCPAuthAPIKey || kind == store.MCPAuthBearer || kind == store.MCPAuthHeaders
}

// validate checks f for the caller. prev is the stored server when editing
// (nil when adding) and info its owner-only credentials.
func (p *Portal) validate(ctx context.Context, c caller, f *serverForm, prev *store.MCPServer, info CredentialInfo) (*validated, error) {
	if prev == nil {
		if err := ValidateName(f.Name); err != nil {
			return nil, err
		}
	}
	out := &validated{}
	u, err := p.formURL(ctx, c, f)
	if err != nil {
		return nil, err
	}
	out.url = u

	if !slices.Contains(allKinds, f.AuthKind) {
		return nil, bad("Choose an authentication kind.")
	}
	if f.CredentialMode != store.MCPCredentialShared || f.AuthKind == store.MCPAuthNone {
		f.CredentialMode = store.MCPCredentialPerUser
	}
	if f.AuthKind == store.MCPAuthOAuth && f.CredentialMode == store.MCPCredentialShared {
		return nil, bad("Shared OAuth tokens are not supported; use per-user connections, or a shared API key, bearer token or headers.")
	}

	var ac authConfig
	if f.Scopes != "" {
		ac.Scopes = strings.Fields(f.Scopes)
		if len(ac.Scopes) > maxLines || slices.ContainsFunc(ac.Scopes, hasCTL) || len(f.Scopes) > maxFieldValue {
			return nil, bad("Scopes must be up to %d space-separated words.", maxLines)
		}
	}
	if f.AuthKind == store.MCPAuthAPIKey && (f.APIKeyName != "" || f.APIKeyIn != "") {
		switch f.APIKeyIn {
		case "header", "":
			if f.APIKeyName != "" && !validHeaderName(f.APIKeyName) {
				return nil, bad("%q is not a valid header name.", f.APIKeyName)
			}
			if f.APIKeyName != "" {
				ac.APIKey = &apiKeyConfig{Header: f.APIKeyName}
			}
		case "query":
			if !queryNameRE.MatchString(f.APIKeyName) {
				return nil, bad("Enter the query parameter name (letters, digits, '-', '_' or '.').")
			}
			ac.APIKey = &apiKeyConfig{Query: f.APIKeyName}
		default:
			return nil, bad("The API key goes in either a header or a query parameter.")
		}
	}
	if out.authConfig, err = json.Marshal(ac); err != nil {
		return nil, err
	}

	var hc headerConfig
	if hc.Static, err = parseHeaderLines(f.StaticHeaders, true); err != nil {
		return nil, err
	}
	if hc.PerUser, err = parseHeaderNames(f.PerUserHeaders); err != nil {
		return nil, err
	}
	if out.headerConfig, err = json.Marshal(hc); err != nil {
		return nil, err
	}

	if f.CredentialMode == store.MCPCredentialShared && secretKind(f.AuthKind) {
		cred, err := sharedCredential(f)
		if err != nil {
			return nil, err
		}
		// A stored secret is sealed to its auth kind and the server URL,
		// so a new kind or a new URL needs a new secret.
		keep := prev != nil && info.SharedSecret && prev.AuthKind == f.AuthKind && prev.CredentialMode == store.MCPCredentialShared &&
			prev.URL == out.url
		switch {
		case cred != nil:
			out.shared = cred
		case !keep:
			return nil, bad("%s", map[string]string{
				store.MCPAuthAPIKey:  "Enter the shared API key.",
				store.MCPAuthBearer:  "Enter the shared bearer token.",
				store.MCPAuthHeaders: "Enter at least one shared header.",
			}[f.AuthKind])
		}
	}

	if f.AuthKind == store.MCPAuthOAuth && f.ClientID != "" {
		if hasCTL(f.ClientID) || len(f.ClientID) > maxFieldValue || hasCTL(f.clientSecret) || len(f.clientSecret) > maxFieldValue {
			return nil, bad("The client ID or secret is not valid.")
		}
		if f.ClientIssuer != "" && !absHTTPSURL(f.ClientIssuer) {
			return nil, bad("The issuer must be an https URL.")
		}
		out.client = prev == nil || f.clientSecret != "" || f.ClientID != info.StaticClientID
	}
	return out, nil
}

// sharedCredential reads the shared secret fields for the form's kind
// (nil when none was entered).
func sharedCredential(f *serverForm) (*auth.Credential, error) {
	switch f.AuthKind {
	case store.MCPAuthAPIKey:
		if f.sharedAPIKey != "" {
			return &auth.Credential{APIKey: f.sharedAPIKey}, nil
		}
	case store.MCPAuthBearer:
		if f.sharedBearer != "" {
			return &auth.Credential{Bearer: f.sharedBearer}, nil
		}
	case store.MCPAuthHeaders:
		h, err := parseHeaderLines(f.sharedHeaders, false)
		if err != nil || len(h) == 0 {
			return nil, err
		}
		return &auth.Credential{Headers: h}, nil
	}
	return nil, nil
}

// formURL returns the server URL of the form: an https URL, or a tunnel URL
// of one of the caller's live tunnels.
func (p *Portal) formURL(ctx context.Context, c caller, f *serverForm) (string, error) {
	if f.URLMode == "tunnel" {
		tunnels, err := p.d.Store.ListTunnels(ctx, c.UserID)
		if err != nil {
			return "", err
		}
		if !slices.ContainsFunc(tunnels, func(t store.MCPTunnel) bool { return t.ID == f.TunnelID && t.RevokedAt == nil }) {
			return "", bad("Choose one of your tunnels.")
		}
		path := f.TunnelPath
		if path != "" && !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		u := tunnel.URL(f.TunnelID, path)
		if _, _, err := tunnel.ParseURL(u); err != nil || len(u) > maxURL || hasCTL(path) {
			return "", bad("The tunnel path is not valid.")
		}
		return u, nil
	}
	f.URLMode = "https"
	if !absHTTPSURL(f.URL) {
		return "", bad("The address must be an https URL (no user name or password, no fragment).")
	}
	return f.URL, nil
}

func absHTTPSURL(raw string) bool {
	if len(raw) > maxURL || hasCTL(raw) {
		return false
	}
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.Hostname() != "" && u.User == nil && u.Fragment == "" && u.Opaque == ""
}

var queryNameRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// reservedHeaders are set by the transport or the MCP SDK (the union of
// what internal/federation/client and auth refuse).
var reservedHeaders = map[string]bool{
	"Host": true, "Content-Length": true, "Content-Type": true, "Accept": true, "Connection": true,
	"Transfer-Encoding": true, "Te": true, "Trailer": true, "Upgrade": true, "Keep-Alive": true,
	"Last-Event-Id": true, "Cache-Control": true, "Accept-Encoding": true,
}

func validHeaderName(name string) bool {
	if name == "" || len(name) > 256 {
		return false
	}
	for i := 0; i < len(name); i++ {
		if !isTokenChar(name[i]) {
			return false
		}
	}
	k := http.CanonicalHeaderKey(name)
	return !reservedHeaders[k] && !strings.HasPrefix(k, "Mcp-") && !strings.HasPrefix(k, "Proxy-")
}

func isTokenChar(c byte) bool {
	return c < 0x80 && (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0)
}

func hasCTL(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

func lines(s string) []string {
	var out []string
	for l := range strings.SplitSeq(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// secretHeaders may not be static headers: those are stored in plain text
// (header_config) and shown on the edit form.
var secretHeaders = map[string]bool{"Authorization": true, "Cookie": true, "Set-Cookie": true, "X-Api-Key": true}

// parseHeaderLines reads "Name: value" lines. static refuses credential
// headers (static headers are not secret).
func parseHeaderLines(s string, static bool) (map[string]string, error) {
	ls := lines(s)
	if len(ls) == 0 {
		return nil, nil
	}
	if len(ls) > maxLines || len(s) > maxFieldValue*4 {
		return nil, bad("Up to %d headers.", maxLines)
	}
	out := make(map[string]string, len(ls))
	for _, l := range ls {
		name, value, ok := strings.Cut(l, ":")
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		if !ok || name == "" || value == "" {
			return nil, bad("Header lines must look like “Name: value”.")
		}
		if !validHeaderName(name) {
			return nil, bad("%q is not a valid header name.", name)
		}
		if static && secretHeaders[http.CanonicalHeaderKey(name)] {
			return nil, bad("%q carries a credential: set it as a shared secret or a per-user header, not as a static header.", name)
		}
		if hasCTL(value) || len(value) > maxFieldValue {
			return nil, bad("The value of header %q is not valid.", name)
		}
		out[http.CanonicalHeaderKey(name)] = value
	}
	return out, nil
}

// parseHeaderNames reads one header name per line.
func parseHeaderNames(s string) ([]string, error) {
	ls := lines(s)
	if len(ls) > maxLines {
		return nil, bad("Up to %d headers.", maxLines)
	}
	var out []string
	for _, l := range ls {
		if !validHeaderName(l) {
			return nil, bad("%q is not a valid header name.", l)
		}
		if k := http.CanonicalHeaderKey(l); !slices.Contains(out, k) {
			out = append(out, k)
		}
	}
	return out, nil
}

// --- pages ---------------------------------------------------------------------------

type kindOption struct {
	Value, Label string
	Checked      bool
	Offered      bool
}

var kindLabels = map[string]string{
	store.MCPAuthOAuth:   "OAuth (each user signs in)",
	store.MCPAuthAPIKey:  "API key",
	store.MCPAuthBearer:  "Bearer token",
	store.MCPAuthHeaders: "Custom headers",
	store.MCPAuthNone:    "None",
}

// detectView is what detection found, for the form.
type detectView struct {
	Kinds         []string
	OAuth         bool
	DCR, CIMD     bool
	S256, Offline bool
	Scopes        []string
	Blocked       []string
	Error         string
}

type formPage struct {
	Title    string
	Caller   caller
	Edit     bool
	ServerID string
	Form     serverForm
	Kinds    []kindOption
	Tunnels  []tunnelRow
	Detect   *detectView
	Info     CredentialInfo
	Error    string
	Notice   string
	// Locked is set on the edit form of a published server: its address
	// and sign-in settings are shown read-only (locked.go).
	Locked *lockedView
}

// lockedView is the read-only summary of a published server's settings.
type lockedView struct {
	Note     string
	Address  string
	AuthKind string
	// CredentialForm: the kind takes a shared secret, so the owner may
	// switch the credential mode and rotate the shared secret.
	CredentialForm bool
}

func (p *Portal) formPage(ctx context.Context, c caller, f serverForm, d *detectView) (formPage, error) {
	page := formPage{Title: "Add server", Caller: c, Form: f, Detect: d}
	if page.Form.URLMode == "" {
		page.Form.URLMode = "https"
	}
	if page.Form.AuthKind == "" {
		page.Form.AuthKind = store.MCPAuthOAuth
	}
	if page.Form.CredentialMode == "" {
		page.Form.CredentialMode = store.MCPCredentialPerUser
	}
	for _, k := range allKinds {
		o := kindOption{Value: k, Label: kindLabels[k], Checked: k == page.Form.AuthKind}
		if d != nil {
			o.Offered = slices.Contains(d.Kinds, k)
		}
		page.Kinds = append(page.Kinds, o)
	}
	tunnels, err := p.d.Store.ListTunnels(ctx, c.UserID)
	if err != nil {
		return page, err
	}
	for _, t := range tunnels {
		if t.RevokedAt == nil {
			page.Tunnels = append(page.Tunnels, tunnelRow{ID: t.ID, Name: t.Name, Online: p.d.Tunnels.Online(t.ID)})
		}
	}
	// Online tunnels first (a server added through an offline one cannot
	// be refreshed), and an online one pre-selected when the form has none.
	slices.SortStableFunc(page.Tunnels, func(a, b tunnelRow) int {
		switch {
		case a.Online == b.Online:
			return 0
		case a.Online:
			return -1
		}
		return 1
	})
	if page.Form.TunnelID == "" && len(page.Tunnels) > 0 {
		page.Form.TunnelID = page.Tunnels[0].ID
	}
	return page, nil
}

func (p *Portal) renderForm(w http.ResponseWriter, r *http.Request, status int, page formPage) {
	p.render(w, r, status, "server_form.html", page)
}

func (p *Portal) newForm(w http.ResponseWriter, r *http.Request, c caller) {
	page, err := p.formPage(r.Context(), c, serverForm{}, nil)
	if err != nil {
		p.fail(w, r, "new server form", err)
		return
	}
	p.renderForm(w, r, http.StatusOK, page)
}

// create handles both buttons of the add form: action=detect re-renders
// the form with what detection found; anything else creates the server.
func (p *Portal) create(w http.ResponseWriter, r *http.Request, c caller) {
	f := parseServerForm(r)
	if r.PostForm.Get("action") == "detect" {
		p.detect(w, r, c, f)
		return
	}
	ctx := r.Context()
	v, err := p.validate(ctx, c, &f, nil, CredentialInfo{})
	if err != nil {
		p.formError(w, r, c, f, err)
		return
	}
	s := &store.MCPServer{
		Name: f.Name, URL: v.url, Transport: store.MCPTransportAuto, CredentialMode: f.CredentialMode, AuthKind: f.AuthKind,
		AuthConfig: v.authConfig, HeaderConfig: v.headerConfig,
	}
	if err := p.d.Store.CreateServer(ctx, c.UserID, s); err != nil {
		var ce *caps.ExceededError
		switch {
		case errors.Is(err, ErrNameTaken):
			err = bad("The name %q is already taken.", f.Name)
		case errors.As(err, &ce):
			err = bad("%s", ce.Error())
		}
		p.formError(w, r, c, f, err)
		return
	}
	if err := p.storeCredentials(ctx, c, s.ID, &f, v); err != nil {
		// Roll back so the owner can simply submit again.
		if derr := p.d.Store.DeleteServer(ctx, c.UserID, s.ID); derr != nil {
			p.log.Error("roll back server", "event", "federation.portal_rollback_failed", "server_id", s.ID, "error", derr.Error())
		}
		p.formError(w, r, c, f, err)
		return
	}
	p.log.Info("server added", "event", "federation.server_added", "user_id", c.UserID, "server_id", s.ID, "auth_kind", s.AuthKind, "credential_mode", s.CredentialMode)
	p.changed(ctx, s.ID)
	http.Redirect(w, r, "/servers/"+s.ID+"?created=1", http.StatusSeeOther)
}

// storeCredentials writes the shared secret and the static OAuth client.
func (p *Portal) storeCredentials(ctx context.Context, c caller, serverID string, f *serverForm, v *validated) error {
	actor := auth.Actor{UserID: c.UserID}
	if v.shared != nil {
		if err := p.d.Auth.SetSharedCredential(ctx, actor, serverID, *v.shared); err != nil {
			return credentialError(err)
		}
	}
	if v.client {
		if err := p.d.Auth.SetStaticClient(ctx, actor, serverID, f.ClientID, f.clientSecret, f.ClientIssuer); err != nil {
			return credentialError(err)
		}
	}
	return nil
}

// credentialError keeps the auth package's safe sentinels and hides
// anything else.
func credentialError(err error) error {
	for _, e := range []error{auth.ErrInvalidCredential, auth.ErrUnsupported, auth.ErrForbidden} {
		if errors.Is(err, e) {
			return bad("%s", strings.TrimPrefix(err.Error(), "auth: "))
		}
	}
	return err
}

// formError re-renders the form with a user error (422), or fails.
func (p *Portal) formError(w http.ResponseWriter, r *http.Request, c caller, f serverForm, err error) {
	var ue *userError
	if !errors.As(err, &ue) {
		p.fail(w, r, "save server", err)
		return
	}
	page, lerr := p.formPage(r.Context(), c, f, nil)
	if lerr != nil {
		p.fail(w, r, "server form", lerr)
		return
	}
	page.Error = ue.msg
	p.renderForm(w, r, http.StatusUnprocessableEntity, page)
}

// detect runs auth detection (through netguard, inside the auth service)
// and pre-selects the first offered kind.
func (p *Portal) detect(w http.ResponseWriter, r *http.Request, c caller, f serverForm) {
	d := &detectView{}
	switch {
	case f.URLMode == "tunnel":
		d.Error = "Detection is not available for tunnel servers; choose the authentication kind yourself."
	case !absHTTPSURL(f.URL):
		d.Error = "The address must be an https URL (no user name or password, no fragment)."
	default:
		res, err := p.d.Auth.Detect(r.Context(), f.URL)
		if err != nil {
			d.Error = detectMessage(err)
			p.log.Info("detect failed", "event", "federation.portal_detect_failed", "user_id", c.UserID, "error", err.Error())
			break
		}
		d.Kinds = res.AuthKinds
		d.OAuth = slices.Contains(res.AuthKinds, store.MCPAuthOAuth)
		d.DCR, d.CIMD, d.S256, d.Offline = res.SupportsDCR, res.SupportsCIMD, res.SupportsS256, res.OfflineAccess
		for _, s := range res.Scopes {
			d.Scopes = append(d.Scopes, snapshot.DisplayName(s))
		}
		for _, b := range res.Blocked {
			d.Blocked = append(d.Blocked, snapshot.DisplayTitle(b))
		}
		if len(res.AuthKinds) > 0 {
			f.AuthKind = res.AuthKinds[0]
		}
	}
	page, err := p.formPage(r.Context(), c, f, d)
	if err != nil {
		p.fail(w, r, "server form", err)
		return
	}
	p.renderForm(w, r, http.StatusOK, page)
}

// detectMessage turns a detection failure into its class-level message.
func detectMessage(err error) string {
	if errors.Is(err, auth.ErrInvalidServerURL) {
		return "The address is not a valid server URL."
	}
	var ce *client.Error
	if !errors.As(err, &ce) {
		return "Detection failed. Choose the authentication kind yourself."
	}
	return upstreamMessage(ce.Class)
}

// upstreamMessage is the user-facing text of a federation client error
// class (never upstream text).
func upstreamMessage(class client.Class) string {
	switch class {
	case client.ClassBlocked:
		return "The address is blocked by the gateway's network policy (SSRF protection). An admin can allow-list the host if it is meant to be reachable."
	case client.ClassUnreachable:
		return "The server could not be reached."
	case client.ClassTimeout:
		return "The server did not answer in time."
	case client.ClassProtocol:
		return "The server did not answer like an MCP server."
	case client.ClassTooLarge:
		return "The server's answer was too large."
	case client.ClassForbidden:
		return "The server refused the request (HTTP 403)."
	case client.ClassAuthRequired:
		return "The server asked for credentials."
	case client.ClassToolError:
		return "The server answered with an error."
	}
	return "The request to the server failed."
}

func (p *Portal) editForm(w http.ResponseWriter, r *http.Request, c caller, s *store.MCPServer) {
	info, err := p.d.Store.CredentialInfo(r.Context(), c.UserID, s.ID)
	if err != nil {
		p.fail(w, r, "credential info", err)
		return
	}
	p.renderEdit(w, r, c, s, info, formFromServer(s, info), http.StatusOK, "")
}

func (p *Portal) renderEdit(w http.ResponseWriter, r *http.Request, c caller, s *store.MCPServer, info CredentialInfo, f serverForm, status int, msg string) {
	f.Name = s.Name
	page, err := p.formPage(r.Context(), c, f, nil)
	if err != nil {
		p.fail(w, r, "edit form", err)
		return
	}
	page.Title, page.Edit, page.ServerID, page.Info, page.Error = "Edit "+s.Name, true, s.ID, info, msg
	if isLocked(s) {
		// Read-only settings: show the stored ones, whatever was posted.
		page.Form = formFromServer(s, info)
		page.Form.Name = s.Name
		names := make(map[string]string, len(page.Tunnels))
		for _, t := range page.Tunnels {
			names[t.ID] = t.Name
		}
		page.Locked = &lockedView{
			Note: lockedMessage, Address: displayURL(s.URL, names), AuthKind: kindLabels[s.AuthKind],
			CredentialForm: secretKind(s.AuthKind),
		}
	}
	p.renderForm(w, r, status, page)
}

func (p *Portal) save(w http.ResponseWriter, r *http.Request, c caller, s *store.MCPServer) {
	ctx := r.Context()
	info, err := p.d.Store.CredentialInfo(ctx, c.UserID, s.ID)
	if err != nil {
		p.fail(w, r, "credential info", err)
		return
	}
	if isLocked(s) {
		p.saveLocked(w, r, c, s, info)
		return
	}
	f := parseServerForm(r)
	f.Name = s.Name
	v, err := p.validate(ctx, c, &f, s, info)
	if err == nil && v.url != s.URL && !p.d.Permissions.CanAddServers(ctx, c.UserID) {
		// A new address is a different server: adding one needs the
		// permission.
		err = bad("Changing the address needs permission to add MCP servers. Ask an admin for a role that may add MCP servers.")
	}
	if err == nil {
		next := *s
		next.URL, next.CredentialMode, next.AuthKind, next.AuthConfig, next.HeaderConfig = v.url, f.CredentialMode, f.AuthKind, v.authConfig, v.headerConfig
		if err = p.d.Store.UpdateServer(ctx, c.UserID, &next); err == nil {
			err = p.storeCredentials(ctx, c, s.ID, &f, v)
		}
	}
	if err != nil {
		p.formSaveError(w, r, c, s, info, f, err)
		return
	}
	p.log.Info("server edited", "event", "federation.server_edited", "user_id", c.UserID, "server_id", s.ID)
	p.changed(ctx, s.ID)
	http.Redirect(w, r, "/servers/"+s.ID+"?saved=1", http.StatusSeeOther)
}

// formSaveError answers a failed edit: a user error or the store's lock
// (the server was published meanwhile: migration 00017) re-renders the
// form (422), a missing server is the 404 page, anything else fails.
func (p *Portal) formSaveError(w http.ResponseWriter, r *http.Request, c caller, s *store.MCPServer, info CredentialInfo, f serverForm, err error) {
	var ue *userError
	switch {
	case errors.As(err, &ue):
		p.renderEdit(w, r, c, s, info, f, http.StatusUnprocessableEntity, ue.msg)
	case errors.Is(err, store.ErrMCPServerLocked):
		p.renderEdit(w, r, c, s, info, f, http.StatusUnprocessableEntity, lockedMessage)
	case errors.Is(err, store.ErrNotFound):
		p.notFound(w, r)
	default:
		p.fail(w, r, "save server", err)
	}
}

func (p *Portal) delete(w http.ResponseWriter, r *http.Request, c caller, s *store.MCPServer) {
	err := p.d.Store.DeleteServer(r.Context(), c.UserID, s.ID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		p.notFound(w, r)
		return
	case err != nil:
		p.fail(w, r, "delete server", err)
		return
	}
	p.log.Info("server deleted", "event", "federation.server_deleted", "user_id", c.UserID, "server_id", s.ID)
	p.changed(r.Context(), s.ID)
	http.Redirect(w, r, "/servers?deleted=1", http.StatusSeeOther)
}
