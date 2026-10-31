package google

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"google.golang.org/api/calendar/v3"
	"google.golang.org/api/chat/v1"
	"google.golang.org/api/docs/v1"
	"google.golang.org/api/drive/v3"
	"google.golang.org/api/forms/v1"
	"google.golang.org/api/gmail/v1"
	"google.golang.org/api/option"
	"google.golang.org/api/people/v1"
	"google.golang.org/api/sheets/v4"
	"google.golang.org/api/slides/v1"
	"google.golang.org/api/tasks/v1"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// TokenSourceFunc returns the oauth2.TokenSource of one of userID's
// connections (connections.Service.TokenSource has this signature). The
// connector calls it once per tool call with Call.Principal.UserID and
// Call.Account and never keeps the token.
type TokenSourceFunc func(ctx context.Context, userID, connectionID string) oauth2.TokenSource

// DefaultTimeout bounds one tool call's Google requests.
const DefaultTimeout = 30 * time.Second

// maxPerPage is the largest page any tool asks Google for (the Tasks
// API's own ceiling; Calendar and Gmail allow more, but the gateway's
// bounds never do).
const maxPerPage = 100

// Options configures New. Tokens is required; the rest is optional.
type Options struct {
	// Tokens supplies the connection's token source per call.
	Tokens TokenSourceFunc
	// Accounts, when set, is consulted on every call for the account's
	// granted scopes: a tool whose RequiredScopes the account did not
	// grant answers scope_required before any request (granular
	// consent). connections.Service implements it. Nil disables the
	// local check and leaves it to Google (403 insufficientPermissions).
	Accounts connectors.AccountSource
	// HTTPClient is the base client Google requests go through (its
	// Transport is wrapped with the bearer token); http.DefaultClient's
	// transport when nil.
	HTTPClient *http.Client
	// BaseURL replaces the root of every Google API endpoint (with a
	// trailing slash): the Calendar API is reached at
	// BaseURL + "calendar/v3/", Drive at BaseURL + "drive/v3/", Tasks,
	// Gmail, Docs, Sheets, People and Chat at BaseURL + "tasks/v1/",
	// "gmail/v1/", "v1/documents", "v4/spreadsheets", "v1/people",
	// "v1/spaces", Slides at "v1/presentations" and Forms at "v1/forms".
	// Empty means Google's own hosts; tests point it at an httptest
	// server.
	BaseURL string
	// Bounds caps page size (at most 100) and result size for every
	// tool; zero fields take the package defaults.
	Bounds connectors.Bounds
	// Timeout bounds one tool call; DefaultTimeout when zero.
	Timeout time.Duration
}

// Connector holds what the apps share: the token source, the transport,
// the bounds and the timeout. It is not a connectors.Connector itself;
// Apps returns the ones that are. Safe for concurrent use: it holds no
// per-call state and builds one API client per call.
type Connector struct {
	tokens    TokenSourceFunc
	accounts  connectors.AccountSource
	transport http.RoundTripper
	baseURL   string
	bounds    connectors.Bounds
	timeout   time.Duration

	calendar, tasks, gmail *App
	drive, docs, sheets    *App
	contacts, chat, slides *App
	forms                  *App
}

// New builds the Google connector.
func New(opts Options) (*Connector, error) {
	if opts.Tokens == nil {
		return nil, errors.New("google: Options.Tokens is required")
	}
	base := ""
	if opts.BaseURL != "" {
		u, err := url.Parse(opts.BaseURL)
		if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
			return nil, fmt.Errorf("google: BaseURL %q must be an absolute http(s) URL", opts.BaseURL)
		}
		if !strings.HasSuffix(u.Path, "/") {
			u.Path += "/"
		}
		base = u.String()
	}
	bounds := opts.Bounds
	if bounds.MaxPageSize <= 0 {
		bounds.MaxPageSize = connectors.DefaultMaxPageSize
	}
	if bounds.MaxPageSize > maxPerPage {
		bounds.MaxPageSize = maxPerPage
	}
	if bounds.MaxResultBytes <= 0 {
		bounds.MaxResultBytes = connectors.DefaultMaxResultBytes
	}
	transport := http.DefaultTransport
	if opts.HTTPClient != nil && opts.HTTPClient.Transport != nil {
		transport = opts.HTTPClient.Transport
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	c := &Connector{tokens: opts.Tokens, accounts: opts.Accounts, transport: transport, baseURL: base, bounds: bounds, timeout: timeout}
	c.calendar = c.newApp(AppCalendar,
		append(c.calendarReadTools(), c.calendarManageReadTools()...),
		slices.Concat(c.calendarWriteTools(), c.calendarManageWriteTools(), c.calendarWorkspaceWriteTools()),
		merge(c.calendarReadHandlers(), c.calendarManageReadHandlers()),
		merge(c.calendarWriteHandlers(), c.calendarManageWriteHandlers(), c.calendarWorkspaceWriteHandlers()))
	c.tasks = c.newApp(AppTasks,
		append(c.tasksReadTools(), c.tasksManageReadTools()...), append(c.tasksWriteTools(), c.tasksManageWriteTools()...),
		merge(c.tasksReadHandlers(), c.tasksManageReadHandlers()), merge(c.tasksWriteHandlers(), c.tasksManageWriteHandlers()))
	c.gmail = c.newApp(AppGmail,
		slices.Concat(c.gmailReadTools(), c.gmailManageReadTools(), c.gmailSettingsReadTools()),
		slices.Concat(c.gmailWriteTools(), c.gmailManageWriteTools(), c.gmailSettingsWriteTools(), c.gmailMessageWriteTools()),
		merge(c.gmailReadHandlers(), c.gmailManageReadHandlers(), c.gmailSettingsReadHandlers()),
		merge(c.gmailWriteHandlers(), c.gmailManageWriteHandlers(), c.gmailSettingsWriteHandlers(), c.gmailMessageWriteHandlers()))
	c.drive = c.newApp(AppDrive,
		slices.Concat(c.driveReadTools(), c.driveManageReadTools(), c.driveSharedReadTools()), append(c.driveWriteTools(), c.driveManageWriteTools()...),
		merge(c.driveReadHandlers(), c.driveManageReadHandlers(), c.driveSharedReadHandlers()), merge(c.driveWriteHandlers(), c.driveManageWriteHandlers()))
	c.docs = c.newApp(AppDocs, c.docsReadTools(), append(c.docsWriteTools(), c.docsManageWriteTools()...),
		c.docsReadHandlers(), merge(c.docsWriteHandlers(), c.docsManageWriteHandlers()))
	c.sheets = c.newApp(AppSheets,
		append(c.sheetsReadTools(), c.sheetsManageReadTools()...), append(c.sheetsWriteTools(), c.sheetsManageWriteTools()...),
		merge(c.sheetsReadHandlers(), c.sheetsManageReadHandlers()), merge(c.sheetsWriteHandlers(), c.sheetsManageWriteHandlers()))
	c.contacts = c.newApp(AppContacts,
		slices.Concat(c.contactsReadTools(), c.contactsManageReadTools(), c.contactsDirectoryReadTools()), c.contactsWriteTools(),
		merge(c.contactsReadHandlers(), c.contactsManageReadHandlers(), c.contactsDirectoryReadHandlers()), c.contactsWriteHandlers())
	c.chat = c.newApp(AppChat, c.chatReadTools(), c.chatWriteTools(), c.chatReadHandlers(), c.chatWriteHandlers())
	c.slides = c.newApp(AppSlides, c.slidesReadTools(), c.slidesWriteTools(), c.slidesReadHandlers(), c.slidesWriteHandlers())
	c.forms = c.newApp(AppForms, c.formsReadTools(), nil, c.formsReadHandlers(), nil)
	return c, nil
}

// Apps returns the connector apps in registration order (Apps):
// calendar, tasks, gmail, drive, docs, sheets, contacts, chat, slides,
// forms. Each is
// registered with connectors.RegisterConnector and mapped to Vendor with
// connections.Service.MapApp.
func (c *Connector) Apps() []*App {
	return []*App{c.calendar, c.tasks, c.gmail, c.drive, c.docs, c.sheets, c.contacts, c.chat, c.slides, c.forms}
}

// Forms returns the "forms" app (read only).
func (c *Connector) Forms() *App { return c.forms }

// Slides returns the "slides" app.
func (c *Connector) Slides() *App { return c.slides }

// Chat returns the "chat" app (Google Workspace accounts only).
func (c *Connector) Chat() *App { return c.chat }

// Drive returns the "drive" app.
func (c *Connector) Drive() *App { return c.drive }

// Docs returns the "docs" app.
func (c *Connector) Docs() *App { return c.docs }

// Sheets returns the "sheets" app.
func (c *Connector) Sheets() *App { return c.sheets }

// Contacts returns the "contacts" app.
func (c *Connector) Contacts() *App { return c.contacts }

// Calendar returns the "calendar" app.
func (c *Connector) Calendar() *App { return c.calendar }

// Tasks returns the "tasks" app.
func (c *Connector) Tasks() *App { return c.tasks }

// Gmail returns the "gmail" app.
func (c *Connector) Gmail() *App { return c.gmail }

// handler runs one tool against an authenticated client.
type handler func(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error)

// merge joins handler maps (the base tools and an app's later
// additions); names never repeat.
func merge(maps ...map[string]handler) map[string]handler {
	out := map[string]handler{}
	for _, m := range maps {
		for name, h := range m {
			out[name] = h
		}
	}
	return out
}

// App is one of the connector apps (connectors.Connector). Tools are
// declared with nil handlers: Call dispatches by name.
type App struct {
	c      *Connector
	name   string
	tools  []connectors.Tool
	byName map[string]connectors.Tool
	reads  map[string]handler
	writes map[string]handler
}

func (c *Connector) newApp(name string, readTools, writeTools []connectors.Tool, reads, writes map[string]handler) *App {
	a := &App{c: c, name: name, byName: map[string]connectors.Tool{}, reads: reads, writes: writes}
	a.tools = append(append([]connectors.Tool(nil), readTools...), writeTools...)
	for _, t := range a.tools {
		a.byName[t.Name] = t
	}
	return a
}

// App implements connectors.Connector.
func (a *App) App() string { return a.name }

// Tools implements connectors.Connector. Handlers are nil: Call
// dispatches by name (see connectors.Connector).
func (a *App) Tools() []connectors.Tool { return append([]connectors.Tool(nil), a.tools...) }

// Call implements connectors.Connector: dispatches by name, refuses a
// write without an operation id and a call without an account, applies
// the scope gate, fetches the connection's token, runs the tool under
// the timeout and maps failures (5xx and network to Unavailable for
// reads, rate limits to RateLimited, the rest to *Error).
func (a *App) Call(ctx context.Context, call connectors.Call) (connectors.Result, error) {
	name := shortName(call.Tool, a.name)
	run, ok := a.reads[name]
	write := false
	if !ok {
		run, ok = a.writes[name]
		write = true
	}
	if !ok {
		return connectors.Result{}, fmt.Errorf("%w: %q", connectors.ErrUnknownTool, call.Tool)
	}
	if write && call.OperationID == "" {
		return connectors.Result{}, ErrMissingOperation
	}
	if call.Account == "" {
		return connectors.Result{}, &Error{Class: ClassNoAccount, Message: "no connected Google account: connect one on the portal (Connections)"}
	}
	if call.Args == nil {
		call.Args = map[string]any{}
	}
	ctx, cancel := context.WithTimeout(ctx, a.c.timeout)
	defer cancel()
	if err := a.checkScopes(ctx, call, a.byName[name]); err != nil {
		return connectors.Result{}, err
	}
	res, err := run(ctx, a.c.client(call), call)
	return a.finish(write, res, err)
}

// finish turns an unreachable Google into Result{Unavailable} for reads;
// a write never does (its error says whether the outcome is known).
func (a *App) finish(write bool, res connectors.Result, err error) (connectors.Result, error) {
	if err == nil {
		return res, nil
	}
	var e *Error
	if !write && errors.As(err, &e) && e.Class == ClassUnavailable {
		return connectors.Result{Unavailable: true}, nil
	}
	return connectors.Result{}, err
}

// checkScopes is the local granular-consent gate: with an account
// source, the account's recorded scopes must cover the tool's
// RequiredScopes (Grants), or the tool must be one drive.file admits on
// the files the gateway created or the user opened with it
// (GrantsOrPerFile; Google answers not_found for the rest), unless the
// tool lists no file (wholeDriveTools: list_shared_drives). A missing
// Workspace-only scope (WorkspaceOnlyScope) is reported as one personal
// accounts cannot grant. An account the source does not list, or one
// without recorded scopes, is not blocked here (Google decides).
func (a *App) checkScopes(ctx context.Context, call connectors.Call, tool connectors.Tool) error {
	if a.c.accounts == nil || len(tool.RequiredScopes) == 0 {
		return nil
	}
	owned, err := a.c.accounts.ListAccounts(ctx, call.Principal.UserID, a.name)
	if err != nil {
		return fmt.Errorf("google: look up the account's scopes: %w", err)
	}
	for _, acct := range owned {
		if acct.ID != call.Account || len(acct.Scopes) == 0 {
			continue
		}
		for _, required := range tool.RequiredScopes {
			if toolGrants(tool, acct.Scopes, required) {
				continue
			}
			if WorkspaceOnlyScope(required) {
				return &Error{Class: ClassScopeRequired, Message: fmt.Sprintf(
					"%s needs the Google scope %s, which only Google Workspace accounts can grant: personal Google (gmail.com) accounts cannot grant it; with a Google Workspace account, grant more access on the portal (Connections)",
					call.Tool, required)}
			}
			return &Error{Class: ClassScopeRequired, Message: fmt.Sprintf(
				"%s needs the Google scope %s, which this account did not grant; grant more access on the portal (Connections) by reconnecting the account with that scope",
				call.Tool, required)}
		}
	}
	return nil
}

// client is the per-call authenticated client: the token is fetched on
// first use (after the handler validated its arguments, so an invalid
// call never touches the token source), and the API services are built
// on demand over one http.Client carrying the bearer.
type client struct {
	c    *Connector
	call connectors.Call
	http *http.Client
	base string
}

func (c *Connector) client(call connectors.Call) *client {
	return &client{c: c, call: call, base: c.baseURL}
}

// authenticate fetches the connection's token (one call to the token
// source: a refresh happens there when needed) and builds the
// authenticated http.Client, once per call.
func (cl *client) authenticate(ctx context.Context) error {
	if cl.http != nil {
		return nil
	}
	tok, err := cl.c.tokens(ctx, cl.call.Principal.UserID, cl.call.Account).Token()
	if err != nil {
		return classify("authenticate", err)
	}
	cl.http = &http.Client{Transport: &oauth2.Transport{Source: oauth2.StaticTokenSource(tok), Base: cl.c.transport}}
	return nil
}

// options are the client options every service is built with.
func (cl *client) options(suffix string) []option.ClientOption {
	opts := []option.ClientOption{option.WithHTTPClient(cl.http), option.WithUserAgent(userAgent)}
	if cl.base != "" {
		opts = append(opts, option.WithEndpoint(cl.base+suffix))
	}
	return opts
}

// calendar builds the Calendar API service.
func (cl *client) calendar(ctx context.Context) (*calendar.Service, error) {
	if err := cl.authenticate(ctx); err != nil {
		return nil, err
	}
	svc, err := calendar.NewService(ctx, cl.options("calendar/v3/")...)
	if err != nil {
		return nil, &Error{Class: ClassVendorError, Message: "calendar client: " + err.Error(), Err: err}
	}
	return svc, nil
}

// tasks builds the Tasks API service.
func (cl *client) tasks(ctx context.Context) (*tasks.Service, error) {
	if err := cl.authenticate(ctx); err != nil {
		return nil, err
	}
	svc, err := tasks.NewService(ctx, cl.options("")...)
	if err != nil {
		return nil, &Error{Class: ClassVendorError, Message: "tasks client: " + err.Error(), Err: err}
	}
	return svc, nil
}

// gmail builds the Gmail API service.
func (cl *client) gmail(ctx context.Context) (*gmail.Service, error) {
	if err := cl.authenticate(ctx); err != nil {
		return nil, err
	}
	svc, err := gmail.NewService(ctx, cl.options("")...)
	if err != nil {
		return nil, &Error{Class: ClassVendorError, Message: "gmail client: " + err.Error(), Err: err}
	}
	return svc, nil
}

// drive builds the Drive API service.
func (cl *client) drive(ctx context.Context) (*drive.Service, error) {
	if err := cl.authenticate(ctx); err != nil {
		return nil, err
	}
	svc, err := drive.NewService(ctx, cl.options("drive/v3/")...)
	if err != nil {
		return nil, &Error{Class: ClassVendorError, Message: "drive client: " + err.Error(), Err: err}
	}
	return svc, nil
}

// docs builds the Docs API service.
func (cl *client) docs(ctx context.Context) (*docs.Service, error) {
	if err := cl.authenticate(ctx); err != nil {
		return nil, err
	}
	svc, err := docs.NewService(ctx, cl.options("")...)
	if err != nil {
		return nil, &Error{Class: ClassVendorError, Message: "docs client: " + err.Error(), Err: err}
	}
	return svc, nil
}

// sheets builds the Sheets API service.
func (cl *client) sheets(ctx context.Context) (*sheets.Service, error) {
	if err := cl.authenticate(ctx); err != nil {
		return nil, err
	}
	svc, err := sheets.NewService(ctx, cl.options("")...)
	if err != nil {
		return nil, &Error{Class: ClassVendorError, Message: "sheets client: " + err.Error(), Err: err}
	}
	return svc, nil
}

// people builds the People API service (Contacts).
func (cl *client) people(ctx context.Context) (*people.Service, error) {
	if err := cl.authenticate(ctx); err != nil {
		return nil, err
	}
	svc, err := people.NewService(ctx, cl.options("")...)
	if err != nil {
		return nil, &Error{Class: ClassVendorError, Message: "people client: " + err.Error(), Err: err}
	}
	return svc, nil
}

// chat builds the Chat API service. Its base path is the host root
// (method paths start with "v1/"), so the endpoint prefix is empty.
func (cl *client) chat(ctx context.Context) (*chat.Service, error) {
	if err := cl.authenticate(ctx); err != nil {
		return nil, err
	}
	svc, err := chat.NewService(ctx, cl.options("")...)
	if err != nil {
		return nil, &Error{Class: ClassVendorError, Message: "chat client: " + err.Error(), Err: err}
	}
	return svc, nil
}

// slides builds the Slides API service. Its base path is the host root
// (method paths start with "v1/"), so the endpoint prefix is empty.
func (cl *client) slides(ctx context.Context) (*slides.Service, error) {
	if err := cl.authenticate(ctx); err != nil {
		return nil, err
	}
	svc, err := slides.NewService(ctx, cl.options("")...)
	if err != nil {
		return nil, &Error{Class: ClassVendorError, Message: "slides client: " + err.Error(), Err: err}
	}
	return svc, nil
}

// forms builds the Forms API service. Its base path is the host root
// (method paths start with "v1/"), so the endpoint prefix is empty.
func (cl *client) forms(ctx context.Context) (*forms.Service, error) {
	if err := cl.authenticate(ctx); err != nil {
		return nil, err
	}
	svc, err := forms.NewService(ctx, cl.options("")...)
	if err != nil {
		return nil, &Error{Class: ClassVendorError, Message: "forms client: " + err.Error(), Err: err}
	}
	return svc, nil
}

// shortName strips the "<app>." prefix; a tool of another app keeps its
// full name so the lookup fails.
func shortName(tool, app string) string {
	if rest, ok := strings.CutPrefix(tool, app+"."); ok {
		return rest
	}
	return tool
}
