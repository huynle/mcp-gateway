package tokens

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/store"
)

// Identity resolves the caller of a portal page: the session's user ID
// (empty when not signed in) and its CSRF token, which the forms echo. The
// portal module supplies it so this package never touches sessions.
type Identity func(r *http.Request) (userID, csrfToken string)

//go:embed templates/*.html
var templateFS embed.FS

// Portal serves the self-service token pages:
//
//	GET  /tokens              list (name, prefix, created, expires, last used, scope, revoke)
//	GET  /tokens/new          form
//	POST /tokens/new          create; renders the token once with harness snippets
//	POST /tokens/{id}/revoke  revoke, then back to the list
//
// It is mounted behind the portal's signed-in and CSRF checks (MountUser)
// and still refuses anonymous callers itself.
type Portal struct {
	svc     *Service
	who     Identity
	baseURL string
	log     *slog.Logger
	tpl     *template.Template
}

// NewPortal builds the pages. baseURL is GATEWAY_BASE_URL; the MCP endpoint
// in the snippets is baseURL + "/mcp".
func NewPortal(svc *Service, who Identity, baseURL string, log *slog.Logger) *Portal {
	if log == nil {
		log = slog.Default()
	}
	tpl := template.Must(template.New("").Funcs(template.FuncMap{
		"fmtTime": func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04") },
		"fmtDate": func(t time.Time) string { return t.UTC().Format("2006-01-02") },
	}).ParseFS(templateFS, "templates/*.html"))
	return &Portal{svc: svc, who: who, baseURL: strings.TrimRight(baseURL, "/"), log: log, tpl: tpl}
}

// Mount registers the routes through mount (portal.MountUser or a
// ServeMux's Handle).
func (p *Portal) Mount(mount func(pattern string, handler http.Handler)) {
	mount("GET /tokens", p.withUser(p.list))
	mount("GET /tokens/new", p.withUser(p.newForm))
	mount("POST /tokens/new", p.withUser(p.create))
	mount("POST /tokens/{id}/revoke", p.withUser(p.revoke))
}

// caller is the signed-in user as the templates see them.
type caller struct {
	UserID    string
	CSRFToken string
}

type handler func(w http.ResponseWriter, r *http.Request, c caller)

func (p *Portal) withUser(h handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID, csrfToken := p.who(r)
		if userID == "" {
			http.Error(w, "sign in to manage your tokens", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		h(w, r, caller{UserID: userID, CSRFToken: csrfToken})
	})
}

// --- pages -------------------------------------------------------------------

type listData struct {
	Title   string
	Caller  caller
	Tokens  []Info
	Now     time.Time
	Revoked bool
}

func (p *Portal) list(w http.ResponseWriter, r *http.Request, c caller) {
	list, err := p.svc.List(r.Context(), c.UserID)
	if err != nil {
		p.fail(w, r, "list tokens", err)
		return
	}
	p.render(w, r, http.StatusOK, "list.html", listData{Title: "Tokens", Caller: c, Tokens: list, Now: p.svc.now(), Revoked: r.URL.Query().Get("revoked") == "1"})
}

// formData is the new-token form, re-rendered with the user's input and
// an error on validation failure.
type formData struct {
	Title         string
	Caller        caller
	Name          string
	ExpiryDays    int
	ReadOnly      bool
	AllowList     string
	Error         string
	MaxExpiryDays int
	MaxNameLen    int
}

func (p *Portal) newForm(w http.ResponseWriter, r *http.Request, c caller) {
	p.render(w, r, http.StatusOK, "new.html", formData{Title: "New token", Caller: c, ExpiryDays: DefaultExpiryDays, MaxExpiryDays: MaxExpiryDays, MaxNameLen: MaxNameLen})
}

type createdData struct {
	Title    string
	Caller   caller
	Token    Info
	Raw      string
	Snippets Snippets
}

func (p *Portal) create(w http.ResponseWriter, r *http.Request, c caller) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "the form could not be read", http.StatusBadRequest)
		return
	}
	form := formData{
		Title:         "New token",
		Caller:        c,
		Name:          r.PostForm.Get("name"),
		ReadOnly:      r.PostForm.Get("read_only") != "",
		AllowList:     r.PostForm.Get("allow_list"),
		MaxExpiryDays: MaxExpiryDays,
		MaxNameLen:    MaxNameLen,
	}
	days := DefaultExpiryDays
	if v := strings.TrimSpace(r.PostForm.Get("expiry_days")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			form.ExpiryDays = DefaultExpiryDays
			form.Error = "Expiry must be a number of days between 1 and " + strconv.Itoa(MaxExpiryDays) + "."
			p.render(w, r, http.StatusBadRequest, "new.html", form)
			return
		}
		days = n
	}
	form.ExpiryDays = days
	created, err := p.svc.Create(r.Context(), c.UserID, CreateRequest{Name: form.Name, ExpiryDays: days, ReadOnly: form.ReadOnly, AllowList: form.AllowList})
	switch {
	case errors.Is(err, ErrInvalid):
		form.Error = userMessage(err)
		p.render(w, r, http.StatusBadRequest, "new.html", form)
		return
	case err != nil:
		p.fail(w, r, "create token", err)
		return
	}
	p.render(w, r, http.StatusOK, "created.html", createdData{Title: "Token created", Caller: c, Token: created.Token, Raw: created.Raw, Snippets: HarnessSnippets(p.baseURL, created.Raw)})
}

func (p *Portal) revoke(w http.ResponseWriter, r *http.Request, c caller) {
	err := p.svc.Revoke(r.Context(), c.UserID, r.PathValue("id"))
	switch {
	case errors.Is(err, store.ErrNotFound) || isBadUUID(err):
		http.Error(w, "no such token", http.StatusNotFound)
		return
	case err != nil:
		p.fail(w, r, "revoke token", err)
		return
	}
	http.Redirect(w, r, "/tokens?revoked=1", http.StatusSeeOther)
}

// isBadUUID recognises PostgreSQL's complaint about an id that is not a
// uuid (invalid_text_representation, 22P02): for the portal that is "no
// such token", not a server error.
func isBadUUID(err error) bool {
	return err != nil && strings.Contains(err.Error(), "22P02")
}

// userMessage strips the sentinel prefix from a validation error.
func userMessage(err error) string {
	msg := strings.TrimPrefix(err.Error(), ErrInvalid.Error()+": ")
	msg = strings.TrimPrefix(msg, "tokens: ")
	if msg == "" {
		return "The form is invalid."
	}
	return strings.ToUpper(msg[:1]) + msg[1:] + "."
}

// --- harness snippets --------------------------------------------------------

// Snippets are ready-to-paste harness configurations for one token.
type Snippets struct {
	MCPURL        string
	OpenCode      string // opencode.json
	ClaudeCode    string // .mcp.json
	ClaudeCodeCLI string // claude mcp add ...
	Curl          string
}

// HarnessSnippets renders the configurations for a token against the
// gateway at baseURL (GATEWAY_BASE_URL). Called with the raw token only on
// the one-time page.
func HarnessSnippets(baseURL, raw string) Snippets {
	mcpURL := strings.TrimRight(baseURL, "/") + "/mcp"
	auth := "Bearer " + raw
	openCode, _ := json.MarshalIndent(map[string]any{
		"$schema": "https://opencode.ai/config.json",
		"mcp": map[string]any{
			"gateway": map[string]any{
				"type":    "remote",
				"url":     mcpURL,
				"enabled": true,
				"headers": map[string]string{"Authorization": auth},
			},
		},
	}, "", "  ")
	claude, _ := json.MarshalIndent(map[string]any{
		"mcpServers": map[string]any{
			"gateway": map[string]any{
				"type":    "http",
				"url":     mcpURL,
				"headers": map[string]string{"Authorization": auth},
			},
		},
	}, "", "  ")
	return Snippets{
		MCPURL:        mcpURL,
		OpenCode:      string(openCode),
		ClaudeCode:    string(claude),
		ClaudeCodeCLI: fmt.Sprintf(`claude mcp add --transport http gateway %s --header "Authorization: %s"`, mcpURL, auth),
		Curl: fmt.Sprintf(`curl -sS %s -H "Authorization: %s" -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'`, mcpURL, auth),
	}
}

// --- rendering ---------------------------------------------------------------

func (p *Portal) render(w http.ResponseWriter, r *http.Request, status int, name string, data any) {
	var buf bytes.Buffer
	if err := p.tpl.ExecuteTemplate(&buf, name, data); err != nil {
		p.fail(w, r, "render "+name, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

func (p *Portal) fail(w http.ResponseWriter, r *http.Request, what string, err error) {
	p.log.Error("token page failed", "event", "tokens.page_failed", "what", what, "path", r.URL.Path,
		"request_id", observability.RequestIDFromContext(r.Context()), "error", observability.RedactError(err))
	http.Error(w, "the request could not be completed; try again", http.StatusInternalServerError)
}
