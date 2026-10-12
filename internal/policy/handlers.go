package policy

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/huynle/mcp-gateway/internal/portal/nav"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/store"
)

// Identity resolves the caller of an admin page: the session's user ID
// (empty when not signed in), its CSRF token (echoed by every form) and
// whether the user is an admin. The portal module supplies it so this
// package never touches sessions.
type Identity func(r *http.Request) (userID, csrfToken string, isAdmin bool)

//go:embed templates/*.html
var templateFS embed.FS

// MaxConditionRows bounds the conditional-rule rows one form may carry;
// blankConditionRows is how many empty rows the editor offers.
const (
	MaxConditionRows   = 200
	blankConditionRows = 3
)

// Portal serves the admin role pages (decision 490o45d0: roles are
// structured data; no page accepts Cedar text):
//
//	GET  /admin/roles                    list
//	GET  /admin/roles/new                editor (empty)
//	POST /admin/roles/new                create
//	GET  /admin/roles/{name}             editor
//	POST /admin/roles/{name}             update
//	POST /admin/roles/{name}/delete      delete (refused while assigned)
//	GET  /admin/settings/default-role    choose the role new users get
//	POST /admin/settings/default-role
//
// Mount it behind the portal's admin and CSRF checks (portal.MountAdmin);
// every handler also refuses non-admins itself with the same 404 a
// signed-in non-admin gets from the portal.
type Portal struct {
	svc      *Service
	registry *connectors.Registry
	who      Identity
	log      *slog.Logger
	tpl      *template.Template
}

// NewPortal builds the pages over svc; registry supplies the tool grid.
func NewPortal(svc *Service, registry *connectors.Registry, who Identity, log *slog.Logger) *Portal {
	if log == nil {
		log = slog.Default()
	}
	tpl := template.Must(nav.Setup(template.New("")).Funcs(template.FuncMap{
		"outcomes":   func() []Outcome { return []Outcome{OutcomeAllow, OutcomeConfirm, OutcomeDeny, OutcomeHidden} },
		"allowances": func() []Allowance { return []Allowance{AllowanceAllow, AllowanceConfirmWrites, AllowanceDeny} },
		"ops":        func() []Op { return []Op{OpEquals, OpPrefix, OpGlob} },
		"inc":        func(i int) int { return i + 1 },
	}).ParseFS(templateFS, "templates/*.html"))
	return &Portal{svc: svc, registry: registry, who: who, log: log, tpl: tpl}
}

// Mount registers the routes through mount (portal.MountAdmin or a
// ServeMux's Handle).
func (p *Portal) Mount(mount func(pattern string, handler http.Handler)) {
	mount("GET /admin/roles", p.admin(p.list))
	mount("GET /admin/roles/new", p.admin(p.newForm))
	mount("POST /admin/roles/new", p.admin(p.create))
	mount("GET /admin/roles/{name}", p.admin(p.editForm))
	mount("POST /admin/roles/{name}", p.admin(p.update))
	mount("POST /admin/roles/{name}/delete", p.admin(p.remove))
	mount("GET /admin/settings/default-role", p.admin(p.defaultRoleForm))
	mount("POST /admin/settings/default-role", p.admin(p.setDefaultRole))
}

// caller is the signed-in admin as the templates see them.
type caller struct {
	UserID    string
	CSRFToken string
}

type handler func(w http.ResponseWriter, r *http.Request, c caller)

// admin refuses anyone who is not a signed-in admin with a plain 404: the
// pages do not exist for them (decision 7datr7x4).
func (p *Portal) admin(h handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID, csrfToken, isAdmin := p.who(r)
		if userID == "" || !isAdmin {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		h(w, r, caller{UserID: userID, CSRFToken: csrfToken})
	})
}

// --- list ----------------------------------------------------------------------

type roleRow struct {
	StoredRole
	Rules int
}

type listData struct {
	Title   string
	Caller  caller
	Roles   []roleRow
	Version string
	Error   string
}

func (p *Portal) list(w http.ResponseWriter, r *http.Request, c caller) {
	p.renderList(w, r, c, http.StatusOK, "")
}

func (p *Portal) renderList(w http.ResponseWriter, r *http.Request, c caller, status int, errMsg string) {
	roles, err := p.svc.Roles(r.Context())
	if err != nil {
		p.fail(w, r, "list roles", err)
		return
	}
	rows := make([]roleRow, 0, len(roles))
	for _, role := range roles {
		rows = append(rows, roleRow{StoredRole: role, Rules: len(role.Rules)})
	}
	version := ""
	if cur, err := p.svc.Current(r.Context()); err == nil {
		version = cur.Version
	}
	p.render(w, r, status, "roles.html", listData{Title: "Roles", Caller: c, Roles: rows, Version: version, Error: errMsg})
}

// --- editor --------------------------------------------------------------------

// gridTool is one row of the tool grid.
type gridTool struct {
	Name     string // full "app.tool", or "app.*" for the wildcard row
	Short    string // tool name, "*" for the wildcard
	Kind     string
	Outcome  Outcome // the unconditional rule's outcome, "" for none
	Unknown  bool    // not in the registry (kept from the stored role)
	Wildcard bool
}

// gridApp groups the grid by app.
type gridApp struct {
	Name     string
	Tools    []gridTool
	Personal Allowance
}

// condRow is one conditional rule: exactly one condition per row in the
// form (the compiler accepts several; the editor keeps it simple).
type condRow struct {
	App, Tool string
	Outcome   Outcome
	Key       string
	Op        Op
	Value     string
}

type editorData struct {
	Title  string
	Caller caller
	New    bool
	Name   string
	Action string
	Role   Role
	Apps   []gridApp
	// Conds are the role's conditional rules followed by blank rows to
	// fill in; rows are numbered from 1 in the form (cond.<n>.<field>).
	Conds []condRow
	Error string
}

func (p *Portal) newForm(w http.ResponseWriter, r *http.Request, c caller) {
	p.renderEditor(w, r, c, http.StatusOK, Role{}, true, "")
}

func (p *Portal) editForm(w http.ResponseWriter, r *http.Request, c caller) {
	role, err := p.svc.Role(r.Context(), r.PathValue("name"))
	switch {
	case errors.Is(err, store.ErrNotFound):
		http.NotFound(w, r)
		return
	case err != nil:
		p.fail(w, r, "load role", err)
		return
	}
	p.renderEditor(w, r, c, http.StatusOK, role, false, "")
}

func (p *Portal) create(w http.ResponseWriter, r *http.Request, c caller) {
	role, err := p.parseForm(w, r, "")
	if err != nil {
		p.renderEditor(w, r, c, http.StatusBadRequest, role, true, userMessage(err))
		return
	}
	if _, err := p.svc.Role(r.Context(), role.Name); err == nil {
		p.renderEditor(w, r, c, http.StatusBadRequest, role, true, "A role with that name already exists.")
		return
	} else if !errors.Is(err, store.ErrNotFound) {
		p.fail(w, r, "check role", err)
		return
	}
	p.save(w, r, c, role, true)
}

func (p *Portal) update(w http.ResponseWriter, r *http.Request, c caller) {
	name := r.PathValue("name")
	if _, err := p.svc.Role(r.Context(), name); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		p.fail(w, r, "load role", err)
		return
	}
	role, err := p.parseForm(w, r, name)
	if err != nil {
		p.renderEditor(w, r, c, http.StatusBadRequest, role, false, userMessage(err))
		return
	}
	p.save(w, r, c, role, false)
}

func (p *Portal) save(w http.ResponseWriter, r *http.Request, c caller, role Role, isNew bool) {
	err := p.svc.SaveRole(r.Context(), c.UserID, role)
	switch {
	case errors.Is(err, ErrInvalidRole):
		p.renderEditor(w, r, c, http.StatusBadRequest, role, isNew, userMessage(err))
		return
	case err != nil:
		p.fail(w, r, "save role", err)
		return
	}
	http.Redirect(w, r, "/admin/roles/"+url.PathEscape(role.Name), http.StatusSeeOther)
}

func (p *Portal) remove(w http.ResponseWriter, r *http.Request, c caller) {
	name := r.PathValue("name")
	err := p.svc.DeleteRole(r.Context(), c.UserID, name)
	switch {
	case errors.Is(err, store.ErrNotFound):
		http.NotFound(w, r)
		return
	case errors.Is(err, ErrRoleAssigned):
		p.renderList(w, r, c, http.StatusConflict, fmt.Sprintf("Role %q is assigned to users; reassign them first.", name))
		return
	case err != nil:
		p.fail(w, r, "delete role", err)
		return
	}
	http.Redirect(w, r, "/admin/roles", http.StatusSeeOther)
}

// parseForm reads the structured editor fields into a Role. name, when
// set, is the role being edited (the posted name is ignored). It never
// reads anything that could be policy text.
func (p *Portal) parseForm(w http.ResponseWriter, r *http.Request, name string) (Role, error) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		return Role{}, fmt.Errorf("%w: the form could not be read", ErrInvalidRole)
	}
	role := Role{Name: name, Description: strings.TrimSpace(r.PostForm.Get("description")),
		MayAddServers: r.PostForm.Get("may_add_servers") != ""}
	if name == "" {
		role.Name = strings.ToLower(strings.TrimSpace(r.PostForm.Get("name")))
	}
	for key, values := range r.PostForm {
		if len(values) == 0 {
			continue
		}
		v := strings.TrimSpace(values[0])
		switch {
		case strings.HasPrefix(key, "outcome."):
			if v == "" {
				continue
			}
			app, tool, ok := strings.Cut(strings.TrimPrefix(key, "outcome."), ".")
			if !ok {
				continue
			}
			role.Rules = append(role.Rules, ToolRule{App: app, Tool: tool, Outcome: Outcome(v)})
		case strings.HasPrefix(key, "personal."):
			if v == "" || v == string(AllowanceAllow) {
				continue
			}
			if role.PersonalAccounts == nil {
				role.PersonalAccounts = map[string]Allowance{}
			}
			role.PersonalAccounts[strings.TrimPrefix(key, "personal.")] = Allowance(v)
		}
	}
	for i := 1; i <= MaxConditionRows; i++ {
		prefix := "cond." + strconv.Itoa(i) + "."
		app := strings.TrimSpace(r.PostForm.Get(prefix + "app"))
		tool := strings.TrimSpace(r.PostForm.Get(prefix + "tool"))
		outcome := strings.TrimSpace(r.PostForm.Get(prefix + "outcome"))
		key := strings.TrimSpace(r.PostForm.Get(prefix + "key"))
		op := strings.TrimSpace(r.PostForm.Get(prefix + "op"))
		value := strings.TrimSpace(r.PostForm.Get(prefix + "value"))
		if _, present := r.PostForm[prefix+"app"]; !present && i > 1 {
			break
		}
		if app == "" && tool == "" && key == "" && value == "" {
			continue // blank row
		}
		if app == "" || tool == "" {
			return role, fmt.Errorf("%w: conditional rule %d needs an app and a tool", ErrInvalidRole, i)
		}
		role.Rules = append(role.Rules, ToolRule{App: app, Tool: tool, Outcome: Outcome(outcome),
			Conditions: []Condition{{Key: key, Op: Op(op), Value: value}}})
	}
	role.Normalize()
	if err := role.Validate(); err != nil {
		return role, err
	}
	return role, nil
}

// renderEditor builds the grid from the registry plus whatever the role
// already names, and splits the role's rules into grid outcomes
// (unconditional) and condition rows.
func (p *Portal) renderEditor(w http.ResponseWriter, r *http.Request, c caller, status int, role Role, isNew bool, errMsg string) {
	apps := map[string]*gridApp{}
	ensureApp := func(name string) *gridApp {
		a, ok := apps[name]
		if !ok {
			a = &gridApp{Name: name, Personal: AllowanceAllow}
			a.Tools = append(a.Tools, gridTool{Name: name + ".*", Short: Wildcard, Wildcard: true})
			apps[name] = a
		}
		return a
	}
	known := map[string]bool{}
	for _, t := range p.registry.List() {
		a := ensureApp(t.App)
		a.Tools = append(a.Tools, gridTool{Name: t.FullName(), Short: t.Name, Kind: string(t.Kind)})
		known[t.FullName()] = true
	}
	var conds []condRow
	for _, rule := range role.Rules {
		a := ensureApp(rule.App)
		full := rule.App + "." + rule.Tool
		if len(rule.Conditions) > 0 {
			for _, cond := range rule.Conditions {
				conds = append(conds, condRow{App: rule.App, Tool: rule.Tool, Outcome: rule.Outcome, Key: cond.Key, Op: cond.Op, Value: cond.Value})
			}
			continue
		}
		found := false
		for i := range a.Tools {
			if a.Tools[i].Name == full {
				a.Tools[i].Outcome = rule.Outcome
				found = true
			}
		}
		if !found {
			a.Tools = append(a.Tools, gridTool{Name: full, Short: rule.Tool, Outcome: rule.Outcome, Unknown: !known[full]})
		}
	}
	for app, allowance := range role.PersonalAccounts {
		ensureApp(app).Personal = allowance
	}
	names := make([]string, 0, len(apps))
	for name := range apps {
		names = append(names, name)
	}
	sort.Strings(names)
	grid := make([]gridApp, 0, len(names))
	for _, name := range names {
		grid = append(grid, *apps[name])
	}
	title := "Edit role " + role.Name
	if isNew {
		title = "New role"
	}
	action := "/admin/roles/new"
	if !isNew {
		action = "/admin/roles/" + url.PathEscape(role.Name)
	}
	for i := 0; i < blankConditionRows; i++ {
		conds = append(conds, condRow{Outcome: OutcomeDeny, Op: OpEquals})
	}
	p.render(w, r, status, "role_edit.html", editorData{Title: title, Caller: c, New: isNew, Name: role.Name, Action: action,
		Role: role, Apps: grid, Conds: conds, Error: errMsg})
}

// --- default role ---------------------------------------------------------------

type defaultRoleData struct {
	Title   string
	Caller  caller
	Roles   []StoredRole
	Current string
	Error   string
	Saved   bool
}

func (p *Portal) defaultRoleForm(w http.ResponseWriter, r *http.Request, c caller) {
	p.renderDefaultRole(w, r, c, http.StatusOK, "")
}

func (p *Portal) renderDefaultRole(w http.ResponseWriter, r *http.Request, c caller, status int, errMsg string) {
	roles, err := p.svc.Roles(r.Context())
	if err != nil {
		p.fail(w, r, "list roles", err)
		return
	}
	current := ""
	for _, role := range roles {
		if role.IsDefault {
			current = role.Name
		}
	}
	p.render(w, r, status, "default_role.html", defaultRoleData{Title: "Default role", Caller: c, Roles: roles, Current: current, Error: errMsg, Saved: r.URL.Query().Get("saved") == "1"})
}

func (p *Portal) setDefaultRole(w http.ResponseWriter, r *http.Request, c caller) {
	name := strings.ToLower(strings.TrimSpace(r.FormValue("default_role")))
	if name == "" {
		p.renderDefaultRole(w, r, c, http.StatusBadRequest, "Choose a role.")
		return
	}
	err := p.svc.SetDefaultRole(r.Context(), c.UserID, name)
	switch {
	case errors.Is(err, store.ErrNotFound):
		p.renderDefaultRole(w, r, c, http.StatusBadRequest, "That role does not exist.")
		return
	case err != nil:
		p.fail(w, r, "set default role", err)
		return
	}
	http.Redirect(w, r, "/admin/settings/default-role?saved=1", http.StatusSeeOther)
}

// --- rendering ---------------------------------------------------------------

// userMessage strips the sentinel prefix from a validation error.
func userMessage(err error) string {
	msg := strings.TrimPrefix(err.Error(), ErrInvalidRole.Error()+": ")
	msg = strings.TrimPrefix(msg, "policy: ")
	if msg == "" {
		return "The form is invalid."
	}
	return strings.ToUpper(msg[:1]) + msg[1:] + "."
}

func (p *Portal) render(w http.ResponseWriter, r *http.Request, status int, name string, data any) {
	var buf bytes.Buffer
	if err := nav.Execute(p.tpl, r, &buf, name, data); err != nil {
		p.fail(w, r, "render "+name, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

func (p *Portal) fail(w http.ResponseWriter, r *http.Request, what string, err error) {
	p.log.Error("role page failed", "event", "policy.page_failed", "what", what, "path", r.URL.Path,
		"request_id", observability.RequestIDFromContext(r.Context()), "error", observability.RedactError(err))
	http.Error(w, "the request could not be completed; try again", http.StatusInternalServerError)
}
