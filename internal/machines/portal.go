package machines

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/huynle/mcp-gateway/internal/authserver"
	"github.com/huynle/mcp-gateway/internal/caps"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/portal/nav"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

// Identity resolves the caller of a page: the signed-in (active) user's
// id ("" when none), the session's CSRF token and the admin flag.
type Identity func(r *http.Request) (userID, csrfToken string, isAdmin bool)

// HarnessGrants is the authorization server's side of /activate: harness
// device grants (RFC 8628) share the page and the user-code format with
// machine device requests. *authserver.Service implements it.
type HarnessGrants interface {
	LookupDeviceGrant(ctx context.Context, userCode string) (*authserver.DeviceGrantView, error)
	ApproveDeviceGrant(ctx context.Context, userID, id string) (*authserver.DeviceGrantView, error)
	DenyDeviceGrant(ctx context.Context, userID, id string) error
}

// Portal serves the machine pages:
//
//	GET  /activate                       enter a user code, or confirm ?code=
//	POST /activate                       action=lookup | approve | deny
//	GET  /machines                       my machines and enrollment codes
//	POST /machines/{id}/revoke           revoke my machine
//	POST /machines/codes                 create an enrollment code (shown once)
//	POST /machines/codes/{id}/revoke     revoke an unused code
//	GET  /admin/machines                 admin: every machine
//	POST /admin/machines/{id}/revoke     admin: revoke any machine
//
// The gateway mounts them through the portal (sign-in, pending users
// redirected, CSRF, admin check for /admin); every handler checks the
// caller, the CSRF token of POSTs and the admin flag again and sets
// Cache-Control: no-store and X-Frame-Options: DENY. A machine the caller
// may not touch is the 404 page.
//
// /activate confirms machine device requests and, once SetHarnessGrants
// is called, harness device grants: the code the user enters (or a
// ?code= link prefills; that only shows the request) is looked up in
// both, and the confirmation names its kind. Approving or denying is
// always a POST with the CSRF token whose request_id must belong to the
// code. Wrong codes count against the user and the client address. A
// code found in both (the store prevents it) is treated as unknown.
type Portal struct {
	svc         *Service
	id          Identity
	log         *slog.Logger
	tpl         *template.Template
	harness     HarnessGrants
	userLimiter *tokens.FailureLimiter
	ipLimiter   *tokens.FailureLimiter
	clientIP    func(*http.Request) string
}

// NewPortal builds the pages. Without svc (no machine enrollment) only
// /activate is served, for harness device grants.
func NewPortal(svc *Service, id Identity, log *slog.Logger) *Portal {
	if log == nil {
		log = slog.Default()
	}
	tpl := template.Must(nav.Setup(template.New("")).Funcs(template.FuncMap{
		"fp":       DisplayFingerprint,
		"fmtTime":  func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") },
		"fmtTimeP": fmtTimeP,
		"rowsOf": func(rows []machineRow, csrf string, admin bool) rowsView {
			return rowsView{Rows: rows, CSRF: csrf, Admin: admin}
		},
		"adminRowsOf": func(rows []machineRow, csrf string) rowsView {
			return rowsView{Rows: rows, CSRF: csrf, Admin: true, Prefix: "/admin"}
		},
	}).Parse(portalTemplates))
	p := &Portal{svc: svc, id: id, log: log, tpl: tpl, clientIP: remoteIP,
		userLimiter: tokens.NewFailureLimiter(10, time.Minute), ipLimiter: tokens.NewFailureLimiter(30, time.Minute)}
	if svc != nil {
		p.userLimiter, p.ipLimiter, p.clientIP = svc.userCodeLimiter, svc.userCodeIPLimit, svc.clientIP
	}
	return p
}

// SetHarnessGrants lets /activate confirm harness device grants too.
func (p *Portal) SetHarnessGrants(h HarnessGrants) { p.harness = h }

func fmtTimeP(t *time.Time) string {
	if t == nil {
		return "never"
	}
	return t.UTC().Format("2006-01-02 15:04 UTC")
}

// Mount registers the pages through mount (portal.MountUser or the
// gateway's admin-aware portalMount).
func (p *Portal) Mount(mount func(pattern string, h http.Handler)) {
	mount("GET "+ActivatePath, p.user(p.activateGet))
	mount("POST "+ActivatePath, p.user(p.activatePost))
	if p.svc == nil {
		return
	}
	mount("GET /machines", p.user(p.list))
	mount("POST /machines/{id}/revoke", p.user(p.revoke))
	mount("POST /machines/codes", p.user(p.createCode))
	mount("POST /machines/codes/{id}/revoke", p.user(p.revokeCode))
	mount("GET /admin/machines", p.admin(p.adminList))
	mount("POST /admin/machines/{id}/revoke", p.admin(p.adminRevoke))
}

type caller struct {
	UserID, CSRF string
	IsAdmin      bool
}

type handler func(w http.ResponseWriter, r *http.Request, c caller)

const maxPortalForm = 16 << 10

func (p *Portal) user(h handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID, token, isAdmin := p.id(r)
		if userID == "" {
			http.Error(w, "sign in first", http.StatusUnauthorized)
			return
		}
		hd := w.Header()
		hd.Set("Cache-Control", "no-store")
		hd.Set("X-Frame-Options", "DENY")
		if hd.Get("Content-Security-Policy") == "" {
			hd.Set("Content-Security-Policy", "frame-ancestors 'none'")
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			r.Body = http.MaxBytesReader(w, r.Body, maxPortalForm)
			if err := r.ParseForm(); err != nil {
				http.Error(w, "the form could not be read", http.StatusBadRequest)
				return
			}
			got := r.Header.Get("X-CSRF-Token")
			if got == "" {
				got = r.PostForm.Get("_csrf")
			}
			if token == "" || subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
				http.Error(w, "invalid or missing CSRF token; reload the page and try again", http.StatusForbidden)
				return
			}
		}
		h(w, r, caller{UserID: userID, CSRF: token, IsAdmin: isAdmin})
	})
}

func (p *Portal) admin(h handler) http.Handler {
	return p.user(func(w http.ResponseWriter, r *http.Request, c caller) {
		if !c.IsAdmin {
			p.notFound(w, r)
			return
		}
		h(w, r, c)
	})
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

func (p *Portal) notFound(w http.ResponseWriter, r *http.Request) {
	p.render(w, r, http.StatusNotFound, "message", messageData{Title: "Page not found", Message: "There is no page at this address."})
}

func (p *Portal) fail(w http.ResponseWriter, r *http.Request, what string, err error) {
	p.log.Error("machines page failed", "what", what, "path", r.URL.Path,
		"request_id", observability.RequestIDFromContext(r.Context()), "error", observability.RedactError(err))
	http.Error(w, "the request could not be completed; try again", http.StatusInternalServerError)
}

type messageData struct {
	Title, Message string
	OK             bool
	// Harness links the Harnesses page instead of Machines.
	Harness bool
}

// --- /activate -----------------------------------------------------------------------

type activateData struct {
	Title   string
	CSRF    string
	Code    string
	Error   string
	Request *requestView
	Harness *authserver.DeviceGrantView
}

type requestView struct {
	ID, Code, Name, Fingerprint, FullFingerprint, IP, ClientVersion string
	Requested                                                       time.Time
	Expires                                                         time.Time
}

// activation is what a user code confirms: a machine request or a
// harness grant.
type activation struct {
	machine *store.MachineDeviceRequest
	harness *authserver.DeviceGrantView
}

func (a *activation) id() string {
	if a.harness != nil {
		return a.harness.ID
	}
	return a.machine.ID
}

const formTitle = "Connect a machine or harness"

func (p *Portal) activateGet(w http.ResponseWriter, r *http.Request, c caller) {
	code := strings.TrimSpace(r.URL.Query().Get("code"))
	if code == "" {
		p.render(w, r, http.StatusOK, "activate", activateData{Title: formTitle, CSRF: c.CSRF})
		return
	}
	p.showRequest(w, r, c, code)
}

// lookup resolves a user code to the pending request it confirms:
// ErrTooManyAttempts while the user or the address is over its budget,
// ErrUnknownUserCode (counted against both) when neither kind has it.
func (p *Portal) lookup(r *http.Request, c caller, code string) (*activation, error) {
	ip := p.clientIP(r)
	if ok, _ := p.userLimiter.Allow(c.UserID); !ok {
		return nil, ErrTooManyAttempts
	}
	if ok, _ := p.ipLimiter.Allow(ip); !ok {
		return nil, ErrTooManyAttempts
	}
	unknown := func() (*activation, error) {
		p.userLimiter.Fail(c.UserID)
		p.ipLimiter.Fail(ip)
		return nil, ErrUnknownUserCode
	}
	n, ok := NormalizeUserCode(code)
	if !ok {
		return unknown()
	}
	var a activation
	if p.svc != nil {
		d, err := p.svc.pendingRequest(r.Context(), n)
		switch {
		case err == nil:
			a.machine = d
		case !errors.Is(err, ErrUnknownUserCode):
			return nil, err
		}
	}
	if p.harness != nil {
		v, err := p.harness.LookupDeviceGrant(r.Context(), n)
		switch {
		case err == nil:
			a.harness = v
		case !errors.Is(err, authserver.ErrDeviceGrantGone):
			return nil, err
		}
	}
	switch {
	case a.machine == nil && a.harness == nil:
		return unknown()
	case a.machine != nil && a.harness != nil:
		p.log.Warn("user code held by a machine request and a harness grant; refused", "event", "machine.user_code_ambiguous",
			"request_id", a.machine.ID, "device_grant_id", a.harness.ID)
		return nil, ErrUnknownUserCode
	}
	return &a, nil
}

// showRequest renders the confirmation page of a user code, or the form
// again with an error.
func (p *Portal) showRequest(w http.ResponseWriter, r *http.Request, c caller, code string) {
	a, err := p.lookup(r, c, code)
	data := activateData{Title: formTitle, CSRF: c.CSRF, Code: code}
	switch {
	case errors.Is(err, ErrTooManyAttempts):
		data.Error = "Too many wrong codes. Wait a minute and try again."
		p.render(w, r, http.StatusTooManyRequests, "activate", data)
		return
	case errors.Is(err, ErrUnknownUserCode):
		data.Error = "No pending request has this code. Check the code shown by mcp-gateway login or your harness; it is valid for 10 minutes."
		p.render(w, r, http.StatusOK, "activate", data)
		return
	case err != nil:
		p.fail(w, r, "lookup user code", err)
		return
	}
	if a.harness != nil {
		data.Title, data.Harness = "Connect a harness", a.harness
		p.render(w, r, http.StatusOK, "activate", data)
		return
	}
	d := a.machine
	n, _ := NormalizeUserCode(code)
	data.Title = "Connect a machine"
	data.Request = &requestView{
		ID: d.ID, Code: FormatUserCode(n), Name: d.Name, Fingerprint: DisplayFingerprint(d.Fingerprint), FullFingerprint: d.Fingerprint,
		IP: d.RequestIP, ClientVersion: d.ClientVersion, Requested: d.CreatedAt, Expires: d.ExpiresAt,
	}
	p.render(w, r, http.StatusOK, "activate", data)
}

func (p *Portal) activatePost(w http.ResponseWriter, r *http.Request, c caller) {
	code := strings.TrimSpace(r.PostForm.Get("code"))
	action := r.PostForm.Get("action")
	if action == "lookup" || action == "" {
		p.showRequest(w, r, c, code)
		return
	}
	if action != "approve" && action != "deny" {
		http.Error(w, "unknown action", http.StatusBadRequest)
		return
	}
	// The request id must belong to the code the user confirmed.
	a, err := p.lookup(r, c, code)
	switch {
	case errors.Is(err, ErrTooManyAttempts):
		p.render(w, r, http.StatusTooManyRequests, "activate", activateData{Title: formTitle, CSRF: c.CSRF, Code: code,
			Error: "Too many wrong codes. Wait a minute and try again."})
		return
	case err != nil || a.id() != r.PostForm.Get("request_id"):
		if err != nil && !errors.Is(err, ErrUnknownUserCode) {
			p.fail(w, r, "lookup user code", err)
			return
		}
		p.render(w, r, http.StatusOK, "activate", activateData{Title: formTitle, CSRF: c.CSRF, Code: code,
			Error: "This request is no longer waiting for approval. Start again on the machine or in the harness."})
		return
	}
	if a.harness != nil {
		p.decideHarness(w, r, c, a.harness, action)
		return
	}
	d := a.machine
	switch action {
	case "approve":
		m, err := p.svc.Approve(r.Context(), c.UserID, d.ID)
		var ce *caps.ExceededError
		switch {
		case errors.As(err, &ce):
			p.render(w, r, http.StatusUnprocessableEntity, "message", messageData{Title: "Machine not connected", Message: ce.Error()})
		case errors.Is(err, ErrRequestGone):
			p.render(w, r, http.StatusOK, "message", messageData{Title: "Machine not connected", Message: "This request is no longer waiting for approval. Run mcp-gateway login again."})
		case errors.Is(err, ErrInactiveOwner):
			p.render(w, r, http.StatusForbidden, "message", messageData{Title: "Machine not connected", Message: "Your account is not active."})
		case err != nil:
			p.fail(w, r, "approve machine", err)
		default:
			p.render(w, r, http.StatusOK, "message", messageData{Title: "Machine connected", OK: true,
				Message: "You approved “" + m.Name + "” (" + DisplayFingerprint(m.Fingerprint) + "). It is now your machine; mcp-gateway login finishes on its own. You can revoke it on the Machines page at any time."})
		}
	case "deny":
		if err := p.svc.Deny(r.Context(), c.UserID, d.ID); err != nil && !errors.Is(err, ErrRequestGone) {
			p.fail(w, r, "deny machine", err)
			return
		}
		p.render(w, r, http.StatusOK, "message", messageData{Title: "Request denied", Message: "The request was denied; the machine was not connected."})
	}
}

// decideHarness allows or denies a harness device grant.
func (p *Portal) decideHarness(w http.ResponseWriter, r *http.Request, c caller, g *authserver.DeviceGrantView, action string) {
	gone := messageData{Title: "Harness not connected", Harness: true, Message: "This request is no longer waiting for approval. Start the sign-in again in the harness."}
	if action == "deny" {
		err := p.harness.DenyDeviceGrant(r.Context(), c.UserID, g.ID)
		if err != nil && !errors.Is(err, authserver.ErrDeviceGrantGone) {
			p.fail(w, r, "deny harness", err)
			return
		}
		p.render(w, r, http.StatusOK, "message", messageData{Title: "Request denied", Harness: true, Message: "The request was denied; the harness was not connected."})
		return
	}
	v, err := p.harness.ApproveDeviceGrant(r.Context(), c.UserID, g.ID)
	switch {
	case errors.Is(err, authserver.ErrDeviceGrantGone):
		p.render(w, r, http.StatusOK, "message", gone)
	case err != nil:
		p.fail(w, r, "approve harness", err)
	default:
		p.render(w, r, http.StatusOK, "message", messageData{Title: "Harness connected", OK: true, Harness: true,
			Message: "You allowed “" + v.ClientName + "” (" + v.Scope + ") to use the gateway as you. It finishes signing in on its own within a few seconds. You can disconnect it on the Harnesses page at any time."})
	}
}

// --- /machines -----------------------------------------------------------------------

type machineRow struct {
	store.Machine
	Servers []string
	Online  bool
}

type codeRow struct {
	store.MachineEnrollmentCode
	State string
}

type listData struct {
	Title    string
	CSRF     string
	Notice   string
	Error    string
	BaseURL  string
	Machines []machineRow
	Codes    []codeRow
	NewCode  *newCode
	IsAdmin  bool
}

type newCode struct {
	Code, Label, Command string
	Expires              time.Time
}

func (p *Portal) rows(r *http.Request, ms []store.Machine) ([]machineRow, error) {
	out := make([]machineRow, 0, len(ms))
	for _, m := range ms {
		row := machineRow{Machine: m}
		if m.RevokedAt == nil {
			ts, err := p.svc.MachineTunnels(r.Context(), m.ID)
			if err != nil {
				return nil, err
			}
			for _, t := range ts {
				if t.RevokedAt == nil {
					row.Servers = append(row.Servers, t.ServerName)
					row.Online = row.Online || p.svc.Online(t.ID)
				}
			}
		}
		out = append(out, row)
	}
	return out, nil
}

func (p *Portal) loadList(r *http.Request, c caller) (listData, error) {
	data := listData{Title: "Machines", CSRF: c.CSRF, BaseURL: p.svc.BaseURL(), IsAdmin: c.IsAdmin}
	ms, err := p.svc.ListMachines(r.Context(), c.UserID)
	if err != nil {
		return data, err
	}
	if data.Machines, err = p.rows(r, ms); err != nil {
		return data, err
	}
	codes, err := p.svc.ListEnrollmentCodes(r.Context(), c.UserID)
	if err != nil {
		return data, err
	}
	now := p.svc.now()
	for _, cd := range codes {
		state := "unused"
		switch {
		case cd.UsedAt != nil:
			state = "used"
		case cd.RevokedAt != nil:
			state = "revoked"
		case !now.Before(cd.ExpiresAt):
			state = "expired"
		}
		data.Codes = append(data.Codes, codeRow{MachineEnrollmentCode: cd, State: state})
	}
	return data, nil
}

func (p *Portal) list(w http.ResponseWriter, r *http.Request, c caller) {
	data, err := p.loadList(r, c)
	if err != nil {
		p.fail(w, r, "list machines", err)
		return
	}
	switch {
	case r.URL.Query().Get("revoked") == "1":
		data.Notice = "Machine revoked. Its connection was closed and its servers are offline."
	case r.URL.Query().Get("code_revoked") == "1":
		data.Notice = "Enrollment code revoked."
	}
	p.render(w, r, http.StatusOK, "machines", data)
}

func (p *Portal) revoke(w http.ResponseWriter, r *http.Request, c caller) {
	err := p.svc.Revoke(r.Context(), r.PathValue("id"), c.UserID, c.UserID, store.MachineRevokedByOwner)
	if errors.Is(err, store.ErrNotFound) {
		p.notFound(w, r)
		return
	}
	if err != nil {
		p.fail(w, r, "revoke machine", err)
		return
	}
	http.Redirect(w, r, "/machines?revoked=1", http.StatusSeeOther)
}

var ttls = map[string]time.Duration{"1h": time.Hour, "24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour}

func (p *Portal) createCode(w http.ResponseWriter, r *http.Request, c caller) {
	label := strings.TrimSpace(r.PostForm.Get("label"))
	ttl, ok := ttls[r.PostForm.Get("ttl")]
	var raw string
	var code *store.MachineEnrollmentCode
	err := ErrInvalidLifetime
	if ok {
		raw, code, err = p.svc.CreateEnrollmentCode(r.Context(), c.UserID, label, ttl)
	}
	data, lerr := p.loadList(r, c)
	if lerr != nil {
		p.fail(w, r, "list machines", lerr)
		return
	}
	if err != nil {
		if errors.Is(err, ErrInvalidLifetime) || errors.Is(err, ErrTooManyCodes) || strings.HasPrefix(err.Error(), "machines: a label") {
			data.Error = strings.TrimPrefix(err.Error(), "machines: ")
			p.render(w, r, http.StatusUnprocessableEntity, "machines", data)
			return
		}
		p.fail(w, r, "create enrollment code", err)
		return
	}
	data.NewCode = &newCode{Code: raw, Label: code.Label, Expires: code.ExpiresAt,
		Command: "mcp-gateway login --gateway " + p.svc.BaseURL() + " --enroll-code " + raw}
	p.render(w, r, http.StatusOK, "machines", data)
}

func (p *Portal) revokeCode(w http.ResponseWriter, r *http.Request, c caller) {
	err := p.svc.RevokeEnrollmentCode(r.Context(), c.UserID, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		p.notFound(w, r)
		return
	}
	if err != nil {
		p.fail(w, r, "revoke enrollment code", err)
		return
	}
	http.Redirect(w, r, "/machines?code_revoked=1", http.StatusSeeOther)
}

// --- /admin/machines -----------------------------------------------------------------

func (p *Portal) adminList(w http.ResponseWriter, r *http.Request, c caller) {
	ms, err := p.svc.ListAllMachines(r.Context())
	if err != nil {
		p.fail(w, r, "list all machines", err)
		return
	}
	rows, err := p.rows(r, ms)
	if err != nil {
		p.fail(w, r, "list all machines", err)
		return
	}
	data := listData{Title: "All machines", CSRF: c.CSRF, Machines: rows, IsAdmin: true}
	if r.URL.Query().Get("revoked") == "1" {
		data.Notice = "Machine revoked."
	}
	p.render(w, r, http.StatusOK, "admin_machines", data)
}

func (p *Portal) adminRevoke(w http.ResponseWriter, r *http.Request, c caller) {
	err := p.svc.Revoke(r.Context(), r.PathValue("id"), "", c.UserID, store.MachineRevokedByAdmin)
	if errors.Is(err, store.ErrNotFound) {
		p.notFound(w, r)
		return
	}
	if err != nil {
		p.fail(w, r, "admin revoke machine", err)
		return
	}
	http.Redirect(w, r, "/admin/machines?revoked=1", http.StatusSeeOther)
}
