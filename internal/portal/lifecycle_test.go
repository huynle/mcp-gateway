package portal_test

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/account"
	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/store"
)

// fakeAccount is an in-memory portal.Account.
type fakeAccount struct {
	mu        sync.Mutex
	exportErr error
	status    account.Status
	deleteErr error
	exported  []string
	deleted   []string // "self:<id>" or "<actor>:<id>"
}

func (f *fakeAccount) Export(_ context.Context, userID string, w io.Writer) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.exportErr != nil {
		return f.exportErr
	}
	f.exported = append(f.exported, userID)
	_, err := io.WriteString(w, `{"format":"test","user_id":"`+userID+`"}`)
	return err
}

func (f *fakeAccount) Status(context.Context, string) (*account.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	st := f.status
	return &st, nil
}

func (f *fakeAccount) DeleteSelf(_ context.Context, userID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.deleteErr != nil {
		return f.deleteErr
	}
	f.deleted = append(f.deleted, "self:"+userID)
	return nil
}

func (f *fakeAccount) DeleteByAdmin(_ context.Context, actorID, userID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.deleteErr != nil {
		return f.deleteErr
	}
	f.deleted = append(f.deleted, actorID+":"+userID)
	return nil
}

func (f *fakeAccount) ReauthWindow() time.Duration { return 10 * time.Minute }

func newLifecycleHarness(t *testing.T) (*harness, *fakeAccount) {
	t.Helper()
	h := newHarness(t)
	a := &fakeAccount{status: account.Status{Fresh: true}}
	h.portal.SetAccount(a)
	h.h = h.portal.Handler()
	return h, a
}

func TestAccountPageOffersExportAndDelete(t *testing.T) {
	h, _ := newLifecycleHarness(t)
	ck, _ := h.session(t, memberSub, "Member")
	body := h.do(t, request{method: http.MethodGet, path: "/account", cookie: ck}).Body.String()
	for _, want := range []string{`action="/account/export"`, `href="/account/delete"`, "Download my data"} {
		if !strings.Contains(body, want) {
			t.Errorf("My account lacks %q", want)
		}
	}
	// Without the service there is neither.
	plain := newHarness(t)
	ck2, _ := plain.session(t, memberSub, "Member")
	if b := plain.do(t, request{method: http.MethodGet, path: "/account", cookie: ck2}).Body.String(); strings.Contains(b, "/account/export") {
		t.Error("export offered without an account service")
	}
}

func TestExportDownload(t *testing.T) {
	h, a := newLifecycleHarness(t)
	ck, p := h.session(t, memberSub, "Member")
	if rec := h.do(t, request{method: http.MethodPost, path: "/account/export", cookie: ck, form: url.Values{}}); rec.Code != http.StatusForbidden {
		t.Errorf("export without CSRF = %d, want 403", rec.Code)
	}
	rec := h.do(t, request{method: http.MethodPost, path: "/account/export", cookie: ck, form: url.Values{"_csrf": {p.CSRFToken}}})
	if rec.Code != http.StatusOK {
		t.Fatalf("export = %d %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment;") || !strings.Contains(cd, ".json") {
		t.Errorf("Content-Disposition = %q", cd)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q", rec.Header().Get("Cache-Control"))
	}
	if !strings.Contains(rec.Body.String(), p.UserID) || len(a.exported) != 1 || a.exported[0] != p.UserID {
		t.Errorf("exported %v, body %s", a.exported, rec.Body.String())
	}

	a.exportErr = &account.ExportTooSoonError{RetryAfter: 4*time.Minute + 10*time.Second}
	rec = h.do(t, request{method: http.MethodPost, path: "/account/export", cookie: ck, form: url.Values{"_csrf": {p.CSRFToken}}})
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "250" {
		t.Errorf("rate limited export = %d Retry-After %q", rec.Code, rec.Header().Get("Retry-After"))
	}
	if !strings.Contains(rec.Body.String(), "5 minutes") || rec.Header().Get("Content-Disposition") != "" {
		t.Errorf("rate limit page = %s", rec.Body.String())
	}
}

func TestDeletePageStates(t *testing.T) {
	h, a := newLifecycleHarness(t)
	ck, _ := h.session(t, memberSub, "Member")
	get := func() string {
		rec := h.do(t, request{method: http.MethodGet, path: "/account/delete", cookie: ck})
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /account/delete = %d", rec.Code)
		}
		return rec.Body.String()
	}
	if b := get(); !strings.Contains(b, `action="/account/delete"`) || !strings.Contains(b, account.ConfirmPhrase) {
		t.Errorf("fresh page lacks the confirm form:\n%s", b)
	}
	a.status = account.Status{Fresh: false}
	b := get()
	if strings.Contains(b, `action="/account/delete"`) {
		t.Error("stale sign-in still shows the delete form")
	}
	if !strings.Contains(b, "/auth/dex/start?return_to=%2Faccount%2Fdelete") {
		t.Errorf("stale page lacks the re-sign-in link:\n%s", b)
	}
	a.status = account.Status{Fresh: true, Blockers: []string{"This is the last admin account."}}
	b = get()
	if strings.Contains(b, `action="/account/delete"`) || !strings.Contains(b, "This is the last admin account.") {
		t.Errorf("blocked page:\n%s", b)
	}
}

func TestDeleteSelf(t *testing.T) {
	h, a := newLifecycleHarness(t)
	ck, p := h.session(t, memberSub, "Member")
	post := func(phrase string) *http.Response {
		return h.do(t, request{method: http.MethodPost, path: "/account/delete", cookie: ck,
			form: url.Values{"_csrf": {p.CSRFToken}, "confirm": {phrase}}}).Result()
	}
	if res := post("delete it"); res.StatusCode != http.StatusUnprocessableEntity || len(a.deleted) != 0 {
		t.Errorf("wrong phrase = %d, deleted %v", res.StatusCode, a.deleted)
	}
	a.deleteErr = account.ErrReauthRequired
	if res := post(account.ConfirmPhrase); res.StatusCode != http.StatusForbidden {
		t.Errorf("stale sign-in = %d, want 403", res.StatusCode)
	}
	a.deleteErr = &account.BlockedError{Reasons: []string{"owns published servers"}}
	if res := post(account.ConfirmPhrase); res.StatusCode != http.StatusConflict {
		t.Errorf("blocked = %d, want 409", res.StatusCode)
	}
	a.deleteErr = nil
	res := post("  Delete My Account ")
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/account/deleted" {
		t.Fatalf("delete = %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	if len(a.deleted) != 1 || a.deleted[0] != "self:"+p.UserID {
		t.Errorf("deleted = %v", a.deleted)
	}
	cleared := false
	for _, c := range res.Cookies() {
		if c.Name == identity.SessionCookie && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Errorf("session cookie not cleared: %v", res.Cookies())
	}
	rec := h.do(t, request{method: http.MethodGet, path: "/account/deleted"})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "deleted") {
		t.Errorf("deleted page = %d", rec.Code)
	}
}

func TestAdminDeleteUser(t *testing.T) {
	h, a := newLifecycleHarness(t)
	member, mp := h.session(t, memberSub, "Member")
	admin, ap := h.session(t, adminSub, "Admin")
	path := "/admin/users/" + mp.UserID + "/delete"
	if rec := h.do(t, request{method: http.MethodGet, path: path, cookie: member}); rec.Code != http.StatusNotFound {
		t.Errorf("member GET admin delete = %d, want 404", rec.Code)
	}
	if rec := h.do(t, request{method: http.MethodPost, path: path, cookie: member, form: url.Values{"_csrf": {mp.CSRFToken}, "confirm": {account.AdminConfirmPhrase}}}); rec.Code != http.StatusNotFound {
		t.Errorf("member POST admin delete = %d, want 404", rec.Code)
	}
	users := h.do(t, request{method: http.MethodGet, path: "/admin/users", cookie: admin}).Body.String()
	if !strings.Contains(users, `href="`+path+`"`) || strings.Contains(users, `href="/admin/users/`+ap.UserID+`/delete"`) {
		t.Error("admin user list: delete link missing for the member or shown for the admin")
	}
	page := h.do(t, request{method: http.MethodGet, path: path, cookie: admin}).Body.String()
	if !strings.Contains(page, `action="`+path+`"`) || !strings.Contains(page, account.AdminConfirmPhrase) {
		t.Errorf("admin delete page:\n%s", page)
	}
	if rec := h.do(t, request{method: http.MethodPost, path: path, cookie: admin, form: url.Values{"_csrf": {ap.CSRFToken}, "confirm": {"nope"}}}); rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("wrong phrase = %d", rec.Code)
	}
	res := h.do(t, request{method: http.MethodPost, path: path, cookie: admin, form: url.Values{"_csrf": {ap.CSRFToken}, "confirm": {account.AdminConfirmPhrase}}}).Result()
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/admin/users" {
		t.Errorf("admin delete = %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	if len(a.deleted) != 1 || a.deleted[0] != ap.UserID+":"+mp.UserID {
		t.Errorf("deleted = %v", a.deleted)
	}
	for err, want := range map[error]int{
		account.ErrOwnAccount:                         http.StatusBadRequest,
		store.ErrNotFound:                             http.StatusNotFound,
		&account.BlockedError{Reasons: []string{"x"}}: http.StatusConflict,
	} {
		a.deleteErr = err
		if rec := h.do(t, request{method: http.MethodPost, path: path, cookie: admin, form: url.Values{"_csrf": {ap.CSRFToken}, "confirm": {account.AdminConfirmPhrase}}}); rec.Code != want {
			t.Errorf("%v = %d, want %d", err, rec.Code, want)
		}
	}
}
