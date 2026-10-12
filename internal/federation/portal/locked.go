package portal

import (
	"net/http"
	"strings"

	"github.com/huynle/mcp-gateway/internal/store"
)

// Published servers are admin-governed (Brain task mpszh6h0, decision
// q7vbxlyk point 3). The admin reviewed the server's tools for its address
// and sign-in settings; everyone it is published to sends their arguments
// there. So the owner may not change the address (URL or tunnel), the
// authentication kind, the auth config (scopes, API key placement), the
// extra headers or the static OAuth client while the server is published:
// the edit form shows them read-only and a POST that changes any of them
// is refused with lockedMessage (422). The database refuses the same
// columns on the request path (migration 00017). The owner may still
// switch between per-user and shared credentials and rotate the shared
// secret: neither changes where calls go, and stored credentials stay
// sealed to the URL (decision 4l6dik46).

// lockedMessage is shown on the read-only form and on a refused edit.
const lockedMessage = "This server is shared; ask an admin to change its address or sign-in settings."

// isLocked reports whether s's address and sign-in settings are locked for
// its owner.
func isLocked(s *store.MCPServer) bool { return s.Audience == store.MCPAudiencePublished }

// lockedField reads one locked form field from the stored form.
type lockedField struct {
	key    string
	stored func(f *serverForm) string
}

var lockedFields = []lockedField{
	{"url_mode", func(f *serverForm) string { return f.URLMode }},
	{"url", func(f *serverForm) string { return f.URL }},
	{"tunnel_id", func(f *serverForm) string { return f.TunnelID }},
	{"tunnel_path", func(f *serverForm) string { return f.TunnelPath }},
	{"auth_kind", func(f *serverForm) string { return f.AuthKind }},
	{"api_key_in", func(f *serverForm) string { return f.APIKeyIn }},
	{"api_key_name", func(f *serverForm) string { return f.APIKeyName }},
	{"scopes", func(f *serverForm) string { return f.Scopes }},
	{"static_headers", func(f *serverForm) string { return f.StaticHeaders }},
	{"per_user_headers", func(f *serverForm) string { return f.PerUserHeaders }},
	{"client_id", func(f *serverForm) string { return f.ClientID }},
	{"client_issuer", func(f *serverForm) string { return f.ClientIssuer }},
	{"client_secret", func(*serverForm) string { return "" }},
}

// normalizeField compares form values line by line, ignoring surrounding
// space and line-ending differences.
func normalizeField(v string) string { return strings.Join(lines(v), "\n") }

// lockedChange reports whether the posted form changes any locked field of
// the stored settings. Fields that are not posted keep their stored value
// (the read-only form posts only the credential mode and shared secret).
func lockedChange(r *http.Request, stored *serverForm) bool {
	for _, lf := range lockedFields {
		vals, ok := r.PostForm[lf.key]
		if !ok {
			continue
		}
		posted := ""
		if len(vals) > 0 {
			posted = vals[0]
		}
		if normalizeField(posted) != normalizeField(lf.stored(stored)) {
			return true
		}
	}
	return false
}

// saveLocked handles the owner's POST of a published server's edit form:
// any change to a locked field is refused; otherwise only the credential
// mode and a new shared secret are stored.
func (p *Portal) saveLocked(w http.ResponseWriter, r *http.Request, c caller, s *store.MCPServer, info CredentialInfo) {
	ctx := r.Context()
	stored := formFromServer(s, info)
	if lockedChange(r, &stored) {
		p.log.Info("edit of a published server refused", "event", "federation.server_edit_locked", "user_id", c.UserID, "server_id", s.ID)
		p.renderEdit(w, r, c, s, info, stored, http.StatusUnprocessableEntity, lockedMessage)
		return
	}
	posted := parseServerForm(r)
	f := stored
	if _, ok := r.PostForm["credential_mode"]; ok {
		f.CredentialMode = posted.CredentialMode
	}
	f.sharedAPIKey, f.sharedBearer, f.sharedHeaders = posted.sharedAPIKey, posted.sharedBearer, posted.sharedHeaders
	v, err := p.validate(ctx, c, &f, s, info)
	if err == nil && f.CredentialMode != s.CredentialMode {
		// Only the credential mode changes; the locked columns are
		// written back unchanged.
		next := *s
		next.CredentialMode = f.CredentialMode
		err = p.d.Store.UpdateServer(ctx, c.UserID, &next)
	}
	if err == nil {
		// Unchanged static client: never written here.
		v.client = false
		err = p.storeCredentials(ctx, c, s.ID, &f, v)
	}
	if err != nil {
		p.formSaveError(w, r, c, s, info, stored, err)
		return
	}
	p.log.Info("server edited", "event", "federation.server_edited", "user_id", c.UserID, "server_id", s.ID)
	p.changed(ctx, s.ID)
	http.Redirect(w, r, "/servers/"+s.ID+"?saved=1", http.StatusSeeOther)
}
