package google_test

import (
	"context"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/google"
)

// Increment 5: account settings (send-as and signatures, IMAP, POP,
// auto-forwarding, forwarding addresses, language).

const (
	settingsBase       = gm + "settings/"
	sendAsPath         = "GET " + settingsBase + "sendAs"
	patchSendAsPath    = "PATCH " + settingsBase + "sendAs/alice@example.test"
	getImapPath        = "GET " + settingsBase + "imap"
	putImapPath        = "PUT " + settingsBase + "imap"
	getPopPath         = "GET " + settingsBase + "pop"
	putPopPath         = "PUT " + settingsBase + "pop"
	autoForwardingPath = "GET " + settingsBase + "autoForwarding"
	forwardingPath     = "GET " + settingsBase + "forwardingAddresses"
	getLanguagePath    = "GET " + settingsBase + "language"
	putLanguagePath    = "PUT " + settingsBase + "language"
)

func TestGmailPrefsDeclarations(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	r, w := connectors.KindRead, connectors.KindWrite
	for _, name := range []string{"list_send_as", "get_imap", "get_pop", "get_auto_forwarding", "list_forwarding_addresses", "get_language"} {
		tool := declared(t, c, "gmail."+name, r, []string{google.ScopeGmailReadonly}, "")
		if id := tool.ResourceIdentity(map[string]any{}); len(id) != 0 {
			t.Errorf("%s identity = %v, want none", name, id)
		}
	}
	sig := declared(t, c, "gmail.update_signature", w, []string{google.ScopeGmailSettingsBasic}, connectors.ReconcileNone)
	imap := declared(t, c, "gmail.update_imap", w, []string{google.ScopeGmailSettingsBasic}, connectors.ReconcileStableID)
	pop := declared(t, c, "gmail.update_pop", w, []string{google.ScopeGmailSettingsBasic}, connectors.ReconcileStableID)
	lang := declared(t, c, "gmail.update_language", w, []string{google.ScopeGmailSettingsBasic}, connectors.ReconcileStableID)

	if id := sig.ResourceIdentity(map[string]any{"send_as_email": "Alice@Example.test", "signature": "<b>secret</b>"}); id["setting"] != "signature" || id["send_as_domain"] != "example.test" || len(id) != 2 {
		t.Errorf("update_signature identity = %v", id)
	}
	if id := imap.ResourceIdentity(map[string]any{"enabled": true, "expunge_behavior": "trash", "max_folder_size": 1000}); id["setting"] != "imap" || id["enabled"] != "true" ||
		id["expunge_behavior"] != "trash" || id["max_folder_size"] != "1000" || len(id) != 4 {
		t.Errorf("update_imap identity = %v", id)
	}
	if id := pop.ResourceIdentity(map[string]any{"access_window": "allMail"}); id["setting"] != "pop" || id["access_window"] != "allMail" || len(id) != 2 {
		t.Errorf("update_pop identity = %v", id)
	}
	if id := lang.ResourceIdentity(map[string]any{"display_language": "fr"}); id["setting"] != "language" || id["display_language"] != "fr" || len(id) != 2 {
		t.Errorf("update_language identity = %v", id)
	}
}

func TestListSendAs(t *testing.T) {
	srv := newAPIServer(t, map[string]route{sendAsPath: {status: 200, body: "gmail_send_as.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("gmail.list_send_as", nil))
	if err != nil {
		t.Fatal(err)
	}
	type sendAs struct {
		SendAsEmail        string `json:"send_as_email"`
		DisplayName        string `json:"display_name"`
		ReplyTo            string `json:"reply_to"`
		Signature          string `json:"signature"`
		IsPrimary          bool   `json:"is_primary"`
		IsDefault          bool   `json:"is_default"`
		TreatAsAlias       bool   `json:"treat_as_alias"`
		VerificationStatus string `json:"verification_status"`
	}
	var page struct {
		Items     []sendAs `json:"items"`
		Truncated bool     `json:"truncated"`
	}
	decode(t, res, &page)
	if len(page.Items) != 3 || res.Empty || res.Partial {
		t.Fatalf("page = %+v, res = %+v", page, res)
	}
	p, a := page.Items[0], page.Items[1]
	if p.SendAsEmail != "alice@example.test" || !p.IsPrimary || !p.IsDefault || !strings.Contains(p.Signature, "Platform team") || p.VerificationStatus != "accepted" {
		t.Errorf("primary = %+v", p)
	}
	if a.ReplyTo != "alice@example.test" || !a.TreatAsAlias || a.IsPrimary {
		t.Errorf("alias = %+v", a)
	}
	c2, _ := newConnector(t, srv, connectors.Bounds{MaxResultBytes: 250})
	res, err = run(t, c2, call("gmail.list_send_as", nil))
	if err != nil {
		t.Fatal(err)
	}
	page.Items = nil
	decode(t, res, &page)
	if !page.Truncated || !res.Partial || len(page.Items) == 0 || len(page.Items) == 3 || encodedSizeOf(t, res) > 250 {
		t.Errorf("bounded: page = %+v (%d bytes)", page, encodedSizeOf(t, res))
	}
	for _, tc := range readErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{sendAsPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			res, err := run(t, c, call("gmail.list_send_as", nil))
			checkReadError(t, tc, res, err)
		})
	}
}

func TestUpdateSignature(t *testing.T) {
	srv := newAPIServer(t, map[string]route{patchSendAsPath: {status: 200, body: "gmail_send_as_updated.json"}})
	c, tk := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("gmail.update_signature", map[string]any{"send_as_email": "alice@example.test", "signature": "<div>New</div>"}))
	if err != nil {
		t.Fatal(err)
	}
	if body := bodyOf(t, srv.Last(t, patchSendAsPath)); body["signature"] != "<div>New</div>" || len(body) != 1 {
		t.Errorf("patch body = %v, want only the signature", body)
	}
	var out struct {
		SendAsEmail string `json:"send_as_email"`
		Updated     bool   `json:"updated"`
		Signature   string `json:"signature"`
	}
	decode(t, res, &out)
	if out.SendAsEmail != "alice@example.test" || !out.Updated || out.Signature != "" {
		t.Errorf("out = %+v (never the signature)", out)
	}
	if ids := toolOf(t, c, "gmail.update_signature").ResultIDs(res); ids["setting"] != "signature" || ids["send_as_domain"] != "example.test" {
		t.Errorf("ResultIDs = %v", ids)
	}
	// An empty signature clears it (sent explicitly).
	if _, err := run(t, c, write("gmail.update_signature", map[string]any{"send_as_email": "alice@example.test", "signature": ""})); err != nil {
		t.Fatal(err)
	}
	if body := bodyOf(t, srv.Last(t, patchSendAsPath)); body["signature"] != "" {
		t.Errorf("clear body = %v", body)
	}
	tk.calls = nil
	for name, args := range map[string]map[string]any{
		"no address":   {"signature": "x"},
		"bad address":  {"send_as_email": "nobody", "signature": "x"},
		"no signature": {"send_as_email": "alice@example.test"},
		"too long":     {"send_as_email": "alice@example.test", "signature": strings.Repeat("x", 10_001)},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := run(t, c, write("gmail.update_signature", args))
			wantClass(t, err, google.ClassInvalidArgument, 0)
		})
	}
	if len(tk.calls) != 0 {
		t.Errorf("token calls for invalid arguments = %d", len(tk.calls))
	}
	for _, tc := range writeErrorCases("gmail_send_as_updated.json") {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{patchSendAsPath: tc.rt})
			res, err := run(t, shortTimeout(t, srv), write("gmail.update_signature", map[string]any{"send_as_email": "alice@example.test", "signature": "x"}))
			checkWriteError(t, tc, res, err)
		})
	}
}

// simpleRead runs a no-argument settings read against fixture and
// decodes it into out; it also runs the read error table.
func simpleRead(t *testing.T, tool, path, fixture string, out any) connectors.Result {
	t.Helper()
	srv := newAPIServer(t, map[string]route{path: {status: 200, body: fixture}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call(tool, nil))
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	decode(t, res, out)
	for _, tc := range readErrorCases() {
		t.Run(tool+" "+tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{path: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			res, err := run(t, c, call(tool, nil))
			checkReadError(t, tc, res, err)
		})
	}
	return res
}

func TestSettingsReads(t *testing.T) {
	var imap struct {
		Enabled         bool   `json:"enabled"`
		AutoExpunge     bool   `json:"auto_expunge"`
		ExpungeBehavior string `json:"expunge_behavior"`
		MaxFolderSize   int64  `json:"max_folder_size"`
	}
	simpleRead(t, "gmail.get_imap", getImapPath, "gmail_imap_off.json", &imap)
	if imap.Enabled || !imap.AutoExpunge || imap.ExpungeBehavior != "trash" || imap.MaxFolderSize != 1000 {
		t.Errorf("imap = %+v", imap)
	}
	var pop struct {
		AccessWindow string `json:"access_window"`
		Disposition  string `json:"disposition"`
	}
	simpleRead(t, "gmail.get_pop", getPopPath, "gmail_pop_on.json", &pop)
	if pop.AccessWindow != "fromNowOn" || pop.Disposition != "archive" {
		t.Errorf("pop = %+v", pop)
	}
	var fwd struct {
		Enabled      bool   `json:"enabled"`
		EmailAddress string `json:"email_address"`
		Disposition  string `json:"disposition"`
	}
	simpleRead(t, "gmail.get_auto_forwarding", autoForwardingPath, "gmail_auto_forwarding.json", &fwd)
	if !fwd.Enabled || fwd.EmailAddress != "archive@example.test" || fwd.Disposition != "leaveInInbox" {
		t.Errorf("auto forwarding = %+v", fwd)
	}
	var addrs struct {
		Items []struct {
			ForwardingEmail    string `json:"forwarding_email"`
			VerificationStatus string `json:"verification_status"`
		} `json:"items"`
	}
	simpleRead(t, "gmail.list_forwarding_addresses", forwardingPath, "gmail_forwarding_addresses.json", &addrs)
	if len(addrs.Items) != 2 || addrs.Items[0].ForwardingEmail != "archive@example.test" || addrs.Items[1].VerificationStatus != "pending" {
		t.Errorf("forwarding addresses = %+v", addrs)
	}
	srv := newAPIServer(t, map[string]route{forwardingPath: {status: 200, body: `{}`}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("gmail.list_forwarding_addresses", nil))
	if err != nil || !res.Empty {
		t.Errorf("no forwarding addresses: res = %+v, err = %v", res, err)
	}
	var lang struct {
		DisplayLanguage string `json:"display_language"`
	}
	simpleRead(t, "gmail.get_language", getLanguagePath, "gmail_language.json", &lang)
	if lang.DisplayLanguage != "en-GB" {
		t.Errorf("language = %+v", lang)
	}
}

func TestUpdateImap(t *testing.T) {
	srv := newAPIServer(t, map[string]route{getImapPath: {status: 200, body: "gmail_imap_off.json"}, putImapPath: {status: 200, body: "gmail_imap.json"}})
	c, tk := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("gmail.update_imap", map[string]any{"enabled": true, "expunge_behavior": "archive", "max_folder_size": 0}))
	if err != nil {
		t.Fatal(err)
	}
	body := bodyOf(t, srv.Last(t, putImapPath))
	// Given fields change; the rest keeps its current value (autoExpunge
	// true); false and 0 are sent.
	if body["enabled"] != true || body["expungeBehavior"] != "archive" || body["maxFolderSize"] != float64(0) || body["autoExpunge"] != true {
		t.Errorf("body = %v", body)
	}
	var out struct {
		Enabled         bool   `json:"enabled"`
		ExpungeBehavior string `json:"expunge_behavior"`
	}
	decode(t, res, &out)
	if !out.Enabled || out.ExpungeBehavior != "archive" {
		t.Errorf("out = %+v", out)
	}
	if ids := toolOf(t, c, "gmail.update_imap").ResultIDs(res); ids["setting"] != "imap" {
		t.Errorf("ResultIDs = %v", ids)
	}
	if _, err := run(t, c, write("gmail.update_imap", map[string]any{"auto_expunge": false})); err != nil {
		t.Fatal(err)
	}
	if body := bodyOf(t, srv.Last(t, putImapPath)); body["autoExpunge"] != false || body["enabled"] != false {
		t.Errorf("body = %v, want autoExpunge false sent and enabled kept false", body)
	}
	tk.calls = nil
	for name, args := range map[string]map[string]any{
		"nothing":       {},
		"bad enabled":   {"enabled": "yes"},
		"bad behavior":  {"expunge_behavior": "shred"},
		"bad size":      {"max_folder_size": 1234},
		"size not int":  {"max_folder_size": "big"},
		"unknown field": {"enabled": true, "port": 993},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := run(t, c, write("gmail.update_imap", args))
			wantClass(t, err, google.ClassInvalidArgument, 0)
		})
	}
	if len(tk.calls) != 0 {
		t.Errorf("token calls for invalid arguments = %d", len(tk.calls))
	}
	srvGet := newAPIServer(t, map[string]route{getImapPath: {status: 500, body: "error_server.json"}})
	_, err = run(t, shortTimeout(t, srvGet), write("gmail.update_imap", map[string]any{"enabled": true}))
	wantClass(t, err, google.ClassUnavailable, 500)
	if srvGet.Count(putImapPath) != 0 {
		t.Error("update sent after the read failed")
	}
	for _, tc := range writeErrorCases("gmail_imap.json") {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{getImapPath: {status: 200, body: "gmail_imap_off.json"}, putImapPath: tc.rt})
			res, err := run(t, shortTimeout(t, srv), write("gmail.update_imap", map[string]any{"enabled": true}))
			checkWriteError(t, tc, res, err)
		})
	}
	on := map[string]any{"enabled": true, "expunge_behavior": "archive", "max_folder_size": 0}
	for name, tc := range map[string]struct {
		args map[string]any
		rt   route
		want string
	}{
		"applied":     {on, route{status: 200, body: "gmail_imap.json"}, "found"},
		"not applied": {on, route{status: 200, body: "gmail_imap_off.json"}, "not_found"},
		"one field":   {map[string]any{"auto_expunge": true}, route{status: 200, body: "gmail_imap_off.json"}, "found"},
		"500":         {on, route{status: 500, body: "error_server.json"}, "cannot"},
	} {
		t.Run("check "+name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{getImapPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			tool, in := reconcileInput(t, c, "gmail.update_imap", tc.args)
			out, err := tool.Reconcile.Check(context.Background(), in)
			wantOutcome(t, out, err, tc.want, "imap")
		})
	}
}

func TestUpdatePop(t *testing.T) {
	srv := newAPIServer(t, map[string]route{getPopPath: {status: 200, body: "gmail_pop.json"}, putPopPath: {status: 200, body: "gmail_pop_on.json"}})
	c, tk := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("gmail.update_pop", map[string]any{"access_window": "fromNowOn", "disposition": "archive"}))
	if err != nil {
		t.Fatal(err)
	}
	if body := bodyOf(t, srv.Last(t, putPopPath)); body["accessWindow"] != "fromNowOn" || body["disposition"] != "archive" {
		t.Errorf("body = %v", body)
	}
	if _, err := run(t, c, write("gmail.update_pop", map[string]any{"disposition": "trash"})); err != nil {
		t.Fatal(err)
	}
	if body := bodyOf(t, srv.Last(t, putPopPath)); body["accessWindow"] != "disabled" || body["disposition"] != "trash" {
		t.Errorf("merge body = %v", body)
	}
	if ids := toolOf(t, c, "gmail.update_pop").ResultIDs(res); ids["setting"] != "pop" {
		t.Errorf("ResultIDs = %v", ids)
	}
	tk.calls = nil
	for name, args := range map[string]map[string]any{
		"nothing":         {},
		"bad window":      {"access_window": "always"},
		"bad disposition": {"disposition": "shred"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := run(t, c, write("gmail.update_pop", args))
			wantClass(t, err, google.ClassInvalidArgument, 0)
		})
	}
	if len(tk.calls) != 0 {
		t.Errorf("token calls for invalid arguments = %d", len(tk.calls))
	}
	for _, tc := range writeErrorCases("gmail_pop_on.json") {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{getPopPath: {status: 200, body: "gmail_pop.json"}, putPopPath: tc.rt})
			res, err := run(t, shortTimeout(t, srv), write("gmail.update_pop", map[string]any{"access_window": "allMail"}))
			checkWriteError(t, tc, res, err)
		})
	}
	on := map[string]any{"access_window": "fromNowOn", "disposition": "archive"}
	for name, tc := range map[string]struct {
		rt   route
		want string
	}{
		"applied":     {route{status: 200, body: "gmail_pop_on.json"}, "found"},
		"not applied": {route{status: 200, body: "gmail_pop.json"}, "not_found"},
		"401":         {route{status: 401, body: "error_unauthorized.json"}, "cannot"},
	} {
		t.Run("check "+name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{getPopPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			tool, in := reconcileInput(t, c, "gmail.update_pop", on)
			out, err := tool.Reconcile.Check(context.Background(), in)
			wantOutcome(t, out, err, tc.want, "pop")
		})
	}
}

func TestUpdateLanguage(t *testing.T) {
	srv := newAPIServer(t, map[string]route{putLanguagePath: {status: 200, body: "gmail_language_fr.json"}})
	c, tk := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("gmail.update_language", map[string]any{"display_language": "fr"}))
	if err != nil {
		t.Fatal(err)
	}
	if body := bodyOf(t, srv.Last(t, putLanguagePath)); body["displayLanguage"] != "fr" {
		t.Errorf("body = %v", body)
	}
	var out struct {
		DisplayLanguage string `json:"display_language"`
	}
	decode(t, res, &out)
	if out.DisplayLanguage != "fr" {
		t.Errorf("out = %+v", out)
	}
	if ids := toolOf(t, c, "gmail.update_language").ResultIDs(res); ids["setting"] != "language" || ids["display_language"] != "fr" {
		t.Errorf("ResultIDs = %v", ids)
	}
	tk.calls = nil
	for _, args := range []map[string]any{{}, {"display_language": "french!"}, {"display_language": 5}} {
		_, err := run(t, c, write("gmail.update_language", args))
		wantClass(t, err, google.ClassInvalidArgument, 0)
	}
	if len(tk.calls) != 0 {
		t.Errorf("token calls for invalid arguments = %d", len(tk.calls))
	}
	for _, tc := range writeErrorCases("gmail_language_fr.json") {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{putLanguagePath: tc.rt})
			res, err := run(t, shortTimeout(t, srv), write("gmail.update_language", map[string]any{"display_language": "fr"}))
			checkWriteError(t, tc, res, err)
		})
	}
	// Gmail may store a close supported language instead of the one asked
	// for, so a different language is "cannot tell", never not_found.
	for name, tc := range map[string]struct {
		rt   route
		want string
	}{
		"applied":   {route{status: 200, body: "gmail_language_fr.json"}, "found"},
		"different": {route{status: 200, body: "gmail_language.json"}, "cannot"},
		"500":       {route{status: 500, body: "error_server.json"}, "cannot"},
	} {
		t.Run("check "+name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{getLanguagePath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			tool, in := reconcileInput(t, c, "gmail.update_language", map[string]any{"display_language": "FR"})
			out, err := tool.Reconcile.Check(context.Background(), in)
			wantOutcome(t, out, err, tc.want, "language")
		})
	}
}

// Every settings write needs gmail.settings.basic (their update methods
// accept no other scope); the reads work with gmail.readonly.
func TestGmailPrefsScopeGate(t *testing.T) {
	srv := newAPIServer(t, map[string]route{getImapPath: {status: 200, body: "gmail_imap.json"}})
	accounts := connectors.NewStaticAccountSource()
	accounts.Add(alice, connectors.Account{ID: "a3000000-0000-4000-8000-000000000001", App: google.AppGmail, Label: connectors.LabelPersonal, Scopes: []string{google.ScopeMail}})
	c, err := google.New(google.Options{Tokens: (&tokens{}).source, BaseURL: srv.URL + "/", Accounts: accounts})
	if err != nil {
		t.Fatal(err)
	}
	cl := call("gmail.get_imap", nil)
	cl.Account = "a3000000-0000-4000-8000-000000000001"
	if _, err := run(t, c, cl); err != nil {
		t.Errorf("get_imap with mail.google.com: %v", err)
	}
	for _, full := range []string{"gmail.update_signature", "gmail.update_imap", "gmail.update_pop", "gmail.update_language", "gmail.create_filter", "gmail.delete_filter"} {
		w := write(full, map[string]any{})
		w.Account = "a3000000-0000-4000-8000-000000000001"
		_, err := run(t, c, w)
		wantClass(t, err, google.ClassScopeRequired, 0)
	}
}
