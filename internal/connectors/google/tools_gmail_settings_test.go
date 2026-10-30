package google_test

import (
	"context"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/google"
)

// Increment 4: Gmail settings (vacation responder, filters).

const (
	vacationPath    = "/gmail/v1/users/me/settings/vacation"
	getVacationPath = "GET " + vacationPath
	putVacationPath = "PUT " + vacationPath
	filtersPath     = "GET /gmail/v1/users/me/settings/filters"

	vacationStartMS = "1797724800000" // 2026-12-20T00:00:00Z
	vacationEndMS   = "1799020800000" // 2027-01-04T00:00:00Z
)

func TestGmailSettingsDeclarations(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	r, w := connectors.KindRead, connectors.KindWrite
	declared(t, c, "gmail.get_vacation", r, []string{google.ScopeGmailReadonly}, "")
	declared(t, c, "gmail.list_filters", r, []string{google.ScopeGmailReadonly}, "")
	set := declared(t, c, "gmail.set_vacation", w, []string{google.ScopeGmailSettingsBasic}, connectors.ReconcileStableID)
	for _, full := range []string{"gmail.get_vacation", "gmail.list_filters"} {
		if tool := toolOf(t, c, full); tool.ResourceIdentity != nil && len(tool.ResourceIdentity(map[string]any{})) != 0 {
			t.Errorf("%s identity = %v, want none", full, tool.ResourceIdentity(map[string]any{}))
		}
	}
	id := set.ResourceIdentity(map[string]any{
		"enabled": true, "subject": "secret subject", "body": "secret body",
		"start": "2026-12-20T00:00:00Z", "end": "2027-01-04T00:00:00Z", "restrict_to_domain": true,
	})
	want := map[string]string{"setting": "vacation", "enabled": "true", "start": vacationStartMS, "end": vacationEndMS, "restrict_to_domain": "true", "message": "true"}
	if len(id) != len(want) {
		t.Errorf("set_vacation identity = %v, want %v", id, want)
	}
	for k, v := range want {
		if id[k] != v {
			t.Errorf("set_vacation identity[%s] = %q, want %q (all: %v)", k, id[k], v, id)
		}
	}
	for _, v := range id {
		if strings.Contains(v, "secret") {
			t.Errorf("set_vacation identity carries content: %v", id)
		}
	}
	id = set.ResourceIdentity(map[string]any{"enabled": false, "start": ""})
	if len(id) != 3 || id["enabled"] != "false" || id["start"] != "none" || id["message"] != "" {
		t.Errorf("disable identity = %v, want setting, enabled=false, start=none", id)
	}
}

func TestGmailGetVacation(t *testing.T) {
	srv := newAPIServer(t, map[string]route{getVacationPath: {status: 200, body: "gmail_vacation.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("gmail.get_vacation", nil))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Enabled            bool   `json:"enabled"`
		Subject            string `json:"subject"`
		BodyText           string `json:"body_text"`
		BodyHTML           string `json:"body_html"`
		RestrictToContacts bool   `json:"restrict_to_contacts"`
		RestrictToDomain   bool   `json:"restrict_to_domain"`
		StartTime          string `json:"start_time"`
		EndTime            string `json:"end_time"`
		Truncated          bool   `json:"truncated"`
	}
	decode(t, res, &out)
	if !out.Enabled || out.Subject != "Out of office" || !strings.HasPrefix(out.BodyText, "I am away") || out.BodyHTML == "" ||
		out.RestrictToContacts || !out.RestrictToDomain || out.StartTime != "2026-12-20T00:00:00Z" || out.EndTime != "2027-01-04T00:00:00Z" || out.Truncated {
		t.Errorf("out = %+v", out)
	}
	if res.Partial || res.Empty {
		t.Errorf("res = %+v", res)
	}

	// Bounds: the bodies are cut (HTML first), the settings stay.
	c2, _ := newConnector(t, srv, connectors.Bounds{MaxResultBytes: 260})
	res, err = run(t, c2, call("gmail.get_vacation", nil))
	if err != nil {
		t.Fatal(err)
	}
	out.BodyHTML, out.Truncated = "", false
	decode(t, res, &out)
	if !out.Truncated || !res.Partial || out.BodyHTML != "" || out.Subject != "Out of office" || encodedSizeOf(t, res) > 260 {
		t.Errorf("bounded: out = %+v (%d bytes), partial %v", out, encodedSizeOf(t, res), res.Partial)
	}

	// Disabled, no times: empty times omitted.
	srv3 := newAPIServer(t, map[string]route{getVacationPath: {status: 200, body: "gmail_vacation_off.json"}})
	c3, _ := newConnector(t, srv3, connectors.Bounds{})
	res, err = run(t, c3, call("gmail.get_vacation", nil))
	if err != nil {
		t.Fatal(err)
	}
	out = struct {
		Enabled            bool   `json:"enabled"`
		Subject            string `json:"subject"`
		BodyText           string `json:"body_text"`
		BodyHTML           string `json:"body_html"`
		RestrictToContacts bool   `json:"restrict_to_contacts"`
		RestrictToDomain   bool   `json:"restrict_to_domain"`
		StartTime          string `json:"start_time"`
		EndTime            string `json:"end_time"`
		Truncated          bool   `json:"truncated"`
	}{}
	decode(t, res, &out)
	if out.Enabled || !out.RestrictToContacts || out.StartTime != "" || out.EndTime != "" {
		t.Errorf("off: out = %+v", out)
	}

	for _, tc := range readErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{getVacationPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			res, err := run(t, c, call("gmail.get_vacation", nil))
			checkReadError(t, tc, res, err)
		})
	}
}

func TestGmailListFilters(t *testing.T) {
	srv := newAPIServer(t, map[string]route{filtersPath: {status: 200, body: "gmail_filters.json"}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("gmail.list_filters", nil))
	if err != nil {
		t.Fatal(err)
	}
	type filter struct {
		ID       string `json:"id"`
		Criteria struct {
			From           string `json:"from"`
			To             string `json:"to"`
			Subject        string `json:"subject"`
			Query          string `json:"query"`
			NegatedQuery   string `json:"negated_query"`
			HasAttachment  bool   `json:"has_attachment"`
			ExcludeChats   bool   `json:"exclude_chats"`
			Size           int64  `json:"size"`
			SizeComparison string `json:"size_comparison"`
		} `json:"criteria"`
		Action struct {
			AddLabelIDs    []string `json:"add_label_ids"`
			RemoveLabelIDs []string `json:"remove_label_ids"`
			Forward        string   `json:"forward"`
		} `json:"action"`
	}
	var page struct {
		Items     []filter `json:"items"`
		Truncated bool     `json:"truncated"`
	}
	decode(t, res, &page)
	if len(page.Items) != 3 || res.Empty || res.Partial {
		t.Fatalf("page = %+v, res = %+v", page, res)
	}
	f1, f2 := page.Items[0], page.Items[1]
	if f1.ID != "ANe1BmjExample1" || f1.Criteria.From != "billing@vendor.example" || !f1.Criteria.HasAttachment ||
		strings.Join(f1.Action.AddLabelIDs, ",") != "Label_12" || strings.Join(f1.Action.RemoveLabelIDs, ",") != "INBOX" {
		t.Errorf("filter 1 = %+v", f1)
	}
	if f2.Criteria.Query != "list:dev.example.test" || f2.Criteria.NegatedQuery != "urgent" || f2.Criteria.Size != 1048576 ||
		f2.Criteria.SizeComparison != "larger" || !f2.Criteria.ExcludeChats || f2.Action.Forward != "archive@example.test" {
		t.Errorf("filter 2 = %+v", f2)
	}
	if page.Items[2].Criteria.To != "team@example.test" || page.Items[2].Criteria.Subject != "weekly report" {
		t.Errorf("filter 3 = %+v", page.Items[2])
	}

	// Bounds: trailing filters dropped, never below one.
	c2, _ := newConnector(t, srv, connectors.Bounds{MaxResultBytes: 300})
	res, err = run(t, c2, call("gmail.list_filters", nil))
	if err != nil {
		t.Fatal(err)
	}
	page.Items = nil
	decode(t, res, &page)
	if !page.Truncated || !res.Partial || len(page.Items) == 0 || len(page.Items) == 3 {
		t.Errorf("bounded: page = %+v, res = %+v", page, res)
	}

	srvEmpty := newAPIServer(t, map[string]route{filtersPath: {status: 200, body: "gmail_filters_empty.json"}})
	cEmpty, _ := newConnector(t, srvEmpty, connectors.Bounds{})
	res, err = run(t, cEmpty, call("gmail.list_filters", nil))
	if err != nil {
		t.Fatal(err)
	}
	page.Items = nil
	decode(t, res, &page)
	if !res.Empty || page.Items == nil || len(page.Items) != 0 {
		t.Errorf("empty: page = %+v, res = %+v (items must be [])", page, res)
	}

	for _, tc := range readErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{filtersPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			res, err := run(t, c, call("gmail.list_filters", nil))
			checkReadError(t, tc, res, err)
		})
	}
}

func TestGmailSetVacation(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		getVacationPath: {status: 200, body: "gmail_vacation_off.json"},
		putVacationPath: {status: 200, body: "gmail_vacation.json"},
	})
	c, tk := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("gmail.set_vacation", map[string]any{
		"enabled": true, "subject": "Out of office", "body": "Back on January 4.",
		"start": "2026-12-20T00:00:00Z", "end": "2027-01-04T00:00:00Z", "restrict_to_domain": true,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(tk.calls) != 1 {
		t.Errorf("token calls = %v", tk.calls)
	}
	body := bodyOf(t, srv.Last(t, putVacationPath))
	if body["enableAutoReply"] != true || body["responseSubject"] != "Out of office" || body["responseBodyPlainText"] != "Back on January 4." ||
		body["startTime"] != vacationStartMS || body["endTime"] != vacationEndMS || body["restrictToDomain"] != true {
		t.Errorf("body = %v", body)
	}
	// Omitted settings keep their current value (restrict_to_contacts was
	// true); a new plain-text body drops the old HTML body (Gmail would
	// otherwise prefer it).
	if body["restrictToContacts"] != true || body["responseBodyHtml"] != nil {
		t.Errorf("merge: body = %v", body)
	}
	var out struct {
		Enabled   bool   `json:"enabled"`
		StartTime string `json:"start_time"`
		EndTime   string `json:"end_time"`
		Subject   string `json:"subject"`
		Body      string `json:"body_text"`
	}
	decode(t, res, &out)
	if !out.Enabled || out.StartTime != "2026-12-20T00:00:00Z" || out.EndTime != "2027-01-04T00:00:00Z" || out.Subject != "" || out.Body != "" {
		t.Errorf("out = %+v (never the subject or body)", out)
	}
	if ids := toolOf(t, c, "gmail.set_vacation").ResultIDs(res); ids["setting"] != "vacation" || ids["enabled"] != "true" {
		t.Errorf("ResultIDs = %v", ids)
	}

	// Disabling sends enableAutoReply false and keeps the message; an
	// empty start clears it.
	if _, err := run(t, c, write("gmail.set_vacation", map[string]any{"enabled": false, "start": ""})); err != nil {
		t.Fatal(err)
	}
	body = bodyOf(t, srv.Last(t, putVacationPath))
	if body["enableAutoReply"] != false || body["responseSubject"] != "Old subject" || body["responseBodyPlainText"] != "Old body." || body["startTime"] != nil {
		t.Errorf("disable: body = %v", body)
	}

	cl, tk := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	for _, args := range []map[string]any{
		{},
		{"enabled": "yes"},
		{"enabled": true, "start": "tomorrow"},
		{"enabled": true, "start": "2027-01-04T00:00:00Z", "end": "2026-12-20T00:00:00Z"},
		{"enabled": true, "subject": 5},
		{"enabled": true, "body": strings.Repeat("x", google.MaxVacationBodyChars+1)},
		{"enabled": true, "restrict_to_contacts": "no"},
	} {
		_, err := run(t, cl, write("gmail.set_vacation", args))
		wantClass(t, err, google.ClassInvalidArgument, 0)
	}
	if len(tk.calls) != 0 {
		t.Errorf("token calls for invalid arguments = %d", len(tk.calls))
	}

	// The read before the update failing is a known outcome: nothing sent.
	srvGet := newAPIServer(t, map[string]route{getVacationPath: {status: 500, body: "error_server.json"}})
	_, err = run(t, shortTimeout(t, srvGet), write("gmail.set_vacation", map[string]any{"enabled": true}))
	wantClass(t, err, google.ClassUnavailable, 500)
	if srvGet.Count(putVacationPath) != 0 {
		t.Error("update sent after the read failed")
	}

	for _, tc := range writeErrorCases("gmail_vacation.json") {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{getVacationPath: {status: 200, body: "gmail_vacation_off.json"}, putVacationPath: tc.rt})
			res, err := run(t, shortTimeout(t, srv), write("gmail.set_vacation", map[string]any{"enabled": true}))
			checkWriteError(t, tc, res, err)
		})
	}
}

func TestGmailSetVacationCheck(t *testing.T) {
	enable := map[string]any{"enabled": true, "start": "2026-12-20T00:00:00Z", "end": "2027-01-04T00:00:00Z", "restrict_to_domain": true}
	withMessage := map[string]any{"enabled": true, "subject": "x", "start": "2026-12-20T00:00:00Z"}
	cases := []struct {
		name string
		args map[string]any
		rt   route
		want string
	}{
		{"state matches", enable, route{status: 200, body: "gmail_vacation.json"}, "found"},
		{"disabled as asked", map[string]any{"enabled": false}, route{status: 200, body: "gmail_vacation_off.json"}, "found"},
		{"still disabled", enable, route{status: 200, body: "gmail_vacation_off.json"}, "not_found"},
		{"other end", map[string]any{"enabled": true, "end": "2027-02-01T00:00:00Z"}, route{status: 200, body: "gmail_vacation.json"}, "not_found"},
		{"start cleared but set", map[string]any{"enabled": true, "start": ""}, route{status: 200, body: "gmail_vacation.json"}, "not_found"},
		{"matches but message unverifiable", withMessage, route{status: 200, body: "gmail_vacation.json"}, "cannot_tell"},
		{"message given, state differs", map[string]any{"enabled": false, "body": "x"}, route{status: 200, body: "gmail_vacation.json"}, "not_found"},
		{"500", enable, route{status: 500, body: "error_server.json"}, "cannot_tell"},
		{"404", enable, route{status: 404, body: "error_not_found.json"}, "cannot_tell"},
		{"401", enable, route{status: 401, body: "error_unauthorized.json"}, "cannot_tell"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{getVacationPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			tool, in := reconcileInput(t, c, "gmail.set_vacation", tc.args)
			out, err := tool.Reconcile.Check(context.Background(), in)
			wantOutcome(t, out, err, tc.want, "vacation")
		})
	}
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	tool, in := reconcileInput(t, c, "gmail.set_vacation", enable)
	in.ResourceIdentity = map[string]string{"setting": "vacation"}
	out, err := tool.Reconcile.Check(context.Background(), in)
	wantCannotTell(t, out, err)
}

// get_vacation and list_filters work with gmail.readonly (and what covers
// it); set_vacation needs gmail.settings.basic: updateVacation accepts no
// other scope, not even mail.google.com.
func TestGmailSettingsScopeGate(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		getVacationPath: {status: 200, body: "gmail_vacation.json"},
		putVacationPath: {status: 200, body: "gmail_vacation.json"},
		filtersPath:     {status: 200, body: "gmail_filters.json"},
	})
	grants := map[string][]string{
		"a2000000-0000-4000-8000-000000000001": {google.ScopeGmailReadonly},
		"a2000000-0000-4000-8000-000000000002": {google.ScopeGmailModify},
		"a2000000-0000-4000-8000-000000000003": {google.ScopeMail},
		"a2000000-0000-4000-8000-000000000004": {google.ScopeGmailSettingsBasic},
		"a2000000-0000-4000-8000-000000000005": {google.ScopeGmailReadonly, google.ScopeGmailSettingsBasic},
	}
	accounts := connectors.NewStaticAccountSource()
	for id, scopes := range grants {
		accounts.Add(alice, connectors.Account{ID: id, App: google.AppGmail, Label: connectors.LabelPersonal, Scopes: scopes})
	}
	c, err := google.New(google.Options{Tokens: (&tokens{}).source, BaseURL: srv.URL + "/", Accounts: accounts})
	if err != nil {
		t.Fatal(err)
	}
	for id, scopes := range grants {
		settings := strings.Contains(strings.Join(scopes, " "), "settings.basic")
		reads := len(scopes) > 1 || scopes[0] != google.ScopeGmailSettingsBasic
		for _, full := range []string{"gmail.get_vacation", "gmail.list_filters"} {
			cl := call(full, nil)
			cl.Account = id
			_, err := run(t, c, cl)
			if reads && err != nil {
				t.Errorf("%s with %v: %v", full, scopes, err)
			}
			if !reads {
				wantClass(t, err, google.ClassScopeRequired, 0)
			}
		}
		cl := write("gmail.set_vacation", map[string]any{"enabled": false})
		cl.Account = id
		_, err := run(t, c, cl)
		if settings && err != nil {
			t.Errorf("set_vacation with %v: %v", scopes, err)
		}
		if !settings {
			wantClass(t, err, google.ClassScopeRequired, 0)
		}
	}
	if google.Grants([]string{google.ScopeMail}, google.ScopeGmailSettingsBasic) || google.Grants([]string{google.ScopeGmailModify}, google.ScopeGmailSettingsBasic) {
		t.Error("mail.google.com / gmail.modify must not imply gmail.settings.basic (updateVacation accepts only gmail.settings.basic)")
	}
}
