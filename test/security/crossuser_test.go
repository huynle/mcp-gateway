//go:build integration || e2e || security

package security

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/approvals"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

const randomID = "9b2d1c1e-0d5b-4f8a-9a1c-5b9f3d2e1a00"

// sameAnswer asserts two wire answers are identical once the ids they
// were asked about are normalised: a foreign id must be answered exactly
// like a nonexistent one (no existence leak).
func sameAnswer(t *testing.T, what string, a, idA, b string) {
	t.Helper()
	na := strings.ReplaceAll(a, idA, "<id>")
	nb := strings.ReplaceAll(b, randomID, "<id>")
	if na != nb {
		t.Errorf("%s: foreign id and random id answered differently:\n%s\n%s", what, a, b)
	}
}

// TestSecurityCrossUserThroughConnectors: with the real GitHub and
// Slack connectors (stub vendors), nothing of alice's is reachable from
// bob's token or session, every refusal is byte-identical to the answer
// for a nonexistent id, and the vendor stubs are never called on bob's
// behalf with alice's identity.
func TestSecurityCrossUserThroughConnectors(t *testing.T) {
	w := newWorld(t, options{})
	aliceTok, bobTok := w.token(w.alice, tokens.CreateRequest{}), w.token(w.bob, tokens.CreateRequest{})
	alice, bob := w.clientWith(aliceTok), w.clientWith(bobTok)

	// --- another user's connection id as `account`, per connector -----
	for _, tc := range []struct {
		tool    string
		foreign string
		args    map[string]any
	}{
		{"github.get_me", w.aliceGH, map[string]any{}},
		{"github.search_issues", w.aliceGH, map[string]any{"q": "is:open"}},
		{"slack.list_channels", w.aliceSlack, map[string]any{}},
		{"fake.list_items", w.aliceAcc, map[string]any{}},
		// an id of the right user but the wrong app
		{"github.get_me", w.bobSlack, map[string]any{}},
	} {
		ghBefore, slBefore := w.github.count(), w.slack.count()
		withForeign := map[string]any{"account": tc.foreign}
		withRandom := map[string]any{"account": randomID}
		for k, v := range tc.args {
			withForeign[k], withRandom[k] = v, v
		}
		_, _, gotF := w.rawCall(bobTok, tc.tool, withForeign)
		_, _, gotR := w.rawCall(bobTok, tc.tool, withRandom)
		if !strings.Contains(string(gotF), "unknown account") {
			t.Errorf("%s with %s: %s", tc.tool, tc.foreign, gotF)
		}
		sameAnswer(t, tc.tool+" foreign account", stripID(gotF), tc.foreign, stripID(gotR))
		if w.github.count() != ghBefore || w.slack.count() != slBefore {
			t.Errorf("%s with a foreign account reached a vendor", tc.tool)
		}
	}

	// --- list_accounts isolation, per connector ---------------------------
	for _, tc := range []struct{ tool, own, foreign string }{
		{"github.list_accounts", w.bobGH, w.aliceGH},
		{"slack.list_accounts", w.bobSlack, w.aliceSlack},
		{"fake.list_accounts", w.bobAcc, w.aliceAcc},
	} {
		res, err := w.call(bob, tc.tool, nil)
		if err != nil {
			t.Fatalf("%s: %v", tc.tool, err)
		}
		body := text(t, res)
		if !strings.Contains(body, tc.own) || strings.Contains(body, tc.foreign) || strings.Contains(body, "alice") {
			t.Errorf("%s for bob = %s", tc.tool, body)
		}
		if strings.Contains(body, githubStubToken) || strings.Contains(body, slackUserToken) {
			t.Errorf("%s leaks a token", tc.tool)
		}
	}

	// --- approvals: alice's approval id through bob, in every state -----
	_, err := w.call(alice, "github.create_issue", map[string]any{"owner": "acme", "repo": "web", "title": "alice's"})
	pending := approvalRequired(t, err)
	// bob retries with it while pending (same tool, same args).
	_, _, gotF := w.rawCall(bobTok, "github.create_issue", map[string]any{"owner": "acme", "repo": "web", "title": "alice's", "approval_id": pending})
	_, _, gotR := w.rawCall(bobTok, "github.create_issue", map[string]any{"owner": "acme", "repo": "web", "title": "alice's", "approval_id": randomID})
	if !strings.Contains(string(gotF), "does not match") {
		t.Errorf("bob with alice's pending approval: %s", gotF)
	}
	sameAnswer(t, "pending approval", stripID(gotF), pending, stripID(gotR))
	// bob approves / denies it in the portal: 404, same as a random id.
	for _, action := range []string{"approve", "deny"} {
		codeF, _, bodyF := w.post(w.bob, "/approvals/"+pending+"/"+action, nil)
		codeR, _, bodyR := w.post(w.bob, "/approvals/"+randomID+"/"+action, nil)
		if codeF != http.StatusNotFound || codeR != http.StatusNotFound {
			t.Errorf("bob %s alice's approval: %d, random %d", action, codeF, codeR)
		}
		sameAnswer(t, "portal "+action, bodyF, pending, bodyR)
	}
	if a, err := w.approval.Get(t.Context(), w.alice.id, pending); err != nil || a.Status != approvals.StatusPending {
		t.Errorf("alice's approval after bob's attempts: %+v %v", a, err)
	}
	for _, path := range []string{"/approvals", "/approvals/history"} {
		if code, _, body := w.get(w.bob, path); code != http.StatusOK || strings.Contains(body, pending) || strings.Contains(body, "alice's") {
			t.Errorf("bob GET %s = %d shows alice's approval", path, code)
		}
	}
	// alice approves; bob retries with the approved id: still not his.
	if code, _, _ := w.post(w.alice, "/approvals/"+pending+"/approve", nil); code != http.StatusSeeOther {
		t.Fatalf("alice approve = %d", code)
	}
	ghBefore := w.github.count()
	_, _, gotF = w.rawCall(bobTok, "github.create_issue", map[string]any{"owner": "acme", "repo": "web", "title": "alice's", "approval_id": pending})
	if !strings.Contains(string(gotF), "does not match") || w.github.count() != ghBefore {
		t.Errorf("bob with alice's approved approval: %s (vendor calls %d)", gotF, w.github.count()-ghBefore)
	}
	// alice consumes it; the issue is created under alice's token only.
	res, err := w.call(alice, "github.create_issue", map[string]any{"owner": "acme", "repo": "web", "title": "drifted", "approval_id": pending})
	if err != nil || res.IsError {
		t.Fatalf("alice retry: err=%v res=%+v", err, res)
	}
	if issues := w.github.created("acme/web"); len(issues) != 1 || issues[0].Title != "alice's" {
		t.Errorf("issues = %+v, want the stored arguments once", issues)
	}
	// bob with the consumed id: the same answer as an unknown id (never
	// "already used", which would confirm it exists).
	_, _, gotF = w.rawCall(bobTok, "github.create_issue", map[string]any{"owner": "acme", "repo": "web", "title": "alice's", "approval_id": pending})
	_, _, gotR = w.rawCall(bobTok, "github.create_issue", map[string]any{"owner": "acme", "repo": "web", "title": "alice's", "approval_id": randomID})
	sameAnswer(t, "consumed approval", stripID(gotF), pending, stripID(gotR))

	// --- ledger: alice's operation and result are not bob's ---------------
	aliceOp := w.opFor(w.alice, "github.create_issue", store.LedgerSucceeded)
	if aliceOp == nil {
		t.Fatal("no alice operation")
	}
	if code, _, body := w.get(w.bob, "/operations"); code != http.StatusOK || strings.Contains(body, aliceOp.ID) || strings.Contains(body, "acme/web") {
		t.Errorf("bob GET /operations = %d shows alice's operation", code)
	}
	// bob posting the exact arguments alice posted in acme-labs (an
	// unconfirmed write) is a new operation, never a replay of hers.
	args := map[string]any{"owner": "acme-labs", "repo": "tools", "title": "shared title"}
	if res, err := w.call(alice, "github.create_issue", args); err != nil || res.IsError {
		t.Fatalf("alice acme-labs: err=%v res=%+v", err, res)
	}
	res, err = w.call(bob, "github.create_issue", args)
	if err != nil || res.IsError {
		t.Fatalf("bob acme-labs: err=%v res=%+v", err, res)
	}
	if body := text(t, res); strings.Contains(body, "replayed") {
		t.Errorf("bob replayed alice's result: %s", body)
	}
	if issues := w.github.created("acme-labs/tools"); len(issues) != 2 {
		t.Errorf("acme-labs issues = %d, want one per user", len(issues))
	}
	// And a replay of bob's own call stays bob's: it names his operation.
	res, err = w.call(bob, "github.create_issue", args)
	if err != nil || res.IsError || !strings.Contains(text(t, res), "replayed") {
		t.Fatalf("bob's replay: err=%v res=%+v", err, res)
	}
	var replay struct {
		OperationID string `json:"operation_id"`
	}
	_ = json.Unmarshal([]byte(text(t, res)), &replay)
	if op := w.opFor(w.bob, "github.create_issue", store.LedgerSucceeded); op == nil || replay.OperationID != op.ID {
		t.Errorf("replayed operation %q is not bob's", replay.OperationID)
	}

	// --- personal account where the role forbids it, on a real app --------
	// bob's restricted role denies personal fake accounts; a personal
	// GitHub account is allowed for the role but bob has none, so naming
	// alice's is unknown (above). The fake personal account is denied
	// with the policy code, and the vendor stub sees nothing.
	_, err = w.call(bob, "fake.post_note", map[string]any{"text": "home", "account": w.bobPersonal})
	_ = rpcError(t, err, mcp.CodeDenied)
	if notes := w.fake.State().Notes(w.bobPersonal); len(notes) != 0 {
		t.Errorf("personal notes = %+v", notes)
	}

	// --- portal: foreign ids on every id-bearing POST ------------------------
	aliceToken, err := w.tokens.Create(t.Context(), w.alice.id, tokens.CreateRequest{Name: "revoke-me"})
	if err != nil {
		t.Fatal(err)
	}
	w.forbid(aliceToken.Raw, "alice's token")
	family := w.oauthFamily(w.alice)
	for _, tc := range []struct{ what, path, foreign string }{
		{"token revoke", "/tokens/%s/revoke", aliceToken.Token.ID},
		{"connection disconnect", "/connections/%s/disconnect", w.aliceGH},
		{"harness revoke", "/harnesses/%s/revoke", family},
	} {
		codeF, _, bodyF := w.post(w.bob, strings.Replace(tc.path, "%s", tc.foreign, 1), nil)
		codeR, _, bodyR := w.post(w.bob, strings.Replace(tc.path, "%s", randomID, 1), nil)
		if codeF != http.StatusNotFound || codeR != http.StatusNotFound {
			t.Errorf("bob %s: foreign %d, random %d", tc.what, codeF, codeR)
		}
		sameAnswer(t, "portal "+tc.what, bodyF, tc.foreign, bodyR)
	}
	// Nothing of alice's was touched.
	if _, err := w.tokens.Authenticate(t.Context(), aliceToken.Raw); err != nil {
		t.Errorf("alice's token after bob's revoke attempt: %v", err)
	}
	if res, err := w.call(alice, "github.get_me", map[string]any{"account": w.aliceGH}); err != nil || res.IsError {
		t.Errorf("alice's GitHub connection after bob's disconnect attempt: err=%v res=%+v", err, res)
	}
	if code, _, body := w.get(w.alice, "/harnesses"); code != http.StatusOK || !strings.Contains(body, family) {
		t.Errorf("alice's harness after bob's revoke attempt: %d", code)
	}
	// bob's pages do not list alice's rows.
	for _, path := range []string{"/tokens", "/connections", "/harnesses"} {
		code, _, body := w.get(w.bob, path)
		if code != http.StatusOK {
			t.Errorf("bob GET %s = %d", path, code)
		}
		for _, foreign := range []string{aliceToken.Token.ID, aliceToken.Token.PublicID, w.aliceGH, w.aliceSlack, family, "alice-gh", "alice@acme", "revoke-me"} {
			if strings.Contains(body, foreign) {
				t.Errorf("bob GET %s shows alice's %q", path, foreign)
			}
		}
	}

	// --- audit: every attempt is on bob's rows, none on alice's ----------
	for _, ev := range w.events(w.alice) {
		if ev.EventType == "tool_call" && ev.TokenID != "" && ev.TokenID == bobTokenID(t, w, bobTok) {
			t.Errorf("bob's call audited under alice: %+v", ev)
		}
	}
}

// oauthFamily signs u's browser through the OAuth flow with a freshly
// registered public client and returns the refresh-token family id (the
// /harnesses row), the way a harness would.
func (w *world) oauthFamily(u user) string {
	w.t.Helper()
	const redirect = "http://127.0.0.1:9/cb"
	reg, _ := json.Marshal(map[string]any{"client_name": "sec-harness", "redirect_uris": []string{redirect}, "token_endpoint_auth_method": "none"})
	req, _ := http.NewRequestWithContext(w.t.Context(), http.MethodPost, w.srv.URL+"/oauth/register", bytes.NewReader(reg))
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		w.t.Fatal(err)
	}
	var client struct {
		ClientID string `json:"client_id"`
	}
	_ = json.NewDecoder(res.Body).Decode(&client)
	_ = res.Body.Close()
	if client.ClientID == "" {
		w.t.Fatalf("register: %d", res.StatusCode)
	}
	verifier := strings.Repeat("v", 43)
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"client_id": {client.ClientID}, "redirect_uri": {redirect}, "response_type": {"code"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"},
		"state": {"s"}, "scope": {"mcp"}, "resource": {baseURL + "/mcp"},
	}
	if code, _, _ := w.get(u, "/oauth/authorize?"+q.Encode()); code != http.StatusOK {
		w.t.Fatalf("authorize = %d", code)
	}
	form := url.Values{}
	for k, v := range q {
		form[k] = v
	}
	form.Set("action", "approve")
	code, h, _ := w.post(u, "/oauth/authorize/consent", form)
	if code != http.StatusSeeOther && code != http.StatusFound {
		w.t.Fatalf("consent = %d", code)
	}
	loc, _ := url.Parse(h.Get("Location"))
	authCode := loc.Query().Get("code")
	if authCode == "" {
		w.t.Fatalf("no code in %s", loc)
	}
	w.forbid(authCode, "authorization code")
	req, _ = http.NewRequestWithContext(w.t.Context(), http.MethodPost, w.srv.URL+"/oauth/token", strings.NewReader(url.Values{
		"grant_type": {"authorization_code"}, "code": {authCode}, "redirect_uri": {redirect},
		"client_id": {client.ClientID}, "code_verifier": {verifier}, "resource": {baseURL + "/mcp"},
	}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		w.t.Fatal(err)
	}
	var tok map[string]any
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	_ = json.Unmarshal(body, &tok)
	rt, _ := tok["refresh_token"].(string)
	at, _ := tok["access_token"].(string)
	if rt == "" || at == "" {
		w.t.Fatalf("token exchange = %d %s", res.StatusCode, body)
	}
	w.forbid(rt, "refresh token")
	w.forbid(at, "access token")
	_, _, page := w.get(u, "/harnesses")
	m := regexp.MustCompile(`/harnesses/([0-9a-f-]{36})/revoke`).FindStringSubmatch(page)
	if m == nil {
		w.t.Fatalf("no harness row on /harnesses:\n%s", page)
	}
	return m[1]
}

// bobTokenID returns the id of the token raw belongs to.
func bobTokenID(t *testing.T, w *world, raw string) string {
	t.Helper()
	p, err := w.tokens.Authenticate(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}
	return p.TokenID
}
