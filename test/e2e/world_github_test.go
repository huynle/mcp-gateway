//go:build integration || e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/github"
	"github.com/huynle/mcp-gateway/internal/policy"
	"github.com/huynle/mcp-gateway/internal/store"
)

// The GitHub world: the real GitHub connector (writes behind the whole
// safety core) against stubGitHub, an httptest stand-in for the few REST
// endpoints create_issue and its reconciliation use. The connection row
// is a real connections row of vendor github; its token comes from a
// static token source (the stub checks the bearer) rather than a stored
// bundle, so the world needs no OAuth flow.

const (
	githubStubToken = "ghu_e2e-stub-token-5a1c"
	githubLogin     = "alice-gh"
	githubTimeout   = 1500 * time.Millisecond
)

// stubFault says what the stub does with the next create_issue request.
type stubFault int

const (
	stubNormal stubFault = iota
	// stubCreateThenHang applies the write and never answers (the
	// connector times out: outcome unknown, issue exists).
	stubCreateThenHang
	// stubHangWithoutCreate never answers and applies nothing (outcome
	// unknown, issue does not exist).
	stubHangWithoutCreate
)

// stubIssue is one issue the stub holds.
type stubIssue struct {
	ID      int64    `json:"id"`
	Number  int      `json:"number"`
	Title   string   `json:"title"`
	Body    string   `json:"body"`
	State   string   `json:"state"`
	URL     string   `json:"html_url"`
	RepoURL string   `json:"repository_url"`
	User    stubUser `json:"user"`
	Labels  []struct {
		Name string `json:"name"`
	} `json:"labels"`
	repo string
}

type stubUser struct {
	Login string `json:"login"`
	ID    int64  `json:"id"`
}

// stubGitHub serves POST /repos/{o}/{r}/issues, GET /search/issues,
// GET /user and GET /repos/{o}/{r}/issues (by creator, newest first).
type stubGitHub struct {
	srv    *httptest.Server
	mu     sync.Mutex
	fault  stubFault
	issues []stubIssue
	nextID int64
	hangs  int
}

var (
	issuesRE = regexp.MustCompile(`^/repos/([^/]+)/([^/]+)/issues$`)
	phraseRE = regexp.MustCompile(`"([^"]+)"`)
	repoQRE  = regexp.MustCompile(`repo:([^\s]+)`)
)

func newStubGitHub(t *testing.T) *stubGitHub {
	t.Helper()
	s := &stubGitHub{nextID: 5000}
	s.srv = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *stubGitHub) URL() string { return s.srv.URL + "/" }

// setFault arms the fault for the next create.
func (s *stubGitHub) setFault(f stubFault) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fault = f
}

// list returns the issues of repo ("owner/name"), oldest first.
func (s *stubGitHub) list(repo string) []stubIssue {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []stubIssue
	for _, is := range s.issues {
		if is.repo == repo {
			out = append(out, is)
		}
	}
	return out
}

func (s *stubGitHub) serve(w http.ResponseWriter, r *http.Request) {
	if got := r.Header.Get("Authorization"); got != "Bearer "+githubStubToken {
		http.Error(w, `{"message":"Bad credentials"}`, http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	path := r.URL.Path
	switch {
	case r.Method == http.MethodGet && path == "/user":
		_ = json.NewEncoder(w).Encode(stubUser{Login: githubLogin, ID: 1001})
	case r.Method == http.MethodGet && path == "/search/issues":
		s.search(w, r)
	case r.Method == http.MethodPost && issuesRE.MatchString(path):
		m := issuesRE.FindStringSubmatch(path)
		s.create(w, r, m[1]+"/"+m[2])
	case r.Method == http.MethodGet && issuesRE.MatchString(path):
		m := issuesRE.FindStringSubmatch(path)
		s.listByRepo(w, r, m[1]+"/"+m[2])
	default:
		http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
	}
}

func (s *stubGitHub) create(w http.ResponseWriter, r *http.Request, repo string) {
	var in struct {
		Title     string   `json:"title"`
		Body      string   `json:"body"`
		Labels    []string `json:"labels"`
		Assignees []string `json:"assignees"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || strings.TrimSpace(in.Title) == "" {
		http.Error(w, `{"message":"Validation Failed"}`, http.StatusUnprocessableEntity)
		return
	}
	s.mu.Lock()
	fault := s.fault
	s.fault = stubNormal
	var is stubIssue
	if fault != stubHangWithoutCreate {
		s.nextID++
		is = stubIssue{
			ID: s.nextID, Number: len(s.issues) + 1, Title: in.Title, Body: in.Body, State: "open",
			URL:     "https://github.example.test/" + repo + "/issues/" + strconv.Itoa(len(s.issues)+1),
			RepoURL: s.srv.URL + "/repos/" + repo, User: stubUser{Login: githubLogin, ID: 1001}, repo: repo,
		}
		for _, l := range in.Labels {
			is.Labels = append(is.Labels, struct {
				Name string `json:"name"`
			}{l})
		}
		s.issues = append(s.issues, is)
	}
	if fault != stubNormal {
		s.hangs++
	}
	s.mu.Unlock()
	if fault != stubNormal {
		<-r.Context().Done()
		return
	}
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(is)
}

// search answers the connector's marker query: issues of the repo:
// qualifier whose body contains the quoted phrase.
func (s *stubGitHub) search(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	phrase := ""
	if m := phraseRE.FindStringSubmatch(q); m != nil {
		phrase = m[1]
	}
	repo := ""
	if m := repoQRE.FindStringSubmatch(q); m != nil {
		repo = m[1]
	}
	items := []stubIssue{}
	for _, is := range s.list(repo) {
		if phrase != "" && strings.Contains(is.Body, phrase) {
			items = append(items, is)
		}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"total_count": len(items), "incomplete_results": false, "items": items})
}

func (s *stubGitHub) listByRepo(w http.ResponseWriter, r *http.Request, repo string) {
	creator := r.URL.Query().Get("creator")
	all := s.list(repo)
	out := []stubIssue{}
	for i := len(all) - 1; i >= 0; i-- {
		if creator == "" || all[i].User.Login == creator {
			out = append(out, all[i])
		}
	}
	_ = json.NewEncoder(w).Encode(out)
}

// --- the GitHub world ---------------------------------------------------------

// githubWorld is a world with the GitHub connector registered against
// the stub, alice connected to GitHub (company account) and the member
// role granting github.create_issue: confirm in org acme, allow in org
// acme-labs, nothing elsewhere (so any other org is denied).
type githubWorld struct {
	*world
	stub    *stubGitHub
	aliceGH string // alice's GitHub connection id
}

func newGitHubWorld(t *testing.T) *githubWorld {
	t.Helper()
	stub := newStubGitHub(t)
	gw := &githubWorld{stub: stub}
	w := newWorld(t, options{register: func(reg *connectors.Registry) error {
		c, err := github.New(github.Options{
			Tokens: func(context.Context, string, string) oauth2.TokenSource {
				return oauth2.StaticTokenSource(&oauth2.Token{AccessToken: githubStubToken})
			},
			BaseURL: stub.URL(), Timeout: githubTimeout,
		})
		if err != nil {
			return err
		}
		return connectors.RegisterConnector(reg, c, gw.accounts())
	}})
	gw.world = w
	w.forbid(githubStubToken, "github stub token")
	ctx := t.Context()

	// The vendor app and alice's connection row, as the connect flow
	// would leave them (minus the token bundle).
	app := connections.Defaults(connections.VendorGitHub, "")
	app.ClientID, app.ClientSecret = "gh-cid", "gh-client-secret-e2e"
	app.Extra[connections.ExtraCompanyOrgs] = "acme"
	saved, err := w.conn.SaveVendorApp(ctx, w.admin.id, app)
	if err != nil {
		t.Fatalf("SaveVendorApp github: %v", err)
	}
	w.forbid("gh-client-secret-e2e", "github client secret")
	err = w.st.WithUser(ctx, w.alice.id, func(tx store.Tx) error {
		row := &store.Connection{
			UserID: w.alice.id, VendorAppID: saved.ID, ExternalAccountID: "github:1001",
			Label: store.AccountCompany, DisplayName: githubLogin, Status: store.ConnectionActive,
		}
		if err := tx.Connections().Create(ctx, row); err != nil {
			return err
		}
		gw.aliceGH = row.ID
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	gw.saveGitHubRules()
	return gw
}

// accounts is the account source handed to RegisterConnector: the
// connections table, as in production (the world's service is created
// inside newWorld, after the register hook is defined, hence the
// indirection).
func (gw *githubWorld) accounts() connectors.AccountSource {
	return accountSourceFunc(func(ctx context.Context, userID, app string) ([]connectors.Account, error) {
		return gw.conn.ListAccounts(ctx, userID, app)
	})
}

type accountSourceFunc func(ctx context.Context, userID, app string) ([]connectors.Account, error)

func (f accountSourceFunc) ListAccounts(ctx context.Context, userID, app string) ([]connectors.Account, error) {
	return f(ctx, userID, app)
}

// saveGitHubRules adds the GitHub rules to the member role: writes only
// in the company's organizations (confirm in acme, allow in acme-labs).
func (gw *githubWorld) saveGitHubRules() {
	gw.t.Helper()
	ctx := gw.t.Context()
	member, err := gw.policy.Role(ctx, roleMember)
	if err != nil {
		gw.t.Fatal(err)
	}
	member.Rules = append(member.Rules,
		policy.ToolRule{App: github.App, Tool: github.ToolCreateIssue, Outcome: policy.OutcomeConfirm, Conditions: []policy.Condition{{Key: "org", Op: policy.OpEquals, Value: "acme"}}},
		policy.ToolRule{App: github.App, Tool: github.ToolCreateIssue, Outcome: policy.OutcomeAllow, Conditions: []policy.Condition{{Key: "org", Op: policy.OpEquals, Value: "acme-labs"}}},
		policy.ToolRule{App: github.App, Tool: github.ToolGetMe, Outcome: policy.OutcomeAllow},
		policy.ToolRule{App: github.App, Tool: connectors.ListAccountsName, Outcome: policy.OutcomeAllow},
	)
	if err := gw.policy.SaveRole(ctx, gw.admin.id, member); err != nil {
		gw.t.Fatalf("SaveRole member: %v", err)
	}
	gw.policy.Invalidate()
}

// issueArgs builds create_issue arguments; title and body are content
// that must never reach the logs or audit rows.
func (gw *githubWorld) issueArgs(owner, repo, title, body string) map[string]any {
	gw.forbid(title, "issue title")
	gw.forbid(body, "issue body")
	return map[string]any{"owner": owner, "repo": repo, "title": title, "body": body}
}

// issueWithMarker returns the stub's issue in repo carrying the
// operation's marker, or nil.
func (gw *githubWorld) issueWithMarker(repo, operationID string) *stubIssue {
	for _, is := range gw.stub.list(repo) {
		if strings.Contains(is.Body, github.Marker(operationID)) {
			found := is
			return &found
		}
	}
	return nil
}

// resultIDs decodes a ledger row's stored result ids.
func resultIDs(t *testing.T, op *store.LedgerOperation) map[string]string {
	t.Helper()
	out := map[string]string{}
	if len(op.ResultIDs) == 0 {
		return out
	}
	if err := json.Unmarshal(op.ResultIDs, &out); err != nil {
		t.Fatalf("result ids %s: %v", op.ResultIDs, err)
	}
	return out
}

// resource decodes a ledger row's stored resource identity.
func resource(t *testing.T, op *store.LedgerOperation) map[string]string {
	t.Helper()
	out := map[string]string{}
	if len(op.Resource) == 0 {
		return out
	}
	if err := json.Unmarshal(op.Resource, &out); err != nil {
		t.Fatalf("resource %s: %v", op.Resource, err)
	}
	return out
}

// errorCode reads the ledger row's error class, "" when none.
func errorCode(op *store.LedgerOperation) string {
	if op.ErrorCode == nil {
		return ""
	}
	return *op.ErrorCode
}

// describe renders an operation row for failure messages.
func describe(op *store.LedgerOperation) string {
	if op == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s %s state=%s code=%s ids=%s", op.ID[:8], op.Tool, op.State, errorCode(op), op.ResultIDs)
}
