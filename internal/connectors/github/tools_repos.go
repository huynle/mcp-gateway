// Tool descriptions and argument shapes are adapted from
// github/github-mcp-server, pkg/github/repositories.go (get_file_contents,
// list_branches, list_commits, get_commit, list_tags, list_releases,
// get_latest_release, get_release_by_tag, create_or_update_file) and
// search.go (search_code, search_repositories, search_users) at commit
// eb47a99ddb866ca2b8a162920e6bda9521f33ebb, MIT License, Copyright (c)
// 2025 GitHub. Modified for mcp-gateway: flat result shapes, page bounds
// and result-size bounds, content downloads read only up to the bound,
// get_release merging the latest / by-tag lookups, resource identity, and
// a commit trailer carrying the ledger operation id for reconciliation.
// See THIRD_PARTY_NOTICES.md.

package github

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	gh "github.com/google/go-github/v90/github"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Repository tool names.
const (
	ToolGetFileContents    = "get_file_contents"
	ToolListBranches       = "list_branches"
	ToolListCommits        = "list_commits"
	ToolGetCommit          = "get_commit"
	ToolListTags           = "list_tags"
	ToolListReleases       = "list_releases"
	ToolGetRelease         = "get_release"
	ToolSearchCode         = "search_code"
	ToolSearchRepositories = "search_repositories"
	ToolSearchUsers        = "search_users"
	ToolCreateOrUpdateFile = "create_or_update_file"
)

// PermissionContentsRead is the Contents: read GitHub App permission.
const PermissionContentsRead = "contents:read"

const (
	// rawMediaType asks the contents API for the file bytes themselves.
	rawMediaType = "application/vnd.github.raw+json"
	// commitTrailerKey starts the trailer CommitTrailer builds.
	commitTrailerKey = "Mcp-Gateway-Operation: "
)

// MaxFileWriteBytes caps create_or_update_file's content (1 MiB): the
// contents API takes the whole file base64-encoded in one JSON body.
const MaxFileWriteBytes = 1 << 20

// CommitTrailer is the git trailer create_or_update_file appends to its
// commit message: "Mcp-Gateway-Operation: <operation id>". A commit
// message cannot hide an HTML comment, so the marker is a conventional
// trailer; the reconciler finds the commit by it.
func CommitTrailer(operationID string) string { return commitTrailerKey + operationID }

// repoTools declares the repository, release and search tools.
func (c *Connector) repoTools() []connectors.Tool {
	paged := connectors.Bounds{MaxPageSize: c.bounds.MaxPageSize, MaxResultBytes: c.bounds.MaxResultBytes}
	single := connectors.Bounds{MaxResultBytes: c.bounds.MaxResultBytes}
	contents := []string{PermissionContentsRead}
	read := func(name, desc string, props []property, required []string, scopes []string, ident func(map[string]any) map[string]string, b connectors.Bounds) connectors.Tool {
		return connectors.Tool{App: App, Name: name, Kind: connectors.KindRead, Description: desc, InputSchema: objectSchema(props, required),
			RequiredScopes: scopes, ResourceIdentity: ident, Bounds: b}
	}
	or := []string{"owner", "repo"}
	return []connectors.Tool{
		read(ToolGetFileContents, "Get a file or a directory listing from a GitHub repository at a branch, tag or commit (ref; the default branch when omitted). "+
			"A text file comes back as text, a binary file as base64; content is cut to fit the result bounds (truncated says so). "+
			"Give a directory path (or none for the root) to list its entries.",
			[]property{ownerProperty, repoProperty,
				{"path", "string", "Path of the file or directory in the repository; the root when omitted.", nil},
				{"ref", "string", "Branch, tag or commit sha; the default branch when omitted.", nil}},
			or, contents, pathIdentity("path", "ref"), single),
		read(ToolListBranches, "List the branches of a GitHub repository with their head commit sha and protection flag. Paginated.",
			[]property{ownerProperty, repoProperty, {"protected", "boolean", "Only protected (true) or unprotected (false) branches.", nil}, pageProperty, perPageProperty},
			or, contents, identity(false), paged),
		read(ToolListCommits, "List the commits of a GitHub repository, newest first, on a branch or from a sha (the default branch when omitted), "+
			"optionally only those touching path, by author, or in a time window. Paginated.",
			[]property{ownerProperty, repoProperty,
				{"sha", "string", "Branch name or commit sha to start from; the default branch when omitted.", nil},
				{"path", "string", "Only commits touching this file or directory.", nil},
				{"author", "string", "Only commits by this GitHub login or email address.", nil},
				{"since", "string", "Only commits after this time (ISO 8601, e.g. 2026-01-02T15:04:05Z).", nil},
				{"until", "string", "Only commits before this time (ISO 8601).", nil},
				pageProperty, perPageProperty},
			or, contents, identity(false), paged),
		read(ToolGetCommit, "Get one commit of a GitHub repository by sha (or branch / tag name): message, author, stats and the changed files with their patches "+
			"(the largest patches are dropped first to fit the result bounds).",
			[]property{ownerProperty, repoProperty, {"sha", "string", "Commit sha, branch or tag name.", nil}},
			[]string{"owner", "repo", "sha"}, contents, pathIdentity("", "sha"), single),
		read(ToolListTags, "List the git tags of a GitHub repository with the commit sha each points to. Paginated.",
			[]property{ownerProperty, repoProperty, pageProperty, perPageProperty}, or, nil, identity(false), paged),
		read(ToolListReleases, "List the releases of a GitHub repository, newest first: tag, name, draft and prerelease flags, author and dates "+
			"(use get_release for the release notes). Paginated.",
			[]property{ownerProperty, repoProperty, pageProperty, perPageProperty}, or, contents, identity(false), paged),
		read(ToolGetRelease, "Get one release of a GitHub repository with its notes: the release of tag, or the latest published release when tag is omitted.",
			[]property{ownerProperty, repoProperty, {"tag", "string", "Tag name of the release; the latest release when omitted.", nil}},
			or, contents, identity(false), single),
		read(ToolSearchCode, "Search code across GitHub with the code search syntax (e.g. 'retry language:go', 'path:src/ symbol:Upload', 'org:acme'). "+
			"Give owner and repo to limit the search to one repository. Results are limited to what the connected account can see; "+
			"GitHub allows about 10 code searches per minute.",
			[]property{{"q", "string", "Search query in GitHub code search syntax.", nil},
				{"owner", "string", "Optional repository owner; with repo, limits the search to that repository.", nil},
				{"repo", "string", "Optional repository name; with owner, limits the search to that repository.", nil},
				pageProperty, perPageProperty},
			[]string{"q"}, nil, identity(false), paged),
		read(ToolSearchRepositories, "Search GitHub repositories by name, description, topics or qualifiers (e.g. 'org:acme language:go archived:false'). "+
			"Results are limited to what the connected account can see.",
			[]property{{"q", "string", "Search query in GitHub repository search syntax.", nil},
				{"sort", "string", "Sort field: stars, forks, help-wanted-issues or updated. Default: best match.", []string{"stars", "forks", "help-wanted-issues", "updated"}},
				{"order", "string", "Sort order: asc or desc.", []string{"asc", "desc"}},
				pageProperty, perPageProperty},
			[]string{"q"}, nil, identity(false), paged),
		read(ToolSearchUsers, "Search GitHub users and organizations by login, name, location or qualifiers (e.g. 'type:user location:Berlin').",
			[]property{{"q", "string", "Search query in GitHub user search syntax.", nil},
				{"sort", "string", "Sort field: followers, repositories or joined. Default: best match.", []string{"followers", "repositories", "joined"}},
				{"order", "string", "Sort order: asc or desc.", []string{"asc", "desc"}},
				pageProperty, perPageProperty},
			[]string{"q"}, nil, identity(false), paged),
		{
			App: App, Name: ToolCreateOrUpdateFile, Kind: connectors.KindWrite,
			Description: "Create a file in a GitHub repository, or replace an existing one (pass its current blob sha from get_file_contents), " +
				"as one commit on branch (the default branch when omitted). Content is text, at most 1 MiB. Files under .github/workflows " +
				"also need the GitHub App's Workflows permission. Returns the file's blob sha and the commit sha.",
			InputSchema: objectSchema([]property{ownerProperty, repoProperty,
				{"path", "string", "Path of the file in the repository.", nil},
				{"content", "string", "The complete new file content (text).", nil},
				{"message", "string", "Commit message.", nil},
				{"branch", "string", "Branch to commit to; the default branch when omitted.", nil},
				{"sha", "string", "Blob sha of the file being replaced; required to update an existing file.", nil},
			}, []string{"owner", "repo", "path", "content", "message"}),
			RequiredScopes:   []string{PermissionContentsWrite},
			ResourceIdentity: pathIdentity("path", "branch"),
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileMarker, Check: c.checkFileCommit},
			ResultIDs:        fileResultIDs,
			Bounds:           single,
		},
	}
}

// repoHandlers maps the repository tools to their implementation.
func (c *Connector) repoHandlers() (reads, writes map[string]handler) {
	return map[string]handler{
			ToolGetFileContents: c.getFileContents, ToolListBranches: c.listBranches, ToolListCommits: c.listCommits,
			ToolGetCommit: c.getCommit, ToolListTags: c.listTags, ToolListReleases: c.listReleases, ToolGetRelease: c.getRelease,
			ToolSearchCode: c.searchCode, ToolSearchRepositories: c.searchRepositories, ToolSearchUsers: c.searchUsers,
		}, map[string]handler{
			ToolCreateOrUpdateFile: c.createOrUpdateFile,
		}
}

// pathIdentity extends identity(false) with the argument named by
// pathKey under "path" and the one named by refKey under its own name
// (both as given: paths and refs are case-sensitive).
func pathIdentity(pathKey, refKey string) func(map[string]any) map[string]string {
	base := identity(false)
	return func(args map[string]any) map[string]string {
		out := base(args)
		for _, k := range []string{pathKey, refKey} {
			if k == "" {
				continue
			}
			if v, _ := args[k].(string); strings.TrimSpace(v) != "" {
				name := k
				if k == pathKey {
					name = "path"
				}
				out[name] = strings.TrimSpace(v)
			}
		}
		return out
	}
}

// --- shared list helpers ------------------------------------------------------

// ListPage is the result of a paginated list tool.
type ListPage[T any] struct {
	Page      int  `json:"page"`
	PerPage   int  `json:"per_page"`
	HasMore   bool `json:"has_more"`
	Truncated bool `json:"truncated,omitempty"`
	Items     []T  `json:"items"`
}

// SearchResults is the result of a search tool.
type SearchResults[T any] struct {
	TotalCount        int  `json:"total_count"`
	IncompleteResults bool `json:"incomplete_results"`
	ListPage[T]
}

// fitItems drops trailing items (never below one) until size() fits max;
// it reports whether any were dropped.
func fitItems[T any](items *[]T, max int, size func() int) bool {
	dropped := false
	for size() > max && len(*items) > 1 {
		*items = (*items)[:len(*items)-1]
		dropped = true
	}
	return dropped
}

// listResult builds a bounded ListPage result.
func listResult[T any](c *Connector, items []T, page, perPage int, resp *gh.Response, clamped bool) connectors.Result {
	out := ListPage[T]{Page: page, PerPage: perPage, HasMore: resp != nil && resp.NextPage > 0, Items: items}
	if out.Items == nil {
		out.Items = []T{}
	}
	out.Truncated = fitItems(&out.Items, c.bounds.MaxResultBytes, func() int { return encodedSize(out) })
	return connectors.Result{Content: out, Empty: len(out.Items) == 0, Partial: clamped || out.Truncated}
}

// searchResult builds a bounded SearchResults result.
func searchResult[T any](c *Connector, items []T, total int, incomplete bool, page, perPage int, resp *gh.Response, clamped bool) connectors.Result {
	out := SearchResults[T]{TotalCount: total, IncompleteResults: incomplete, ListPage: ListPage[T]{Page: page, PerPage: perPage, HasMore: resp != nil && resp.NextPage > 0, Items: items}}
	if out.Items == nil {
		out.Items = []T{}
	}
	out.Truncated = fitItems(&out.Items, c.bounds.MaxResultBytes, func() int { return encodedSize(out) })
	return connectors.Result{Content: out, Empty: len(out.Items) == 0, Partial: clamped || incomplete || out.Truncated}
}

// queryArg reads the required search query.
func queryArg(args map[string]any) (string, error) {
	q, _ := args["q"].(string)
	if q = strings.TrimSpace(q); q == "" {
		return "", invalid("q is required: a GitHub search query")
	}
	return q, nil
}

// repoPath validates a repository path: no leading or trailing slash
// matters, "." and ".." segments are refused.
func repoPath(raw string) (string, error) {
	p := strings.Trim(strings.TrimSpace(raw), "/")
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." || seg == "." {
			return "", invalid("path must not contain . or .. segments")
		}
	}
	return p, nil
}

// timeArg parses an optional RFC 3339 time argument.
func timeArg(args map[string]any, name string) (time.Time, error) {
	s, err := optionalString(args, name)
	if err != nil || strings.TrimSpace(s) == "" {
		return time.Time{}, err
	}
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(s))
	if err != nil {
		return time.Time{}, invalid("%s must be an ISO 8601 time such as 2026-01-02T15:04:05Z", name)
	}
	return t, nil
}

// optionalBool reads an optional boolean argument (nil when absent).
func optionalBool(args map[string]any, name string) (*bool, error) {
	v, ok := args[name]
	if !ok || v == nil {
		return nil, nil
	}
	b, ok := v.(bool)
	if !ok {
		return nil, invalid("%s must be a boolean", name)
	}
	return &b, nil
}

// rawGet fetches path (relative to the API root) with the given Accept
// header and reads at most limit bytes of the body; truncated says more
// was there. The request goes through the authenticated client, so it
// never leaves the API host.
func rawGet(ctx context.Context, client *gh.Client, path, accept string, limit int) (body []byte, truncated bool, err error) {
	req, err := client.NewRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, false, invalid("bad request: %v", err)
	}
	req.Header.Set("Accept", accept)
	resp, err := client.BareDo(req)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err = io.ReadAll(io.LimitReader(resp.Body, int64(limit)+1))
	if err != nil {
		return nil, false, err
	}
	if len(body) > limit {
		return body[:limit], true, nil
	}
	return body, false, nil
}

// --- get_file_contents --------------------------------------------------------

// FileContents is get_file_contents's result: a file (Encoding text or
// base64, Content) or a directory (Entries).
type FileContents struct {
	Type      string     `json:"type"`
	Name      string     `json:"name,omitempty"`
	Path      string     `json:"path"`
	SHA       string     `json:"sha,omitempty"`
	Size      int        `json:"size,omitempty"`
	URL       string     `json:"url,omitempty"`
	Encoding  string     `json:"encoding,omitempty"`
	Content   string     `json:"content,omitempty"`
	Entries   []DirEntry `json:"entries,omitempty"`
	Truncated bool       `json:"truncated,omitempty"`
}

// DirEntry is one entry of a directory listing.
type DirEntry struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Type string `json:"type"`
	Size int    `json:"size,omitempty"`
	SHA  string `json:"sha,omitempty"`
}

func (c *Connector) getFileContents(ctx context.Context, client *gh.Client, call connectors.Call) (connectors.Result, error) {
	owner, repo, err := repoArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	raw, err := optionalString(call.Args, "path")
	if err != nil {
		return connectors.Result{}, err
	}
	path, err := repoPath(raw)
	if err != nil {
		return connectors.Result{}, err
	}
	ref, err := optionalString(call.Args, "ref")
	if err != nil {
		return connectors.Result{}, err
	}
	ref = strings.TrimSpace(ref)
	file, dir, _, err := client.Repositories.GetContents(ctx, owner, repo, path, &gh.RepositoryContentGetOptions{Ref: ref})
	if err := classify("get file contents", err); err != nil {
		return connectors.Result{}, err
	}
	max := c.bounds.MaxResultBytes
	if file == nil {
		out := FileContents{Type: "dir", Path: path, Entries: make([]DirEntry, 0, len(dir))}
		for _, e := range dir {
			if e != nil {
				out.Entries = append(out.Entries, DirEntry{Name: e.GetName(), Path: e.GetPath(), Type: e.GetType(), Size: e.GetSize(), SHA: e.GetSHA()})
			}
		}
		out.Truncated = fitItems(&out.Entries, max, func() int { return encodedSize(out) })
		return connectors.Result{Content: out, Empty: len(out.Entries) == 0, Partial: out.Truncated}, nil
	}
	out := FileContents{Type: file.GetType(), Name: file.GetName(), Path: file.GetPath(), SHA: file.GetSHA(), Size: file.GetSize(), URL: file.GetHTMLURL()}
	if out.Type != "file" {
		return connectors.Result{Content: out}, nil
	}
	var data []byte
	cut := false
	if file.GetEncoding() == "base64" {
		s, err := file.GetContent()
		if err != nil {
			return connectors.Result{}, &Error{Class: ClassVendorError, Message: "get file contents: GitHub returned undecodable content"}
		}
		data = []byte(s)
		if len(data) > max {
			data, cut = data[:max], true
		}
	} else if out.Size > 0 {
		// Over 1 MB the contents API sends no content; the raw media
		// type of the same endpoint does, read only up to the bound.
		u := fmt.Sprintf("repos/%s/%s/contents/%s", owner, repo, (&url.URL{Path: path}).String())
		if ref != "" {
			u += "?ref=" + url.QueryEscape(ref)
		}
		data, cut, err = rawGet(ctx, client, u, rawMediaType, max)
		if err := classify("get file contents", err); err != nil {
			return connectors.Result{}, err
		}
	}
	out.Truncated = cut || len(data) < out.Size
	if cut {
		data = trimPartialRune(data)
	}
	if isText(data) {
		out.Encoding, out.Content = "text", string(data)
		fitBody(&out.Content, &out.Truncated, max, func() any { return out })
	} else {
		out.Encoding = "base64"
		fitBase64(&out, data, max)
	}
	return connectors.Result{Content: out, Partial: out.Truncated}, nil
}

// isText reports whether data is UTF-8 without NUL bytes.
func isText(data []byte) bool {
	return utf8.Valid(data) && !strings.ContainsRune(string(data), 0)
}

// trimPartialRune drops up to three trailing bytes of a rune a cut split.
func trimPartialRune(data []byte) []byte {
	for i := 0; i < utf8.UTFMax-1 && len(data) > 0 && !utf8.Valid(data); i++ {
		data = data[:len(data)-1]
	}
	return data
}

// fitBase64 sets out.Content to the base64 of the longest prefix of data
// whose result fits max.
func fitBase64(out *FileContents, data []byte, max int) {
	for {
		out.Content = base64.StdEncoding.EncodeToString(data)
		over := encodedSize(*out) - max
		if over <= 0 || len(data) == 0 {
			return
		}
		out.Truncated = true
		n := len(data) - (over*3+3)/4 - 3
		if n < 0 {
			n = 0
		}
		data = data[:n]
	}
}

// --- branches, commits, tags, releases --------------------------------------------

// BranchItem is one list_branches entry.
type BranchItem struct {
	Name      string `json:"name"`
	SHA       string `json:"sha"`
	Protected bool   `json:"protected"`
}

func (c *Connector) listBranches(ctx context.Context, client *gh.Client, call connectors.Call) (connectors.Result, error) {
	owner, repo, err := repoArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	protected, err := optionalBool(call.Args, "protected")
	if err != nil {
		return connectors.Result{}, err
	}
	page, perPage, clamped, err := c.pageArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	branches, resp, err := client.Repositories.ListBranches(ctx, owner, repo, &gh.BranchListOptions{Protected: protected, ListOptions: gh.ListOptions{Page: page, PerPage: perPage}})
	if err := classify("list branches", err); err != nil {
		return connectors.Result{}, err
	}
	items := make([]BranchItem, 0, len(branches))
	for _, b := range branches {
		if b != nil {
			items = append(items, BranchItem{Name: b.GetName(), SHA: b.GetCommit().GetSHA(), Protected: b.GetProtected()})
		}
	}
	return listResult(c, items, page, perPage, resp, clamped), nil
}

// CommitItem is one list_commits entry.
type CommitItem struct {
	SHA         string `json:"sha"`
	Message     string `json:"message"`
	Author      string `json:"author,omitempty"`
	AuthorLogin string `json:"author_login,omitempty"`
	Date        string `json:"date,omitempty"`
	URL         string `json:"url,omitempty"`
}

func toCommitItem(rc *gh.RepositoryCommit) CommitItem {
	return CommitItem{
		SHA: rc.GetSHA(), Message: rc.GetCommit().GetMessage(), Author: rc.GetCommit().GetAuthor().GetName(),
		AuthorLogin: rc.GetAuthor().GetLogin(), Date: timestamp(rc.GetCommit().GetAuthor().Date), URL: rc.GetHTMLURL(),
	}
}

func (c *Connector) listCommits(ctx context.Context, client *gh.Client, call connectors.Call) (connectors.Result, error) {
	owner, repo, err := repoArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	opts := &gh.CommitsListOptions{}
	for name, dst := range map[string]*string{"sha": &opts.SHA, "path": &opts.Path, "author": &opts.Author} {
		v, err := optionalString(call.Args, name)
		if err != nil {
			return connectors.Result{}, err
		}
		*dst = strings.TrimSpace(v)
	}
	if opts.Since, err = timeArg(call.Args, "since"); err != nil {
		return connectors.Result{}, err
	}
	if opts.Until, err = timeArg(call.Args, "until"); err != nil {
		return connectors.Result{}, err
	}
	page, perPage, clamped, err := c.pageArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	opts.ListOptions = gh.ListOptions{Page: page, PerPage: perPage}
	commits, resp, err := client.Repositories.ListCommits(ctx, owner, repo, opts)
	if err := classify("list commits", err); err != nil {
		return connectors.Result{}, err
	}
	items := make([]CommitItem, 0, len(commits))
	for _, rc := range commits {
		if rc != nil {
			items = append(items, toCommitItem(rc))
		}
	}
	return listResult(c, items, page, perPage, resp, clamped), nil
}

// Commit is get_commit's result.
type Commit struct {
	CommitItem
	Additions      int    `json:"additions"`
	Deletions      int    `json:"deletions"`
	Total          int    `json:"total"`
	Files          []File `json:"files"`
	FilesTruncated bool   `json:"files_truncated,omitempty"`
}

func (c *Connector) getCommit(ctx context.Context, client *gh.Client, call connectors.Call) (connectors.Result, error) {
	owner, repo, err := repoArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	sha, err := requiredString(call.Args, "sha")
	if err != nil {
		return connectors.Result{}, err
	}
	rc, _, err := client.Repositories.GetCommit(ctx, owner, repo, sha, nil)
	if err := classify("get commit", err); err != nil {
		return connectors.Result{}, err
	}
	out := Commit{CommitItem: toCommitItem(rc), Additions: rc.GetStats().GetAdditions(), Deletions: rc.GetStats().GetDeletions(),
		Total: rc.GetStats().GetTotal(), Files: toFiles(rc.Files)}
	partial := fitFiles(&out.Files, c.bounds.MaxResultBytes, func() int { return encodedSize(out) }, &out.FilesTruncated)
	return connectors.Result{Content: out, Partial: partial}, nil
}

// fitFiles drops patches largest first, then whole files from the end
// (never below one), until size() fits max; it reports whether anything
// was dropped and sets *filesDropped when files were.
func fitFiles(files *[]File, max int, size func() int, filesDropped *bool) bool {
	if size() <= max {
		return false
	}
	for size() > max {
		biggest := -1
		for i, f := range *files {
			if f.Patch != "" && (biggest < 0 || len(f.Patch) > len((*files)[biggest].Patch)) {
				biggest = i
			}
		}
		if biggest < 0 {
			break
		}
		(*files)[biggest].Patch, (*files)[biggest].PatchTruncated = "", true
	}
	if fitItems(files, max, size) {
		*filesDropped = true
	}
	return true
}

// TagItem is one list_tags entry.
type TagItem struct {
	Name string `json:"name"`
	SHA  string `json:"sha"`
}

func (c *Connector) listTags(ctx context.Context, client *gh.Client, call connectors.Call) (connectors.Result, error) {
	owner, repo, err := repoArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	page, perPage, clamped, err := c.pageArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	tags, resp, err := client.Repositories.ListTags(ctx, owner, repo, &gh.ListOptions{Page: page, PerPage: perPage})
	if err := classify("list tags", err); err != nil {
		return connectors.Result{}, err
	}
	items := make([]TagItem, 0, len(tags))
	for _, tg := range tags {
		if tg != nil {
			items = append(items, TagItem{Name: tg.GetName(), SHA: tg.GetCommit().GetSHA()})
		}
	}
	return listResult(c, items, page, perPage, resp, clamped), nil
}

// Release is one release; list_releases leaves Body empty.
type Release struct {
	ID              int64  `json:"id"`
	TagName         string `json:"tag_name"`
	Name            string `json:"name,omitempty"`
	Draft           bool   `json:"draft"`
	Prerelease      bool   `json:"prerelease"`
	TargetCommitish string `json:"target_commitish,omitempty"`
	Author          string `json:"author,omitempty"`
	URL             string `json:"url,omitempty"`
	CreatedAt       string `json:"created_at,omitempty"`
	PublishedAt     string `json:"published_at,omitempty"`
	Body            string `json:"body,omitempty"`
	Truncated       bool   `json:"truncated,omitempty"`
}

func toRelease(r *gh.RepositoryRelease) Release {
	return Release{ID: r.GetID(), TagName: r.GetTagName(), Name: r.GetName(), Draft: r.GetDraft(), Prerelease: r.GetPrerelease(),
		TargetCommitish: r.GetTargetCommitish(), Author: r.GetAuthor().GetLogin(), URL: r.GetHTMLURL(),
		CreatedAt: timestamp(&r.CreatedAt), PublishedAt: timestamp(r.PublishedAt)}
}

func (c *Connector) listReleases(ctx context.Context, client *gh.Client, call connectors.Call) (connectors.Result, error) {
	owner, repo, err := repoArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	page, perPage, clamped, err := c.pageArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	releases, resp, err := client.Repositories.ListReleases(ctx, owner, repo, &gh.ListOptions{Page: page, PerPage: perPage})
	if err := classify("list releases", err); err != nil {
		return connectors.Result{}, err
	}
	items := make([]Release, 0, len(releases))
	for _, r := range releases {
		if r != nil {
			items = append(items, toRelease(r))
		}
	}
	return listResult(c, items, page, perPage, resp, clamped), nil
}

func (c *Connector) getRelease(ctx context.Context, client *gh.Client, call connectors.Call) (connectors.Result, error) {
	owner, repo, err := repoArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	tag, err := optionalString(call.Args, "tag")
	if err != nil {
		return connectors.Result{}, err
	}
	var r *gh.RepositoryRelease
	if tag = strings.TrimSpace(tag); tag == "" {
		r, _, err = client.Repositories.GetLatestRelease(ctx, owner, repo)
	} else {
		r, _, err = client.Repositories.GetReleaseByTag(ctx, owner, repo, tag)
	}
	if err := classify("get release", err); err != nil {
		return connectors.Result{}, err
	}
	out := toRelease(r)
	out.Body = r.GetBody()
	fitBody(&out.Body, &out.Truncated, c.bounds.MaxResultBytes, func() any { return out })
	return connectors.Result{Content: out, Partial: out.Truncated}, nil
}

// --- search -----------------------------------------------------------------------

// CodeItem is one search_code hit.
type CodeItem struct {
	Name string `json:"name"`
	Path string `json:"path"`
	SHA  string `json:"sha,omitempty"`
	URL  string `json:"url,omitempty"`
	Repo string `json:"repo"`
}

func (c *Connector) searchCode(ctx context.Context, client *gh.Client, call connectors.Call) (connectors.Result, error) {
	q, err := queryArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	owner, _ := call.Args["owner"].(string)
	repo, _ := call.Args["repo"].(string)
	if owner, repo = strings.TrimSpace(owner), strings.TrimSpace(repo); owner != "" && repo != "" {
		if !nameRE.MatchString(owner) || !nameRE.MatchString(repo) {
			return connectors.Result{}, invalid("owner and repo must be a repository owner and name")
		}
		if !hasQualifier(q, "repo") {
			q = "repo:" + owner + "/" + repo + " " + q
		}
	}
	page, perPage, clamped, err := c.pageArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	result, resp, err := client.Search.Code(ctx, q, &gh.SearchOptions{ListOptions: gh.ListOptions{Page: page, PerPage: perPage}})
	if err := classify("search code", err); err != nil {
		return connectors.Result{}, err
	}
	items := make([]CodeItem, 0, len(result.CodeResults))
	for _, r := range result.CodeResults {
		if r != nil {
			items = append(items, CodeItem{Name: r.GetName(), Path: r.GetPath(), SHA: r.GetSHA(), URL: r.GetHTMLURL(), Repo: r.GetRepository().GetFullName()})
		}
	}
	return searchResult(c, items, result.GetTotal(), result.GetIncompleteResults(), page, perPage, resp, clamped), nil
}

// RepoItem is one search_repositories hit.
type RepoItem struct {
	FullName      string `json:"full_name"`
	Description   string `json:"description,omitempty"`
	URL           string `json:"url,omitempty"`
	Language      string `json:"language,omitempty"`
	Stars         int    `json:"stars"`
	Forks         int    `json:"forks"`
	Private       bool   `json:"private"`
	Archived      bool   `json:"archived,omitempty"`
	DefaultBranch string `json:"default_branch,omitempty"`
	UpdatedAt     string `json:"updated_at,omitempty"`
}

func (c *Connector) searchRepositories(ctx context.Context, client *gh.Client, call connectors.Call) (connectors.Result, error) {
	q, err := queryArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	page, perPage, clamped, err := c.pageArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	sortBy, _ := call.Args["sort"].(string)
	order, _ := call.Args["order"].(string)
	result, resp, err := client.Search.Repositories(ctx, q, &gh.SearchOptions{Sort: sortBy, Order: order, ListOptions: gh.ListOptions{Page: page, PerPage: perPage}})
	if err := classify("search repositories", err); err != nil {
		return connectors.Result{}, err
	}
	items := make([]RepoItem, 0, len(result.Repositories))
	for _, r := range result.Repositories {
		if r != nil {
			items = append(items, RepoItem{FullName: r.GetFullName(), Description: r.GetDescription(), URL: r.GetHTMLURL(), Language: r.GetLanguage(),
				Stars: r.GetStargazersCount(), Forks: r.GetForksCount(), Private: r.GetPrivate(), Archived: r.GetArchived(),
				DefaultBranch: r.GetDefaultBranch(), UpdatedAt: timestamp(r.UpdatedAt)})
		}
	}
	return searchResult(c, items, result.GetTotal(), result.GetIncompleteResults(), page, perPage, resp, clamped), nil
}

// UserItem is one search_users hit.
type UserItem struct {
	Login string `json:"login"`
	ID    int64  `json:"id"`
	Type  string `json:"type,omitempty"`
	URL   string `json:"url,omitempty"`
}

func (c *Connector) searchUsers(ctx context.Context, client *gh.Client, call connectors.Call) (connectors.Result, error) {
	q, err := queryArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	page, perPage, clamped, err := c.pageArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	sortBy, _ := call.Args["sort"].(string)
	order, _ := call.Args["order"].(string)
	result, resp, err := client.Search.Users(ctx, q, &gh.SearchOptions{Sort: sortBy, Order: order, ListOptions: gh.ListOptions{Page: page, PerPage: perPage}})
	if err := classify("search users", err); err != nil {
		return connectors.Result{}, err
	}
	items := make([]UserItem, 0, len(result.Users))
	for _, u := range result.Users {
		if u != nil {
			items = append(items, UserItem{Login: u.GetLogin(), ID: u.GetID(), Type: u.GetType(), URL: u.GetHTMLURL()})
		}
	}
	return searchResult(c, items, result.GetTotal(), result.GetIncompleteResults(), page, perPage, resp, clamped), nil
}

// --- create_or_update_file ---------------------------------------------------------

// CreatedFile is create_or_update_file's result.
type CreatedFile struct {
	Path      string `json:"path"`
	SHA       string `json:"sha"`
	URL       string `json:"url,omitempty"`
	CommitSHA string `json:"commit_sha"`
	CommitURL string `json:"commit_url,omitempty"`
	Repo      string `json:"repo"`
	Branch    string `json:"branch,omitempty"`
}

func fileResultIDs(res connectors.Result) map[string]string {
	v, ok := res.Content.(CreatedFile)
	if !ok || v.CommitSHA == "" {
		return nil
	}
	return map[string]string{"commit_sha": v.CommitSHA, "sha": v.SHA, "url": v.CommitURL}
}

func (c *Connector) createOrUpdateFile(ctx context.Context, client *gh.Client, call connectors.Call) (connectors.Result, error) {
	owner, repo, err := repoArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	rawPath, err := requiredString(call.Args, "path")
	if err != nil {
		return connectors.Result{}, err
	}
	path, err := repoPath(rawPath)
	if err != nil {
		return connectors.Result{}, err
	}
	content, ok := call.Args["content"].(string)
	if !ok {
		return connectors.Result{}, invalid("content is required: the complete file content as text")
	}
	if len(content) > MaxFileWriteBytes {
		return connectors.Result{}, invalid("content is %d bytes; at most %d are accepted", len(content), MaxFileWriteBytes)
	}
	message, err := requiredString(call.Args, "message")
	if err != nil {
		return connectors.Result{}, err
	}
	opts := &gh.RepositoryContentFileOptions{Message: gh.Ptr(message + "\n\n" + CommitTrailer(call.OperationID)), Content: []byte(content)}
	branch, err := optionalString(call.Args, "branch")
	if err != nil {
		return connectors.Result{}, err
	}
	if branch = strings.TrimSpace(branch); branch != "" {
		opts.Branch = gh.Ptr(branch)
	}
	sha, err := optionalString(call.Args, "sha")
	if err != nil {
		return connectors.Result{}, err
	}
	if sha = strings.TrimSpace(sha); sha != "" {
		opts.SHA = gh.Ptr(sha)
	}
	out, _, err := client.Repositories.CreateFile(ctx, owner, repo, path, opts)
	if err := classifyWrite("create or update file", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: CreatedFile{
		Path: out.GetContent().GetPath(), SHA: out.GetContent().GetSHA(), URL: out.GetContent().GetHTMLURL(),
		CommitSHA: out.GetSHA(), CommitURL: out.GetHTMLURL(), Repo: owner + "/" + repo, Branch: branch,
	}}, nil
}

// checkFileCommit is create_or_update_file's marker reconciliation: the
// commits touching path on the branch (the default branch when the write
// named none), newest first, bounded by MaxReconcilePages. A commit whose
// message carries the operation's trailer is found; the end of the list
// without it is not_found; running out of pages or a listing error is
// "cannot tell yet".
func (c *Connector) checkFileCommit(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	tg, err := c.target(ctx, in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	path := in.ResourceIdentity["path"]
	if path == "" {
		return connectors.ReconcileResult{}, fmt.Errorf("%w: resource identity has no path", ErrNotReconcilable)
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	trailer := CommitTrailer(tg.operationID)
	opts := &gh.CommitsListOptions{SHA: in.ResourceIdentity["branch"], Path: path, ListOptions: gh.ListOptions{PerPage: reconcilePerPage}}
	for page := 1; page <= MaxReconcilePages; page++ {
		opts.Page = page
		commits, resp, err := tg.client.Repositories.ListCommits(ctx, tg.owner, tg.repo, opts)
		if err := classify("reconcile: list commits", err); err != nil {
			return connectors.ReconcileResult{}, err
		}
		for _, rc := range commits {
			if rc != nil && strings.Contains(rc.GetCommit().GetMessage(), trailer) {
				return found(rc.GetSHA()), nil
			}
		}
		if resp.NextPage == 0 {
			return notFound, nil
		}
	}
	return connectors.ReconcileResult{}, fmt.Errorf("github: reconcile: more than %d pages of commits on %s in %s/%s; cannot tell yet", MaxReconcilePages, path, tg.owner, tg.repo)
}
