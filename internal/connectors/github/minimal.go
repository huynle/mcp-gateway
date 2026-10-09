// Adapted from github/github-mcp-server, pkg/github/minimal_types.go
// (commit eb47a99ddb866ca2b8a162920e6bda9521f33ebb), MIT License,
// Copyright (c) 2025 GitHub. Modified for mcp-gateway: the result shapes
// are flattened (user logins instead of nested user objects, repo as
// "owner/name", url instead of html_url), carry page metadata and the
// truncation flags the bounds need, and drop the fields no gateway tool
// returns. See THIRD_PARTY_NOTICES.md.

package github

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	gh "github.com/google/go-github/v90/github"
)

// User is get_me's result.
type User struct {
	Login      string `json:"login"`
	ID         int64  `json:"id"`
	ProfileURL string `json:"profile_url,omitempty"`
	AvatarURL  string `json:"avatar_url,omitempty"`
	Name       string `json:"name,omitempty"`
	Company    string `json:"company,omitempty"`
	Location   string `json:"location,omitempty"`
	Email      string `json:"email,omitempty"`
	Bio        string `json:"bio,omitempty"`
	CreatedAt  string `json:"created_at,omitempty"`
}

// SearchItem is one search_issues hit: an issue or a pull request.
type SearchItem struct {
	Number        int      `json:"number"`
	Title         string   `json:"title"`
	State         string   `json:"state"`
	StateReason   string   `json:"state_reason,omitempty"`
	URL           string   `json:"url"`
	Repo          string   `json:"repo"`
	IsPullRequest bool     `json:"is_pull_request"`
	User          string   `json:"user,omitempty"`
	Labels        []string `json:"labels,omitempty"`
	Assignees     []string `json:"assignees,omitempty"`
	Comments      int      `json:"comments,omitempty"`
	CreatedAt     string   `json:"created_at,omitempty"`
	UpdatedAt     string   `json:"updated_at,omitempty"`
	ClosedAt      string   `json:"closed_at,omitempty"`
}

// SearchPage is search_issues's result.
type SearchPage struct {
	TotalCount        int          `json:"total_count"`
	IncompleteResults bool         `json:"incomplete_results"`
	Page              int          `json:"page"`
	PerPage           int          `json:"per_page"`
	HasMore           bool         `json:"has_more"`
	Truncated         bool         `json:"truncated,omitempty"`
	Items             []SearchItem `json:"items"`
}

// Issue is get_issue's result.
type Issue struct {
	Number            int      `json:"number"`
	Title             string   `json:"title"`
	Body              string   `json:"body,omitempty"`
	State             string   `json:"state"`
	StateReason       string   `json:"state_reason,omitempty"`
	Locked            bool     `json:"locked,omitempty"`
	URL               string   `json:"url"`
	Repo              string   `json:"repo"`
	IsPullRequest     bool     `json:"is_pull_request,omitempty"`
	User              string   `json:"user,omitempty"`
	AuthorAssociation string   `json:"author_association,omitempty"`
	Labels            []string `json:"labels,omitempty"`
	Assignees         []string `json:"assignees"`
	Milestone         string   `json:"milestone,omitempty"`
	Comments          int      `json:"comments,omitempty"`
	CreatedAt         string   `json:"created_at,omitempty"`
	UpdatedAt         string   `json:"updated_at,omitempty"`
	ClosedAt          string   `json:"closed_at,omitempty"`
	ClosedBy          string   `json:"closed_by,omitempty"`
	// Truncated says the body was cut to fit the result bounds.
	Truncated bool `json:"truncated,omitempty"`
}

// Branch is a pull request's head or base.
type Branch struct {
	Ref  string `json:"ref"`
	SHA  string `json:"sha"`
	Repo string `json:"repo,omitempty"`
}

// PullRequest is get_pull_request's result.
type PullRequest struct {
	Number             int      `json:"number"`
	Title              string   `json:"title"`
	Body               string   `json:"body,omitempty"`
	State              string   `json:"state"`
	Draft              bool     `json:"draft"`
	Merged             bool     `json:"merged"`
	MergeableState     string   `json:"mergeable_state,omitempty"`
	URL                string   `json:"url"`
	Repo               string   `json:"repo"`
	User               string   `json:"user,omitempty"`
	Labels             []string `json:"labels,omitempty"`
	Assignees          []string `json:"assignees,omitempty"`
	RequestedReviewers []string `json:"requested_reviewers,omitempty"`
	MergedBy           string   `json:"merged_by,omitempty"`
	Head               *Branch  `json:"head,omitempty"`
	Base               *Branch  `json:"base,omitempty"`
	Additions          int      `json:"additions,omitempty"`
	Deletions          int      `json:"deletions,omitempty"`
	ChangedFiles       int      `json:"changed_files,omitempty"`
	Commits            int      `json:"commits,omitempty"`
	Comments           int      `json:"comments,omitempty"`
	CreatedAt          string   `json:"created_at,omitempty"`
	UpdatedAt          string   `json:"updated_at,omitempty"`
	ClosedAt           string   `json:"closed_at,omitempty"`
	MergedAt           string   `json:"merged_at,omitempty"`
	Milestone          string   `json:"milestone,omitempty"`
	// Truncated says the body was cut to fit the result bounds.
	Truncated bool `json:"truncated,omitempty"`
}

// File is one changed file of a pull request.
type File struct {
	Filename         string `json:"filename"`
	Status           string `json:"status,omitempty"`
	Additions        int    `json:"additions,omitempty"`
	Deletions        int    `json:"deletions,omitempty"`
	Changes          int    `json:"changes,omitempty"`
	Patch            string `json:"patch,omitempty"`
	PreviousFilename string `json:"previous_filename,omitempty"`
	// PatchTruncated says the patch was dropped to fit the result bounds.
	PatchTruncated bool `json:"patch_truncated,omitempty"`
}

// CreatedIssue is create_issue's result: the identifiers of the new
// issue, never its content (the ledger keeps number, id and url).
type CreatedIssue struct {
	Number int    `json:"number"`
	ID     int64  `json:"id"`
	URL    string `json:"url"`
	Repo   string `json:"repo"`
	State  string `json:"state,omitempty"`
}

// CreatedComment is add_issue_comment's result.
type CreatedComment struct {
	ID     int64  `json:"id"`
	URL    string `json:"url"`
	Repo   string `json:"repo"`
	Number int    `json:"number"`
}

// CreatedPullRequest is create_pull_request's result.
type CreatedPullRequest struct {
	Number int    `json:"number"`
	ID     int64  `json:"id"`
	URL    string `json:"url"`
	Repo   string `json:"repo"`
	State  string `json:"state,omitempty"`
	Draft  bool   `json:"draft"`
	Head   string `json:"head,omitempty"`
	Base   string `json:"base,omitempty"`
}

// CreatedBranch is create_branch's result.
type CreatedBranch struct {
	Ref    string `json:"ref"`
	Branch string `json:"branch"`
	SHA    string `json:"sha"`
	URL    string `json:"url,omitempty"`
	Repo   string `json:"repo"`
}

// FilesPage is list_pull_request_files's result.
type FilesPage struct {
	Page      int    `json:"page"`
	PerPage   int    `json:"per_page"`
	HasMore   bool   `json:"has_more"`
	Truncated bool   `json:"truncated,omitempty"`
	Files     []File `json:"files"`
}

func toUser(u *gh.User) User {
	return User{
		Login: u.GetLogin(), ID: u.GetID(), ProfileURL: u.GetHTMLURL(), AvatarURL: u.GetAvatarURL(),
		Name: u.GetName(), Company: u.GetCompany(), Location: u.GetLocation(), Email: u.GetEmail(), Bio: u.GetBio(),
		CreatedAt: timestamp(u.CreatedAt),
	}
}

func toSearchItem(is *gh.Issue) SearchItem {
	return SearchItem{
		Number: is.GetNumber(), Title: is.GetTitle(), State: is.GetState(), StateReason: is.GetStateReason(),
		URL: is.GetHTMLURL(), Repo: repoFromURL(is.GetRepositoryURL()), IsPullRequest: is.IsPullRequest(),
		User: is.GetUser().GetLogin(), Labels: labelNames(is.Labels), Assignees: logins(is.Assignees), Comments: is.GetComments(),
		CreatedAt: timestamp(is.CreatedAt), UpdatedAt: timestamp(is.UpdatedAt), ClosedAt: timestamp(is.ClosedAt),
	}
}

func toIssue(is *gh.Issue, fallbackRepo string) Issue {
	repo := repoFromURL(is.GetRepositoryURL())
	if repo == "" {
		repo = fallbackRepo
	}
	out := Issue{
		Number: is.GetNumber(), Title: is.GetTitle(), Body: is.GetBody(), State: is.GetState(), StateReason: is.GetStateReason(),
		Locked: is.GetLocked(), URL: is.GetHTMLURL(), Repo: repo, IsPullRequest: is.IsPullRequest(),
		User: is.GetUser().GetLogin(), AuthorAssociation: is.GetAuthorAssociation(),
		Labels: labelNames(is.Labels), Assignees: logins(is.Assignees), Comments: is.GetComments(),
		CreatedAt: timestamp(is.CreatedAt), UpdatedAt: timestamp(is.UpdatedAt), ClosedAt: timestamp(is.ClosedAt),
		ClosedBy: is.GetClosedBy().GetLogin(), Milestone: is.GetMilestone().GetTitle(),
	}
	if out.Assignees == nil {
		out.Assignees = []string{}
	}
	return out
}

func toPullRequest(pr *gh.PullRequest, repo string) PullRequest {
	out := PullRequest{
		Number: pr.GetNumber(), Title: pr.GetTitle(), Body: pr.GetBody(), State: pr.GetState(), Draft: pr.GetDraft(),
		Merged: pr.GetMerged(), MergeableState: pr.GetMergeableState(), URL: pr.GetHTMLURL(), Repo: repo,
		User: pr.GetUser().GetLogin(), Labels: labelNames(pr.Labels), Assignees: logins(pr.Assignees),
		RequestedReviewers: logins(pr.RequestedReviewers), MergedBy: pr.GetMergedBy().GetLogin(),
		Additions: pr.GetAdditions(), Deletions: pr.GetDeletions(), ChangedFiles: pr.GetChangedFiles(),
		Commits: pr.GetCommits(), Comments: pr.GetComments(),
		CreatedAt: timestamp(pr.CreatedAt), UpdatedAt: timestamp(pr.UpdatedAt), ClosedAt: timestamp(pr.ClosedAt), MergedAt: timestamp(pr.MergedAt),
		Milestone: pr.GetMilestone().GetTitle(),
	}
	if pr.Head != nil {
		out.Head = &Branch{Ref: pr.Head.GetRef(), SHA: pr.Head.GetSHA(), Repo: pr.Head.GetRepo().GetFullName()}
	}
	if pr.Base != nil {
		out.Base = &Branch{Ref: pr.Base.GetRef(), SHA: pr.Base.GetSHA(), Repo: pr.Base.GetRepo().GetFullName()}
	}
	return out
}

func toCreatedIssue(is *gh.Issue, repo string) CreatedIssue {
	return CreatedIssue{Number: is.GetNumber(), ID: is.GetID(), URL: is.GetHTMLURL(), Repo: repo, State: is.GetState()}
}

func toCreatedComment(cm *gh.IssueComment, repo string, number int) CreatedComment {
	return CreatedComment{ID: cm.GetID(), URL: cm.GetHTMLURL(), Repo: repo, Number: number}
}

func toCreatedPullRequest(pr *gh.PullRequest, repo string) CreatedPullRequest {
	return CreatedPullRequest{
		Number: pr.GetNumber(), ID: pr.GetID(), URL: pr.GetHTMLURL(), Repo: repo, State: pr.GetState(), Draft: pr.GetDraft(),
		Head: pr.GetHead().GetRef(), Base: pr.GetBase().GetRef(),
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

func i64toa(n int64) string { return strconv.FormatInt(n, 10) }

func toFiles(files []*gh.CommitFile) []File {
	out := make([]File, 0, len(files))
	for _, f := range files {
		if f == nil {
			continue
		}
		out = append(out, File{
			Filename: f.GetFilename(), Status: f.GetStatus(), Additions: f.GetAdditions(), Deletions: f.GetDeletions(),
			Changes: f.GetChanges(), Patch: f.GetPatch(), PreviousFilename: f.GetPreviousFilename(),
		})
	}
	return out
}

func labelNames(labels []*gh.Label) []string {
	var out []string
	for _, l := range labels {
		if l != nil && l.GetName() != "" {
			out = append(out, l.GetName())
		}
	}
	return out
}

func logins(users []*gh.User) []string {
	var out []string
	for _, u := range users {
		if u != nil && u.GetLogin() != "" {
			out = append(out, u.GetLogin())
		}
	}
	return out
}

func timestamp(t *gh.Timestamp) string {
	if t == nil || t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// repoFromURL turns ".../repos/{owner}/{repo}" into "owner/repo".
func repoFromURL(u string) string {
	_, rest, ok := strings.Cut(u, "/repos/")
	if !ok {
		return ""
	}
	parts := strings.SplitN(strings.Trim(rest, "/"), "/", 3)
	if len(parts) < 2 {
		return ""
	}
	return parts[0] + "/" + parts[1]
}

// encodedSize is the serialised size of v, the measure the bounds apply to.
func encodedSize(v any) int {
	b, err := json.Marshal(v)
	if err != nil {
		return 0
	}
	return len(b)
}
