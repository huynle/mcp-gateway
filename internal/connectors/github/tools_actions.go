// Tool descriptions and argument shapes are adapted from
// github/github-mcp-server, pkg/github/actions.go (actions_list
// list_workflow_runs / list_workflow_jobs, actions_get get_workflow_run,
// get_job_logs, actions_run_trigger run_workflow / rerun_workflow_run /
// rerun_failed_jobs / cancel_workflow_run) at commit
// eb47a99ddb866ca2b8a162920e6bda9521f33ebb, MIT License, Copyright (c)
// 2025 GitHub. Modified for mcp-gateway: one tool per operation, flat
// bounded results, logs streamed with a bounded download keeping only the
// tail, the signed log URL fetched without the account's token, resource
// identity, reconciliation. See THIRD_PARTY_NOTICES.md.

package github

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	gh "github.com/google/go-github/v90/github"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Actions tool names.
const (
	ToolListWorkflowRuns  = "list_workflow_runs"
	ToolGetWorkflowRun    = "get_workflow_run"
	ToolListWorkflowJobs  = "list_workflow_jobs"
	ToolGetJobLogs        = "get_job_logs"
	ToolRunWorkflow       = "run_workflow"
	ToolRerunWorkflowRun  = "rerun_workflow_run"
	ToolCancelWorkflowRun = "cancel_workflow_run"
)

// GitHub App permissions of the Actions tools.
const (
	PermissionActionsRead  = "actions:read"
	PermissionActionsWrite = "actions:write"
)

const (
	// MaxLogDownloadBytes bounds how much of a job log get_job_logs
	// reads (64 MiB); only the tail that fits the result is kept.
	MaxLogDownloadBytes = 64 << 20
	// defaultTailLines and maxTailLines bound tail_lines.
	defaultTailLines = 500
	maxTailLines     = 10000
)

// actionsTools declares the GitHub Actions tools.
func (c *Connector) actionsTools() []connectors.Tool {
	paged := connectors.Bounds{MaxPageSize: c.bounds.MaxPageSize, MaxResultBytes: c.bounds.MaxResultBytes}
	single := connectors.Bounds{MaxResultBytes: c.bounds.MaxResultBytes}
	runID := property{"run_id", "integer", "The workflow run id.", nil}
	aRead, aWrite := []string{PermissionActionsRead}, []string{PermissionActionsWrite}
	none := connectors.Reconciliation{Kind: connectors.ReconcileNone}
	return []connectors.Tool{
		{
			App: App, Name: ToolListWorkflowRuns, Kind: connectors.KindRead,
			Description: "List GitHub Actions workflow runs of a repository, newest first, optionally of one workflow (file name such as ci.yml, or id) " +
				"and filtered by branch, event, status or conclusion (e.g. failure, in_progress), actor or head sha. Paginated.",
			InputSchema: objectSchema([]property{ownerProperty, repoProperty,
				{"workflow", "string", "Workflow file name (ci.yml) or numeric id; every workflow when omitted.", nil},
				{"branch", "string", "Only runs on this branch.", nil},
				{"event", "string", "Only runs triggered by this event (push, pull_request, workflow_dispatch, ...).", nil},
				{"status", "string", "Status or conclusion: queued, in_progress, completed, success, failure, cancelled, ...", nil},
				{"actor", "string", "Only runs triggered by this login.", nil},
				{"head_sha", "string", "Only runs for this commit sha.", nil},
				pageProperty, perPageProperty,
			}, []string{"owner", "repo"}),
			RequiredScopes: aRead, ResourceIdentity: runIdentity, Bounds: paged,
		},
		{
			App: App, Name: ToolGetWorkflowRun, Kind: connectors.KindRead,
			Description:    "Get one GitHub Actions workflow run: workflow, status, conclusion, branch, commit, attempt and url.",
			InputSchema:    objectSchema([]property{ownerProperty, repoProperty, runID}, []string{"owner", "repo", "run_id"}),
			RequiredScopes: aRead, ResourceIdentity: runIdentity, Bounds: single,
		},
		{
			App: App, Name: ToolListWorkflowJobs, Kind: connectors.KindRead,
			Description: "List the jobs of a workflow run with their status, conclusion and steps (use the failing job's id with get_job_logs). Paginated.",
			InputSchema: objectSchema([]property{ownerProperty, repoProperty, runID,
				{"filter", "string", "latest (default: the jobs of the latest attempt) or all.", []string{"latest", "all"}},
				pageProperty, perPageProperty,
			}, []string{"owner", "repo", "run_id"}),
			RequiredScopes: aRead, ResourceIdentity: runIdentity, Bounds: paged,
		},
		{
			App: App, Name: ToolGetJobLogs, Kind: connectors.KindRead,
			Description: "Get the end of a GitHub Actions job's log: the last tail_lines lines (default 500, at most 10000), cut further from the start to fit " +
				"the result bounds. Use it to see why a job failed.",
			InputSchema: objectSchema([]property{ownerProperty, repoProperty,
				{"job_id", "integer", "The job id (from list_workflow_jobs).", nil},
				{"tail_lines", "integer", "How many lines from the end of the log to return (default 500, at most 10000).", nil},
			}, []string{"owner", "repo", "job_id"}),
			RequiredScopes: aRead, ResourceIdentity: runIdentity, Bounds: single,
		},
		{
			App: App, Name: ToolRunWorkflow, Kind: connectors.KindWrite,
			Description: "Start a GitHub Actions workflow that has a workflow_dispatch trigger, on ref (branch or tag) with optional inputs. " +
				"Returns the new run's id and url when GitHub reports them.",
			InputSchema: objectSchema([]property{ownerProperty, repoProperty,
				{"workflow", "string", "Workflow file name (deploy.yml) or numeric id.", nil},
				{"ref", "string", "Branch or tag to run the workflow on.", nil},
				{"inputs", "object", "The workflow's inputs as name: value pairs (at most 25).", nil},
			}, []string{"owner", "repo", "workflow", "ref"}),
			RequiredScopes: aWrite, ResourceIdentity: runIdentity, Reconcile: none, ResultIDs: dispatchResultIDs, Bounds: single,
		},
		{
			App: App, Name: ToolRerunWorkflowRun, Kind: connectors.KindWrite,
			Description: "Re-run a GitHub Actions workflow run: every job, or only the failed jobs (and their dependents) with failed_only.",
			InputSchema: objectSchema([]property{ownerProperty, repoProperty, runID,
				{"failed_only", "boolean", "Re-run only the failed jobs.", nil},
			}, []string{"owner", "repo", "run_id"}),
			RequiredScopes: aWrite, ResourceIdentity: runIdentity, Reconcile: none, ResultIDs: runActionResultIDs, Bounds: single,
		},
		{
			App: App, Name: ToolCancelWorkflowRun, Kind: connectors.KindWrite,
			Description:    "Cancel a queued or in-progress GitHub Actions workflow run.",
			InputSchema:    objectSchema([]property{ownerProperty, repoProperty, runID}, []string{"owner", "repo", "run_id"}),
			RequiredScopes: aWrite, ResourceIdentity: runIdentity,
			Reconcile: connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: c.checkCancelled}, ResultIDs: runActionResultIDs, Bounds: single,
		},
	}
}

// actionsHandlers maps the Actions tools to their implementation.
func (c *Connector) actionsHandlers() (reads, writes map[string]handler) {
	return map[string]handler{
			ToolListWorkflowRuns: c.listWorkflowRuns, ToolGetWorkflowRun: c.getWorkflowRun, ToolListWorkflowJobs: c.listWorkflowJobs, ToolGetJobLogs: c.getJobLogs,
		}, map[string]handler{
			ToolRunWorkflow: c.runWorkflow, ToolRerunWorkflowRun: c.rerunWorkflowRun, ToolCancelWorkflowRun: c.cancelWorkflowRun,
		}
}

// runIdentity is identity(false) plus run_id, job_id, workflow and ref
// when given (identifiers only; never inputs).
func runIdentity(args map[string]any) map[string]string {
	out := identity(false)(args)
	for _, k := range []string{"run_id", "job_id"} {
		if n, err := toInt(args[k]); err == nil && n > 0 {
			out[k] = strconv.Itoa(n)
		}
	}
	for _, k := range []string{"workflow", "ref"} {
		switch v := args[k].(type) {
		case string:
			if v = strings.TrimSpace(v); v != "" {
				out[k] = v
			}
		case float64, int, int64:
			if n, err := toInt(v); err == nil && n > 0 {
				out[k] = strconv.Itoa(n)
			}
		}
	}
	return out
}

// idArg reads a required positive integer id argument.
func idArg(args map[string]any, name string) (int64, error) {
	v, ok := args[name]
	if !ok {
		return 0, invalid("%s is required", name)
	}
	n, err := toInt(v)
	if err != nil || n < 1 {
		return 0, invalid("%s must be a positive integer", name)
	}
	return int64(n), nil
}

// workflowArg reads the workflow argument: a numeric id or a file name.
func workflowArg(args map[string]any) (id int64, file string, err error) {
	switch v := args["workflow"].(type) {
	case nil:
		return 0, "", nil
	case string:
		v = strings.TrimSpace(v)
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			return n, "", nil
		}
		if strings.ContainsAny(v, "/\\") || v == "." || v == ".." {
			return 0, "", invalid("workflow must be a workflow file name (ci.yml) or a numeric id")
		}
		return 0, v, nil
	default:
		n, err := toInt(v)
		if err != nil || n < 1 {
			return 0, "", invalid("workflow must be a workflow file name (ci.yml) or a numeric id")
		}
		return int64(n), "", nil
	}
}

// --- reads ----------------------------------------------------------------------

// RunItem is one workflow run.
type RunItem struct {
	ID           int64  `json:"id"`
	Name         string `json:"name,omitempty"`
	DisplayTitle string `json:"display_title,omitempty"`
	Status       string `json:"status"`
	Conclusion   string `json:"conclusion,omitempty"`
	Event        string `json:"event,omitempty"`
	Branch       string `json:"branch,omitempty"`
	HeadSHA      string `json:"head_sha,omitempty"`
	RunNumber    int    `json:"run_number,omitempty"`
	RunAttempt   int    `json:"run_attempt,omitempty"`
	Actor        string `json:"actor,omitempty"`
	URL          string `json:"url,omitempty"`
	CreatedAt    string `json:"created_at,omitempty"`
	UpdatedAt    string `json:"updated_at,omitempty"`
}

func toRunItem(r *gh.WorkflowRun) RunItem {
	return RunItem{ID: r.GetID(), Name: r.GetName(), DisplayTitle: r.GetDisplayTitle(), Status: r.GetStatus(), Conclusion: r.GetConclusion(),
		Event: r.GetEvent(), Branch: r.GetHeadBranch(), HeadSHA: r.GetHeadSHA(), RunNumber: r.GetRunNumber(), RunAttempt: r.GetRunAttempt(),
		Actor: r.GetActor().GetLogin(), URL: r.GetHTMLURL(), CreatedAt: timestamp(r.CreatedAt), UpdatedAt: timestamp(r.UpdatedAt)}
}

// countedResult is a ListPage result with the vendor's total count.
type countedPage[T any] struct {
	TotalCount int `json:"total_count"`
	ListPage[T]
}

func countedResult[T any](c *Connector, items []T, total, page, perPage int, resp *gh.Response, clamped bool) connectors.Result {
	res := listResult(c, items, page, perPage, resp, clamped)
	out := countedPage[T]{TotalCount: total, ListPage: res.Content.(ListPage[T])}
	if fitItems(&out.Items, c.bounds.MaxResultBytes, func() int { return encodedSize(out) }) {
		out.Truncated, res.Partial = true, true
	}
	res.Content = out
	return res
}

func (c *Connector) listWorkflowRuns(ctx context.Context, client *gh.Client, call connectors.Call) (connectors.Result, error) {
	owner, repo, err := repoArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	wfID, wfFile, err := workflowArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	opts := &gh.ListWorkflowRunsOptions{}
	for name, dst := range map[string]*string{"branch": &opts.Branch, "event": &opts.Event, "status": &opts.Status, "actor": &opts.Actor, "head_sha": &opts.HeadSHA} {
		v, err := optionalString(call.Args, name)
		if err != nil {
			return connectors.Result{}, err
		}
		*dst = strings.TrimSpace(v)
	}
	page, perPage, clamped, err := c.pageArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	opts.ListOptions = gh.ListOptions{Page: page, PerPage: perPage}
	var runs *gh.WorkflowRuns
	var resp *gh.Response
	switch {
	case wfID > 0:
		runs, resp, err = client.Actions.ListWorkflowRunsByID(ctx, owner, repo, wfID, opts)
	case wfFile != "":
		runs, resp, err = client.Actions.ListWorkflowRunsByFileName(ctx, owner, repo, wfFile, opts)
	default:
		runs, resp, err = client.Actions.ListRepositoryWorkflowRuns(ctx, owner, repo, opts)
	}
	if err := classify("list workflow runs", err); err != nil {
		return connectors.Result{}, err
	}
	items := make([]RunItem, 0, len(runs.WorkflowRuns))
	for _, r := range runs.WorkflowRuns {
		if r != nil {
			items = append(items, toRunItem(r))
		}
	}
	return countedResult(c, items, runs.GetTotalCount(), page, perPage, resp, clamped), nil
}

func (c *Connector) getWorkflowRun(ctx context.Context, client *gh.Client, call connectors.Call) (connectors.Result, error) {
	owner, repo, err := repoArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	id, err := idArg(call.Args, "run_id")
	if err != nil {
		return connectors.Result{}, err
	}
	run, _, err := client.Actions.GetWorkflowRunByID(ctx, owner, repo, id)
	if err := classify("get workflow run", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: toRunItem(run)}, nil
}

// StepItem is one step of a job.
type StepItem struct {
	Number     int64  `json:"number"`
	Name       string `json:"name"`
	Status     string `json:"status"`
	Conclusion string `json:"conclusion,omitempty"`
}

// JobItem is one list_workflow_jobs entry.
type JobItem struct {
	ID          int64      `json:"id"`
	Name        string     `json:"name"`
	Status      string     `json:"status"`
	Conclusion  string     `json:"conclusion,omitempty"`
	URL         string     `json:"url,omitempty"`
	StartedAt   string     `json:"started_at,omitempty"`
	CompletedAt string     `json:"completed_at,omitempty"`
	Steps       []StepItem `json:"steps,omitempty"`
}

func (c *Connector) listWorkflowJobs(ctx context.Context, client *gh.Client, call connectors.Call) (connectors.Result, error) {
	owner, repo, err := repoArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	id, err := idArg(call.Args, "run_id")
	if err != nil {
		return connectors.Result{}, err
	}
	filter, err := enumArg(call.Args, "filter", "latest", "all")
	if err != nil {
		return connectors.Result{}, err
	}
	page, perPage, clamped, err := c.pageArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	jobs, resp, err := client.Actions.ListWorkflowJobs(ctx, owner, repo, id, &gh.ListWorkflowJobsOptions{Filter: filter, ListOptions: gh.ListOptions{Page: page, PerPage: perPage}})
	if err := classify("list workflow jobs", err); err != nil {
		return connectors.Result{}, err
	}
	items := make([]JobItem, 0, len(jobs.Jobs))
	for _, j := range jobs.Jobs {
		if j == nil {
			continue
		}
		item := JobItem{ID: j.GetID(), Name: j.GetName(), Status: j.GetStatus(), Conclusion: j.GetConclusion(), URL: j.GetHTMLURL(),
			StartedAt: timestamp(j.StartedAt), CompletedAt: timestamp(j.CompletedAt)}
		for _, s := range j.Steps {
			if s != nil {
				item.Steps = append(item.Steps, StepItem{Number: s.GetNumber(), Name: s.GetName(), Status: s.GetStatus(), Conclusion: s.GetConclusion()})
			}
		}
		items = append(items, item)
	}
	return countedResult(c, items, jobs.GetTotalCount(), page, perPage, resp, clamped), nil
}

// JobLogs is get_job_logs's result: the last Lines of TotalLines lines.
type JobLogs struct {
	JobID      int64  `json:"job_id"`
	Logs       string `json:"logs"`
	Lines      int    `json:"lines"`
	TotalLines int    `json:"total_lines"`
	Truncated  bool   `json:"truncated,omitempty"`
}

func (c *Connector) getJobLogs(ctx context.Context, client *gh.Client, call connectors.Call) (connectors.Result, error) {
	owner, repo, err := repoArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	id, err := idArg(call.Args, "job_id")
	if err != nil {
		return connectors.Result{}, err
	}
	tail := defaultTailLines
	if v, ok := call.Args["tail_lines"]; ok && v != nil {
		if tail, err = toInt(v); err != nil || tail < 1 {
			return connectors.Result{}, invalid("tail_lines must be a positive integer")
		}
		tail = min(tail, maxTailLines)
	}
	logURL, resp, err := client.Actions.GetWorkflowJobLogs(ctx, owner, repo, id, 0)
	if err != nil {
		if resp != nil && resp.StatusCode != http.StatusFound {
			return connectors.Result{}, fromStatus("get job logs", resp.StatusCode, "", err)
		}
		return connectors.Result{}, classify("get job logs", err)
	}
	if err := c.checkLogURL(logURL); err != nil {
		return connectors.Result{}, err
	}
	data, total, lines, capped, err := c.downloadTail(ctx, logURL.String(), c.bounds.MaxResultBytes)
	if err != nil {
		return connectors.Result{}, err
	}
	kept := strings.SplitAfter(string(data), "\n")
	if kept[len(kept)-1] == "" {
		kept = kept[:len(kept)-1]
	}
	if total > len(data) && len(kept) > 0 {
		kept = kept[1:] // the first kept line was cut by the tail window
	}
	if len(kept) > tail {
		kept = kept[len(kept)-tail:]
	}
	out := JobLogs{JobID: id, TotalLines: lines, Truncated: capped}
	for {
		out.Logs, out.Lines = strings.Join(kept, ""), len(kept)
		if encodedSize(out) <= c.bounds.MaxResultBytes || len(kept) == 0 {
			break
		}
		kept = kept[1:]
	}
	if out.Lines < out.TotalLines {
		out.Truncated = true
	}
	return connectors.Result{Content: out, Partial: out.Truncated, Empty: out.TotalLines == 0}, nil
}

// checkLogURL accepts the signed log location only over https, or over
// the API's own scheme and host (GHES, tests).
func (c *Connector) checkLogURL(u *url.URL) error {
	base, _ := url.Parse(c.baseURL)
	if u == nil || u.Host == "" || (u.Scheme != "https" && !(base != nil && u.Scheme == base.Scheme && u.Host == base.Host)) {
		return &Error{Class: ClassVendorError, Message: "get job logs: GitHub returned an unusable log location"}
	}
	return nil
}

// downloadTail GETs the signed log URL without the account's token
// (the URL carries its own signature) through the connector's base
// transport, reads at most MaxLogDownloadBytes, and keeps the last keep
// bytes. total is how many bytes were read, lines how many lines they
// held, capped whether the download stopped at the cap.
func (c *Connector) downloadTail(ctx context.Context, u string, keep int) (tail []byte, total, lines int, capped bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, 0, false, &Error{Class: ClassVendorError, Message: "get job logs: bad log location"}
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := (&http.Client{Transport: c.transport}).Do(req)
	if err != nil {
		return nil, 0, 0, false, classify("download job logs", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, 0, false, fromStatus("download job logs", resp.StatusCode, "", nil)
	}
	body := io.LimitReader(resp.Body, MaxLogDownloadBytes+1)
	buf := make([]byte, 32<<10)
	var last byte
	for {
		n, rerr := body.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			total += n
			lines += bytes.Count(chunk, []byte{'\n'})
			last = chunk[n-1]
			tail = append(tail, chunk...)
			if len(tail) > 2*keep {
				tail = append([]byte(nil), tail[len(tail)-keep:]...)
			}
		}
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			return nil, 0, 0, false, classify("download job logs", rerr)
		}
	}
	if total > MaxLogDownloadBytes {
		capped = true
	}
	if total > 0 && last != '\n' {
		lines++
	}
	if len(tail) > keep {
		tail = tail[len(tail)-keep:]
	}
	return tail, total, lines, capped, nil
}

// --- writes ---------------------------------------------------------------------

// DispatchedRun is run_workflow's result.
type DispatchedRun struct {
	Workflow string `json:"workflow"`
	Ref      string `json:"ref"`
	RunID    int64  `json:"run_id,omitempty"`
	URL      string `json:"url,omitempty"`
	Repo     string `json:"repo"`
}

func dispatchResultIDs(res connectors.Result) map[string]string {
	v, ok := res.Content.(DispatchedRun)
	if !ok {
		return nil
	}
	if v.RunID == 0 {
		return map[string]string{"workflow": v.Workflow, "ref": v.Ref}
	}
	return map[string]string{"run_id": i64toa(v.RunID), "url": v.URL}
}

func (c *Connector) runWorkflow(ctx context.Context, client *gh.Client, call connectors.Call) (connectors.Result, error) {
	owner, repo, err := repoArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	wfID, wfFile, err := workflowArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	if wfID == 0 && wfFile == "" {
		return connectors.Result{}, invalid("workflow is required: a workflow file name (deploy.yml) or numeric id")
	}
	ref, err := requiredString(call.Args, "ref")
	if err != nil {
		return connectors.Result{}, err
	}
	req := gh.CreateWorkflowDispatchEventRequest{Ref: ref, ReturnRunDetails: gh.Ptr(true)}
	if v, ok := call.Args["inputs"]; ok && v != nil {
		inputs, ok := v.(map[string]any)
		if !ok {
			return connectors.Result{}, invalid("inputs must be an object of input name: value pairs")
		}
		req.Inputs = inputs
	}
	var details *gh.WorkflowDispatchRunDetails
	workflow := wfFile
	if wfID > 0 {
		workflow = strconv.FormatInt(wfID, 10)
		details, _, err = client.Actions.CreateWorkflowDispatchEventByID(ctx, owner, repo, wfID, req)
	} else {
		details, _, err = client.Actions.CreateWorkflowDispatchEventByFileName(ctx, owner, repo, wfFile, req)
	}
	if err := classifyWrite("run workflow", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: DispatchedRun{Workflow: workflow, Ref: ref, RunID: details.GetWorkflowRunID(), URL: details.GetHTMLURL(), Repo: owner + "/" + repo}}, nil
}

// RunAction is the result of rerun_workflow_run and cancel_workflow_run.
type RunAction struct {
	RunID  int64  `json:"run_id"`
	Action string `json:"action"`
	Repo   string `json:"repo"`
}

func runActionResultIDs(res connectors.Result) map[string]string {
	v, ok := res.Content.(RunAction)
	if !ok || v.RunID == 0 {
		return nil
	}
	return map[string]string{"run_id": i64toa(v.RunID)}
}

// acceptedOK treats GitHub's 202 Accepted (go-github's AcceptedError)
// as success: the action was queued.
func acceptedOK(err error) error {
	var accepted *gh.AcceptedError
	if errors.As(err, &accepted) {
		return nil
	}
	return err
}

func (c *Connector) rerunWorkflowRun(ctx context.Context, client *gh.Client, call connectors.Call) (connectors.Result, error) {
	owner, repo, err := repoArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	id, err := idArg(call.Args, "run_id")
	if err != nil {
		return connectors.Result{}, err
	}
	failedOnly, err := optionalBool(call.Args, "failed_only")
	if err != nil {
		return connectors.Result{}, err
	}
	action := "rerun"
	if failedOnly != nil && *failedOnly {
		action = "rerun_failed_jobs"
		_, err = client.Actions.RerunFailedJobsByID(ctx, owner, repo, id)
	} else {
		_, err = client.Actions.RerunWorkflowByID(ctx, owner, repo, id)
	}
	if err := classifyWrite("re-run workflow run", acceptedOK(err)); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: RunAction{RunID: id, Action: action, Repo: owner + "/" + repo}}, nil
}

func (c *Connector) cancelWorkflowRun(ctx context.Context, client *gh.Client, call connectors.Call) (connectors.Result, error) {
	owner, repo, err := repoArgs(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	id, err := idArg(call.Args, "run_id")
	if err != nil {
		return connectors.Result{}, err
	}
	_, err = client.Actions.CancelWorkflowRunByID(ctx, owner, repo, id)
	if err := classifyWrite("cancel workflow run", acceptedOK(err)); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: RunAction{RunID: id, Action: "cancel", Repo: owner + "/" + repo}}, nil
}

// checkCancelled is cancel_workflow_run's stable-id reconciliation: the
// run finished with conclusion cancelled is found; finished with any
// other conclusion is not_found; still queued or running (a cancel takes
// a moment) is "cannot tell yet".
func (c *Connector) checkCancelled(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	id, err := strconv.ParseInt(in.ResourceIdentity["run_id"], 10, 64)
	if err != nil || id < 1 {
		return connectors.ReconcileResult{}, fmt.Errorf("%w: resource identity has no run id", ErrNotReconcilable)
	}
	tg, err := c.target(ctx, in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	run, _, err := tg.client.Actions.GetWorkflowRunByID(ctx, tg.owner, tg.repo, id)
	if err := classify("reconcile: get workflow run", err); err != nil {
		return connectors.ReconcileResult{}, err
	}
	switch {
	case run.GetConclusion() == "cancelled":
		return found(i64toa(id)), nil
	case run.GetStatus() == "completed":
		return notFound, nil
	}
	return connectors.ReconcileResult{}, fmt.Errorf("github: reconcile: run %d is %s; cannot tell yet", id, run.GetStatus())
}
