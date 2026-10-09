# GitHub connector

App `github` (`internal/connectors/github`), the reference connector every other connector copies (Brain decision `bt8ukyrd`). It binds a user's GitHub account through the GitHub App user-to-server OAuth flow and exposes read and write tools over the REST API through [go-github](https://github.com/google/go-github) v90. Every write runs behind the safety core (policy, approvals, the write ledger) and declares how it is reconciled after an unknown outcome (see [Writes](#writes)).

## Tools

The first five are reads (`Kind: read`: no approval and no ledger unless policy says `confirm`); the four writes follow in [Writes](#writes). The gateway adds `account` and `approval_id` to every schema and generates `github.list_accounts`.

| Tool | Arguments | Result | GitHub App permission |
|---|---|---|---|
| `github.get_me` | none | `{login, id, profile_url, avatar_url, name, company, location, email, bio, created_at}` | none (`GET /user`) |
| `github.search_issues` | `q` (required; GitHub issues search syntax), `owner` + `repo` (optional; adds `repo:owner/repo` unless `q` already has one), `sort`, `order`, `page`, `per_page` | `{total_count, incomplete_results, page, per_page, has_more, truncated?, items: [{number, title, state, state_reason?, url, repo, is_pull_request, user, labels, assignees, comments, created_at, updated_at, closed_at}]}` | none (`GET /search/issues`; results limited to what the account can see) |
| `github.get_issue` | `owner`, `repo`, `number` | `{number, title, body, state, state_reason?, locked?, url, repo, is_pull_request?, user, author_association, labels, assignees, milestone, comments, created_at, updated_at, closed_at, closed_by, truncated?}` | Issues: read |
| `github.get_pull_request` | `owner`, `repo`, `number` | `{number, title, body, state, draft, merged, mergeable_state, url, repo, user, labels, assignees, requested_reviewers, merged_by, head: {ref, sha, repo}, base: {ref, sha, repo}, additions, deletions, changed_files, commits, comments, created_at, updated_at, closed_at, merged_at, milestone, truncated?}` | Pull requests: read |
| `github.list_pull_request_files` | `owner`, `repo`, `number`, `page`, `per_page` | `{page, per_page, has_more, truncated?, files: [{filename, status, additions, deletions, changes, patch, previous_filename, patch_truncated?}]}` | Pull requests: read |

Metadata (read) is mandatory for every GitHub App and is set automatically. The tools declare the permissions above as `RequiredScopes` (`issues:read`, `pull_requests:read`); GitHub App user tokens carry no OAuth scopes, so nothing hides on them (scope enforcement is not active in the gateway yet).

**Resource identity** (policy conditions and audit): `owner`, `repo` as `owner/name`, `org` = owner, and `number` where the tool takes one, all lower-cased. A role rule such as *confirm `github.*` when `repo` prefix `acme/`* therefore matches `acme/widgets`. `search_issues` only has an identity when `owner` and `repo` are given; `get_me` has none.

**Pagination and bounds.** `page` starts at 1; `per_page` defaults to 30 and is clamped to the tool's `MaxPageSize` (the package default 50, never above GitHub's 100). `has_more` says whether a next page exists (GitHub's `Link` header). `MaxResultBytes` (default 256 KiB) bounds the serialised result: lists drop trailing items (`truncated: true`, never below one item), `list_pull_request_files` drops the largest patches first (`patch_truncated: true`) and only then files, and single objects cut their `body` (`truncated: true`).

**Result markers** (`_meta["mcp-gateway/read"]`, decision `dovthftx`):

| Marker | When |
|---|---|
| `empty` | `search_issues` matched nothing, or the pull request has no files on that page |
| `partial` | `per_page` was clamped, the result was truncated to the bounds, or GitHub reported `incomplete_results` (search timed out) |
| `unavailable` | GitHub answered 5xx or could not be reached (DNS, TLS, connection reset); no content is returned |

**Errors.** A `*github.Error` carries `Status` and a `Class`; the message tells the harness what to do:

| Class | Cause | What the harness should do |
|---|---|---|
| `reconnect_required` | 401 from GitHub, or the connection has no usable token (`connections.ErrNeedsReconnect`) | ask the user to reconnect GitHub on `/connections` |
| `no_account` | the call carried no connected account (the pipeline normally answers `-32031` first) | ask the user to connect GitHub |
| `not_found` | 404/410: the resource does not exist or the account cannot see it | check owner/repo/number; GitHub hides private resources as 404 |
| `forbidden` | 403 that is not a rate limit: the GitHub App is not installed on that repository or organization, or lacks the permission | an org owner must install the app (see setup) |
| `invalid_argument` | the connector rejected the arguments, or GitHub answered 400/422 | fix the arguments |
| `vendor_error` | any other GitHub status | retry later |

Primary rate limits (403/429 with `X-RateLimit-Remaining: 0`) and secondary rate limits (`Retry-After` or the "secondary rate limit" message) are returned as `*connectors.RateLimited{App: "github", RetryAfter}` (the reset time, the `Retry-After` header, or 60 s when GitHub gives none); the harness gets `-32029` with `retry_after` and the app is paused for everyone until then. Context cancellation and deadlines pass through unchanged. Every call is bounded by `Options.Timeout` (default 30 s).

The pipeline's audit row records any connector error as class `tool_error` today (the connector's class is in the error text); surfacing `Error.Class` on the audit row is a follow-up for the pipeline.

## Writes

Four write tools (`Kind: write`: always policy, approval when the role says `confirm`, and the write ledger; decision `dovthftx`). Each returns only the identifiers of what it created; the ledger stores those (`ResultIDs`) and replays them for a duplicate call inside the idempotency window.

| Tool | Arguments | Result / `ResultIDs` | Reconciliation | GitHub App permission |
|---|---|---|---|---|
| `github.create_issue` | `owner`, `repo`, `title`, `body?`, `labels?` (array of names), `assignees?` (array of logins) | `{number, id, url, repo, state}` / `number`, `id`, `url` | **marker** in the issue body | Issues: write |
| `github.add_issue_comment` | `owner`, `repo`, `number` (issue or pull request), `body` | `{id, url, repo, number}` / `id`, `url` | **marker** in the comment body | Issues: write |
| `github.create_pull_request` | `owner`, `repo`, `title`, `head` (`branch` or `login:branch` for a fork), `base`, `body?`, `draft?` | `{number, id, url, repo, state, draft, head, base}` / `number`, `id`, `url` | **marker** in the pull request body | Pull requests: write |
| `github.create_branch` | `owner`, `repo`, `branch`, `from_branch?` (the repository's default branch when omitted) | `{ref, branch, sha, url, repo}` / `sha`, `ref`, `url` | **stable id** (the branch name) | Contents: write |

**Resource identity** of the writes: `owner`, `repo` (`owner/name`), `org` (= owner), lower-cased as for the reads; `add_issue_comment` adds `number`; `create_pull_request` adds `branch` (= `head`, as given) and `base`; `create_branch` adds `branch`. Branch names keep their case: git refs are case-sensitive and the reconciler looks the branch up by this value. A role rule such as *confirm `github.create_issue` when `org` equals `acme`* confirms writes in the company organization and, with no other rule for the tool, denies them anywhere else (`-32030 denied by policy`).

**Operation id.** The ledger stage sets `Call.OperationID` before dispatch. Every write requires it and answers `github.ErrMissingOperation` without one: a write that reached the connector without the ledger could never be verified afterwards, so it is refused rather than guessed about. This can only happen through a wiring bug, never through a harness.

**Markers.** The three marker-reconciled writes append a hidden HTML comment to the body they create, on its own paragraph:

```
<!-- mcp-gateway op:<operation id> -->
```

GitHub renders nothing for an HTML comment, so users never see it; the reconciler searches for it. The marker is the whole reconciliation key: nothing else about the write (not the title, not the text) is stored by the ledger, which keeps only the resource identity and the operation id (decision `enlsy40f`). `github.Marker(operationID)` builds it.

**Outcomes.** A GitHub answer is a known outcome: 422/400 is `invalid_argument` (including "Reference already exists" from `create_branch` and "A pull request already exists" from `create_pull_request`), 403 `forbidden`, 404 `not_found`, 401 `reconnect_required`, rate limits `*connectors.RateLimited`; the ledger records `failed` and the key is free again. Anything that leaves the outcome open after the request was sent — a 5xx, a timeout (`Options.Timeout`), a cancelled context, a dropped connection — is returned wrapped in `connectors.ErrOutcomeUnknown`: the ledger marks the operation `unknown`, the harness sees *outcome unknown*, a duplicate call answers `-32033 pending verification`, and the reconciler job takes over. Writes never return `Result{Unavailable: true}`. `create_branch`'s lookups before the write (the repository's default branch, the source branch's commit) are reads: their failures are known (`not_found`, `unavailable`, ...) and the branch is not created.

### Reconciliation

`Reconciliation.Check` runs from the ledger row alone — the resource identity, the operation id and the account; arguments are never stored — with the same account's token through the same per-call token source. A definite answer closes the operation (`found` → `succeeded` with `{"id": <resource id>}`, `not_found` → `failed`); an error is "cannot tell yet" and the reconciler retries with backoff until its own limits make the operation `unresolved` and notify the user (decision `enlsy40f`). Every list is bounded by `github.MaxReconcilePages` (5 pages of 100); running out of pages is "cannot tell yet", never `not_found`.

| Tool | Check | found | not_found |
|---|---|---|---|
| `create_issue` | 1. `GET /search/issues` with `repo:owner/name "mcp-gateway op:<id>" in:body`; a hit whose body carries the marker is the issue. The search index lags and may not cover HTML comments, so search only ever proves presence. 2. Otherwise `GET /user` for the login, then `GET /repos/owner/name/issues?creator=<login>&state=all&sort=created&direction=desc`, newest first, bounded. | issue number | the user's issues in the repository were listed to the end without the marker |
| `add_issue_comment` | `GET /repos/owner/name/issues/<number>/comments` (GitHub lists oldest first): page 1 tells where the last page is, then the pages are walked backwards (newest first), bounded. A 404 is "cannot tell" (the account may have lost access). | comment id | every page read without the marker |
| `create_pull_request` | `GET /repos/owner/name/pulls?state=all&head=<owner>:<branch>` (`head` as given when it already names a fork `login:branch`), newest first, bounded; the list endpoint is not a search index, so its answer is authoritative. | pull request number | the end of the list without the marker |
| `create_branch` | `GET /repos/owner/name/git/ref/heads/<branch>` | the commit sha | 404 |

The reconciler stores `found`'s resource id under `id`; the original `ResultIDs` keys (`number`, `url`, ...) are only known when the write itself answered.

**Permissions.** Repository permissions: Issues write, Pull requests write, Contents write (the reads' permissions are implied). Organization **Members: read** is only needed for the binder's private-membership check (see [Account binding](#account-binding)); the writes and their checks need none. The search API has its own rate limit (30 requests per minute per token); the checks use it once per attempt and fall back to the REST listing on any search error.

## Account binding

`github.Binder` implements `connections.Binder` for vendor `github` and is installed by `cmd/gateway` (`registerGitHub`: `connSvc.RegisterBinder("github", github.Binder{})`, `connSvc.MapApp("github", "github")`). After the code exchange it:

1. calls `GET /user` with the new token: the permanent numeric id becomes the external account id `github:<id>` (logins can be renamed; ids cannot), the login the display name;
2. labels the account **company** when the user is an *active* member of one of the organizations in the vendor app's `company_orgs` extra (comma separated, case-insensitive), checked through `GET /user/memberships/orgs/{org}`; when that endpoint answers 403 (the app lacks the *Members* organization permission) it falls back to the public membership check `GET /orgs/{org}/members/{login}`; a 404 or a pending membership means not a member. Everything else, and every account when `company_orgs` is empty, is **personal**;
3. reports scopes from the token response's `scope`, else the `X-OAuth-Scopes` header (OAuth Apps); GitHub App user tokens have neither, so it reports none and the connect flow records the requested scopes.

The binder follows the vendor app's **User info URL** for the API root (`https://api.github.com/user` by default; `https://<ghes>/api/v3/user` for GitHub Enterprise Server), so the membership lookups go to the same host. `github.Options.BaseURL` does the same for the tools (not configurable from `cmd/gateway` yet).

A 401 on `/user` fails the connect with `reconnect_required`; a 5xx fails it with `unavailable` (the user can retry). The binder never guesses the label on an unexpected error.

## Setup

1. Register the GitHub App as described in [`docs/vendor-apps.md`](../vendor-apps.md) section 1 (user-to-server tokens, expiring tokens on, no webhook). Repository permissions: Issues read and write, Pull requests read and write, Contents write (for `create_branch`). Organization permissions: add **Members: read** if company classification must see *private* org memberships; without it only public memberships count (the fallback above). The writes need no organization permission.
2. An **org owner installs the app on the company organization**; users install it on their own accounts for personal repositories. A valid token on a repository the app is not installed on answers `forbidden`.
3. In the portal, **Settings -> Vendor apps -> github**: client ID, client secret, the default endpoints (authorization `https://github.com/login/oauth/authorize`, token `https://github.com/login/oauth/access_token`, user info `https://api.github.com/user`), and in **Extra parameters** the line
   ```
   company_orgs=acme,acme-labs
   ```
   Leave *Scopes* empty: GitHub Apps ignore the `scope` parameter; permissions are app-level. `company_orgs` is a reserved binder hint (`connections.ExtraCompanyOrgs`): it is read by the gateway and never sent to GitHub as an authorization parameter.
4. Users connect on `/connections` -> GitHub -> *Connect*. The connection's label and display name appear on the page; `github.list_accounts` shows them to a harness.
5. Grant the tools to a role on `/admin/roles` (`github.*` allow, or per tool; use `repo` prefix or `org` equals conditions to confirm or deny by repository or organization; a write with only conditional rules is denied wherever no condition holds).

The connector is registered whenever the connections module is mounted (a key provider is configured), before the vendor app exists; until a user connects, every tool answers *no connected account* (`-32031` from the pipeline).

## Tests

- `go test ./internal/connectors/github/`: the contract test (`connectortest.ContractTest`), the binder (company / personal / public-membership fallback / scopes / 401 / GHES root), and every tool against hand-written, scrubbed fixtures under `testdata/` served by an `httptest` server that also checks the bearer: reads (success, empty, partial, 404, 401, 403, 5xx, network failure, primary and secondary rate limits, cancelled context, argument validation, resource identity and schema shape) and writes (the marker in the request body, `ResultIDs`, the missing operation id, 422 / 403 / 404 / 401 / 429 as known outcomes, 5xx / timeout / dropped connection as `ErrOutcomeUnknown`, `create_branch`'s pre-write lookups failing as known outcomes) and every `Check` (found, not_found, cannot tell, bounded pagination with the marker on a later page, the search hit without the marker not trusted, missing identity). No real tokens or personal data appear in the fixtures (`octocat` / `example-org` / `*.example.test`).
- `make test-e2e` (`test/e2e/github_test.go`): the real connector behind the whole gateway against a stub GitHub API (`world_github_test.go`): `create_issue` in org `acme` needs an approval, the approved retry creates the issue with the marker in its body and the ledger stores the ids; a write in another org is denied; a timed-out write that GitHub applied is reconciled to `succeeded` by its marker and a duplicate call replays the stored ids; a timed-out write GitHub did not apply ends `failed` (`not_found`) and the block is lifted.
- `GITHUB_LIVE_TOKEN=... go test -tags live -run Live ./internal/connectors/github/`: `get_me` against api.github.com with a dedicated test account's token (a GitHub App user token or a fine-grained PAT). With `GITHUB_LIVE_REPO=owner/name` as well (the token needs Issues: write there), `TestLiveCreateIssueAndReconcile` creates an issue under a fresh operation id, runs `create_issue`'s check from the resource identity alone and expects it to find the issue by its marker, then closes the issue. Behind the `live` build tag and skipped without the variables; never run in CI.

## Adding the next tool

1. Declare it in `readTools()` (`tools_read.go`) or `writeTools()` (`tools_write.go`): `App`, `Name`, `Description` (what the model reads), `InputSchema` via `objectSchema(props, required)`, `Kind`, `RequiredScopes` (`<permission>:<access>`), `ResourceIdentity` (`identity(withNumber)`, `branchIdentity(...)` or a custom hook that never returns argument content), `Bounds` (`paged` or `single`). Writes also set `Reconcile{Kind, Check}` and `ResultIDs`.
2. Add the handler to `handlers()` (reads) or `writeHandlers()` (writes) and implement it as `func(ctx, *gh.Client, connectors.Call) (connectors.Result, error)`: validate arguments with `repoArgs` / `numberArg` / `pageArgs` / `requiredString` / `stringList` (return `invalid(...)`), call go-github, convert the response with a `to*` function in `minimal.go` (flat shapes: logins not user objects, `repo` as `owner/name`, `url`). Reads pass every error through `classify(action, err)`, set `Empty` / `Partial` and fit the result to `c.bounds.MaxResultBytes` (`encodedSize`, `fitBody`). Writes embed `withMarker(body, call.OperationID)` when they reconcile by marker, pass the error of the request that performs the write through `classifyWrite` (and of any lookup before it through `classify`), and return a `Created*` result the `ResultIDs` hook reads.
3. For a write, add its `Check` to `reconcile.go` starting from `c.target(ctx, in)` (validates the operation id, the repository and the account, builds the client): bounded listing with `MaxReconcilePages`, `found(id)` / `notFound` for definite answers, an error for everything else. Store in the resource identity whatever the check needs (the branch, the number).
4. Add fixtures under `testdata/` (scrub names, ids, URLs) and tests for success, empty, partial, 404 and a rate limit (reads) or the marker, the error table (`writeErrorCases`) and the check's found / not_found / cannot-tell cases (writes). The contract test picks the tool up automatically.
5. If the description or schema is adapted from `github/github-mcp-server`, keep the headers in `tools_read.go` / `tools_write.go` / `minimal.go` accurate and update the rows in `THIRD_PARTY_NOTICES.md`.
6. Document it in the tables above and, if it needs a new permission, in `docs/vendor-apps.md` section 1.2.
