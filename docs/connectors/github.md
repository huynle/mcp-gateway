# GitHub connector

App `github` (`internal/connectors/github`), the reference connector every other connector copies (Brain decision `bt8ukyrd`). It binds a user's GitHub account through the GitHub App user-to-server OAuth flow and exposes read tools over the REST API through [go-github](https://github.com/google/go-github) v90. Writes land in a later task (`tools_write.go`).

## Tools

All five are reads (`Kind: read`: no approval and no ledger unless policy says `confirm`). The gateway adds `account` and `approval_id` to every schema and generates `github.list_accounts`.

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

## Account binding

`github.Binder` implements `connections.Binder` for vendor `github` and is installed by `cmd/gateway` (`registerGitHub`: `connSvc.RegisterBinder("github", github.Binder{})`, `connSvc.MapApp("github", "github")`). After the code exchange it:

1. calls `GET /user` with the new token: the permanent numeric id becomes the external account id `github:<id>` (logins can be renamed; ids cannot), the login the display name;
2. labels the account **company** when the user is an *active* member of one of the organizations in the vendor app's `company_orgs` extra (comma separated, case-insensitive), checked through `GET /user/memberships/orgs/{org}`; when that endpoint answers 403 (the app lacks the *Members* organization permission) it falls back to the public membership check `GET /orgs/{org}/members/{login}`; a 404 or a pending membership means not a member. Everything else, and every account when `company_orgs` is empty, is **personal**;
3. reports scopes from the token response's `scope`, else the `X-OAuth-Scopes` header (OAuth Apps); GitHub App user tokens have neither, so it reports none and the connect flow records the requested scopes.

The binder follows the vendor app's **User info URL** for the API root (`https://api.github.com/user` by default; `https://<ghes>/api/v3/user` for GitHub Enterprise Server), so the membership lookups go to the same host. `github.Options.BaseURL` does the same for the tools (not configurable from `cmd/gateway` yet).

A 401 on `/user` fails the connect with `reconnect_required`; a 5xx fails it with `unavailable` (the user can retry). The binder never guesses the label on an unexpected error.

## Setup

1. Register the GitHub App as described in [`docs/vendor-apps.md`](../vendor-apps.md) section 1 (user-to-server tokens, expiring tokens on, no webhook). Repository permissions: Issues read, Pull requests read (writes are added by the next task). Organization permissions: add **Members: read** if company classification must see *private* org memberships; without it only public memberships count (the fallback above).
2. An **org owner installs the app on the company organization**; users install it on their own accounts for personal repositories. A valid token on a repository the app is not installed on answers `forbidden`.
3. In the portal, **Settings -> Vendor apps -> github**: client ID, client secret, the default endpoints (authorization `https://github.com/login/oauth/authorize`, token `https://github.com/login/oauth/access_token`, user info `https://api.github.com/user`), and in **Extra parameters** the line
   ```
   company_orgs=acme,acme-labs
   ```
   Leave *Scopes* empty: GitHub Apps ignore the `scope` parameter; permissions are app-level. (Any Extra key the connections module does not reserve is also sent as an authorization parameter; GitHub ignores `company_orgs` there. Adding it to the reserved keys is a small follow-up in `internal/connections`.)
4. Users connect on `/connections` -> GitHub -> *Connect*. The connection's label and display name appear on the page; `github.list_accounts` shows them to a harness.
5. Grant the tools to a role on `/admin/roles` (`github.*` allow, or per tool; use `repo` prefix conditions to confirm or deny by repository).

The connector is registered whenever the connections module is mounted (a key provider is configured), before the vendor app exists; until a user connects, every tool answers *no connected account* (`-32031` from the pipeline).

## Tests

- `go test ./internal/connectors/github/`: the contract test (`connectortest.ContractTest`), the binder (company / personal / public-membership fallback / scopes / 401 / GHES root), and every tool against hand-written, scrubbed fixtures under `testdata/` served by an `httptest` server that also checks the bearer: success, empty, partial (clamped page, truncated result, `incomplete_results`), 404, 401, 403, 5xx, network failure, primary and secondary rate limits, cancelled context, argument validation, resource identity and schema shape. No real tokens or personal data appear in the fixtures (`octocat` / `example-org` / `*.example.test`).
- `GITHUB_LIVE_TOKEN=... go test -tags live -run Live ./internal/connectors/github/`: `get_me` against api.github.com with a dedicated test account's token (a GitHub App user token or a fine-grained PAT with no permissions). Behind the `live` build tag and skipped without the variable; never run in CI.

## Adding the next tool

1. Declare it in `readTools()` (or `tools_write.go` for writes): `App`, `Name`, `Description` (what the model reads), `InputSchema` via `objectSchema(props, required)`, `Kind`, `RequiredScopes` (`<permission>:<access>`), `ResourceIdentity` (`identity(withNumber)` or a custom hook that never returns argument content), `Bounds` (`paged` or `single`). Writes also set `Reconcile{Kind, Check}` and `ResultIDs`.
2. Add the handler to `handlers()` and implement it as `func(ctx, *gh.Client, connectors.Call) (connectors.Result, error)`: validate arguments with `repoArgs` / `numberArg` / `pageArgs` (return `invalid(...)`), call go-github, pass every error through `classify(action, err)`, convert the response with a `to*` function in `minimal.go` (flat shapes: logins not user objects, `repo` as `owner/name`, `url`), set `Empty` / `Partial` and fit the result to `c.bounds.MaxResultBytes` (`encodedSize`, `fitBody`).
3. Add fixtures under `testdata/` (scrub names, ids, URLs) and tests for success, empty, partial, 404 and a rate limit. The contract test picks the tool up automatically.
4. If the description or schema is adapted from `github/github-mcp-server`, keep the headers in `tools_read.go` / `minimal.go` accurate and update the rows in `THIRD_PARTY_NOTICES.md`.
5. Document it in the table above and, if it needs a new permission, in `docs/vendor-apps.md` section 1.2.
