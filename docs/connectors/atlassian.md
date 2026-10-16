# Atlassian connector (Jira + Confluence)

Two connector apps, `jira` and `confluence` (`internal/connectors/atlassian`), over one vendor, `atlassian` (OAuth 2.0 3LO). Built after the GitHub reference connector (Brain decision `bt8ukyrd`; see [`github.md`](github.md) for the conventions it copies): a `connections.Binder` for the account and the site it is bound to, read tools and write tools behind the safety core (policy, approvals, the write ledger), each write declaring how it is reconciled after an unknown outcome.

**Client.** A thin REST client (`client.go`, ~100 lines: one authenticated `http.Client`, the two products' URL prefixes, JSON in/out, `Retry-After`) instead of [`ctreminiom/go-atlassian`](https://github.com/ctreminiom/go-atlassian). The SDK declares `go 1.23` (so it would build) but is a very large generated-style library (hundreds of services, pulls `mergo`, `gjson`, `uuid`, `testify`) for the dozen endpoints this connector uses; the same reasoning as the Microsoft Graph client in `bt8ukyrd`. Every request goes through Atlassian's OAuth gateway: `https://api.atlassian.com/ex/jira/<cloud id>/rest/api/3/...` and `https://api.atlassian.com/ex/confluence/<cloud id>/wiki/...` (`api/v2` for pages and spaces, `rest/api/content/search` for CQL).

**Design source.** Tool names, argument shapes and the simplified result shapes follow [sooperset/mcp-atlassian](https://github.com/sooperset/mcp-atlassian) (MIT) at design level; no code was copied (decision `0sod196t`; the project is Python). The prototype's `src/mcp_gateway/atlassian.py` and `tests/test_atlassian.py` (commit `b6ad1b4`) were the behavioural reference; every test there has a counterpart below ([Prototype test mapping](#prototype-test-mapping)).

## Tools

The gateway adds `account` and `approval_id` to every schema and generates `jira.list_accounts` and `confluence.list_accounts`; both list the same `atlassian` connections.

### Reads (`Kind: read`)

| Tool | Arguments | Result | Scope |
|---|---|---|---|
| `jira.search_issues` | `jql` (required), `max_results` (1-100, default 10, clamped to `MaxPageSize`), `fields` (subset of `summary, status, issuetype, priority, assignee, reporter, labels, created, updated, project`), `next_page_token` (from the previous page) | `{issues: [{key, id, summary, status, issue_type, priority, assignee, reporter, labels, created, updated, url, project}], max_results, has_more, next_page_token?, truncated?}` | `read:jira-work` (`GET /rest/api/3/search/jql`) |
| `jira.get_issue` | `key` (`ABC-123`), `fields` (subset of the above plus `description, components, resolution`) | `{key, id, summary, description (ADF flattened to plain text), status, issue_type, priority, assignee, reporter, labels, components, resolution, created, updated, url, project, truncated?}` | `read:jira-work` (`GET /rest/api/3/issue/{key}`) |
| `jira.list_transitions` | `key` | `{issue, transitions: [{id, name, to}]}` | `read:jira-work` (`GET /rest/api/3/issue/{key}/transitions`) |
| `confluence.search` | `cql` (required), `limit` (1-100, default 10, clamped), `start` (offset, default 0) | `{results: [{id, type, status, title, space, url, last_modified}], start, limit, size, has_more, truncated?}` | `search:confluence` (`GET /wiki/rest/api/content/search?expand=space,version`) |
| `confluence.get_page` | `id` (digits) | `{id, title, status, space_id, parent_id, version, body_format: "storage", body (XHTML), url, created_at, truncated?}` | `read:page:confluence` (`GET /wiki/api/v2/pages/{id}?body-format=storage`) |
| `jira.get_current_user` | none | `{account_id, display_name, email?, time_zone, active, account_type}` | `read:jira-user` (`GET /myself`) |
| `jira.get_user` | `account_id` | same as `get_current_user` | `read:jira-user` (`GET /user?accountId=`) |
| `jira.search_users` | `query` (name or email), `max_results`, `start_at` | `{users: [...], start_at, max_results, has_more}` | `read:jira-user` (`GET /user/search`) |
| `jira.list_assignable_users` | `key` or `project_key`, `query?`, paging | like `search_users` | `read:jira-user` (`GET /user/assignable/search`) |
| `jira.list_projects` | `query?`, `max_results`, `start_at` | `{projects: [{id, key, name, type, style}], start_at, max_results, total, has_more}` | `read:jira-work` (`GET /project/search`) |
| `jira.list_issue_types` | `project_key`, paging | `{project, issue_types: [{id, name, description, subtask}], ...}` | `read:jira-work` (`GET /issue/createmeta/{key}/issuetypes`) |
| `jira.get_create_fields` | `project_key`, `issue_type_id`, paging | `{fields: [{id, name, required, type, items?, custom?, allowed_values (<= 50), more_values?, has_default}], ...}` | `read:jira-work` (`GET /issue/createmeta/{key}/issuetypes/{id}`) |
| `jira.list_project_statuses` | `project_key` | `{project, issue_types: [{issue_type, subtask, statuses: [{id, name, category}]}]}` | `read:jira-work` (`GET /project/{key}/statuses`) |
| `jira.list_project_versions` | `project_key` | `{project, versions: [{id, name, description, released, archived, overdue, start_date, release_date}]}` | `read:jira-work` (`GET /project/{key}/versions`) |
| `jira.list_project_components` | `project_key` | `{project, components: [{id, name, description, lead}]}` | `read:jira-work` (`GET /project/{key}/components`) |
| `jira.get_issue_comments` | `key`, paging | `{issue, comments: [{id, author, body (plain text), created, updated, url}], ...}`, newest first | `read:jira-work` (`GET /issue/{key}/comment`) |
| `jira.get_issue_changelog` | `key`, paging | `{issue, histories: [{id, author, created, items: [{field, from, to}]}], ...}`, oldest first | `read:jira-work` (`GET /issue/{key}/changelog`) |
| `jira.list_issue_links` | `key` | `{issue, links: [{id, type, direction, relation, issue, summary, status, url}]}` | `read:jira-work` (`GET /issue/{key}?fields=issuelinks`) |
| `jira.list_link_types` | none | `{link_types: [{id, name, inward, outward}]}` | `read:jira-work` (`GET /issueLinkType`) |
| `jira.list_remote_links` | `key` | `{issue, links: [{id, global_id, title, url, summary, relationship, application}]}` | `read:jira-work` (`GET /issue/{key}/remotelink`) |
| `jira.list_worklogs` | `key`, paging | `{issue, worklogs: [{id, author, time_spent, time_spent_seconds, started, comment}], ...}` | `read:jira-work` (`GET /issue/{key}/worklog`) |
| `jira.get_watchers` | `key` | `{issue, is_watching, watch_count, watchers: [...]}` | `read:jira-work` (`GET /issue/{key}/watchers`) |
| `jira.list_filters` | `name?`, paging | `{filters: [{id, name, description, owner, favourite, jql}], ...}` | `read:jira-work` (`GET /filter/search?expand=description,favourite,jql,owner`) |
| `jira.list_boards` | `project_key?`, `name?`, `type?` (scrum, kanban, simple), paging | `{boards: [{id, name, type, project}], ...}` | granular `read:board-scope:jira-software` + `read:project:jira` (`GET /rest/agile/1.0/board`) |
| `jira.list_sprints` | `board_id`, `state?` (active, future, closed), paging | `{board_id, sprints: [{id, name, state, start_date, end_date, complete_date, goal}], ...}` | granular `read:sprint:jira-software` (`GET /rest/agile/1.0/board/{id}/sprint`) |
| `jira.get_sprint_issues` | `sprint_id`, `jql?`, paging | the `search_issues` hit shape | granular `read:sprint:jira-software` + `read:issue-details:jira` + `read:jql:jira` (`GET /rest/agile/1.0/sprint/{id}/issue`) |
| `confluence.list_spaces` | `keys?`, `type?`, `limit`, `cursor` | `{spaces: [{id, key, name, type, status, homepage_id, url}], limit, has_more, next_cursor?}` | `read:space:confluence` (`GET /wiki/api/v2/spaces`) |
| `confluence.list_space_pages` | `space_key`, `depth?` (all, root), `limit`, `cursor` | `{space, pages: [{id, title, status, space_id, position?, parent_id?}], ...}` | `read:page:confluence` + `read:space:confluence` (`GET /wiki/api/v2/spaces?keys=`, then `/spaces/{id}/pages`) |
| `confluence.get_page_by_title` | `space_key`, `title` (exact) | like `get_page` | `read:page:confluence` + `read:space:confluence` (`GET /wiki/api/v2/pages?space-id=&title=`) |
| `confluence.get_page_children` | `id`, `limit`, `cursor` | `{parent_id, children: [{id, title, status, space_id, position}], ...}` | `read:page:confluence` (`GET /wiki/api/v2/pages/{id}/children`) |
| `confluence.get_page_comments` | `id`, `kind?` (footer, inline), `limit`, `cursor` | `{page_id, kind, comments: [{id, status, author_id, created_at, body (storage), resolution_status?, inline_selection?, url}], ...}` | `read:comment:confluence` (`GET /wiki/api/v2/pages/{id}/footer-comments` / `inline-comments`) |
| `confluence.list_page_attachments` | `id`, `limit`, `cursor` | metadata only: `{page_id, attachments: [{id, title, media_type, file_size, comment, created_at, download_url, url}], ...}` | `read:attachment:confluence` (`GET /wiki/api/v2/pages/{id}/attachments`) |
| `confluence.get_page_labels` | `id`, `limit`, `cursor` | `{page_id, labels: [{id, name, prefix}], ...}` | `read:page:confluence` (`GET /wiki/api/v2/pages/{id}/labels`) |
| `confluence.get_page_history` | `id`, `limit`, `cursor` | `{page_id, versions: [{number, author_id, message, created_at, minor_edit}], ...}`, newest first | `read:page:confluence` (`GET /wiki/api/v2/pages/{id}/versions`) |

`RequiredScopes` are the Atlassian OAuth 2.0 (3LO) scopes of `docs/vendor-apps.md` section 3 (`read:jira-user` is implied for the user fields); the connect flow records the granted scopes from the token response.

**Resource identity** (policy conditions and audit; never argument content):

| Key | Set by | Value |
|---|---|---|
| `project` | `get_issue`, `list_transitions`, `add_comment`, `transition_issue` (prefix of `key`), `create_issue` (`project_key`), `search_issues` (the `project = KEY` clause of the JQL, when the query mentions the project field exactly once with `=` and a bare or quoted key; `project in (...)`, `!=`, two mentions, or a numeric id give none) | upper-cased project key |
| `issue` | the tools taking `key` | upper-cased issue key |
| `space` | `create_page` (`space_key`), `search` (the `space = KEY` clause of the CQL, same rule, personal `~user` keys included) | space key as given |
| `page` | the Confluence tools taking `id` | page id |
| `board`, `sprint` | `list_sprints` (`board_id`), `get_sprint_issues`, `add_issues_to_sprint` (`sprint_id`) | numeric id |
| `assignee` | `assign_issue` | the account id, or `unassigned` |
| `comment` | `edit_comment` | comment id |
| `linked_issue`, `link_type` | `link_issues` (`outward_key`, `link_type`; `issue` is `inward_key`) | issue key, link type name |
| `watcher` | `add_watcher`, `remove_watcher` | account id |
| `issues` | `add_issues_to_sprint` | the issue keys, comma separated |
| `parent_comment` | `add_page_comment` | footer comment id |
| `labels` | `add_page_labels` | the lower-cased labels, comma separated |

The site is **not** part of the identity: it is a property of the connection (each connection is bound to one site, see [Account binding](#account-binding)), so a policy rule distinguishes sites by account label (company vs personal), not by identity. A role rule such as *confirm `jira.create_issue` when `project` equals `OPS`* works as for GitHub's `repo`.

**Pagination and bounds.** `search_issues` paginates with Jira's `nextPageToken` (`has_more`, `next_page_token`); `search` with `start`/`limit` (`has_more` from Confluence's `_links.next`). Page sizes are clamped to the tool's `MaxPageSize` (package default 50, never above 100) and the result is marked `partial` when clamped. `MaxResultBytes` (default 256 KiB) bounds the serialised result: lists drop trailing items (`truncated: true`, never below one), single objects cut the `description` / `body` (`truncated: true`).

**Result markers** (`_meta["mcp-gateway/read"]`, decision `dovthftx`): `empty` when a search matched nothing or an issue has no transitions; `partial` when clamped or truncated; `unavailable` when Atlassian answered 5xx or could not be reached (no content).

**Errors.** `*atlassian.Error{Status, Class, Message}`; the message carries Atlassian's own `errorMessages` / `errors` / `message` (bounded) so a bad JQL or CQL is explained:

| Class | Cause |
|---|---|
| `reconnect_required` | 401, or the connection has no usable token (`connections.ErrNeedsReconnect`) |
| `no_account` | the call carried no connected account |
| `not_found` | 404/410: the issue, page or space does not exist or the account cannot see it |
| `forbidden` | 403: the account lacks the project/space permission, or the app lacks the scope |
| `invalid_argument` | the connector rejected the arguments, or Atlassian answered 400/422 (bad JQL/CQL, missing field, duplicate page title) |
| `vendor_error` | any other status, a 2xx reply that could not be read (a read), or a connection whose site cannot be resolved |

A 429 is returned as `*connectors.RateLimited{App: "jira" | "confluence", RetryAfter}` (the `Retry-After` header, else 60 s); the two apps are rate-limited separately by the gateway even though they share the vendor's quota. Context cancellation and deadlines pass through unchanged; every call is bounded by `Options.Timeout` (default 30 s).

### Writes (`Kind: write`)

| Tool | Arguments | Result / `ResultIDs` | Reconciliation | Scope |
|---|---|---|---|---|
| `jira.create_issue` | `project_key`, `issue_type` (name: Task, Bug, ...), `summary`, `description?` (plain text, one paragraph per line), `labels?` | `{key, id, url, project}` / `key`, `id`, `url` | **marker** paragraph in the description | `write:jira-work` (`POST /rest/api/3/issue`) |
| `jira.add_comment` | `key`, `body` (plain text) | `{id, issue, url}` / `id`, `url` | **marker** paragraph in the comment | `write:jira-work` (`POST /rest/api/3/issue/{key}/comment`) |
| `jira.transition_issue` | `key`, `transition_id` (from `list_transitions`) | `{issue, transition_id}` / `issue`, `transition_id` | **none** | `write:jira-work` (`POST /rest/api/3/issue/{key}/transitions`) |
| `confluence.create_page` | `space_key`, `title`, `body` (storage format XHTML, or plain text which is escaped and wrapped in `<p>`), `parent_id?` | `{id, space_id, url, space}` / `id`, `url` | **marker** paragraph in the body | `write:page:confluence` + `read:space:confluence` (`GET /wiki/api/v2/spaces?keys=` then `POST /wiki/api/v2/pages`) |
| `jira.update_issue` | `key`, `summary?`, `description?` (replaces), `labels?` (replace), `priority?`, `fields?` (by field id) | `{issue, updated, url}` / `issue`, `url` | **none** (an edit leaves no marker) | `write:jira-work` (`PUT /issue/{key}`) |
| `jira.assign_issue` | `key`, `account_id?` (omit to unassign) | `{issue, assignee}` | **stable id**: the issue's assignee | `write:jira-work` (`PUT /issue/{key}/assignee`) |
| `jira.edit_comment` | `key`, `comment_id`, `body` | `{id, issue, url}` | **marker** in the new body | `write:jira-work` (`PUT /issue/{key}/comment/{id}`) |
| `jira.add_worklog` | `key`, `time_spent` (`1h 30m`), `started?` (RFC 3339), `comment?` | `{id, issue}` | **marker** in the worklog comment | `write:jira-work` (`POST /issue/{key}/worklog`) |
| `jira.link_issues` | `link_type`, `inward_key`, `outward_key` | `{link_type, inward_key, outward_key}` | **stable id**: a link of that type between the two issues | `write:jira-work` (`POST /issueLink`) |
| `jira.add_watcher` / `jira.remove_watcher` | `key`, `account_id` | `{issue, watcher}` | **stable id**: the account is (not) among the watchers | `write:jira-work` (`POST` / `DELETE /issue/{key}/watchers`) |
| `jira.add_issues_to_sprint` | `sprint_id`, `keys` (1-50) | `{sprint_id, issues}` | **stable id**: every issue is in the sprint | granular `write:sprint:jira-software` (`POST /rest/agile/1.0/sprint/{id}/issue`) |
| `jira.add_remote_link` | `key`, `url` (http/https, <= 2048), `title` (<= 255), `summary?` | `{id, issue, url}` | **marker** as the link's `globalId` (`mcp-gateway op:<id>`); a repeat of the operation updates the same link | `write:jira-work` (`POST /issue/{key}/remotelink`) |
| `confluence.update_page` | `id`, `body`, `title?`, `version_message?` | `{id, version, url}` | **marker** in the new body | `write:page:confluence` + `read:page:confluence` (`GET` then `PUT /wiki/api/v2/pages/{id}`) |
| `confluence.add_page_comment` | `id`, `body`, `parent_comment_id?` | `{id, page, url}` | **marker** in the comment | `write:comment:confluence` + `read:comment:confluence` (`POST /wiki/api/v2/footer-comments`) |
| `confluence.add_page_labels` | `id`, `labels` (1-20) | `{page, labels}` | **stable id**: every label is on the page | `write:label:confluence` + `read:label:confluence` + `read:page:confluence` (`POST /wiki/rest/api/content/{id}/label`) |

**Default Ask.** The writes in the second group (`update_issue` through `add_page_labels`) are seeded as **Ask** by migration 25 (`00025_atlassian_default_ask.sql`): every call needs the user's approval until an admin switches the tool to Auto on **Settings -> Vendor apps -> atlassian -> Tool approvals**. `create_issue`, `add_comment`, `transition_issue` and `create_page` stay Auto. `TestAtlassianNewWritesAreSeededAsAsk` (`cmd/gateway`) fails when a new Jira or Confluence write ships without a seed. Deletions (Rovo's admin-enabled `delete_jira` group) are left out on purpose.

**Operation id.** Every write requires `Call.OperationID` (set by the ledger stage) and answers `atlassian.ErrMissingOperation` without one: a write that reached the connector without the ledger could never be verified afterwards.

**Marker.** The three marker-reconciled writes end what they create with a last paragraph

```
mcp-gateway op:<operation id>
```

(`atlassian.Marker`). Unlike GitHub's HTML comment, the marker is **visible**: the Atlassian Document Format (Jira v3 descriptions and comments) has no comment node, and HTML comments in Confluence storage format are not guaranteed to survive a save, so a hidden marker could be silently lost and the reconciler could never prove a write happened. The marker is the whole reconciliation key; the ledger stores only the resource identity and the operation id (decision `enlsy40f`). Jira descriptions and comments are built as ADF (`adf.go`: one paragraph per line, the marker last); Confluence bodies as storage format with the marker as a trailing `<p>`.

**Outcomes** (`classifyWrite`). An Atlassian answer is a known outcome: 400/422 `invalid_argument` (bad project or issue type, duplicate page title), 403 `forbidden`, 404 `not_found`, 401 `reconnect_required`, 429 `*connectors.RateLimited`; the ledger records `failed`. Anything that leaves the outcome open after the request was sent — 5xx, a timeout, a cancelled context, a dropped connection, a 2xx reply that could not be read or carried no key/id — is wrapped in `connectors.ErrOutcomeUnknown`: the ledger marks the operation `unknown` and the reconciler takes over. Writes never return `Result{Unavailable}`. `create_page`'s space lookup before the write is a read: its failures (`not_found` for an unknown key, `unavailable`, ...) are known and nothing is created.

### Reconciliation

`Reconciliation.Check` runs from the ledger row alone (resource identity, operation id, account; arguments are never stored) with the same account's token and site. `found` closes the operation as `succeeded` with the resource id, `not_found` as `failed`; an error is "cannot tell yet" and the reconciler retries with backoff. Every listing is bounded by `atlassian.MaxReconcilePages` (5 pages of 100); running out of pages is "cannot tell yet", never `not_found`. Text searches (JQL `~`, CQL `text ~`) only ever **prove presence**: their index lags, so a miss or a hit without the marker falls back to a listing.

| Tool | Check | found | not_found |
|---|---|---|---|
| `jira.create_issue` | 1. JQL `project = KEY AND description ~ "\"mcp-gateway op:<id>\""` (`fields=description`); a hit whose description carries the marker. 2. Otherwise `project = KEY AND reporter = currentUser() ORDER BY created DESC`, newest first by `nextPageToken`, bounded. | issue key | the user's issues in the project listed to the end (`isLast`) without the marker |
| `jira.add_comment` | `GET /issue/{key}/comment?orderBy=-created&maxResults=100&startAt=N`, newest first, bounded. A 404 is "cannot tell" (the account may have lost access). | comment id | every comment read (`startAt >= total`) without the marker |
| `jira.transition_issue` | none: a transition leaves no marker and the status can change again at any time. An unknown outcome goes straight to `unresolved` and the user is asked to check the issue's status in Jira. | | |
| `confluence.create_page` | 1. CQL `space = "KEY" AND type = page AND text ~ "\"mcp-gateway op:<id>\""` (`expand=body.storage`); a hit whose body carries the marker. 2. Otherwise the space id is looked up again (`GET /wiki/api/v2/spaces?keys=`) and `GET /wiki/api/v2/spaces/{id}/pages?sort=-created-date&body-format=storage&limit=100` is walked by cursor, bounded. A space that no longer resolves is "cannot tell". | page id | the space's pages listed to the end without the marker |
| `jira.assign_issue` | `GET /issue/{key}?fields=assignee` | issue key | someone else (or nobody) is assigned |
| `jira.edit_comment` | `GET /issue/{key}/comment/{id}` | comment id | the comment's body lacks the marker |
| `jira.add_worklog` | `GET /issue/{key}/worklog`, bounded pages | worklog id | every worklog read without the marker |
| `jira.link_issues` | `GET /issue/{key}?fields=issuelinks` | link id | no link of the type to the other issue |
| `jira.add_watcher` / `remove_watcher` | `GET /issue/{key}/watchers` | issue key | the account is not (is) watching |
| `jira.add_issues_to_sprint` | `GET /rest/agile/1.0/sprint/{id}/issue?jql=key in (...)` | sprint id | an issue is missing from the sprint |
| `jira.add_remote_link` | `GET /issue/{key}/remotelink`; the link whose `globalId` is the marker | link id | no link carries the marker |
| `jira.update_issue` | none, like `transition_issue` | | |
| `confluence.update_page` | `GET /wiki/api/v2/pages/{id}?body-format=storage` | page id | the current body lacks the marker |
| `confluence.add_page_comment` | the page's footer comments (or the parent's replies), newest first, bounded | comment id | every comment read without the marker |
| `confluence.add_page_labels` | `GET /wiki/api/v2/pages/{id}/labels`, bounded | page id | a label is missing |

## Account binding

`atlassian.Binder` implements `connections.Binder` for vendor `atlassian`; `cmd/gateway/connectors_atlassian.go` installs it (`connSvc.RegisterBinder("atlassian", atlassian.Binder{})`) and maps both apps to the vendor (`connSvc.MapApp("jira", "atlassian")`, `connSvc.MapApp("confluence", "atlassian")`), so one connection serves both tool sets. After the code exchange it:

1. calls `GET https://api.atlassian.com/me`: the permanent `account_id` and the name;
2. calls `GET https://api.atlassian.com/oauth/token/accessible-resources` and binds the connection to the **first** site listed (`id` = cloud id, `url`): external account id `<account id>@<cloud id>`, display name `<name> @ <site url>`. No accessible site fails the connect (`atlassian.ErrNoSite`);
3. labels the account **company** when the site's hostname is in the vendor app's `company_sites` extra (comma separated, case-insensitive; a URL entry is reduced to its host), else **personal**;
4. reports the scopes from the token response's `scope` field (Atlassian returns the granted set), else none (the flow records the requested scopes).

The API root is derived from the vendor app's user info URL (`https://api.atlassian.com/me`) or `Binder.BaseURL`. A 401 on `/me` fails the connect with `reconnect_required`; a 5xx with `unavailable`.

**Site resolution at call time.** The connector receives the connection's site through `Options.Sites` (`SiteSourceFunc`); `cmd/gateway` implements it over `connections.Service.Connections`: the cloud id is parsed from the external account id (`atlassian.ParseExternalAccountID`) and the site URL, used only for the `url` fields of results, from the display name's `@ <url>` suffix (links are omitted when it is absent). Both are the connection's own row, under row-level security.

**Multi-site accounts.** An Atlassian account often reaches several sites (company and personal). The connect flow has no per-site selection yet, so the binder takes the first site; connecting a second site of the same account needs a connections-flow change (a site picker on the callback, or one connect flow per site with the cloud id in the external account id, which this binder already shapes for). Until then an admin can list the company site first in Atlassian's app sharing, or users can connect accounts that reach one site.

**`company_sites` is sent to Atlassian today.** `connections.VendorApp.AuthParams` forwards every `Extra` key the connections package does not reserve as an authorization parameter; `company_sites` is new and the reserved list (`internal/connections/vendor.go`) is outside this connector's ownership. Atlassian ignores unknown parameters, but the hostnames do appear in the authorize URL. Follow-up: add `atlassian.ExtraCompanySites` to `reservedExtra` (one line).

## Setup

1. Register the OAuth 2.0 (3LO) app as in [`docs/vendor-apps.md`](../vendor-apps.md) section 3: callback `https://<gateway>/connect/atlassian/callback`, Jira classic scopes `read:jira-work`, `read:jira-user`, `write:jira-work` and the granular Jira / Jira Software scopes `read:board-scope:jira-software`, `read:project:jira`, `read:sprint:jira-software`, `read:issue-details:jira`, `read:jql:jira`, `write:sprint:jira-software`; Confluence `search:confluence`, `read:confluence-content.all`, `read:confluence-space.summary`, `write:confluence-content` and the granular `read:page:confluence`, `write:page:confluence`, `read:space:confluence`, `read:comment:confluence`, `write:comment:confluence`, `read:attachment:confluence`, `read:label:confluence`, `write:label:confluence` (section 3.5 lists which tool needs which); enable **Sharing**. Existing connections lack the scopes added later: users get them through **Grant more access** on `/connections`, which requests the missing tool scopes.
2. In the portal, **Settings -> Vendor apps -> atlassian**: client ID and secret, the default endpoints (`https://auth.atlassian.com/authorize`, `https://auth.atlassian.com/oauth/token`, user info `https://api.atlassian.com/me`), scopes `offline_access` plus the ones above, and in **Extra parameters** the lines
   ```
   audience=api.atlassian.com
   prompt=consent
   company_sites=acme.atlassian.net
   ```
3. Users connect on `/connections` -> Atlassian -> *Connect* and consent per site; the connection's label and display name (`<name> @ <site url>`) appear on the page.
4. Grant the tools to a role on `/admin/roles` (`jira.*`, `confluence.*`; use `project` / `space` equals conditions to confirm or deny by project or space).

Both apps are registered whenever the connections module is mounted, before the vendor app exists; until a user connects, every tool answers *no connected account*.

## Tests

- `go test ./internal/connectors/atlassian/`: the contract test for both apps, the binder (first site, hostname label table, scopes, no site, 401, 5xx, API root), and every tool against hand-written, scrubbed fixtures under `testdata/` served by an `httptest` server that checks the bearer: reads (success, empty, partial by clamp and by truncation, 400/401/403/404/409, 5xx and network as `unavailable`, 429 with and without `Retry-After`, a malformed 200, cancelled context, argument validation, JQL/CQL identity tables) and writes (the marker paragraph in the request body, `ResultIDs`, the missing operation id, 400/401/403/404 and 429 as known outcomes, 5xx / timeout / dropped connection / unreadable reply as `ErrOutcomeUnknown`, `create_page`'s lookup failures as known) and every `Check` (found by search, a search hit without the marker not trusted, fallback listing with the marker on a later page, not_found at the end, cannot tell on a listing error or after `MaxReconcilePages`, missing identity). No real tokens, people or sites appear (`Alice Example`, `MOCK`, `DOCS`, `*.example.test`).
- `ATLASSIAN_LIVE_TOKEN=... ATLASSIAN_LIVE_CLOUD_ID=... go test -tags live -run Live ./internal/connectors/atlassian/`: `jira.search_issues` and `confluence.search` against the live site; with `ATLASSIAN_LIVE_PROJECT=KEY` as well, `TestLiveCreateIssueAndReconcile` creates an issue under a fresh operation id and runs `create_issue`'s check from the resource identity alone, expecting it to find the issue by its marker. Behind the `live` build tag; never run in CI.
- `go test ./cmd/gateway/`: both apps registered with the connections service, accounts of vendor `atlassian` listed under `jira` and `confluence`, the site resolved from the connection row (and refused for another user's connection).

### Prototype test mapping

Every test of the prototype's `tests/test_atlassian.py` (commit `b6ad1b4`) has a named counterpart; the prototype ran one FastAPI MCP server per product with mocked tools, so protocol-level cases map to the layer that owns them now.

| Prototype test | Behaviour | Counterpart |
|---|---|---|
| `test_jira_mock_server_lists_and_calls_tools` | `tools/list` includes `search_issues`; `search_issues` with `jql="project = MOCK"` answers with `MOCK-1` | `TestAppsAndToolNames` (jira lists `search_issues`), `TestSearchIssues` (fixture `search_issues.json`: `project = MOCK` -> `MOCK-1`, "Mock issue from JQL search"); the gateway's `tools/list` is covered by the contract test and `TestRegisterConnectorsRegistersAtlassianWithConnections` |
| `test_jira_server_requires_internal_token_when_configured` | a call without the gateway's credential is refused before any tool runs; with it, tools are listed | `TestCallWithoutAccount` (no connected account -> `no_account`, no token lookup, no vendor request) and `TestCallNeedsReconnectFromTokenSource` (a dead token -> `reconnect_required`); harness authentication itself is the gateway's `/mcp` token layer (`internal/mcp`, `test/oauthattack`) |
| `test_atlassian_server_returns_jsonrpc_parse_error_for_malformed_json` | malformed JSON is answered with a parse error, not a crash | `TestErrorClasses/200 malformed json` (an unreadable Atlassian reply is `vendor_error` for a read) and `TestCreateIssueErrors/unreadable reply outcome unknown` (for a write it is `ErrOutcomeUnknown`); JSON-RPC parse errors from the harness are the MCP layer's (`internal/mcp` conformance tests) |
| `test_confluence_mock_server_lists_and_calls_tools` | `tools/list` includes the Confluence search tool; a CQL search `type=page` answers with "Mock Confluence page" | `TestAppsAndToolNames` (confluence lists `search`), `TestConfluenceSearch` (fixture `content_search.json`: `type=page` -> `12345` "Mock Confluence page") |

Prototype tools not carried into v1 (`confluence.update_page`) are follow-up work per the capped tool sets of `bt8ukyrd`; `confluence.search_pages` became `confluence.search` and `get_issue`'s `issue_key` became `key` to match mcp-atlassian's naming.

## Adding the next tool

Same steps as [`github.md`](github.md#adding-the-next-tool): declare it in `readTools()` / `writeTools()` under its app (`tools_read.go`, `tools_write.go`), add the handler to `readHandlers()` / `writeHandlers()` as `func(ctx, *session, connectors.Call)`, build URLs with `s.jiraURL(path, query)` / `s.wikiURL(path, query)`, decode into a wire type in `minimal.go` and convert to a flat result shape, classify read errors with `c.classify` and the write's own request with `c.classifyWrite`, embed `Marker(call.OperationID)` (ADF via `adfDocument`, storage via `storageBody`) for marker-reconciled writes, and add the `Check` in `reconcile.go` from `c.target(ctx, in)`. Fixtures go under `testdata/`; the contract test picks the tool up automatically. Document it in the tables above and, for a new scope, in `docs/vendor-apps.md` section 3.
