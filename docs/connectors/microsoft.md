# Microsoft 365 connector

App `microsoft` (`internal/connectors/microsoft`): Outlook mail and calendar, OneDrive and Teams tools for work (Entra ID) **and** personal Microsoft accounts, over a hand-written Microsoft Graph REST client (`internal/connectors/microsoft/graph`; Brain decision `bt8ukyrd`: no `msgraph-sdk-go`). It copies the shape of the [GitHub reference connector](github.md): a `connections.Binder`, reads and writes with `Reconciliation`, `Error{Status, Class}`, per-call tokens, bounds and markers. Every write runs behind the safety core (policy, approvals, the write ledger) and declares how it is reconciled after an unknown outcome (see [Writes](#writes)).

Tool names are `microsoft.<area>_<verb>`: tool names cannot carry dots and one connector is one app, so the plan's `mail.search` is `microsoft.mail_search`.

## Tools

The first six are reads (`Kind: read`); the four writes follow in [Writes](#writes). The gateway adds `account` and `approval_id` to every schema and generates `microsoft.list_accounts`.

| Tool | Arguments | Result | Graph permission (`RequiredScopes`) |
|---|---|---|---|
| `microsoft.mail_search` | `q` (KQL full-text search: `$search`), **or** `filter` (OData `$filter`, newest first), neither = newest messages; `folder` (`inbox`, `sentitems`, `drafts`, `deleteditems`, `junkemail`, `archive`, or a folder id; all folders when omitted); `top` | `{top, has_more, truncated?, items: [{id, subject, from_name, from_address, received_at, preview, is_read, has_attachments, web_link}]}` | `Mail.Read` |
| `microsoft.mail_get_message` | `id` | `{id, subject, from_name, from_address, to, cc, received_at, sent_at, is_read, has_attachments, conversation_id, web_link, body_content_type, body, truncated?}` (body requested as text: `Prefer: outlook.body-content-type="text"`) | `Mail.Read` |
| `microsoft.calendar_list_events` | `start`, `end` (ISO 8601, at most a year apart), `calendar_id?`, `top` | `{top, has_more, truncated?, items: [{id, subject, start, end, time_zone, is_all_day, is_cancelled, location, organizer_name, organizer_address, web_link}]}` (`calendarView`: series expanded, UTC, ordered by start) | `Calendars.Read` |
| `microsoft.drive_search` | `q`, `drive_id?` (the user's OneDrive when omitted), `top` | `{top, has_more, truncated?, items: [{id, name, is_folder, size, mime_type, web_url, modified_at, drive_id, parent_id, parent_path}]}` | `Files.Read.All` |
| `microsoft.teams_list_channels` | `team_id?` (every joined team when omitted), `top` (teams) | `{has_more, truncated?, items: [{team_id, team_name, channels: [{id, display_name, description, membership_type, web_url}], error?}]}` | `Team.ReadBasic.All`, `Channel.ReadBasic.All` |
| `microsoft.teams_read_channel_messages` | `team_id`, `channel_id`, `top` (1-50, Graph's own cap) | `{top, has_more, truncated?, items: [{id, from_name, from_id, created_at, message_type, content_type, content, web_url}]}` (top-level messages, newest first; replies not included) | `ChannelMessage.Read.All` (admin consent) |

**Resource identity** (policy conditions and audit): `mail_search` -> `folder` (when given; well-known names lower-cased, ids as given); `mail_get_message` -> `message` (the id); `calendar_list_events` -> `calendar` (`calendar_id` or `default`); `drive_search` -> `drive` (`drive_id` or `me`); `teams_list_channels` -> `team` (when given); `teams_read_channel_messages` -> `team`, `channel`. The account's tenant and user principal name are not in the identity: they are properties of the connection (its external account id is `<tenant id>:<object id>`, its display name the UPN) and the audit row already carries the account id and label.

**Pagination and bounds.** Graph pages by `@odata.nextLink`, not by page number, so the reads take `top` only (default 25, clamped to the tool's `MaxPageSize`: the package default 50, never above 100, and never above 50 for channel messages) and report `has_more` when Graph had a next link; narrow the query to see more. `MaxResultBytes` (default 256 KiB) bounds the serialised result: lists drop trailing items (`truncated: true`, never below one item) and `mail_get_message` cuts the `body` (`truncated: true`). `teams_list_channels` reads one team past `top` from `/me/joinedTeams` (which takes no `$top`) to learn `has_more`, then lists each team's channels (bounded).

**Result markers** (`_meta["mcp-gateway/read"]`, decision `dovthftx`):

| Marker | When |
|---|---|
| `empty` | nothing matched (no messages, events, items, teams or channel messages) |
| `partial` | `top` was clamped, the result was truncated to the bounds, or a team's channels could not be listed (`forbidden` / `not_found`; the team is kept with `error`) |
| `unavailable` | Graph answered 5xx (without `Retry-After`) or could not be reached; no content is returned |

**Errors.** A `*microsoft.Error` carries `Status` and a `Class`; the message tells the harness what to do:

| Class | Cause | What the harness should do |
|---|---|---|
| `reconnect_required` | 401 / `InvalidAuthenticationToken`, or the connection has no usable token (`connections.ErrNeedsReconnect`) | ask the user to reconnect Microsoft on `/connections` |
| `no_account` | the call carried no connected account (the pipeline normally answers `-32031` first) | ask the user to connect Microsoft |
| `scope_required` | the connected account has not granted a permission the tool needs (see [Scopes](#scopes-and-personal-accounts)) | a work account grants it on `/connections` (grant more access); personal accounts cannot use Teams |
| `not_found` | 404/410, `ErrorItemNotFound`, `itemNotFound`, `ResourceNotFound`: the resource does not exist or the account cannot see it | check the id |
| `forbidden` | 403, `Authorization_RequestDenied`, `accessDenied`: the token lacks the permission or the tenant denies it | an admin must consent, or the tenant blocks the app |
| `invalid_argument` | the connector rejected the arguments, or Graph answered 400 / 409 (`nameAlreadyExists`) / 422 | fix the arguments |
| `vendor_error` | any other Graph status | retry later |

Throttling -- 429, or 503 **with** `Retry-After` -- is returned as `*connectors.RateLimited{App: "microsoft", RetryAfter}` (the header, or 60 s when Graph gives none); the harness gets `-32029` with `retry_after` and the app is paused for everyone until then. Context cancellation and deadlines pass through unchanged. Every call is bounded by `Options.Timeout` (default 30 s).

### Scopes and personal accounts

Every tool declares the delegated Graph permissions it needs (`RequiredScopes`, the names of [`docs/vendor-apps.md`](../vendor-apps.md) section 5.2). The pipeline does not compare `Tool.RequiredScopes` with `Account.Scopes` yet (nothing does, for any connector: `tools/list` is per principal, not per account), so **this connector enforces it in `Call`** when an `AccountSource` is injected (`cmd/gateway` passes the connections service): the account's granted scopes must cover the tool's, where `<Resource>.ReadWrite` covers `<Resource>.Read`, `.All` covers the non-`.All` form, names are compared case-insensitively with or without the `https://graph.microsoft.com/` prefix (`microsoft.ScopeCovered`). A tool whose scopes are missing is refused with `scope_required` before any token is fetched or request sent; the message names the missing permissions and the portal page. An account the source does not know, or an account recorded without scopes, is not refused: Graph decides.

Personal Microsoft accounts (tenant `9188040d-6c67-4c5b-b112-36a304b66dad`, `microsoft.PersonalTenant`) cannot grant Teams or SharePoint permissions (decision `mh7c6z3v`). The binder strips them from such accounts' granted scopes, so the three Teams tools (`teams_list_channels`, `teams_read_channel_messages`, `teams_post_channel_message`) answer `scope_required` ("personal Microsoft accounts cannot grant Teams or SharePoint permissions") for them and work for a work account that granted the scopes. The tools still appear in `tools/list` (the list is per principal); hiding them per account needs scope enforcement in the pipeline, which would then make the connector's check redundant.

## Writes

Four write tools (`Kind: write`: always policy, approval when the role says `confirm`, and the write ledger; decision `dovthftx`). Each returns only the identifiers of what it created; the ledger stores those (`ResultIDs`) and replays them for a duplicate call inside the idempotency window.

| Tool | Arguments | Result / `ResultIDs` | Reconciliation | Graph permission |
|---|---|---|---|---|
| `microsoft.mail_send` | `to` (array of `addr` or `Name <addr>`), `subject`, `body`, `cc?`, `content_type?` (`text` default, `html`) | `{internet_message_id}` / `internet_message_id` | **marker**: the deterministic `internetMessageId` `<op-<operation id>@mcp-gateway>` plus the header `x-mcp-gateway-op: <operation id>`; a copy is saved to Sent Items | `Mail.Send` |
| `microsoft.calendar_create_event` | `subject`, `start`, `end` (ISO 8601 local times in `time_zone`, UTC by default; `Z`/offsets converted), `time_zone?` (IANA), `attendees?` (invited as required), `body?`, `location?`, `calendar_id?` | `{id, web_link, transaction_id}` / `id`, `web_link`, `transaction_id` | **stable id**: `transactionId` = the operation id | `Calendars.ReadWrite` |
| `microsoft.drive_create_folder` | `name`, `parent_id?` (the drive root when omitted), `drive_id?` | `{id, name, web_url, drive_id, parent_id}` / `id`, `web_url` | **marker (approximated)**: the folder name in its parent, see below | `Files.ReadWrite` (`Files.ReadWrite.All` for other drives) |
| `microsoft.teams_post_channel_message` | `team_id`, `channel_id`, `content`, `content_type?` (`text` default, `html`) | `{id, web_url, team_id, channel_id}` / `id`, `web_url` | **none** | `ChannelMessage.Send` |

**Resource identity** of the writes: `mail_send` -> `mailbox: me`; `calendar_create_event` -> `calendar`; `drive_create_folder` -> `drive`, `parent` (`root` when omitted), `folder` (the name, case kept); `teams_post_channel_message` -> `team`, `channel`. A role rule such as *confirm `microsoft.teams_post_channel_message` when `team` equals `<id>`* confirms posts in that team and, with no other rule for the tool, denies them anywhere else.

**Operation id.** The ledger stage sets `Call.OperationID` before dispatch. Every write requires it and answers `microsoft.ErrMissingOperation` without one: a write that reached the connector without the ledger could never be verified afterwards, so it is refused rather than guessed about.

**Outcomes.** A Graph answer is a known outcome: 400/422 is `invalid_argument` (and 409 `nameAlreadyExists` from `drive_create_folder`, which sends `@microsoft.graph.conflictBehavior: fail` so a duplicate name never silently becomes `name 1`), 403 `forbidden`, 404 `not_found`, 401 `reconnect_required`, throttles `*connectors.RateLimited`; the ledger records `failed` and the key is free again. Anything that leaves the outcome open after the request was sent -- a 5xx, a timeout (`Options.Timeout`), a cancelled context, a dropped connection -- is returned wrapped in `connectors.ErrOutcomeUnknown`: the ledger marks the operation `unknown`, the harness sees *outcome unknown*, a duplicate call answers `-32033 pending verification`, and the reconciler job takes over. Writes never return `Result{Unavailable: true}`.

### Reconciliation

`Reconciliation.Check` runs from the ledger row alone -- the resource identity, the operation id and the account; arguments are never stored -- with the same account's token through the same per-call token source. A definite answer closes the operation (`found` -> `succeeded` with `{"id": <resource id>}`, `not_found` -> `failed`); an error is "cannot tell yet" and the reconciler retries with backoff (its first check runs at least a minute after the write) until its own limits make the operation `unresolved` and notify the user.

| Tool | Check | found | not_found |
|---|---|---|---|
| `mail_send` | `GET /me/messages?$filter=internetMessageId eq '<op-<id>@mcp-gateway>'` (every folder; the sent copy lands in Sent Items within seconds of a send) | the message id | no message carries the id |
| `calendar_create_event` | `GET /me/events?$filter=transactionId eq '<id>'` (or `/me/calendars/<calendar>/events`) | the event id | no event carries the transaction id |
| `drive_create_folder` | `GET /me/drive/root/children` or `/me/drive/items/<parent>/children` (or `/drives/<drive>/...`), `$select=id,name,folder`, 200 per page, bounded by `microsoft.MaxReconcilePages` (5): a **folder** whose name equals the recorded one case-insensitively (OneDrive compares names that way). **Approximation:** a drive item carries no client-chosen id or header, so the name is the whole key; a same-named folder created by other means in the meantime would be taken as this write's. Because the write asks Graph to *fail* on a name conflict, that is the only way two such folders can exist. A 404 is "cannot tell" (the account may have lost access); running out of pages is "cannot tell". | the folder's item id | the end of the children list without such a folder |
| `teams_post_channel_message` | none: a channel message carries no client-chosen key, and a visible marker in the text is not acceptable. An unknown outcome goes straight to `unresolved` and the user is asked to check the channel. | -- | -- |

## Account binding

`microsoft.Binder` implements `connections.Binder` for vendor `microsoft` and is installed by `cmd/gateway` (`registerMicrosoft`: `connSvc.RegisterBinder("microsoft", microsoft.Binder{})`, `connSvc.MapApp("microsoft", "microsoft")`). After the code exchange it:

1. calls `GET /me?$select=id,displayName,userPrincipalName,mail` with the new token: the permanent object id and the user principal name (the display name; `mail`, then `displayName`, when the UPN is absent);
2. finds the **tenant id**: the `tid` claim of the token response's `id_token` when the vendor app requests the `openid` scope (recommended: no extra request, and it works for guests and for personal accounts alike; the id token is read, not verified -- it came straight from the token endpoint over TLS); otherwise `GET /organization?$select=id` -- a work account answers with its organization, while Graph refuses the call for a personal account (400/403/404), which is then the personal tenant `9188040d-6c67-4c5b-b112-36a304b66dad`. A 401, a throttle, a 5xx or a network failure fails the connect (the user can retry); the binder never guesses on those;
3. sets the external account id to `<tenant id>:<object id>` (tenant lower-cased), labels the account **company** when the tenant is in the vendor app's `company_tenants` extra (comma separated, case-insensitive), **personal** otherwise (and always when the list is empty);
4. reports scopes from the token response's `scope`, else the requested scopes, **minus the Teams and SharePoint permissions when the account is personal**.

The binder follows the vendor app's **User info URL** for the Graph root (`https://graph.microsoft.com/v1.0/me` by default; a sovereign cloud's Graph host otherwise), so `/organization` goes to the same host. `microsoft.Options.BaseURL` does the same for the tools (not configurable from `cmd/gateway` yet).

`company_tenants` is read by the gateway like GitHub's `company_orgs`, but it is **not yet in `connections.reservedExtra`** (the connections package is outside this task's ownership), so the connect flow also sends it as an authorization parameter, which Entra ignores. Adding `microsoft.ExtraCompanyTenants` to `reservedExtra` in `internal/connections/vendor.go` is a one-line follow-up.

## Setup

1. Register the Entra app as described in [`docs/vendor-apps.md`](../vendor-apps.md) section 5 (multi-tenant + personal accounts, redirect `/connect/microsoft/callback`) with the delegated permissions of its table 5.2; `ChannelMessage.Read.All` needs admin consent in the company tenant.
2. In the portal, **Settings -> Vendor apps -> microsoft**: client ID, client secret, the default endpoints (`common` authority, user info `https://graph.microsoft.com/v1.0/me`), **Scopes** `openid User.Read offline_access` plus the mail, calendar and files permissions every account may grant (`Mail.Read Mail.Send Calendars.ReadWrite Files.ReadWrite.All`), and in **Extra parameters**
   ```
   company_tenants=<company tenant id>[,<another tenant id>]
   ```
   Do **not** put the Teams permissions in the base scopes if personal accounts must be able to connect: Microsoft refuses the whole consent for a personal account when a Teams scope is requested. Work users add them afterwards with `/connect/microsoft/start?scopes=Team.ReadBasic.All+Channel.ReadBasic.All+ChannelMessage.Read.All+ChannelMessage.Send` (the "grant more access" link; the connection's scopes are the union).
3. Users connect on `/connections` -> Microsoft -> *Connect*. The connection's label and display name appear on the page; `microsoft.list_accounts` shows them to a harness.
4. Grant the tools to a role on `/admin/roles` (`microsoft.*` allow, or per tool; use `team` / `calendar` / `drive` / `folder` conditions to confirm or deny by resource).

The connector is registered whenever the connections module is mounted (a key provider is configured), before the vendor app exists; until a user connects, every tool answers *no connected account* (`-32031` from the pipeline).

## Tests

- `go test ./internal/connectors/microsoft/...`: the graph client (bearer per request, JSON, the error envelope, 429/503 `Retry-After`, `@odata.nextLink` paging bounded by items and pages, foreign next links refused, response size bound, token-source failure); the contract test (`connectortest.ContractTest`); the binder (work account from the id token, company vs personal label by tenant, personal account with Teams scopes stripped, tenant from `/organization`, personal when `/organization` is refused, no guessing on 5xx/401, API root from the user info URL); scope coverage (`ScopeCovered`) and refusal in `Call` (personal account's Teams tools, missing `Files.Read.All`, no account source = no check); every tool against hand-written, scrubbed fixtures under `testdata/` served by an `httptest` Graph that also checks the bearer: reads (success, empty, `has_more`, clamped `top`, truncation to the bounds, 404, 401, 403, 400, 429 with and without `Retry-After`, 503 with and without, 5xx, network failure, cancelled context, argument validation, `$search` vs `$filter` vs newest, folder and calendar and drive variants, a team whose channels are forbidden, Graph's 50-message cap) and writes (request bodies with the internet message id and header, `transactionId`, `conflictBehavior: fail`, recipients parsed, `ResultIDs`, the missing operation id, 400 / 403 / 404 / 401 / 429 as known outcomes, 500 / 503 / timeout / dropped connection as `ErrOutcomeUnknown`, 409 as `invalid_argument`) and every `Check` (found, not_found, a hit without the id not trusted, cannot tell on 5xx/401/429/404, bounded pagination with the folder on a later page, missing identity); and `TestNoGraphSDKImported` (neither `go.mod` nor any source file imports `msgraph-sdk-go` or kiota). No real tokens or personal data appear in the fixtures (`alice@example.test`, `*.example.test`).
- `MS_LIVE_TOKEN=eyJ... go test -tags live -run Live ./internal/connectors/microsoft/`: `mail_search` against graph.microsoft.com with a dedicated test account's delegated token (`Mail.Read`). With `MS_LIVE_WRITE=1` as well (the token needs `Calendars.ReadWrite`), `TestLiveCreateEventAndReconcile` creates an event two days out under a fresh operation id, runs `calendar_create_event`'s check from the resource identity alone and expects it to find the event by its `transactionId`; the event is left for manual deletion. Behind the `live` build tag and skipped without the variables; never run in CI.

## Adding the next tool

1. Declare it in `readTools()` (`tools_read.go`) or `writeTools()` (`tools_write.go`): `App`, `Name` (`<area>_<verb>`), `Description`, `InputSchema` via `objectSchema(props, required)`, `Kind`, `RequiredScopes` (the Graph permission names), `ResourceIdentity` (an existing hook or one that never returns argument content), `Bounds` (`paged` or `single`). Writes also set `Reconcile{Kind, Check}` and `ResultIDs`.
2. Add the handler to `handlers()` or `writeHandlers()` and implement it as `func(ctx, *graph.Client, connectors.Call) (connectors.Result, error)`: validate arguments with `requiredID` / `idArg` / `topArg` / `timeArg` / `addressList` (return `invalid(...)`), call Graph with `client.Get` / `client.Do` / `client.Post` or `graph.Collect[T]`, convert with a `to*` function in `minimal.go`. Reads pass every error through `classify(action, err)`, set `Empty` / `Partial` and fit the result to `c.bounds.MaxResultBytes` (`truncateItems`, `fitBody`). Writes pass the error of the request that performs the write through `classifyWrite` and return a `Created*` / `Sent*` result the `ResultIDs` hook reads.
3. For a write, add its `Check` to `reconcile.go` starting from `c.target(ctx, in)`: a filterable client-chosen id (`transactionId`, `internetMessageId`) when Graph offers one, else a bounded listing with `MaxReconcilePages`; `found(id)` / `notFound` for definite answers, an error for everything else. Store in the resource identity whatever the check needs.
4. Add fixtures under `testdata/` (scrub names, ids, URLs; next links on `https://graph.example.test`, which the test server rewrites to itself) and tests for success, empty, partial, 404 and a throttle (reads) or the request body, the error table (`runWriteErrorCases`) and the check's found / not_found / cannot-tell cases (writes). The contract test picks the tool up automatically.
5. If a new permission is needed, add it to `scopes.go`, to `docs/vendor-apps.md` section 5.2 and to the tables above; if it is a Teams or SharePoint one, make sure `TeamsScope` recognises it so personal accounts are refused cleanly.
