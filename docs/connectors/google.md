# Google Workspace connector (increment 1: Calendar, Tasks, Gmail)

Package `internal/connectors/google`, vendor `google`. One Google connection (bound to the account's permanent `sub`) serves **three connector apps**, each a `connectors.Connector` of its own so tool names read `calendar.list_events`, `tasks.list` and `gmail.search`, roles can grant or deny a whole app, and the restricted Gmail scopes stay separable from Calendar and Tasks:

| App | Tools | Google API |
|---|---|---|
| `calendar` | `list_events`, `get_event`, `create_event` | Calendar API v3 |
| `tasks` | `list`, `create` | Tasks API v1 |
| `gmail` | `search`, `get_message`, `list_labels`, `send`, `create_draft` | Gmail API v1 |

The connector follows the GitHub reference (`docs/connectors/github.md`, Brain decisions `89k5cln0`, `8023b958`): tokens come from the connection's `oauth2.TokenSource` per call and are never stored; every write runs behind the safety core and declares how it is reconciled after an unknown outcome. The APIs are reached through [google.golang.org/api](https://pkg.go.dev/google.golang.org/api) v0.298.0 (the newest release declaring Go 1.25; v0.299+ require Go 1.26). The tool set is designed after [taylorwilsdon/google_workspace_mcp](https://github.com/taylorwilsdon/google_workspace_mcp) (Python, MIT) without copying code.

Increment 2 (Drive, Docs, Sheets, Contacts: `drive.search`, `drive.get_file_metadata`, `docs.get_text`, `sheets.read_range`, `contacts.search`, `drive.create_folder`, `docs.create`, `docs.append_text`, `sheets.append_rows`; scopes in `docs/vendor-apps.md` section 4.3) is a separate task and adds further apps to this package the same way (`Connector.Apps()`).

## Reads

`Kind: read`: no approval and no ledger unless policy says `confirm`. The gateway adds `account` and `approval_id` to every schema and generates `calendar.list_accounts`, `tasks.list_accounts` and `gmail.list_accounts` (all three list the same Google connections).

| Tool | Arguments | Result | Scope (`RequiredScopes`) |
|---|---|---|---|
| `calendar.list_events` | `calendar_id` (default `primary`), `time_min`, `time_max` (RFC 3339; `time_min` defaults to now when both are omitted), `q`, `max_results` (default 25), `page_token` | `{calendar_id, time_zone, time_min, time_max, max_results, next_page_token, has_more, truncated?, items: [{id, calendar_id, summary, description, location, status, start, end, all_day, time_zone, url, meeting_url, organizer, creator, attendees: [{email, name, response_status, optional, organizer, self}], recurring_event_id, created, updated}]}` | `calendar.events.readonly` |
| `calendar.get_event` | `calendar_id`, `event_id` | one item as above plus `truncated?` (description cut to the bounds) | `calendar.events.readonly` |
| `tasks.list` | `tasklist` (default `@default`), `show_completed` (default false; also shows hidden tasks), `max_results` (default 50), `page_token` | `{tasklist, max_results, show_completed, next_page_token, has_more, truncated?, items: [{id, tasklist, title, notes, status, due (date), completed, updated, parent, position, hidden, url}]}` | `tasks.readonly` |
| `gmail.search` | `q` (Gmail search syntax), `label_ids` (array), `include_spam_trash`, `max_results` (default 10), `page_token` | `{query, max_results, result_size_estimate, next_page_token, has_more, truncated?, items: [{id, thread_id, from, to, subject, date, snippet, labels, unread, error?}]}` | `gmail.readonly` |
| `gmail.get_message` | `id` | `{id, thread_id, from, to, cc, bcc, reply_to, subject, date, message_id, in_reply_to, snippet, labels, unread, body, body_type (text/plain or text/html), body_truncated?, attachments: [{id, filename, mime_type, size}], size_estimate}` | `gmail.readonly` |
| `gmail.list_labels` | none | `{items: [{id, name, type}]}` | `gmail.labels` (the non-restricted alternative; `gmail.readonly` covers it too) |

`calendar.list_events` expands recurring events (`singleEvents`) and orders by start time. `gmail.search` lists ids and then fetches each hit's headers (`format=metadata`), one request per hit, which is why its default page is 10; `gmail.get_message` fetches the full message, keeps the `text/plain` part (else the `text/html` part) and **lists attachments without downloading them**. Dates are RFC 3339 UTC; task due values are dates (Google Tasks keeps no time of day).

**Resource identity** (policy conditions and audit): `calendar_id` (lower-cased; `primary` when omitted) and `domain` (the calendar id's domain when it is an address) for the Calendar tools, plus `event_id` for `get_event`; `tasklist` for the Tasks tools; `label` (the `label_ids` joined by commas) for `gmail.search`, `message_id` for `gmail.get_message`, nothing for `gmail.list_labels`; `recipient_domains` (sorted, unique domains of to/cc/bcc) for `gmail.send` and `gmail.create_draft`. Never the query, the subject, the body or the addresses themselves. A role rule such as *confirm `gmail.send` when `recipient_domains` not equals `acme.com`* therefore confirms mail leaving the company.

**Pagination and bounds.** `max_results` is clamped to the tool's `MaxPageSize` (package default 50, never above 100) and the result is marked `partial` when it was; `page_token` / `next_page_token` carry Google's cursors; `has_more` says whether a next page exists. `MaxResultBytes` (default 256 KiB) bounds the serialised result: lists drop trailing items (`truncated: true`, never below one), single objects cut the description or body (`truncated` / `body_truncated`).

**Result markers** (`_meta["mcp-gateway/read"]`, decision `dovthftx`):

| Marker | When |
|---|---|
| `empty` | nothing matched (no events, no tasks, no messages, no labels) |
| `partial` | `max_results` was clamped, the result was truncated to the bounds, or one of `gmail.search`'s header fetches failed (that item keeps its ids and carries `error`) |
| `unavailable` | Google answered 5xx or could not be reached; no content is returned |

**Errors.** A `*google.Error` carries `Status` and a `Class`; the message tells the harness what to do:

| Class | Cause | What the harness should do |
|---|---|---|
| `reconnect_required` | 401 from Google, or the connection has no usable token (`connections.ErrNeedsReconnect`) | ask the user to reconnect Google on `/connections` |
| `no_account` | the call carried no connected account (the pipeline normally answers `-32031` first) | ask the user to connect Google |
| `scope_required` | the account did not grant the tool's scope: blocked by the connector before any request (see [Scopes and granular consent](#scopes-and-granular-consent)), or Google answered 403 `insufficientPermissions` | ask the user to grant more access (reconnect with the scope) |
| `not_found` | 404/410: the calendar, event, list, task or message does not exist or the account cannot see it | check the ids |
| `forbidden` | any other 403 (a Workspace admin blocked the app or the API for the org, a calendar the account may only read) | an admin must allow the app |
| `invalid_argument` | the connector rejected the arguments, or Google answered 400/412/422 | fix the arguments |
| `conflict` | 409: an event with the derived id already exists | the operation already ran; do not retry blindly |
| `vendor_error` | any other Google status | retry later |

429, and 403 with the quota reasons `rateLimitExceeded`, `userRateLimitExceeded`, `quotaExceeded` or `dailyLimitExceeded`, are returned as `*connectors.RateLimited{App: "google", RetryAfter}` (`Retry-After`, or 60 s when Google gives none); the harness gets `-32029` with `retry_after` and the vendor is paused until then. Context cancellation and deadlines pass through unchanged. Every call is bounded by `Options.Timeout` (default 30 s).

## Writes

Four write tools (`Kind: write`: always policy, approval when the role says `confirm`, and the write ledger). Each returns only the identifiers of what it created; the ledger stores those (`ResultIDs`) and replays them for a duplicate call inside the idempotency window.

| Tool | Arguments | Result / `ResultIDs` | Reconciliation | Scope |
|---|---|---|---|---|
| `calendar.create_event` | `calendar_id?`, `summary`, `start`, `end` (RFC 3339 timestamps, or `YYYY-MM-DD` dates for an all-day event; both of the same kind), `time_zone?`, `description?`, `location?`, `attendees?` (addresses), `send_updates?` (`all`, `externalOnly`, `none` = default: attendees are not emailed unless asked) | `{id, calendar_id, url, status, start, end}` / `id`, `url` | **stable id**: the event id is chosen by the connector | `calendar.events` |
| `tasks.create` | `tasklist?`, `title`, `notes?`, `due?` (date) | `{id, tasklist, url, status}` / `id`, `url` | **marker** in the notes | `tasks` |
| `gmail.send` | `to` (array or comma-separated), `cc?`, `bcc?`, `subject`, `body` (plain text), `in_reply_to?` (a Gmail message id: the mail joins that thread with `In-Reply-To` / `References`) | `{id, thread_id, message_id}` / `id`, `thread_id`, `message_id` | **marker**: a deterministic `Message-ID` | `gmail.send` |
| `gmail.create_draft` | same as `gmail.send` | `{id, message_id, thread_id, rfc822_message_id}` / `id`, `message_id`, `thread_id`, `rfc822_message_id` | **marker**: the same `Message-ID` | `gmail.compose` |

**Operation id.** The ledger stage sets `Call.OperationID` before dispatch. Every write requires it and answers `google.ErrMissingOperation` without one: a write that reached the connector without the ledger could never be verified afterwards, so it is refused rather than guessed about.

**Keys derived from the operation id** (nothing else about the write is stored; the ledger keeps the resource identity and the operation id, decision `enlsy40f`):

- `google.EventID(op)`: the lower-case base32hex (`a-v0-9`, the alphabet the Calendar API accepts for client-chosen ids) of `sha256(op)` truncated to 32 characters, sent as the event's `id`. A retry of the same operation would answer 409 `conflict`, never a duplicate event.
- `google.TaskMarker(op)`: `[mcp-gateway op:<op>]`, appended to the notes on its own paragraph. Google Tasks has no hidden field, so the marker is visible in the notes.
- `google.MessageID(op)`: `<op-<op>@mcp-gateway>`, set as the message's `Message-ID` header. Gmail keeps a client-supplied `Message-ID`; its search operator `rfc822msgid:` finds the message by it.

**Outcomes.** A Google answer is a known outcome: 400/412/422 `invalid_argument`, 401 `reconnect_required`, 403 `forbidden` or `scope_required`, 404 `not_found`, 409 `conflict`, rate limits `*connectors.RateLimited`; the ledger records `failed` and the key is free again. Anything that leaves the outcome open after the request was sent (a 5xx, a timeout, a cancelled context, a dropped connection) is returned wrapped in `connectors.ErrOutcomeUnknown`: the ledger marks the operation `unknown`, a duplicate call answers `-32033 pending verification`, and the reconciler job takes over. Writes never return `Result{Unavailable: true}`. The lookup of the message replied to (`in_reply_to`) is a read: its failure is known and nothing is sent.

### Reconciliation

`Reconciliation.Check` runs from the ledger row alone (the resource identity, the operation id and the account; arguments are never stored) with the same account's token. A definite answer closes the operation (`found` → `succeeded` with `{"id": <resource id>}`, `not_found` → `failed`); an error is "cannot tell yet" and the reconciler retries with backoff until its own limits make the operation `unresolved`.

| Tool | Check | found | not_found |
|---|---|---|---|
| `calendar.create_event` | `GET calendars/{calendar_id}/events/{EventID(op)}` | the event id (whatever its status: a cancelled event with that id was created and then removed) | 404 or 410 |
| `tasks.create` | `GET lists/{tasklist}/tasks?showCompleted=true&showHidden=true&maxResults=100`, pages walked up to `google.MaxReconcilePages` (5) | the task whose notes carry the marker | the end of the list without it; running out of pages or any listing error is "cannot tell yet" |
| `gmail.send` | 1. `GET users/me/messages?q=rfc822msgid:op-<op>@mcp-gateway&includeSpamTrash=true` (exact; a hit is the message). 2. The search index can lag, so a miss is confirmed by reading the `Message-ID` header of the newest `google.MaxReconcileScan` (25) messages labelled `SENT`. | the message id | neither the search nor the scan found the header; any error is "cannot tell yet" |
| `gmail.create_draft` | the same over `users/me/drafts` (`drafts.list?q=...`, then the newest 25 drafts read with `format=metadata`) | the draft id | as above |

## Scopes and granular consent

Scopes are listed with their classification in [`docs/vendor-apps.md`](../vendor-apps.md) section 4.3; every tool declares the minimal one it works with (`RequiredScopes`). Google's **granular consent** lets a user untick some of the requested scopes on the consent screen; the token response's `scope` field then lists exactly what was granted and the binder records that (see [Account binding](#account-binding)).

The pipeline does not compare `Tool.RequiredScopes` with `Account.Scopes` yet (nothing hides in `tools/list`), so the connector enforces it in `Call` when `Options.Accounts` is set (`cmd/gateway` passes the connections service): before any request, the account's recorded scopes must cover the tool's scope, with Google's implication applied (`google.Grants`: `calendar` ⊃ `calendar.events` ⊃ `calendar.events.readonly`, `calendar.readonly` ⊃ `calendar.events.readonly`; `tasks` ⊃ `tasks.readonly`; `mail.google.com` ⊃ `gmail.modify` ⊃ `gmail.readonly` ⊃ `gmail.labels`, `gmail.metadata`; `gmail.modify` ⊃ `gmail.compose` ⊃ `gmail.send`). A tool whose scope was declined answers `scope_required` ("grant more access") and nothing is sent; an account that declined only the Gmail scope keeps every Calendar and Tasks tool. An account without recorded scopes is not blocked locally (Google decides and a 403 `insufficientPermissions` is reported as `scope_required`). Hiding such tools from `tools/list` per account is a follow-up for the pipeline (`internal/mcp` visibility).

**Granting more access** today means reconnecting the account on `/connections` with the missing scope in the connect link's `scopes` query (the connection keeps the union of its scopes). A "grant more access" button on the connections page is a follow-up.

## Account binding

`google.Binder` implements `connections.Binder` for vendor `google` and serves both variants (`internal` and `external`); `cmd/gateway` installs it (`registerGoogle`: `connSvc.RegisterBinder("google", google.Binder{})`, `connSvc.MapApp("calendar"|"tasks"|"gmail", "google")`). After the code exchange it:

1. fetches the OpenID Connect userinfo document (the vendor app's *User info URL*, `https://openidconnect.googleapis.com/v1/userinfo` by default) with the new token: the permanent `sub` becomes the external account id `google:<sub>` (emails can change; `sub` cannot), the `email` the display name;
2. labels the account **company** when the `hd` claim (the Workspace hosted domain) or the email's domain is in the vendor app's `company_domains` extra (comma separated, case-insensitive), **personal** otherwise. Without `company_domains`, the `default_label` extra decides, else the variant: the Internal client only admits the Workspace org's accounts, so they are company; the External app's are personal;
3. reports the scopes from the token response's `scope` field, exactly as granted (granular consent); when the response carries none, the connect flow records the requested scopes.

A 401 on userinfo fails the connect with `reconnect_required`; a 5xx with `unavailable` (the user can retry); a document without `sub` with `vendor_error`. The binder never guesses the label on an unexpected error.

## Setup

1. Register the Google apps as described in [`docs/vendor-apps.md`](../vendor-apps.md) section 4: the **Internal** client (only if the company is a Google Workspace org) and the **External** app, *published, unverified*. Enable the Calendar, Tasks and Gmail APIs in each project. Mind the External app's limits: Google shows the unverified-app warning and **caps it at 100 users for its lifetime**; `gmail.readonly` and `gmail.compose` are **restricted** scopes, so submitting the app for verification would also require an annual **CASA** security assessment (decision `mh7c6z3v` defers both; revisit when personal Google users approach 100). Workspace admins may have to allow the Internal app under *Security -> API controls*.
2. In the portal, **Settings -> Vendor apps -> google/internal** and **google/external**: client ID, client secret, the default endpoints (authorization `https://accounts.google.com/o/oauth2/v2/auth`, token `https://oauth2.googleapis.com/token`, user info `https://openidconnect.googleapis.com/v1/userinfo`, revoke `https://oauth2.googleapis.com/revoke`), **Scopes** = the identity scopes plus the increment-1 tool scopes:
   ```
   openid
   https://www.googleapis.com/auth/userinfo.email
   https://www.googleapis.com/auth/calendar.events
   https://www.googleapis.com/auth/tasks
   https://www.googleapis.com/auth/gmail.readonly
   https://www.googleapis.com/auth/gmail.send
   https://www.googleapis.com/auth/gmail.compose
   ```
   (read-only deployments list `calendar.events.readonly`, `tasks.readonly`, `gmail.readonly`; `gmail.labels` alone keeps `list_labels` working without any restricted scope), the extras `access_type=offline`, `prompt=consent`, `include_granted_scopes=true` (defaults), and in **Extra parameters** the line
   ```
   company_domains=acme.com,acme.co.uk
   ```
   `company_domains` is a reserved binder hint: it is read by the gateway and never sent to Google.
3. Users connect on `/connections` -> Google (internal or external) -> *Connect*, and may untick scopes on Google's consent screen; the connection's label, display name and granted scopes appear on the page.
4. Grant the tools to a role on `/admin/roles` (`calendar.*`, `tasks.*`, `gmail.*` allow, or per tool; use `recipient_domains` or `domain` conditions to confirm or deny mail and calendars outside the company).

The connector is registered whenever the connections module is mounted (a key provider is configured), before the vendor apps exist; until a user connects, every tool answers *no connected account* (`-32031` from the pipeline).

## Tests

- `go test ./internal/connectors/google/`: the contract test for each of the three apps (`connectortest.ContractTest`), the error classification table, the binder (company by `hd`, by email domain, personal, the `default_label` and variant fallbacks, granted scopes recorded exactly, 401 / 5xx / no `sub`), and every tool against hand-written, scrubbed fixtures under `testdata/` served by an `httptest` server that also checks the bearer: reads (success, empty, partial, 404, 401 reconnect, 403 forbidden, 403 insufficient scope, 400, 403 and 429 rate limits, 5xx, network failure, timeout, cancellation, argument validation, resource identity and schema shape, bounds truncation, `gmail.search`'s partial header fetches), writes (the derived event id, marker and `Message-ID` in the request, reply threading, `ResultIDs`, the missing operation id, 400 / 403 / 404 / 401 / 409 / 429 as known outcomes, 5xx / timeout / dropped connection / cancellation as `ErrOutcomeUnknown`, the reply lookup failing as a known outcome), every `Check` (found, not_found, cannot tell, bounded pagination with the marker on a later page, the search miss confirmed by the scan, missing identity or operation id), and the scope gate (`TestDeclinedGmailScopeBlocksGmailToolsWhileCalendarWorks`: an account that declined the Gmail scope is blocked on every Gmail tool before any request while `calendar.list_events` works; `Grants`' implication table). No real tokens or personal data appear in the fixtures (`*.example.test`, synthetic ids).
- `go test ./cmd/gateway/`: the three apps and their `list_accounts` tools are registered with the connections service and answer *no connected account* before a user connects.
- `GOOGLE_LIVE_TOKEN=ya29.... go test -tags live -run Live ./internal/connectors/google/`: `calendar.list_events` and `gmail.list_labels` against Google with a dedicated test account's access token (the scopes it carries decide what works). With `GOOGLE_LIVE_WRITE=1` as well, `TestLiveCreateEventAndReconcile` creates an event under a fresh operation id, runs `create_event`'s check from the resource identity alone and expects it to find the event by its derived id, then deletes it. Behind the `live` build tag and skipped without the variables; never run in CI.

## Adding the next tool

1. Declare it in the app's read or write list (`calendarReadTools`, `tasksReadTools`, `gmailReadTools` in `tools_calendar.go` / `tools_tasks.go` / `tools_gmail.go`; the writes in `tools_write.go`): `App`, `Name`, `Description`, `InputSchema` via `objectSchema(props, required)`, `Kind`, the minimal `RequiredScopes`, a `ResourceIdentity` hook that never returns argument content, `Bounds` (`c.pagedBounds()` or `c.singleBounds()`). Writes also set `Reconcile{Kind, Check}` and `ResultIDs`.
2. Add the handler to the app's handler map and implement it as `func(ctx, *client, connectors.Call) (connectors.Result, error)`: validate arguments first (`idArg`, `idArgDefault`, `requiredString`, `optionalTime`, `stringList`, `pageArgs`; return `invalid(...)`) so an invalid call never touches the token source, then build the service (`cl.calendar(ctx)`, `cl.tasks(ctx)`, `cl.gmail(ctx)`), call the API and convert the response to a flat result type. Reads pass every error through `classify(action, err)`, set `Empty` / `Partial` and fit the result to `c.bounds.MaxResultBytes` (`encodedSize`, `fitBody`). Writes derive their key from `call.OperationID`, pass the error of the request that performs the write through `classifyWrite` (and of any lookup before it through `classify`), and return a `Created*` / `Sent*` result the `ResultIDs` hook reads.
3. For a write, add its `Check` to `reconcile.go` starting from `c.target(in)` (validates the operation id and the account): bounded listing with `MaxReconcilePages` / `MaxReconcileScan`, `found(id)` / `notFound` for definite answers, an error for everything else. Store in the resource identity whatever the check needs.
4. Add fixtures under `testdata/` (scrubbed) and tests for success, empty, partial, the error table and, for writes, the key in the request, `writeErrorCases` and the check's found / not_found / cannot-tell cases. The contract test picks the tool up automatically; extend `TestAppsAndToolNames`.
5. A new app (increment 2) is a fourth `*App` built in `New` with `c.newApp(...)`, appended to `Apps()` and to `google.Apps`, and registered by `cmd/gateway/connectors_google.go` through the same loop.
6. Document it in the tables above and, if it needs a new scope, in `docs/vendor-apps.md` section 4.3.
