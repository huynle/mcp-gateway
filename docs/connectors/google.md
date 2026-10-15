# Google Workspace connector (Calendar, Tasks, Gmail, Drive, Docs, Sheets, Contacts)

Package `internal/connectors/google`, vendor `google`. One Google connection (bound to the account's permanent `sub`) serves **seven connector apps**, each a `connectors.Connector` of its own so tool names read `calendar.list_events`, `tasks.list`, `gmail.search` and `drive.search`, roles can grant or deny a whole app, and the restricted Gmail and Drive scopes stay separable from the rest:

| App | Tools | Google API | Increment |
|---|---|---|---|
| `calendar` | `list_events`, `get_event`, `create_event`; `list_calendars`, `free_busy`, `update_event`, `delete_event`, `respond_to_event` | Calendar API v3 | 1, 3 |
| `tasks` | `list`, `create`; `list_tasklists`, `get`, `update`, `complete`, `delete` | Tasks API v1 | 1, 3 |
| `gmail` | `search`, `get_message`, `list_labels`, `send`, `create_draft`; `get_thread`, `list_drafts`, `get_attachment`, `modify_labels`, `trash`, `send_draft` | Gmail API v1 | 1, 3 |
| `drive` | `search`, `get_file_metadata`, `create_folder`; `get_content`, `list_folder`, `list_permissions`, `list_comments`, `create_file`, `update_file`, `share`, `add_comment` | Drive API v3 | 2, 3 |
| `docs` | `get_text`, `create`, `append_text`; `replace_text` | Docs API v1 (+ Drive for `create`) | 2, 3 |
| `sheets` | `read_range`, `append_rows`; `get_metadata`, `update_range`, `create` | Sheets API v4 (+ Drive for `create`) | 2, 3 |
| `contacts` | `search`; `get`, `list` | People API v1 | 2, 3 |

The connector follows the GitHub reference (`docs/connectors/github.md`, Brain decisions `89k5cln0`, `8023b958`): tokens come from the connection's `oauth2.TokenSource` per call and are never stored; every write runs behind the safety core and declares how it is reconciled after an unknown outcome. The APIs are reached through [google.golang.org/api](https://pkg.go.dev/google.golang.org/api) v0.298.0 (the newest release declaring Go 1.25; v0.299+ require Go 1.26). The tool set is designed after [taylorwilsdon/google_workspace_mcp](https://github.com/taylorwilsdon/google_workspace_mcp) (Python, MIT) without copying code.

Increment 2 (Drive, Docs, Sheets, Contacts; Brain decision `85k9b1ig`) adds four apps over the same binding; its design choices are in [Increment 2 notes](#increment-2-notes-drive-docs-sheets-contacts). Increment 3 closes the gaps with Claude's Gmail / Calendar / Drive connectors and `google_workspace_mcp` (Brain plan `5soa9785`): 30 tools listed in [Increment 3: management tools](#increment-3-management-tools); its 16 new writes default to **Ask** (migration `00022`).

## Reads

`Kind: read`: no approval and no ledger unless policy says `confirm`. The gateway adds `account` and `approval_id` to every schema and generates `<app>.list_accounts` for each of the seven apps (all list the same Google connections).

| Tool | Arguments | Result | Scope (`RequiredScopes`) |
|---|---|---|---|
| `calendar.list_events` | `calendar_id` (default `primary`), `time_min`, `time_max` (RFC 3339; `time_min` defaults to now when both are omitted), `q`, `max_results` (default 25), `page_token` | `{calendar_id, time_zone, time_min, time_max, max_results, next_page_token, has_more, truncated?, items: [{id, calendar_id, summary, description, location, status, start, end, all_day, time_zone, url, meeting_url, organizer, creator, attendees: [{email, name, response_status, optional, organizer, self}], recurring_event_id, created, updated}]}` | `calendar.events.readonly` |
| `calendar.get_event` | `calendar_id`, `event_id` | one item as above plus `truncated?` (description cut to the bounds) | `calendar.events.readonly` |
| `tasks.list` | `tasklist` (default `@default`), `show_completed` (default false; also shows hidden tasks), `max_results` (default 50), `page_token` | `{tasklist, max_results, show_completed, next_page_token, has_more, truncated?, items: [{id, tasklist, title, notes, status, due (date), completed, updated, parent, position, hidden, url}]}` | `tasks.readonly` |
| `gmail.search` | `q` (Gmail search syntax), `label_ids` (array), `include_spam_trash`, `max_results` (default 10), `page_token` | `{query, max_results, result_size_estimate, next_page_token, has_more, truncated?, items: [{id, thread_id, from, to, subject, date, snippet, labels, unread, error?}]}` | `gmail.readonly` |
| `gmail.get_message` | `id` | `{id, thread_id, from, to, cc, bcc, reply_to, subject, date, message_id, in_reply_to, snippet, labels, unread, body, body_type (text/plain or text/html), body_truncated?, attachments: [{id, filename, mime_type, size}], size_estimate}` | `gmail.readonly` |
| `gmail.list_labels` | none | `{items: [{id, name, type}]}` | `gmail.labels` (the non-restricted alternative; `gmail.readonly` covers it too) |
| `drive.search` | `q` (Drive `files.list` query syntax; every file when omitted), `drive_id` (a shared drive; My Drive and files shared with the account when omitted), `include_trashed` (default false), `max_results` (default 25), `page_token` | `{query, drive, max_results, next_page_token, has_more, truncated?, items: [{id, name, mime_type, created, modified, url, size, parents, drive_id, trashed, shared, owned_by_me, owners, description}]}` | `drive.metadata.readonly` (**restricted**; or `drive.file`, per file: see [Increment 2 notes](#increment-2-notes-drive-docs-sheets-contacts)) |
| `drive.get_file_metadata` | `file_id` | one item as above plus `truncated?` (description cut to the bounds); never the file's content | `drive.metadata.readonly` (or `drive.file`) |
| `docs.get_text` | `document_id` | `{id, title, revision_id, url, characters, text, truncated?}`: the body as plain text (headings and paragraphs on their own lines, bullets as `- ` indented per level, person chips and rich links as their name or title, tables one row per line with tab-separated cells, tables of contents as their entries; headers, footers, footnotes and further tabs left out); `characters` counts the whole text, `text` is cut to the bounds | `documents.readonly` (or `drive.file`) |
| `sheets.read_range` | `spreadsheet_id`, `range` (A1 notation with the sheet name), `max_rows` (default 200, at most 1000) | `{spreadsheet_id, range, row_count, truncated?, rows: [[cell strings]]}`: values as the sheet displays them (`FORMATTED_VALUE`), the first `max_rows` rows, then the byte bounds drop trailing rows | `spreadsheets.readonly` (or `drive.file`) |
| `contacts.search` | `query` (prefix of a name, address or organization), `max_results` (default 10, at most 30: the People API's ceiling; no further pages) | `{max_results, truncated?, items: [{resource_name, name, given_name, family_name, emails, organization, title}]}` (read mask `names,emailAddresses,organizations`; never phone numbers, photos or notes) | `contacts.readonly` |

`calendar.list_events` expands recurring events (`singleEvents`) and orders by start time. `gmail.search` lists ids and then fetches each hit's headers (`format=metadata`), one request per hit, which is why its default page is 10; `gmail.get_message` fetches the full message, keeps the `text/plain` part (else the `text/html` part) and **lists attachments without downloading them**. `drive.search` appends `trashed = false` to the query unless `include_trashed` is set, uses `corpora=user` (`corpora=drive` with `driveId` when `drive_id` is given) and `supportsAllDrives`, and leaves the order to Google (no `orderBy`: it is ignored for `fullText` queries). `docs.get_text` fetches the document (`fields=documentId,title,revisionId,body`) and renders it with `google.DocumentText`. `contacts.search` is `people.searchContacts`: Google's contact-search cache can be cold the first time after a while and answer nothing (the tool description tells the harness to search again). Dates are RFC 3339 UTC; task due values are dates (Google Tasks keeps no time of day).

**Resource identity** (policy conditions and audit): `calendar_id` (lower-cased; `primary` when omitted) and `domain` (the calendar id's domain when it is an address) for the Calendar tools, plus `event_id` for `get_event`; `tasklist` for the Tasks tools; `label` (the `label_ids` joined by commas) for `gmail.search`, `message_id` for `gmail.get_message`, nothing for `gmail.list_labels`; `recipient_domains` (sorted, unique domains of to/cc/bcc) for `gmail.send` and `gmail.create_draft`; `drive` (`my`, or the shared drive id when `drive_id` is given) for `drive.search`, `drive.create_folder` and `docs.create`, plus `folder_id` (the `parent_id`) for the two creates; `file_id` for `drive.get_file_metadata`; `document_id` for `docs.get_text` and `docs.append_text`; `spreadsheet_id` for the Sheets tools (the range is not identity); nothing for `contacts.search`. Never the query, the subject, the body, the title, the text, the cells or the addresses themselves. A role rule such as *confirm `gmail.send` when `recipient_domains` not equals `acme.com`* therefore confirms mail leaving the company, and *deny `drive.create_folder` when `drive` not equals `my`* keeps the gateway out of shared drives.

**Pagination and bounds.** `max_results` is clamped to the tool's `MaxPageSize` (package default 50, never above 100) and the result is marked `partial` when it was; `page_token` / `next_page_token` carry Google's cursors; `has_more` says whether a next page exists. `MaxResultBytes` (default 256 KiB) bounds the serialised result: lists drop trailing items (`truncated: true`, never below one), single objects cut the description or body (`truncated` / `body_truncated`).

**Result markers** (`_meta["mcp-gateway/read"]`, decision `dovthftx`):

| Marker | When |
|---|---|
| `empty` | nothing matched (no events, no tasks, no messages, no labels, no files, no contacts, an empty range, a document without text) |
| `partial` | `max_results` or `max_rows` was clamped, the result was truncated to the bounds (`docs.get_text`'s text, `sheets.read_range`'s rows, a description, a list's tail), or one of `gmail.search`'s header fetches failed (that item keeps its ids and carries `error`) |
| `unavailable` | Google answered 5xx or could not be reached; no content is returned |

**Errors.** A `*google.Error` carries `Status` and a `Class`; the message tells the harness what to do:

| Class | Cause | What the harness should do |
|---|---|---|
| `reconnect_required` | 401 from Google, or the connection has no usable token (`connections.ErrNeedsReconnect`) | ask the user to reconnect Google on `/connections` |
| `no_account` | the call carried no connected account (the pipeline normally answers `-32031` first) | ask the user to connect Google |
| `scope_required` | the account did not grant the tool's scope: blocked by the connector before any request (see [Scopes and granular consent](#scopes-and-granular-consent)), or Google answered 403 `insufficientPermissions` | ask the user to grant more access (reconnect with the scope) |
| `not_found` | 404/410: the calendar, event, list, task, message, file, document or spreadsheet does not exist or the account cannot see it (with `drive.file` only: it is not a file the gateway created or the user opened with it) | check the ids |
| `forbidden` | any other 403 (a Workspace admin blocked the app or the API for the org, a calendar the account may only read) | an admin must allow the app |
| `invalid_argument` | the connector rejected the arguments, or Google answered 400/412/422 | fix the arguments |
| `conflict` | 409: an event with the derived id already exists | the operation already ran; do not retry blindly |
| `vendor_error` | any other Google status | retry later |

429, and 403 with the quota reasons `rateLimitExceeded`, `userRateLimitExceeded`, `quotaExceeded` or `dailyLimitExceeded`, are returned as `*connectors.RateLimited{App: "google", RetryAfter}` (`Retry-After`, or 60 s when Google gives none); the harness gets `-32029` with `retry_after` and the vendor is paused until then. Context cancellation and deadlines pass through unchanged. Every call is bounded by `Options.Timeout` (default 30 s).

## Writes

Eight write tools (`Kind: write`: always policy, approval when the role says `confirm`, and the write ledger). Each returns only the identifiers of what it created (plus, for `docs.create`, whether the body text went in); the ledger stores the identifiers (`ResultIDs`) and replays them for a duplicate call inside the idempotency window.

| Tool | Arguments | Result / `ResultIDs` | Reconciliation | Scope |
|---|---|---|---|---|
| `calendar.create_event` | `calendar_id?`, `summary`, `start`, `end` (RFC 3339 timestamps, or `YYYY-MM-DD` dates for an all-day event; both of the same kind), `time_zone?`, `description?`, `location?`, `attendees?` (addresses), `send_updates?` (`all`, `externalOnly`, `none` = default: attendees are not emailed unless asked) | `{id, calendar_id, url, status, start, end}` / `id`, `url` | **stable id**: the event id is chosen by the connector | `calendar.events` |
| `tasks.create` | `tasklist?`, `title`, `notes?`, `due?` (date) | `{id, tasklist, url, status}` / `id`, `url` | **marker** in the notes | `tasks` |
| `gmail.send` | `to` (array or comma-separated), `cc?`, `bcc?`, `subject`, `body` (plain text), `in_reply_to?` (a Gmail message id: the mail joins that thread with `In-Reply-To` / `References`) | `{id, thread_id, message_id}` / `id`, `thread_id`, `message_id` | **marker**: a deterministic `Message-ID` | `gmail.send` |
| `gmail.create_draft` | same as `gmail.send` | `{id, message_id, thread_id, rfc822_message_id}` / `id`, `message_id`, `thread_id`, `rfc822_message_id` | **marker**: the same `Message-ID` | `gmail.compose` |
| `drive.create_folder` | `name`, `parent_id?` (folder), `drive_id?` (a shared drive; its root when `parent_id` is omitted; My Drive's root when both are) | `{id, url, parent_id, drive_id}` / `id`, `url` | **marker** in `appProperties` | `drive.file` |
| `docs.create` | `title`, `body_text?` (plain text; line breaks start paragraphs), `parent_id?`, `drive_id?` | `{id, url, parent_id, drive_id, body_status?, body_error?}` / `id`, `url` | **marker** in `appProperties` | `drive.file` |
| `docs.append_text` | `document_id`, `text` (at most 100 000 characters) | `{document_id, characters}` / `document_id` | **none** | `documents` |
| `sheets.append_rows` | `spreadsheet_id`, `range` (the table to append under, e.g. `Sheet1!A:C`), `rows` (array of rows, each an array of cell strings; at most 500 rows and 10 000 cells), `value_input_option?` (`RAW` = default: cells stored as text, so `=SUM(...)` is not a formula; `USER_ENTERED`: parsed as if typed) | `{spreadsheet_id, updated_range, updated_rows, updated_columns, updated_cells}` / `spreadsheet_id`, `updated_range` | **none** | `spreadsheets` |

**Operation id.** The ledger stage sets `Call.OperationID` before dispatch. Every write requires it and answers `google.ErrMissingOperation` without one: a write that reached the connector without the ledger could never be verified afterwards, so it is refused rather than guessed about.

**Keys derived from the operation id** (nothing else about the write is stored; the ledger keeps the resource identity and the operation id, decision `enlsy40f`):

- `google.EventID(op)`: the lower-case base32hex (`a-v0-9`, the alphabet the Calendar API accepts for client-chosen ids) of `sha256(op)` truncated to 32 characters, sent as the event's `id`. A retry of the same operation would answer 409 `conflict`, never a duplicate event.
- `google.TaskMarker(op)`: `[mcp-gateway op:<op>]`, appended to the notes on its own paragraph. Google Tasks has no hidden field, so the marker is visible in the notes.
- `google.MessageID(op)`: `<op-<op>@mcp-gateway>`, set as the message's `Message-ID` header. Gmail keeps a client-supplied `Message-ID`; its search operator `rfc822msgid:` finds the message by it.
- `google.DriveMarkerKey` (`mcp-gateway-op`) = `<op>` in the created file's `appProperties`, sent **in the creating `files.create` request itself**, so the folder or document and its marker exist together or not at all. `appProperties` are private to the gateway's OAuth client (no other app, and no user, sees or edits them) and are never requested by the reads. `google.DriveMarkerQuery(op)` is the `files.list` query `appProperties has { key='mcp-gateway-op' and value='<op>' }`.

**Outcomes.** A Google answer is a known outcome: 400/412/422 `invalid_argument`, 401 `reconnect_required`, 403 `forbidden` or `scope_required`, 404 `not_found`, 409 `conflict`, rate limits `*connectors.RateLimited`; the ledger records `failed` and the key is free again. Anything that leaves the outcome open after the request was sent (a 5xx, a timeout, a cancelled context, a dropped connection) is returned wrapped in `connectors.ErrOutcomeUnknown`: the ledger marks the operation `unknown`, a duplicate call answers `-32033 pending verification`, and the reconciler job takes over (for the two `none` writes it goes straight to `unresolved` and the user is told to check the document or sheet). Writes never return `Result{Unavailable: true}`. The lookup of the message replied to (`in_reply_to`) is a read: its failure is known and nothing is sent.

`docs.create` is two requests: Drive `files.create` (the document with its marker) and, when `body_text` is given, Docs `documents.batchUpdate` (`insertText` at the end of the body). Once the first answered, the document exists and the write **succeeded** whatever the second does: `body_status` is `applied`, `failed` (a known refusal; `body_error` says why; use `docs.append_text`) or `unknown` (a 5xx or timeout on the insert: the text may be there; check the document). Returning `ErrOutcomeUnknown` there would only make the reconciler re-find a document the result already names.

### Reconciliation

`Reconciliation.Check` runs from the ledger row alone (the resource identity, the operation id and the account; arguments are never stored) with the same account's token. A definite answer closes the operation (`found` → `succeeded` with `{"id": <resource id>}`, `not_found` → `failed`); an error is "cannot tell yet" and the reconciler retries with backoff until its own limits make the operation `unresolved`.

| Tool | Check | found | not_found |
|---|---|---|---|
| `calendar.create_event` | `GET calendars/{calendar_id}/events/{EventID(op)}` | the event id (whatever its status: a cancelled event with that id was created and then removed) | 404 or 410 |
| `tasks.create` | `GET lists/{tasklist}/tasks?showCompleted=true&showHidden=true&maxResults=100`, pages walked up to `google.MaxReconcilePages` (5) | the task whose notes carry the marker | the end of the list without it; running out of pages or any listing error is "cannot tell yet" |
| `gmail.send` | 1. `GET users/me/messages?q=rfc822msgid:op-<op>@mcp-gateway&includeSpamTrash=true` (exact; a hit is the message). 2. The search index can lag, so a miss is confirmed by reading the `Message-ID` header of the newest `google.MaxReconcileScan` (25) messages labelled `SENT`. | the message id | neither the search nor the scan found the header; any error is "cannot tell yet" |
| `gmail.create_draft` | the same over `users/me/drafts` (`drafts.list?q=...`, then the newest 25 drafts read with `format=metadata`) | the draft id | as above |
| `drive.create_folder`, `docs.create` | `GET files?q=<DriveMarkerQuery(op)>&corpora=allDrives&includeItemsFromAllDrives=true&supportsAllDrives=true&pageSize=10&fields=files(id,mimeType,trashed)` (every drive the account can see, so a folder created in a shared drive is found too) | the file id (trashed or not: it was created) | an empty list; any error (404, 5xx, rate limit, token) is "cannot tell yet". Drive indexes `appProperties` on write, and the reconciler's first check runs a minute after the unknown outcome, so a miss is taken as definite |
| `docs.append_text`, `sheets.append_rows` | none (appended text and rows carry no client key; a marker there would be visible content) | | |

## Scopes and granular consent

Scopes are listed with their classification in [`docs/vendor-apps.md`](../vendor-apps.md) section 4.3; every tool declares the minimal one it works with (`RequiredScopes`). Google's **granular consent** lets a user untick some of the requested scopes on the consent screen; the token response's `scope` field then lists exactly what was granted and the binder records that (see [Account binding](#account-binding)).

The pipeline does not compare `Tool.RequiredScopes` with `Account.Scopes` yet (nothing hides in `tools/list`), so the connector enforces it in `Call` when `Options.Accounts` is set (`cmd/gateway` passes the connections service): before any request, the account's recorded scopes must cover the tool's scope, with Google's implication applied (`google.Grants`: `calendar` ⊃ `calendar.events` ⊃ `calendar.events.readonly`, `calendar.readonly` ⊃ `calendar.events.readonly`; `tasks` ⊃ `tasks.readonly`; `mail.google.com` ⊃ `gmail.modify` ⊃ `gmail.readonly` ⊃ `gmail.labels`, `gmail.metadata`; `gmail.modify` ⊃ `gmail.compose` ⊃ `gmail.send`; `drive` ⊃ `drive.readonly`, `drive.file`, `drive.metadata`, `documents`, `spreadsheets`; `drive.readonly` ⊃ `drive.metadata.readonly`, `documents.readonly`, `spreadsheets.readonly`; `drive.metadata` ⊃ `drive.metadata.readonly`; `documents` ⊃ `documents.readonly`; `spreadsheets` ⊃ `spreadsheets.readonly`; `contacts` ⊃ `contacts.readonly`: the methods' accepted-scope lists), plus the **per-file admission** (`google.GrantsOrPerFile`): the Drive, Docs and Sheets methods accept `drive.file` for the files the gateway created or the user opened with it, so an account that granted only `drive.file` is admitted to every Drive, Docs and Sheets tool and Google answers `not_found` for other files. A tool whose scope was declined answers `scope_required` ("grant more access") and nothing is sent; an account that declined only the Gmail scope keeps every other app, one that declined only Contacts keeps everything but `contacts.search`. An account without recorded scopes is not blocked locally (Google decides and a 403 `insufficientPermissions` is reported as `scope_required`). Hiding such tools from `tools/list` per account is a follow-up for the pipeline (`internal/mcp` visibility).

**Granting more access.** *Connect* asks for the read scopes of the Google tools the user's role shows; `/connections` then shows **Grant more access** on an account that lacks scopes for visible tools (with `google.Grants` applied, so `gmail.modify` is never reported as missing `gmail.readonly`). The link re-runs the flow for that connection with the missing scopes, the connection's existing scopes and `include_granted_scopes=true` (added even if the app's extras omit it); the connection keeps the union ([`docs/vendor-apps.md`](../vendor-apps.md) 0.4).

## Account binding

`google.Binder` implements `connections.Binder` for vendor `google` and serves both variants (`internal` and `external`); `cmd/gateway` installs it (`registerGoogle`: `connSvc.RegisterBinder("google", google.Binder{})`, `connSvc.MapApp("calendar"|"tasks"|"gmail", "google")`). After the code exchange it:

1. fetches the OpenID Connect userinfo document (the vendor app's *User info URL*, `https://openidconnect.googleapis.com/v1/userinfo` by default) with the new token: the permanent `sub` becomes the external account id `google:<sub>` (emails can change; `sub` cannot), the `email` the display name;
2. labels the account **company** when the `hd` claim (the Workspace hosted domain) or the email's domain is in the vendor app's `company_domains` extra (comma separated, case-insensitive), **personal** otherwise. Without `company_domains`, the `default_label` extra decides, else the variant: the Internal client only admits the Workspace org's accounts, so they are company; the External app's are personal;
3. reports the scopes from the token response's `scope` field, exactly as granted (granular consent); when the response carries none, the connect flow records the requested scopes.

A 401 on userinfo fails the connect with `reconnect_required`; a 5xx with `unavailable` (the user can retry); a document without `sub` with `vendor_error`. The binder never guesses the label on an unexpected error.

## Setup

1. Register the Google apps as described in [`docs/vendor-apps.md`](../vendor-apps.md) section 4: the **Internal** client (only if the company is a Google Workspace org) and the **External** app, *published, unverified*. Enable the Calendar, Tasks, Gmail, Drive, Docs, Sheets and People APIs in each project. Mind the External app's limits: Google shows the unverified-app warning and **caps it at 100 users for its lifetime**; `gmail.readonly`, `gmail.compose` and `drive.metadata.readonly` are **restricted** scopes, so submitting the app for verification would also require an annual **CASA** security assessment (decision `mh7c6z3v` defers both; revisit when personal Google users approach 100). Workspace admins may have to allow the Internal app under *Security -> API controls*.
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
   plus, for increment 2, the Drive, Docs, Sheets and Contacts scopes:
   ```
   https://www.googleapis.com/auth/drive.metadata.readonly
   https://www.googleapis.com/auth/drive.file
   https://www.googleapis.com/auth/documents.readonly
   https://www.googleapis.com/auth/documents
   https://www.googleapis.com/auth/spreadsheets.readonly
   https://www.googleapis.com/auth/spreadsheets
   https://www.googleapis.com/auth/contacts.readonly
   ```
   plus, for increment 3, the new scopes (see [Increment 3](#increment-3-management-tools); `gmail.modify` and `drive.readonly` are **restricted**):
   ```
   https://www.googleapis.com/auth/calendar.calendarlist.readonly
   https://www.googleapis.com/auth/calendar.freebusy
   https://www.googleapis.com/auth/gmail.modify
   https://www.googleapis.com/auth/drive.readonly
   ```
   (read-only deployments list `calendar.events.readonly`, `tasks.readonly`, `gmail.readonly`, `drive.metadata.readonly`, `documents.readonly`, `spreadsheets.readonly`, `contacts.readonly`; `gmail.labels` alone keeps `list_labels` working without any restricted scope; leaving `drive.metadata.readonly` out keeps the External app free of a restricted Drive scope at the price of the [`drive.file` limitation](#increment-2-notes-drive-docs-sheets-contacts)), the extras `access_type=offline`, `prompt=consent`, `include_granted_scopes=true` (defaults), and in **Extra parameters** the line
   ```
   company_domains=acme.com,acme.co.uk
   ```
   `company_domains` is a reserved binder hint: it is read by the gateway and never sent to Google.
3. Users connect on `/connections` -> Google (internal or external) -> *Connect*, and may untick scopes on Google's consent screen; the connection's label, display name and granted scopes appear on the page.
4. Grant the tools to a role on `/admin/roles` (`calendar.*`, `tasks.*`, `gmail.*`, `drive.*`, `docs.*`, `sheets.*`, `contacts.*` allow, or per tool; use `recipient_domains`, `domain` or `drive` conditions to confirm or deny mail, calendars and shared drives outside the company).

The connector is registered whenever the connections module is mounted (a key provider is configured), before the vendor apps exist; until a user connects, every tool answers *no connected account* (`-32031` from the pipeline).

## Tests

- `go test ./internal/connectors/google/`: the contract test for each of the seven apps (`connectortest.ContractTest`), the error classification table, the binder (company by `hd`, by email domain, personal, the `default_label` and variant fallbacks, granted scopes recorded exactly, 401 / 5xx / no `sub`), and every tool against hand-written, scrubbed fixtures under `testdata/` served by an `httptest` server that also checks the bearer: reads (success, empty, partial, 404, 401 reconnect, 403 forbidden, 403 insufficient scope, 400, 403 and 429 rate limits, 5xx, network failure, timeout, cancellation, argument validation, resource identity and schema shape, bounds truncation, `gmail.search`'s partial header fetches), writes (the derived event id, marker and `Message-ID` in the request, reply threading, `ResultIDs`, the missing operation id, 400 / 403 / 404 / 401 / 409 / 429 as known outcomes, 5xx / timeout / dropped connection / cancellation as `ErrOutcomeUnknown`, the reply lookup failing as a known outcome), every `Check` (found, not_found, cannot tell, bounded pagination with the marker on a later page, the search miss confirmed by the scan, missing identity or operation id), and the scope gate (`TestDeclinedGmailScopeBlocksGmailToolsWhileCalendarWorks`: an account that declined the Gmail scope is blocked on every Gmail tool before any request while `calendar.list_events` works; `Grants`' implication table). Increment 2 adds the same per tool (`tools_drive_test.go`, `tools_docs_test.go`, `tools_sheets_test.go`, `tools_contacts_test.go`): `DocumentText` over a hand-written document (headings, chips, bullets, a table, a table of contents), the text / row / description bounds with `partial`, the `trashed = false` and shared-drive query shapes, the marker in the `files.create` body, `docs.create`'s body-insert failures (`body_status` failed / unknown), `append_rows`' RAW default and the `rows` schema, the Drive marker check (found, not_found, cannot tell on 404 / 401 / 403 / 429 / 5xx, missing operation or account; `docs.create` shares it) and the per-app scope gate (`TestDeclinedIncrement2ScopeBlocksOnlyThatApp`: a Drive-only account is blocked on Docs, Sheets and Contacts before any request; a `drive.file`-only account is admitted per file to Drive, Docs and Sheets but not to Contacts). No real tokens or personal data appear in the fixtures (`*.example.test`, synthetic ids).
- `go test ./cmd/gateway/`: the seven apps and their `list_accounts` tools are registered with the connections service and answer *no connected account* before a user connects.
- `GOOGLE_LIVE_TOKEN=ya29.... go test -tags live -run Live ./internal/connectors/google/`: `calendar.list_events`, `gmail.list_labels`, `drive.search` and `contacts.search` against Google with a dedicated test account's access token (the scopes it carries decide what works); `docs.get_text` and `sheets.read_range` read `GOOGLE_LIVE_DOCUMENT_ID` and `GOOGLE_LIVE_SHEET_RANGE` (`<spreadsheet id>!<A1 range>`) when set. With `GOOGLE_LIVE_WRITE=1` as well, `TestLiveCreateEventAndReconcile` creates an event and `TestLiveCreateFolderAndReconcile` a folder, each under a fresh operation id, run the tool's check from the resource identity alone and expect it to find the resource (by its derived id, by its `appProperties` marker), then delete it. Behind the `live` build tag and skipped without the variables; never run in CI.

## Increment 2 notes (Drive, Docs, Sheets, Contacts)

Brain decision `85k9b1ig` (tagged `needs-review`: taken autonomously).

- **Which Drive scope to request.** `drive.search` and `drive.get_file_metadata` declare `drive.metadata.readonly`, the narrowest scope that sees the whole Drive; it is **restricted** (verification plus CASA for the External app, like `gmail.readonly`). The alternative is to request only `drive.file` (non-sensitive): every Drive, Docs and Sheets tool then works, but **only on files the gateway created or the user opened with the gateway** (`drive.search` lists just those; other ids answer `not_found`). The scope gate admits a `drive.file`-only account to those tools (`GrantsOrPerFile`), so the admin decides in the vendor app's scope list; `drive.readonly` (restricted) would also give `docs.get_text` and `sheets.read_range` the whole Drive. `drive.create_folder` and `docs.create` need only `drive.file` in any case.
- **`docs.create` goes through Drive.** The document is created with `files.create` (`mimeType=application/vnd.google-apps.document`) so the operation's `appProperties` marker is set atomically, exactly like `create_folder`; `body_text` is then inserted with the Docs API. The Docs-API-first order (`documents.create`, then `files.update` for the marker) would leave a window where the document exists without a marker and nothing to find it by: the ledger never stores the title, and a resource identity must never carry argument content.
- **Appends are not reconcilable.** `docs.append_text` inserts `"\n" + text` at the end of the body (a new paragraph after the document's last one); `sheets.append_rows` is `values.append` with `insertDataOption=INSERT_ROWS`. Neither leaves a client key, so an unknown outcome ends `unresolved` and the user checks the document or sheet.
- **Bounds.** `docs.get_text`: `MaxResultBytes` on the text (`characters` keeps the full count). `sheets.read_range`: `max_rows` (default 200, ceiling 1000), then `MaxResultBytes` dropping trailing rows, never below one. `sheets.append_rows`: 500 rows and 10 000 cells per call; `docs.append_text` and `body_text`: 100 000 characters. `contacts.search`: one page of at most 30 (the API's cap). `drive.search`: `MaxPageSize` like every list.
- **Formulas.** `sheets.append_rows` sends `valueInputOption=RAW` unless asked for `USER_ENTERED`, so harness-provided cells cannot inject formulas into a sheet by accident.
- **Resource identity `drive`.** `my` for My Drive, else the shared drive id given as `drive_id`; `folder_id` is the parent folder of a create. Policy can confine the creates to My Drive or confirm them in shared drives.

## Increment 3: management tools

Brain plan `5soa9785`. Same conventions as above (argument validation before the token, `classify` / `classifyWrite`, `Empty` / `Partial`, bounds); the tables list only what is new.

### Reads

| Tool | Arguments | Result | Scope |
|---|---|---|---|
| `calendar.list_calendars` | `show_hidden?`, `max_results`, `page_token` | `{max_results, next_page_token, has_more, truncated?, items: [{id, summary, description, time_zone, access_role, primary, selected, hidden}]}` | `calendar.calendarlist.readonly` (**new**; `calendar.readonly` / `calendar` cover it) |
| `calendar.free_busy` | `time_min`, `time_max` (RFC 3339), `calendar_ids?` (at most 50; `primary` by default), `time_zone?` | `{time_min, time_max, truncated?, calendars: [{id, busy: [{start, end}], errors?}]}`; a calendar Google could not read carries `errors` and makes the result `partial` | `calendar.freebusy` (**new**; `calendar.readonly`, `calendar.events.freebusy` cover it) |
| `tasks.list_tasklists` | `max_results`, `page_token` | `{max_results, next_page_token, has_more, items: [{id, title, updated}]}` | `tasks.readonly` |
| `tasks.get` | `tasklist?`, `task_id` | one task as in `tasks.list` (notes cut to the bounds) | `tasks.readonly` |
| `gmail.get_thread` | `thread_id` | `{id, truncated?, messages: [message as get_message]}`; bodies cut oldest first, then trailing messages dropped | `gmail.readonly` |
| `gmail.list_drafts` | `q?`, `max_results` (default 10), `page_token` | `{max_results, next_page_token, has_more, items: [{draft_id, message_id, thread_id, to, subject, date, snippet, error?}]}` (one metadata request per draft, like `search`) | `gmail.readonly` |
| `gmail.get_attachment` | `message_id`, `attachment_id` | `{message_id, attachment_id, size, encoding (text or base64), content}`; at most **5 MiB** (`google.MaxDownloadBytes`), larger is refused with `invalid_argument`, never cut | `gmail.readonly` |
| `drive.get_content` | `file_id`, `export_mime_type?` | `{id, name, mime_type, exported_as?, size, encoding, content}`: Google Docs and Slides exported as `text/plain`, Sheets as `text/csv`, drawings as `image/png` (or `export_mime_type`); other files downloaded as they are (`alt=media`); at most 5 MiB (checked on the metadata size and while reading); folders, forms and other non-exportable types are `invalid_argument` | `drive.readonly` (**new, restricted**; or `drive.file`, per file) |
| `drive.list_folder` | `folder_id?` (`root`), `max_results`, `page_token` | `{folder_id, max_results, next_page_token, has_more, items: [file as drive.search]}` (`'<id>' in parents and trashed = false`, all drives, folders first) | `drive.metadata.readonly` (or `drive.file`) |
| `drive.list_permissions` | `file_id`, `page_token?` | `{file_id, next_page_token, has_more, items: [{id, type, role, email, domain, display_name, expires}]}` | `drive.metadata.readonly` (or `drive.file`) |
| `drive.list_comments` | `file_id`, `max_results`, `page_token` | `{file_id, ..., items: [{id, content, author, email, created, modified, resolved, quoted, replies: [{id, content, author, created}]}]}` | `drive.readonly` (or `drive.file`) |
| `sheets.get_metadata` | `spreadsheet_id` | `{spreadsheet_id, title, url, locale, time_zone, sheets: [{sheet_id, title, index, type, rows, columns, hidden}]}`; never cell values | `spreadsheets.readonly` (or `drive.file`) |
| `contacts.get` | `resource_name` (`people/<id>`) | `{resource_name, name, given_name, family_name, emails, organization, title, phones}` (read mask adds `phoneNumbers`) | `contacts.readonly` |
| `contacts.list` | `max_results`, `page_token` | `{max_results, total, next_page_token, has_more, items: [contact as search]}` (`people/me/connections`) | `contacts.readonly` |

`gmail.get_attachment` and `drive.get_content` declare `Bounds.MaxResultBytes = google.MaxDownloadResultBytes` (8 MiB, enough for 5 MiB in base64); every other tool keeps the default.

### Writes

All 16 default to **Ask** (migration `00022_google_default_ask.sql`; `TestGoogleNewWritesAreSeededAsAsk` keeps the list equal to every Google write except the eight of increments 1 and 2).

| Tool | Arguments | Result / `ResultIDs` | Reconciliation | Scope |
|---|---|---|---|---|
| `calendar.update_event` | `calendar_id?`, `event_id`, any of `summary`, `description`, `location`, `start`, `end`, `time_zone`, `attendees` (the new full list), `send_updates?` | `{id, calendar_id, url, status, start, end}` / `id`, `url` | **marker**: private extended property `mcp-gateway-op` = op set in the same `events.patch` (merged with the event's other private properties, read first) | `calendar.events` |
| `calendar.delete_event` | `calendar_id?`, `event_id`, `send_updates?` | `{id, calendar_id, deleted}` / `id` | **stable id**: the event 404/410 or `cancelled` is found | `calendar.events` |
| `calendar.respond_to_event` | `calendar_id?`, `event_id`, `response` (`accepted`, `declined`, `tentative`), `comment?`, `send_updates?` | `{id, calendar_id, response, url}` / `id`, `response` | **stable id**: the `self` attendee's response equals the identity's `response` | `calendar.events` |
| `tasks.update` | `tasklist?`, `task_id`, any of `title`, `notes`, `due`, `status` | `{id, tasklist, status, url}` / `id`, `tasklist` | **none** | `tasks` |
| `tasks.complete` | `tasklist?`, `task_id` | as above | **stable id**: status `completed` | `tasks` |
| `tasks.delete` | `tasklist?`, `task_id` | `{id, tasklist, deleted}` | **stable id**: 404/410 or `deleted` | `tasks` |
| `gmail.modify_labels` | `message_id` or `thread_id`, `add_label_ids?`, `remove_label_ids?` (archive = remove `INBOX`, read = remove `UNREAD`, star = add `STARRED`) | `{id, target, labels}` / `id`, `target` | **stable id**: every message carries the added and none of the removed labels | `gmail.modify` (**new, restricted**) |
| `gmail.trash` | `message_id` or `thread_id` | as above | **stable id**: every message labelled `TRASH` | `gmail.modify` |
| `gmail.send_draft` | `draft_id` | `{id, thread_id}` / `id`, `thread_id` | **stable id**: the draft still there is `not_found`; gone is "cannot tell" (sent or deleted), so the operation ends `unresolved` | `gmail.compose` |
| `drive.create_file` | `name`, `content`, `content_encoding?` (`text` / `base64`), `mime_type?`, `parent_id?`, `drive_id?`; at most 5 MiB | `{id, name, mime_type, url, parents, drive_id}` / `id`, `url` | **marker** in `appProperties` (multipart upload, one request) | `drive.file` |
| `drive.update_file` | `file_id`, any of `name`, `description`, `parent_id` (move: the current parents are read and removed) | as above | **marker**: `appProperties.mcp-gateway-op` = op on the file (another operation's marker is "cannot tell") | `drive.file` |
| `drive.share` | `file_id`, `role` (`reader`, `commenter`, `writer`; never owner), `type?` (`user` default, `group`, `domain`, `anyone`), `email` / `domain`, `send_notification?` (default true), `message?` | `{file_id, permission_id, type, role, email, domain}` / `file_id`, `permission_id` | **none** | `drive.file` |
| `drive.add_comment` | `file_id`, `content` | `{file_id, comment_id, created}` / `file_id`, `comment_id` | **none** | `drive.file` |
| `docs.replace_text` | `document_id`, `find`, `replace` (empty deletes), `match_case?` (default true) | `{document_id, occurrences_changed}` / `document_id` | **none** | `documents` |
| `sheets.update_range` | `spreadsheet_id`, `range`, `rows`, `value_input_option?` (`RAW` default) | as `append_rows` | **none** | `spreadsheets` |
| `sheets.create` | `title`, `parent_id?`, `drive_id?` | `{id, name, mime_type, url, parents, drive_id}` / `id`, `url` | **marker** in `appProperties` (Drive `files.create`, like `docs.create`) | `drive.file` |

**Resource identity** of the new tools: `calendar_id`, `domain`, `event_id` (+ `response` for `respond_to_event`); `calendar_ids` and `domains` for `free_busy`; `tasklist`, `task_id`; `message_id` / `thread_id` / `attachment_id` / `draft_id` and `add_labels` / `remove_labels` (sorted label ids) for Gmail; `file_id`, `folder_id` (the folder moved into or listed); `drive.share` adds `role`, `type` and `grantee_domain` (the domain of the email, or the domain shared with) so a rule such as *deny `drive.share` when `grantee_domain` not equals `acme.com`* or *when `type` equals `anyone`* keeps files inside the company; `document_id`, `spreadsheet_id`, `resource_name`. Never text, names, titles, cell values or full addresses.

**Not built** (and why): Gmail filters, vacation / out-of-office and label management (settings, not mail); Calendar creation of secondary calendars, focus-time / working-location events; Docs structural edits (tables, images, headers, `batch_update` with arbitrary requests: too open for a reviewed write); Sheets formatting, conditional formatting, tab management; Contacts writes; Forms, Slides, Chat, Apps Script and Custom Search (no app here); Drive permission removal and file deletion (destructive; `update_file` cannot trash).

## Adding the next tool

1. Declare it in the app's read or write list (`calendarReadTools`, `tasksReadTools`, `gmailReadTools` in `tools_calendar.go` / `tools_tasks.go` / `tools_gmail.go`; the increment-1 writes in `tools_write.go`; the increment-2 apps keep reads and writes together in `tools_drive.go`, `tools_docs.go`, `tools_sheets.go`, `tools_contacts.go`): `App`, `Name`, `Description`, `InputSchema` via `objectSchema(props, required)`, `Kind`, the minimal `RequiredScopes`, a `ResourceIdentity` hook that never returns argument content, `Bounds` (`c.pagedBounds()` or `c.singleBounds()`). Writes also set `Reconcile{Kind, Check}` and `ResultIDs`.
2. Add the handler to the app's handler map and implement it as `func(ctx, *client, connectors.Call) (connectors.Result, error)`: validate arguments first (`idArg`, `idArgDefault`, `requiredString`, `optionalTime`, `stringList`, `pageArgs`; return `invalid(...)`) so an invalid call never touches the token source, then build the service (`cl.calendar(ctx)`, `cl.tasks(ctx)`, `cl.gmail(ctx)`, `cl.drive(ctx)`, `cl.docs(ctx)`, `cl.sheets(ctx)`, `cl.people(ctx)`), call the API and convert the response to a flat result type. Reads pass every error through `classify(action, err)`, set `Empty` / `Partial` and fit the result to `c.bounds.MaxResultBytes` (`encodedSize`, `fitBody`). Writes derive their key from `call.OperationID`, pass the error of the request that performs the write through `classifyWrite` (and of any lookup before it through `classify`), and return a `Created*` / `Sent*` result the `ResultIDs` hook reads.
3. For a write, add its `Check` to `reconcile.go` starting from `c.target(in)` (validates the operation id and the account): bounded listing with `MaxReconcilePages` / `MaxReconcileScan`, `found(id)` / `notFound` for definite answers, an error for everything else. Store in the resource identity whatever the check needs.
4. Add fixtures under `testdata/` (scrubbed) and tests for success, empty, partial, the error table and, for writes, the key in the request, `writeErrorCases` and the check's found / not_found / cannot-tell cases. The contract test picks the tool up automatically; extend `TestAppsAndToolNames`.
5. A new app is another `*App` built in `New` with `c.newApp(...)`, appended to `Apps()` and to `google.Apps` (with an accessor), and registered by `cmd/gateway/connectors_google.go` through the same loop; a new Google API gets a `cl.<api>(ctx)` builder in `connector.go` (`option.WithEndpoint(BaseURL + <prefix>)`: the prefix is the part of the API's base path after the host, `drive/v3/` for Drive, empty for APIs whose method paths start with the version).
6. Document it in the tables above and, if it needs a new scope, in `docs/vendor-apps.md` section 4.3.
