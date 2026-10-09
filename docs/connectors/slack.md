# Slack connector

App `slack` (`internal/connectors/slack`), built on the pattern of the [GitHub reference connector](github.md) (Brain decision `bt8ukyrd`; Slack specifics in decision `9qz87rvz`). It binds a user's Slack account through the Slack OAuth v2 flow of the **same Slack app the approval notifier DMs with** ([`docs/vendor-apps.md`](../vendor-apps.md) section 2: user-token scopes drive the tools, the bot token drives approvals) and exposes read and write tools over the Web API through [slack-go](https://github.com/slack-go/slack) v0.29. Every write runs behind the safety core (policy, approvals, the write ledger) and declares how it is reconciled after an unknown outcome (see [Writes](#writes)).

## Tools

The first five are reads (`Kind: read`: no approval and no ledger unless policy says `confirm`); the three writes follow in [Writes](#writes). The gateway adds `account` and `approval_id` to every schema and generates `slack.list_accounts`.

| Tool | Arguments | Result | User token scope |
|---|---|---|---|
| `slack.list_channels` | `types?` (`public_channel`, `private_channel`; default both), `limit?`, `cursor?`, `exclude_archived?` (default true) | `{channels: [{id, name, is_private, is_archived, is_member, num_members, topic, purpose, created}], next_cursor, has_more, limit, truncated?}` | `channels:read`, `groups:read` (`users.conversations`: only channels the user is a member of) |
| `slack.read_channel_history` | `channel` (id or name), `limit?`, `cursor?`, `oldest?`, `latest?` (Slack timestamps) | `{channel, channel_name?, messages: [{ts, thread_ts?, user, username?, bot_id?, text, subtype?, reply_count?, edited?, reactions: [{name, count}], file_count?, time}], has_more, next_cursor, limit, truncated?}` (newest first) | `channels:history`, `groups:history` |
| `slack.get_thread` | `channel`, `thread_ts`, `limit?`, `cursor?` | `{channel, channel_name?, thread_ts, messages: [...], has_more, next_cursor, limit, truncated?}` (parent first) | `channels:history`, `groups:history` |
| `slack.search_messages` | `query` (Slack search syntax: `in:#channel`, `from:@user`, `before:`, `after:`, `has:link`...), `count?` (default 20), `page?`, `sort?` (`score`, `timestamp`), `sort_dir?` | `{total, page, per_page, page_count, has_more, truncated?, messages: [{ts, channel, channel_name, user, username, text, permalink, thread_ts?, time}]}` | `search:read` (user tokens only; Slack has no bot equivalent) |
| `slack.get_user` | `user` (id `U...`/`W...`, with or without `<@...>`; names are not accepted) | `{id, team_id, name, real_name, display_name, title, tz, status_text, status_emoji, avatar_url, is_bot, is_admin, is_owner?, is_restricted?, deleted}` (no email: `users:read` does not grant it) | `users:read` |

Users appear as ids in messages; `get_user` names one. Message text is Slack mrkdwn as stored (`<@U123>` mentions, `<#C123|name>` links).

**Channel arguments.** Every tool that takes a `channel` accepts an id (`C...` public, `G...` private, `D...` DM, upper-cased; also the `<#C123|name>` form) or a name (with or without `#`, case-insensitive). A name is resolved per call among the channels the account is a member of (`users.conversations`, public and private, archived included, pages of 200, at most `slack.MaxResolvePages` = 5); a name that is not found answers `not_found` with the advice to pass the id. Resolution happens before every write too: its failure is a known outcome and nothing is posted.

**Resource identity** (policy conditions and audit): `channel` — the name lower-cased without its `#`, or the id as is — plus `channel_name` or `channel_id` saying which one it was; `thread_ts` for `get_thread`, `reply_in_thread` and `post_message` with a thread; `timestamp` and `reaction` (the emoji name) for `add_reaction`; `user` for `get_user`. `list_channels` and `search_messages` have none (a query is content). The team is not in the identity: the arguments do not carry it; the account does (external account id `<team id>:<user id>`, recorded on every audit row).

A role rule such as **"post only to #eng-\*"** is the condition `channel` *prefix* `eng-` on `slack.post_message` (proven through the policy engine in `TestRoleRulePostOnlyToEngChannels` and end to end in `TestE2ESlackPostOnlyToEngChannels`): `#eng-deploys` matches, `#random` does not, and a harness that names the channel by **id** does not match either and is denied — the safe default, since the gateway cannot know a channel's name without a lookup and policy must not depend on one. Tell harnesses to pass channel names when such rules exist.

**Pagination and bounds.** `list_channels`, `read_channel_history` and `get_thread` are cursor based (`next_cursor` -> `cursor`); `search_messages` is page based (`page`, `count`, `has_more`). `limit`/`count` are clamped to the tool's `MaxPageSize` (the package default 50, never above 100, the smallest of the Slack maximums the tools use) and the result is then `partial`. `MaxResultBytes` (default 256 KiB) bounds the serialised result: lists drop trailing (oldest) items, never below one, and set `truncated: true`.

**Result markers** (`_meta["mcp-gateway/read"]`, decision `dovthftx`):

| Marker | When |
|---|---|
| `empty` | no channels, messages or hits on that page |
| `partial` | `limit`/`count` was clamped, or the result was truncated to the bounds |
| `unavailable` | Slack answered 5xx, `fatal_error` / `internal_error` / `service_unavailable`, or could not be reached; no content is returned |

**Errors.** A `*slack.Error` carries a `Class` and, for HTTP-level failures, the `Status` (Slack normally answers 200 with `ok: false` and an error code, which the message repeats):

| Class | Slack codes / causes | What the harness should do |
|---|---|---|
| `reconnect_required` | `invalid_auth`, `not_authed`, `token_revoked`, `token_expired`, `account_inactive`, HTTP 401, or the connection has no usable token | ask the user to reconnect Slack on `/connections` |
| `no_account` | the call carried no connected account (the pipeline normally answers `-32031` first) | ask the user to connect Slack |
| `not_found` | `channel_not_found`, `user_not_found`, `thread_not_found`, `message_not_found`, a channel name that did not resolve, HTTP 404 | check the channel/user/timestamp; pass the channel id when the name is unknown |
| `forbidden` | `missing_scope`, `not_in_channel`, `restricted_action`, `is_archived`, `not_allowed`, `user_is_restricted`, HTTP 403 | the account lacks the scope (reconnect to grant it), is not a member of the channel, or the workspace forbids the action |
| `invalid_argument` | the connector rejected the arguments, or Slack answered `invalid_arguments`, `invalid_cursor`, `invalid_ts_latest`/`oldest`, `msg_too_long`, `no_text`, `invalid_name`, HTTP 400 | fix the arguments |
| `vendor_error` | any other Slack code or status | retry later |

Rate limits — HTTP 429 with `Retry-After`, HTTP 429 without one, and `ok: false` `ratelimited` — are returned as `*connectors.RateLimited{App: "slack", RetryAfter}` (the header, or 30 s when Slack gives none); the harness gets `-32029` with `retry_after` and the app is paused for everyone until then. Context cancellation and deadlines pass through unchanged. Every call is bounded by `Options.Timeout` (default 30 s).

## Writes

Three write tools (`Kind: write`: always policy, approval when the role says `confirm`, and the write ledger; decision `dovthftx`). Each returns only the identifiers of what it did; the ledger stores those (`ResultIDs`) and replays them for a duplicate call inside the idempotency window.

| Tool | Arguments | Result / `ResultIDs` | Reconciliation | User token scope |
|---|---|---|---|---|
| `slack.post_message` | `channel`, `text`, `thread_ts?` (reply in that thread instead) | `{channel, ts, thread_ts?}` / `channel`, `ts`, `thread_ts?` | **none** by default; **marker** (message metadata) when `marker_reconcile=true` | `chat:write` |
| `slack.reply_in_thread` | `channel`, `thread_ts`, `text` | `{channel, ts, thread_ts}` / `channel`, `ts`, `thread_ts` | **none** by default; **marker** when `marker_reconcile=true` | `chat:write` |
| `slack.add_reaction` | `channel`, `timestamp` (the message's `ts`), `name` (emoji without colons) | `{channel, timestamp, name, already_reacted?}` / `channel`, `timestamp`, `name` | **stable id** (the message + the emoji + the user) | `reactions:write` |

Text is sent as given (Slack mrkdwn); there is no markdown-to-blocks conversion and no Block Kit input in v1. `add_reaction` is idempotent: Slack's `already_reacted` is reported as success with `already_reacted: true` (the desired state holds, whether a retry or the user's own hand put it there).

**Operation id.** The ledger stage sets `Call.OperationID` before dispatch. Every write requires it and answers `slack.ErrMissingOperation` without one: a write that reached the connector without the ledger could never be verified afterwards, so it is refused rather than guessed about. This can only happen through a wiring bug, never through a harness.

**Outcomes.** A Slack answer is a known outcome: `channel_not_found` is `not_found`, `not_in_channel` / `missing_scope` / `is_archived` `forbidden`, `invalid_auth` `reconnect_required`, `msg_too_long` `invalid_argument`, rate limits `*connectors.RateLimited`; the ledger records `failed` and the key is free again. Anything that leaves the outcome open after the request was sent — a 5xx, `fatal_error`, a timeout (`Options.Timeout`), a cancelled context, a dropped connection — is returned wrapped in `connectors.ErrOutcomeUnknown`: the ledger marks the operation `unknown`, the harness sees *outcome unknown*, and what happens next depends on the tool's reconciliation. Writes never return `Result{Unavailable: true}`. The channel-name resolution before a write is a read: its failure is known and nothing is posted.

### Reconciliation

`Reconciliation.Check` runs from the ledger row alone — the resource identity, the operation id and the account; arguments are never stored — with the same account's token through the same per-call token source. A definite answer closes the operation (`found` -> `succeeded` with `{"id": <message ts>}`, `not_found` -> `failed`); an error is "cannot tell yet" and the reconciler retries with backoff until its own limits make the operation `unresolved` and notify the user (decision `enlsy40f`).

**Messages: none by default.** A chat message has no stable id before it is posted and no client-chosen key, so `post_message` and `reply_in_thread` declare `ReconcileNone`: an unknown outcome goes **straight to `unresolved`** at the reconciler's next pass (`not_reconcilable`), the user is notified ("verify in Slack"), the audit row records it and the idempotency block is lifted so the user can deliberately retry (`TestE2ESlackUnknownOutcomeUnresolved`). The connector could embed an invisible text marker instead, but zero-width characters are rendered by some clients and may be normalised away by Slack, and the search API does not index them; the honest default is to ask the user.

**Messages: opt-in marker.** With the Slack vendor app extra `marker_reconcile=true` (read once by `cmd/gateway` at start-up: changing it needs a restart) the two message writes become `ReconcileMarker`: the operation id travels as **message metadata** — `{"event_type": "mcp_gateway_operation", "event_payload": {"operation_id": "<id>"}}` — which Slack clients never render and which the text does not carry. `Check` reads the thread (`conversations.replies`, when the identity has `thread_ts`) or the channel history (`conversations.history`, newest first) with `include_all_metadata`, 200 messages per page, at most `slack.MaxReconcilePages` = 5: the message whose metadata carries the operation id is `found` (its `ts`); the end of the listing without it is `not_found`; running out of pages or any listing error (including a channel name that no longer resolves) is "cannot tell yet". *Trade-off:* message metadata depends on Slack accepting and returning it for the token; if Slack ever drops it, a post that did happen reconciles as `not_found`, the ledger records `failed`, the block lifts, and a retry **duplicates the message**. The live test (`TestLivePostAndReconcile`) verifies metadata round-trips on a real workspace before you enable the extra; leave it off otherwise.

**Reactions: stable id.** `add_reaction`'s `Check` calls `auth.test` for the account's own user id, then `reactions.get` on the message (`full=true`): the user among the reactors of that emoji is `found` (resource id: the message `ts`); the emoji without the user, or `message_not_found` (the message is gone, so the reaction cannot exist), is `not_found`; `channel_not_found` (access may have been lost), 5xx or an auth failure is "cannot tell yet".

## Account binding

`slack.Binder` implements `connections.Binder` for vendor `slack` and is installed by `cmd/gateway` (`registerSlack`: `connSvc.RegisterBinder("slack", slack.Binder{})`, `connSvc.MapApp("slack", "slack")`). A Slack OAuth v2 code exchange of an app with bot and user scopes answers with the **bot token** at the top level and the user's own token, id and scopes under `authed_user`; an app that requests only user scopes answers with no top-level `access_token` at all. The connect flow exchanges the code for vendor `slack` itself (`connections.Service.exchange` -> `exchangeSlack`, not x/oauth2): it decodes the `oauth.v2.access` answer, lifts `authed_user.access_token` (with its `refresh_token` / `expires_in` under token rotation) when the top level has none, keeps the whole answer in the token's extras, and turns an `ok: false` answer into the flow error with Slack's error code in the log. After the exchange the binder:

1. reads `authed_user.id`, `authed_user.scope`, `authed_user.access_token` and `team.id` / `team.name` from the token response;
2. calls `auth.test` with the user token (or with the only token it has) over the flow client's base transport — never through the oauth2 bearer transport, since slack-go sends the token as a form field and Slack must not see two — for the user name and the workspace URL;
3. produces the external account id `connections.SlackAccountID(team, user)` = `<team id>:<user id>` (what `Service.SlackIdentity` reads back for approval DMs), the display name `<team name> / <user name>` (the user id when only a bot token could run `auth.test`);
4. labels the account **company** when the team id equals the vendor app's `company_team_id` extra (case-insensitive) or the workspace domain (the `acme` of `acme.slack.com`, taken from `auth.test`'s `url`) equals `company_team_domain` (`acme` or `acme.slack.com`); everything else, and every account when neither extra is set, is **personal**;
5. reports the `authed_user` scopes, else Slack's `X-OAuth-Scopes` header on the `auth.test` answer, else none (the connect flow then records the requested scopes);
6. returns the `authed_user` token as `Bound.Token`, so the connection stores the **user token** (`xoxp-...`, a bearer token; with rotation on, `authed_user`'s own refresh token and expiry) and never the bot's. `slack.*` tools get it from `connections.Service.TokenSource`. Without an `authed_user` token (a plain user token) the flow keeps the exchanged token.

The binder derives the Web API root from the vendor app's **Token URL** (`https://slack.com/api/oauth.v2.access` -> `https://slack.com/api/`). An `invalid_auth` on `auth.test` fails the connect with `reconnect_required`; a 5xx fails it with `unavailable` (the user can retry). The binder never guesses the label.

**Formerly a known limitation, fixed (Brain task nzpdfnpl).** The connect flow used to store the token it exchanged — the top-level, i.e. bot, token — so every tool call failed with `missing_scope`, and x/oauth2 failed the exchange outright for a `user_scope`-only app. Both are handled now: the Slack-aware exchange above tolerates a missing top-level token and the binder's `Bound.Token` makes the connection store `authed_user.access_token`. `company_team_id`, `company_team_domain` and `marker_reconcile` are reserved by `connections` (`TestAuthParamsExcludeEveryReservedKey` walks every connector's `Extra*` constants) and never reach the authorize URL. Covered by `TestSlackConnectStoresTheUserToken`, `TestSlackConnectUserScopeOnlyApp`, `TestSlackExchangeErrorIsAFlowError`, `TestSlackAuthorizeURLCarriesNoBinderHints` and, on PostgreSQL, `TestIntegrationSlackConnectStoresUserToken` (`internal/connections`).

## Setup

1. Register the Slack app as described in [`docs/vendor-apps.md`](../vendor-apps.md) section 2 (manifest 2.5: user token scopes `channels:read`, `groups:read`, `channels:history`, `groups:history`, `search:read`, `users:read`, `chat:write`, `reactions:write`; bot scopes for approvals; HTTPS redirect URL; public distribution so every member can authorize).
2. In the portal, **Settings -> Vendor apps -> slack**: client ID, client secret, the bot token and signing secret for approvals, the default endpoints, and in **Extra parameters**:
   ```
   company_team_id=T0123ABCD
   company_team_domain=acme
   ```
   (either suffices; the team id is on the workspace's admin page, the domain is the `acme` of `acme.slack.com`). Add `marker_reconcile=true` only after reading the trade-off above. `scope_param=user_scope` stays (the flow sends the scopes as `user_scope`).
3. Users connect on `/connections` -> Slack -> *Connect*. The connection's label and display name appear on the page; `slack.list_accounts` shows them to a harness. Approval DMs go to the company-labelled connection.
4. Grant the tools to a role on `/admin/roles` (`slack.*` allow, or per tool; use `channel` *prefix* or *equals* conditions to confirm or deny by channel name; a write with only conditional rules is denied wherever no condition holds, including when the harness passes an id).

The connector is registered whenever the connections module is mounted (a key provider is configured), before the vendor app exists; until a user connects, every tool answers *no connected account* (`-32031` from the pipeline).

## Tests

- `go test ./internal/connectors/slack/`: the contract test (`connectortest.ContractTest`, default and marker modes), the binder (`authed_user` token extraction and precedence over the bot token, the `authed_user` token returned as `Bound.Token` with its rotation fields, company by team id / domain, personal otherwise, `auth.test` fallback with `X-OAuth-Scopes`, `authed_user` without its own token, `invalid_auth`, 5xx, API root from the token URL), the error vocabulary table, and every tool against hand-written, scrubbed fixtures under `testdata/` served by an `httptest` server that checks the form token: reads (success, empty, partial, clamped and truncated, name resolution found on a later page / not found / bounded, `channel_not_found`, `not_in_channel`, `missing_scope`, `invalid_auth`, 5xx, `fatal_error`, 429 with and without `Retry-After`, `ratelimited`, network failure, cancelled context, argument validation, resource identity and schema shape), writes (the resolved id and text in the request, no metadata by default and the metadata marker when enabled, `ResultIDs`, the missing operation id, the error table as known outcomes, 5xx / `fatal_error` / timeout / dropped connection as `ErrOutcomeUnknown`, `already_reacted` as success) and every `Check` (reaction found / not found / message gone / cannot tell / name resolved / missing identity; marker found on a later page / not found at the end / pages exhausted / listing error / thread vs channel). The role rule "post only to #eng-*" is compiled and decided through the real policy engine. No real tokens or personal data appear in the fixtures (`U0ALICE001` / `T0EXAMPLE1` / `acme.slack.com`).
- `make test-e2e` (`test/e2e/slack_test.go`): the real connector behind the whole gateway against a stub Slack API: `post_message` to `#eng-deploys` needs an approval, the approved retry resolves the name and posts, the ledger stores the ids and the identity carries the channel name; `#random` and a channel id are denied; a post Slack never answers ends `unknown`, the reconciler turns it `unresolved` at once (`not_reconcilable`), notifies the user and lifts the block for a deliberate retry.
- `SLACK_LIVE_USER_TOKEN=xoxp-... go test -tags live -run Live ./internal/connectors/slack/`: `list_channels` against slack.com with a dedicated test workspace's user token. With `SLACK_LIVE_CHANNEL=#gateway-tests` as well, `TestLivePostAndReconcile` posts under a fresh operation id with marker reconciliation on, runs `post_message`'s check from the resource identity alone and expects it to find the message by its metadata (this is the check to run before enabling `marker_reconcile`), then adds a reaction and runs `add_reaction`'s check. Behind the `live` build tag and skipped without the variables; never run in CI.

## Adding the next tool

Follow [the GitHub page's recipe](github.md#adding-the-next-tool) with these substitutions: declare in `readTools()` / `writeTools()` with `objectSchema`, `identity(extraKeys...)` (channel plus the named timestamp-like keys; never content) and the Slack scope as `RequiredScopes`; implement as `func(ctx, *goslack.Client, connectors.Call)`; read channels with `channelArg` + `c.resolveChannel` (a read, even before a write), timestamps with `tsArg` / `optionalTS`, page sizes with `c.limitArg`; pass read errors through `classify` and the write request's error through `ClassifyWrite`; convert with a `to*` function in `minimal.go`; bound lists with `fit`. For a write add its `Check` to `reconcile.go` starting from `c.target(ctx, in)` (validates the operation id, the channel and the account, builds the client, resolves the name) and store in the resource identity whatever the check needs. Keep the slack-mcp-server headers in `tools_read.go` / `tools_write.go` / `minimal.go` accurate and update `THIRD_PARTY_NOTICES.md` when adapting more of it; document the tool above and its scope in `docs/vendor-apps.md` section 2.2.
