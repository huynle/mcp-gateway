# Ephemeral secrets (`secrets.*`, `internal/secrets`)

An agent sometimes needs a password from the user: an upstream API credential, `sudo` on a box, an SSH passphrase, a
database login. Pasting it into the chat puts it into the model context, the transcript and the provider's logs. With
ephemeral secrets the user types the value on a one-time gateway page, and the agent only ever holds a **handle**
(`sec_…`). The gateway puts the value into one call, only for the tool and argument the secret is bound to, and
scrubs it from the result. The agent can **use** the secret but never **read** it.

Design: [plans/2026-10-23-ephemeral-secrets-design.md](plans/2026-10-23-ephemeral-secrets-design.md), including its
"Corrections after code validation", which override the earlier sections. The feature is off unless the operator
sets `GATEWAY_SECRETS_ENABLED=true` ([Operator settings](#operator-settings)).

## Flow

```
 USER (browser)            AGENT HARNESS                     MCP GATEWAY                         TARGET
      │                          │                                │                                  │
      │                ① secrets.request                          │                                  │
      │                  {label, tool:"vault.login",              │                                  │
      │                   arg:"password", ttl:"15m", uses:1}      │                                  │
      │                          │───────────────────────────────▶│ checks the tool is visible and   │
      │                          │                                │ has the argument; stores a       │
      │                          │                                │ PENDING row (hashes only)        │
      │                          │◀───────────────────────────────│ -32042: url <base>/s/<id>,       │
      │                          │                                │ handle sec_…, 4 check words      │
      │◀── shows link + words ───│                                │                                  │
 ② open /s/<id> (signed in) ─────┼───────────────────────────────▶│ owner? pending? link < 10 min?   │
      │◀── entry page: harness, label, binding, TTL, uses, words ─│                                  │
      │── Save (CSRF) ───────────┼───────────────────────────────▶│ ③ envelope-encrypt, AAD          │
      │                          │                                │   {owner,"secret",id,server id}; │
      │                          │                                │   audit secret.provided          │
      │                ④ vault.login {"password":                 │                                  │
      │                     {"$secret":"sec_…"}}                  │                                  │
      │                          │───────────────────────────────▶│ authenticate → resolve → precheck│
      │                          │                                │ (ref as handle string) → policy  │
      │                          │                                │ → ledger → rate limit →          │
      │                          │                                │ SECRET STAGE: owner, harness,    │
      │                          │                                │ binding, TTL, uses (conditional  │
      │                          │                                │ UPDATE takes one use); decrypt;  │
      │                          │                                │ substitute → dispatch            │
      │                          │                                │──────────── plaintext ──────────▶│
      │                          │                                │◀──────────── result ─────────────│
      │                          │◀───────────────────────────────│ ⑤ scrub result and error text,   │
      │                          │                                │ restore handle-form arguments,   │
      │                          │                                │ refund if the call never left;   │
      │                          │                                │ audit secret.used                │
      │                          │                                │ ⑥ expiry job (30 s) wipes the    │
      │                          │                                │   ciphertext when TTL/uses end   │
      │── /secrets → Revoke ─────┼───────────────────────────────▶│ ends it at once, wipes the value │
```

1. **Request.** The agent calls `secrets.request`. The gateway checks the target, stores a pending row bound to the
   caller (user and harness) and answers `-32042` with the entry link, the handle and the fingerprint.
2. **Entry.** The user opens `/s/<id>`, checks the words and the binding, and presses **Save** or **Deny**.
3. **Store.** The value is envelope-encrypted and usable for the TTL from the moment it is saved.
4. **Use.** The agent calls the bound tool with `{"<arg>": {"$secret": "<handle>"}}`. A stage immediately before
   dispatch takes one use and substitutes the value into a copy of the arguments.
5. **Return.** The result and the error text are scrubbed of the value before any other stage sees them.
6. **End.** The expiry job wipes values whose TTL or uses ran out; `/secrets` revokes one at once.

The transport is stateless: the gateway never sends `notifications/elicitation/complete`. The agent retries the real
call with the handle after the user saved the value; while it is still pending the retry gets the same `-32042`.

## For agents: `secrets.request`

| Argument | Required | Meaning |
|---|---|---|
| `label` | yes | What the secret is, as the user sees it on the entry page ("vault password"); 1–80 characters. |
| `tool` | yes | Full name of the tool the secret is for, as in `tools/list`: `<server>.<tool>`, or `<machine>-actions.<action>` for a machine action. |
| `arg` | yes | The **top-level** argument of that tool the value goes into; `secret` for a machine action. It must be in the tool's input schema (a schema without `properties` accepts any name). `account` and `approval_id` are refused. |
| `ttl` | no | How long the secret stays usable after the user saved it, as a Go duration: `1m` to `1h`, default `15m`. |
| `uses` | no | How many calls may use it: 1–10, default 1. |

The answer is always an error (there is nothing to return until the user acted):

```json
{"code": -32042,
 "message": "Ask the user to open https://gw.example.com/s/<id> and enter the secret (check the words: oak-river-mint-amber). Then retry the call with {\"password\": {\"$secret\": \"sec_…\"}}.",
 "data": {
   "elicitations": [{"mode": "url", "elicitationId": "<record id>", "url": "https://gw.example.com/s/<id>",
                     "message": "Enter the secret \"vault password\" on the gateway (check the words: oak-river-mint-amber)."}],
   "url": "https://gw.example.com/s/<id>",
   "handle": "sec_<43 base62 characters>",
   "fingerprint": "oak-river-mint-amber",
   "expires_at": "2026-10-23T18:10:00Z"}}
```

`data.elicitations[]` has the MCP URL-elicitation shape; `url`, `handle` and `fingerprint` repeat what an agent needs,
and the message repeats the link for harnesses that only show error text. `expires_at` is when the entry link ends
(10 minutes). Neither carries a value.

Then call the bound tool with the reference as the whole value of the argument:

```json
{"name": "vault.login", "arguments": {"user": "huy", "password": {"$secret": "sec_…"}}}
```

- A reference is an object with exactly the key `$secret` and a valid handle. Anything else is passed on untouched.
- References must be the value of a top-level argument, the one in the binding; a reference nested deeper, or in
  another argument, is `-32037`.
- Several handles in one call are allowed; nothing is consumed unless all of them are usable. The same handle twice
  in one call takes one use.
- The handle works only for the user and the harness that requested it: a generated token (`mgw_`, by token id) or an
  OAuth harness (by its refresh-token family). A harness that signs in again gets a new family and needs a new secret.

Show the user the link and the words and never ask them to paste the secret into the chat. The tool description says
the same.

### Errors

| Code | Class | When | What the agent does |
|---|---|---|---|
| `-32042` | `secret_required` | answer of `secrets.request`; a retry while the value has not been entered yet (same link and words) | show the link and the words; retry after the user saved it |
| `-32030` | `secret_denied` | the user pressed **Deny** | do not ask again unless the user wants to |
| `-32037` | `secret_unavailable` | expired (link or TTL), used up, revoked, wrong tool or argument, another user's or harness's handle, unknown handle, misplaced reference. One message for every cause: *secret unavailable: it expired, was used up or revoked, or is not for this call; request a new one with secrets.request* | call `secrets.request` again |
| `-32029` | `secret_requests_limited` | more than 5 pending requests or 20 requests in the last hour; `error.data.retry_after` = 600 | wait, or let pending links expire |
| `-32602` | `invalid_params`, `secret_target_unknown` | bad label, TTL or uses; the tool does not exist or is hidden from the caller; a built-in tool; an argument the tool does not have; a secrets tool | fix the arguments |
| `-32603` | `secrets_unavailable` | the request could not be stored | retry later |

A failure of the target itself keeps its own error, scrubbed. When the call never reached the target (a gateway
refusal at dispatch, or `tunnel_offline` / `tunnel_unavailable`), the use is given back. An upstream error, a
timeout or an unknown outcome keeps the use consumed: the value may have been delivered.

`-32042` is the go-sdk's own URL-elicitation code, used with exactly its meaning; every other gateway code stays in
the gateway's block (`internal/mcp/errors.go`). The official go-sdk client returns it from `CallTool` at once as a
`*jsonrpc.Error`, with or without an elicitation handler, and does not run the handler; such harnesses must show the
link from the message or `error.data.url`.

## For users

Only ever type a secret at **`<your gateway>/s/…`**, after signing in, and only when the check words match what your
agent shows. If anything differs, or you did not expect the request, press **Deny**.

| Page | What it does |
|---|---|
| `GET /s/{id}` | Entry page of your own pending request: requesting harness (token or OAuth client name), label, binding (server, tool, argument), TTL, uses and the 4-word fingerprint. One password field (`autocomplete="off"`, 8–4096 bytes), **Save** and **Deny**. Signed-in owner only; anonymous visitors go to sign-in and come back. |
| `POST /s/{id}` | `action=save` stores the value (once); `action=deny` refuses the request. CSRF token required. |
| `GET /secrets` | Your pending and live secrets (label, binding, harness, state, uses left / total, expiry), ended ones last (kept 7 days). Never values. |
| `POST /secrets/{id}/revoke` | Ends a pending or live secret at once and deletes its value. |

Unknown, foreign, expired and already answered links all show the portal's ordinary "Page not found". Every page is
`Cache-Control: no-store`, `X-Frame-Options: DENY` and `Referrer-Policy: no-referrer`, behind the portal's CSP. A
value shorter than 8 bytes is refused (it cannot be scrubbed reliably), as is one longer than 4096 bytes; the page
shows the form again without the value.

### The fingerprint

The four words (`oak-river-mint-amber`) come from the first four bytes of SHA-256 over the request id, one word of a
fixed 256-word list per byte (`internal/secrets/ref`). The agent prints them from the `-32042` answer and the page
shows them for the link. Matching words mean the page belongs to the request the agent made, not to a link someone
else sent. They are a visual check (32 bits), not a secret.

## Bindings

A secret is bound to **one server id, one upstream tool and one top-level argument**. The binding is fixed when the
request is made and shown on the entry page; the secret stage refuses any other target with the generic `-32037`.

- v1 binds only tools of **user-added MCP servers** (federated, including tunnel servers) and **machine servers**
  (including `<machine>-actions`). Built-in apps (`github`, `slack`, `gateway`, …) have no binding target:
  `secrets.request` refuses them with `-32602`.
- The target must be visible to the caller through the same visibility `/mcp` uses (role, review state, token
  scope); a hidden tool is "unknown tool".
- The stored binding is the server id and the upstream tool name, so renaming a server does not move the secret to
  another server, and deleting the server deletes the secret.
- Policy, approvals and the ledger see the handle-form arguments: a write tool needing approval stores the reference,
  not the value, and the precheck validates a copy with each reference replaced by its handle string.

## Scrubbing

The secret stage scrubs, before the ledger, audit and the handler see anything, every result type the pipeline
accepts (strings, content, content slices, `CallToolResult` including `structuredContent`, JSON) and the error text
(including a tool error's `message` and `data`). For each value it replaces with `[secret]`:

- the raw text;
- base64 (standard and URL-safe, with and without padding);
- `url.QueryEscape` and `url.PathEscape`;
- the JSON string-escaped form (with and without HTML escaping);
- hex (lower and upper case).

Machine actions scrub their output a first time on the machine (`<machine>-actions`), and the gateway scrubs again.

Limits: the value inside a larger encoded blob (base64 of a longer string at an unaligned offset, gzip, …) or in any
other encoding is not found. A target that echoes the secret in a transformed form leaks it to the agent; bind
secrets only to tools that do not.

## Machine actions

A secret handed to an arbitrary shell is readable (`echo $PW | base64`). For commands on the user's own machine the
user's `config.yaml` declares **actions**: fixed commands that receive the secret through stdin, file descriptor 3, a
one-shot askpass helper or one environment variable, never through argv. `mcp-gateway up` serves them as the server
`<machine>-actions`, one tool per action, and its tools go through the normal review on the Machines page like any
other machine server. Configuration, delivery modes and their limits: [machines-cli.md](machines-cli.md#actions).

```
 GATEWAY (secret stage)  ══ machine WebSocket ══▶  `mcp-gateway up` (<machine>-actions)
   <machine>-actions.<action>                        ① the action exists in config.yaml; params match patterns
   {params…, "secret": value}                        ② fixed argv, no shell, minimal environment, own session
                                                     ③ deliver by stdin / fd 3 / askpass / env:NAME
                                                     ④ scrub stdout and stderr (64 KiB each)
                         ◀════════ result ════════   (the gateway scrubs again)
```

The agent requests `{"tool": "<machine>-actions.<action>", "arg": "secret"}` and calls the action with
`{"secret": {"$secret": "sec_…"}, …params}`. Before ①, the actions server checks the call's
`_meta["mcp-gateway/tool-digest"]` against the definition it serves: an action edited under the same name since its
review is refused and nothing runs ([machines-cli.md](machines-cli.md#actions)). If the machine is offline the call fails with the tunnel error and the use
is refunded. `TestIntegrationSecretThroughMachineAction` (`cmd/gateway`) runs this path through a real tunnel.

## Policy

`secrets.request` is the built-in `secrets` app (connector in `internal/secrets`), a read tool that needs no account.
The compiled Cedar set has an implicit **secrets layer** (`internal/policy/secrets.go`) beside the gateway layer:

```
@id("secrets/request")    permit list, call on App::"secrets"
@id("secrets/read_only")  forbid list, call on App::"secrets" when context.token.read_only
```

- every user may list and call it without a role grant;
- a **read-only token** (and an OAuth token with `mcp:read`) never sees it, although it is a read tool;
- the token allow-list, user restrictions and role **deny** rules apply: an admin can deny `secrets.*` per role;
- using a secret needs nothing extra: the call to the bound tool is decided like any other call.

The server name `secrets` is reserved for the app: a user-added server cannot take it, and an existing server with
that name gets no tools.

## Limits

| Limit | Value | Where |
|---|---|---|
| Pending requests with a live link, per user | 5 | `MaxPendingPerOwner`; beyond: `-32029` |
| Requests per user per rolling hour | 20 | `MaxRequestsPerHour`; beyond: `-32029` |
| Entry link lifetime | 10 minutes | `LinkTTL`; then the request expires |
| TTL after saving | 1 minute – 1 hour, default 15 minutes | `MinTTL`, `MaxTTL`, `DefaultTTL` |
| Uses | 1 – 10, default 1 | `MaxUses`, `DefaultUses` |
| Value length | 8 – 4096 bytes | `MinValueLen`, `MaxValueLen` |
| Label | 80 characters (tool), 100 (store) | `MaxToolLabelLen`, `MaxLabelLen` |
| Failed `/s/{id}` lookups per client address | 20 per minute, **per replica** | `EntryFailureBurst`, `EntryFailureWindow`; beyond: `429` with `Retry-After` |
| Ended rows kept for `/secrets` | 7 days | `Retention` |

The limits are constants (design correction 7), not settings. The address is the TCP peer; behind an Ingress that is
usually the controller, so the failure budget then acts as a shared limit. The 256-bit request id is the security
boundary; the budget only slows guessing.

## Audit and logs

| Event (`resource.action`) | When | Resource |
|---|---|---|
| `secret.provided` | the user saved a value | `secret_id`, `label` |
| `secret.denied` | the user pressed Deny | `secret_id`, `label` |
| `secret.revoked` | the user revoked on `/secrets` | `secret_id`, `label` |
| `secret.used` | a call used the secret and the use was not refunded | `secret_id`, `label`, `tool`; token id = the harness |

`secrets.request` itself and the call that used a secret are ordinary `tool_call` events (the request's resource is
the target tool's name). Neither audit nor the ledger ever holds a value or a handle.

Logs carry the record id and label only. The redacting logger also masks handles (`sec_…`) and entry link ids after
`/s/` (also URL-encoded, as in a sign-in `return_to`) in every log line ([observability.md](observability.md)); the
portal's CSRF-rejection and server-error logs and the secret pages' own error log print `/s/…`. Metrics label requests
by route pattern (`GET /s/{id}`), never the path.

## Storage and encryption

One table, `secrets` (migration `00031_secrets.sql`, `store.ExpectedSchemaVersion` 31), carries the whole lifecycle:
`pending` → `provided` → `expired` / `revoked`, or `pending` → `denied` / `expired` / `revoked`.

- Only SHA-256 hashes of the request id and the handle are stored. The request id is derived from the handle
  (SHA-256 with a domain tag, base62), so a retry can be answered with the same link without storing either.
- The value is envelope-encrypted with the gateway's key provider (`value_key_id`, `value_wrapped_key`,
  `value_nonce`, `value_ciphertext`) under AAD `{owner, "secret", record id, server id}`; a value moved to another
  row, user or server does not decrypt. The columns are set only while the row is `provided`.
- The columns are in the `/migrate rewrap` registry (`internal/rewrap`), so a key rotation rewraps them
  ([crypto.md](crypto.md)).
- Owner's rows under row-level security; the expiry job and the disable hook run as the jobs role.
- **Consume** is one conditional `UPDATE … WHERE uses_left > 0 AND expires_at > now() … RETURNING`, matching handle
  hash, owner, harness and binding, so concurrent calls never take more uses than there are. **Refund** gives one
  back while the secret is still usable.
- The **expiry job** (`secrets.expire`, every 30 s, one replica) moves rows whose link, TTL or uses ran out to
  `expired` and wipes their ciphertext, and deletes ended rows after 7 days. Calls never wipe inline (a use may still
  be refunded).
- **Disabling a user** revokes every pending and live secret and wipes the values inside the disabling transaction
  (`identity.Service.OnDisable`). **Deleting an account** deletes the rows (`store.DeleteUserData`). Deleting the
  bound server deletes its secrets (foreign key).

The plaintext exists only inside the secret stage (decrypt, substitute, dispatch, scrub) and inside the entry page's
handler; the `[]byte` buffers are zeroed after use.

## Operator settings

| Variable | Default | Notes |
|---|---|---|
| `GATEWAY_SECRETS_ENABLED` | `false` | Helm: `gateway.secrets.enabled`. Registers `secrets.request`, the secret stage, `/s/{id}`, `/secrets`, the expiry job and the disable hook. An unparsable value fails startup. |

The feature also needs a **key provider** (`GATEWAY_KEY_PROVIDER` / `GATEWAY_KEY_FILE`; values are never stored
unencrypted) and **user-added MCP servers** (the federation, which needs the same key provider; otherwise there is
nothing to bind to). Without either it stays off with a startup warning naming the reason. When it is on the log says
`ephemeral secrets ready`.

The Ingress must route `/s` and `/secrets` (the chart's default `ingress.paths` does). Entry links are built from
`GATEWAY_BASE_URL`.

## Threats

| Threat | Defense |
|---|---|
| Phishing link from the agent or a prompt injection | Entry only on the gateway origin behind company sign-in; the page shows harness, binding and a fingerprint the agent also prints; users are told to type secrets only at `<base>/s/…` |
| Injection requests a secret bound to an attacker's server | Bindings only to tools of servers the user owns or that are published to them, visible to the caller and allowed by policy; the entry page names the server, tool and argument |
| Request spam | ≤ 5 pending per user, 20 per hour, `-32029` beyond; pending links expire in 10 minutes |
| Handle replay by another harness or user | Handle checked against owner + harness (token id or OAuth family) and binding in the consume `UPDATE`; every mismatch is the same `-32037` |
| Guessing `/s/<id>` or handles | 256-bit random handles, request ids derived from them, SHA-256 at rest; 404 identical to an unknown page; per-address failure limit |
| Leak through results | Scrubbed on the machine and in the gateway (raw, base64, URL, JSON, hex forms); values shorter than 8 bytes refused |
| Leak through logs, audit, ledger, approvals | Plaintext only inside the secret stage; handle-form arguments restored before audit; audit holds record id and label; the redacting logger masks handles and entry ids |
| Clickjacking or CSRF on the entry page | `X-Frame-Options: DENY`, CSP, CSRF token on every POST, owner check |
| Agent reads the secret through a shell on the machine | Only fixed actions receive secrets, never in argv; the harness's own shell tool never receives one |
| Agent with local file access edits an approved action's command in `config.yaml` (same name) | The gateway sends the approved tool's digest in `_meta["mcp-gateway/tool-digest"]`; the actions server refuses a call whose digest is not the one of the definition it serves, before reading the secret or starting anything; `up` refreshes the actions server on every start and reload, so the edit waits as a pending review until a human approves it |
| Gateway compromise | Envelope encryption under the key provider, as for stored credentials; short TTLs; the expiry job wipes |

## Known limitations

- **Strings cannot be zeroed.** Go strings (the decoded value in the substituted arguments, the JSON request body
  sent upstream, the form value on the entry page, the action's argument on the machine) stay in memory until the
  garbage collector reuses them. Only the `[]byte` copies are wiped.
- **Connector logs.** A connector that logs upstream error text itself, before the stage scrubs the returned error,
  could log a value the upstream echoed. The redacting logger does not know secret values.
- **Schema disagreement.** The precheck validates the arguments with the handle string in place of each reference;
  dispatch validates them again with the value. A `maxLength`, `pattern` or `format` on the argument can accept one
  and refuse the other (the handle is 47 characters). A refusal at dispatch (`args_invalid`) refunds the use.
- **Reserved name.** A user-added server named `secrets` is refused, and one that existed before gets no tools.
- **go-sdk clients** see `-32042` as a plain error from `CallTool` and do not run their elicitation handler; the
  harness must show the link (from the message or `error.data.url`).
- **Transformed echoes.** A target that prints the secret in an encoding the scrubber does not know (or a machine
  action that runs a script the agent can edit) defeats "unreadable". Bind secrets only to tools and actions whose
  behaviour you control. The digest check covers the action's definition (its command line), not the files that
  command reads or runs.
- **Refused after an edit.** A call refused because the action changed since its review reached the machine, so its
  secret use is spent, not refunded; request a new secret after approving the new version.
- **Entry page wording for actions.** Requests made through `secrets.request` carry the argument `secret` for machine
  actions, so the entry page shows them as server `<machine>-actions`, tool `<action>`, argument `secret`.

## Testing

| Gate | Covers |
|---|---|
| `make test` | `internal/secrets`: request limits and defaults, hashes only, lookup and provide (single use, length bounds, envelope), consume mismatches as one error, pending / denied / revoked / expired, refund caps, expiry, disable hook (`service_test.go`); the tool's validation, `-32042` shape, machine-action binding, limits (`tools_test.go`); the stage's substitution, scrubbing of results and errors, identical unavailable answers, refunds, two handles, the pipeline position (`stage_test.go`); the pages, fingerprint parity, uniform 404, CSRF, anonymous callers, revoke (`portal_test.go`); the per-address limiter (`limiter_test.go`); `ref/` and `scrub/` with fuzz tests. Also `internal/policy` (secrets layer), `internal/federation/connector` (precheck with refs, `SecretTarget`), `internal/mcp` (error codes, `-32042` reaching an SDK client), `internal/machineclient` (actions config, delivery modes, nothing in argv or env, scrubbed and capped output, timeouts, the actions server in `up`), `internal/observability` (handles and entry ids redacted), `cmd/gateway` (the feature stays off unless enabled and possible). |
| `make test-integration` | `internal/store/secrets_integration_test.go`: lifecycle and row-level security, request counts, single use under concurrent consumers, expiry wipes ciphertext, revoke on disable; `internal/secrets` over PostgreSQL (limits under concurrency); `cmd/gateway` `TestIntegrationSecretThroughMachineAction` (a secret delivered to a machine action through a real tunnel; after the action is edited under its name and the machine reconnects, the next call is refused, nothing runs and a pending review exists); `internal/federation/snapshot` `TestIntegrationApprovedToolDigestMatchesTheServer` (the digest of the stored, approved tool equals the server's); `cmd/migrate` rewrap drill with a secrets envelope. |
| `make test-e2e` | `test/e2e/secrets_test.go`: request → `-32042` → entry page → retry with the handle → the fake upstream gets the plaintext and the agent's result is scrubbed; the deny path; go-sdk clients get `-32042` at once. |
| `make test-security` | `test/security/secrets_test.go`: handles bound to owner, harness and target; entry page hardening (sign-in, CSRF, framing, guessing, uniform 404); read-only tokens cannot request; approval payloads hold only the handle, and a sweep of logs, audit, ledger and database finds no plaintext. |
