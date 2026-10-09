# Harness conformance checklist

What a real MCP harness must see from the gateway, scenario by scenario, against the local Compose stack with the fake connector. Two kinds of rows:

- **automated: pass** — proven by `make test-e2e` (`test/e2e`, the safety-core gate: the whole gateway in-process over PostgreSQL, driven by the official Go SDK client; Brain task `sougju69`, decision `bt8ukyrd`). CI runs it on every push (`.github/workflows/ci.yml`, job *end-to-end gate*).
- **not yet run** — needs a person at the keyboard with OpenCode or Claude Code. The exact commands and the expected result are given; tick the row and note the harness version when you run it.

The JSON-RPC codes a harness sees (decision `xi9gyo82`; the gateway's own block, clear of the go-sdk's reserved `-32001..-32005`): `-32602` unknown/hidden tool or bad injected argument, `-32029` rate limited, `-32030` denied by policy (also approval mismatch / used / denied / expired), `-32031` no connected account, `-32032` approval required, `-32033` pending verification, `-32034` unauthenticated.

## Setup (both harnesses)

```bash
make compose-up                      # PostgreSQL, dex, migrations, dev key file, gateway on :18080
curl -fsS localhost:18080/readyz     # database, schema, key-provider all "ok"
# 1. browser: http://localhost:18080 -> "Continue with Local dex" -> dev@example.com / password (admin)
# 2. /admin/roles/member: fake.* = allow, fake.create_item = confirm, save
#    (for the deny row, add a conditional rule: fake.get_item deny when id prefix "secret-")
# 3. /tokens -> New token "harness" -> copy the one-time mgw_... value
export T=mgw_...
```

Scripted alternative for steps 1–3 and a full curl walk-through of the write path (the Compose smoke, verified): `deploy/smoke/fake-connector-smoke.sh`.

**OpenCode** (`opencode.json` in a scratch directory, then `opencode` in it):

```jsonc
{ "$schema": "https://opencode.ai/config.json",
  "mcp": { "gateway": { "type": "remote", "url": "http://localhost:18080/mcp", "enabled": true,
                        "headers": { "Authorization": "Bearer mgw_<id>_<secret>" } } } }
```

**Claude Code** (in a scratch directory):

```bash
claude mcp add --transport http gateway http://localhost:18080/mcp --header "Authorization: Bearer $T"
claude mcp list            # gateway: connected
claude                     # interactive; or: claude -p "<prompt>" --allowedTools "mcp__gateway__*"
```

Clean up afterwards: `claude mcp remove gateway`, delete the scratch `opencode.json`, revoke the token on `/tokens`, `make compose-down`.

## Scenarios

| # | Scenario | Prompt / command | Expected | SDK (`make test-e2e`) | OpenCode | Claude Code |
|---|---|---|---|---|---|---|
| 1 | **list**: the harness discovers the tools the role allows | OpenCode: `/mcp` or ask "which gateway tools do you have?". Claude Code: `/mcp` → gateway → view tools | Exactly the six `fake.*` tools (`list_accounts`, `list_items`, `get_item`, `create_item`, `post_note`, `flaky_write`); every schema has the optional `account` and `approval_id` strings | automated: pass (`TestE2EReadsVisibilityAndDeny`) | not yet run | not yet run |
| 2 | **read**: an allowed read runs and the account resolves itself | "List my fake accounts, then list the fake items" | `list_accounts` returns one company account (a UUID, label `company`, "Fake company account"); `list_items` returns `{"items":[]}` (empty on a fresh stack) with no account argument needed | automated: pass (`TestE2EReadsVisibilityAndDeny`) | not yet run | not yet run |
| 3 | **confirm + approve + retry**: a confirmed write waits, then runs once with the stored arguments | "Create a fake item with id demo-1 and name Demo" → while the harness waits (≤ 30 s), approve it at http://localhost:18080/approvals; if it times out, approve and tell the harness "retry with the approval id" | Either the call completes during the wait (one round trip), or the harness reports `-32032 approval required: ask the user to approve approval <id> ...`, and the retry with `approval_id=<id>` creates the item with the **originally** stored name even if the model reworded it. A second retry with the same id: `-32030 approval already used`. `/operations` lists `fake.create_item` succeeded; `/activity` shows the call with the approval id | automated: pass (`TestE2EConfirmPortalApproveRetry`, `TestE2EConfirmSlackApproveRetry`, `TestE2EBoundedWait`, `TestE2EDoubleApprovalUse8Way`) | not yet run | not yet run |
| 4 | **deny**: a conditional deny refuses by resource identity | With the conditional rule from the setup: "Get the fake item with id secret-1" | `-32030 denied by policy`; `/activity` shows `fake.get_item`, resource `id=secret-1`, decision deny, outcome denied | automated: pass (`TestE2EReadsVisibilityAndDeny`) | not yet run | not yet run |
| 5 | **hidden**: a hidden tool is absent and a call to it is indistinguishable from a nonexistent one | On `/admin/roles/member` set `fake.get_item` = hidden, save, reconnect the harness (new `tools/list`); then "Get the fake item with id it-1" | `get_item` is gone from the tool list; if the model still calls it, the answer is `-32602 unknown tool "fake.get_item"`, exactly what `fake.get_item_v2` would get | automated: pass (`TestE2EReadsVisibilityAndDeny`, byte comparison on the wire) | not yet run | not yet run |
| 6 | **duplicate write**: the same unconfirmed write inside 24 h replays | "Post the fake note LGTM" twice | The second answer is `{"_ledger":"replayed","operation_id":...,"result":{"id":"note-..."}}` with the first note's id; only one note exists | automated: pass (`TestE2EDuplicateWritesReplayAndWindow`) | not yet run | not yet run |
| 7 | **no token / revoked token** | Revoke the token on `/tokens`, then any prompt that uses a tool | HTTP 401 with `WWW-Authenticate: Bearer ... error="invalid_token"`; the harness shows the gateway as disconnected or failing to authenticate | automated: pass (`TestE2ERevokedTokenAndAnonymous`) | not yet run | not yet run |

Rows that only the automated gate covers (no harness interaction needed, listed for completeness): Slack approve via a signed button press (`TestE2EConfirmSlackApproveRetry`), unknown outcome → reconciled / unresolved + notified (`TestE2EUnknownOutcomes`), crash mid-call → stale sweep → unknown → reconciled (`TestE2ECrashMidCall`), cross-user isolation with alice's token naming bob's account / approval / operation, personal-account refusal, read-only tokens, `/activity` vs `/admin/audit`, and the redaction scan of the captured gateway log and every audit row (`TestE2ECrossUserAndScope` + the per-world `scanForLeaks` cleanup).

## Recording a manual run

Replace "not yet run" with `pass <harness> <version> <date>` (or `fail` plus a Brain quirk with what the harness showed). Harness-specific findings worth recording: how each harness renders `error.data.instructions` for `-32032`, whether it re-lists tools after a role change without a restart, and whether it retries with `approval_id` on its own when told to.
