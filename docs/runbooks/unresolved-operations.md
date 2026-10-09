# Unresolved operations

Triage of a write the vendor did not confirm and the reconciler could not settle. Background: README "Write ledger", decision `dovthftx`, `enlsy40f`. Checked against `internal/ledger/{reconcile.go,notifier.go,portal.go,doc.go}`, `internal/jobs/{reconciler.go,stale_sweep.go}`, `internal/store/migrations/00007_admin_views.sql` (`admin_ledger_operations`, `admin_audit_events`), `internal/audit/handlers.go`.

## When to use

- Alert `MCPGatewayUnresolvedOperations` (any `ledger_operations_total{state="unresolved"}` increase in the window), or the log line `event=ledger.unresolved` (`ledger.LogNotifier`, the only notifier wired in `cmd/gateway/ledger.go`: there is no Slack/portal push for unresolved writes in v1; the row on `/operations` is the user-facing signal).
- A user asks whether a write happened: `/operations` shows it as **unresolved** with the hint *verify in the app*.

## What the states mean (`ledger_operations.state`, `internal/store/models.go`)

| State | Meaning | Who moves it on |
|---|---|---|
| `in_progress` | the row was inserted before the vendor call; the call is running on some replica | the call's `Finish`; or `ledger.sweep_stale` (every 30 s) turns rows older than `GATEWAY_LEDGER_STALE_AFTER` (2 m) into `unknown` with `error_code=stale`; a draining replica marks its own as `unknown` / `shutdown` |
| `succeeded` | the vendor confirmed; `result_ids` holds identifiers/URLs only | final |
| `failed` | the vendor refused (4xx classes) or the connector reported a known failure; `error_code` is the class | final; the idempotency key is free again |
| `unknown` | the outcome is open; `error_code` says why: `outcome_unknown` (`connectors.ErrOutcomeUnknown` from the connector), `timeout`, `canceled`, `connection_reset`, `stale`, `shutdown` | `ledger.reconcile` (every minute, one replica): calls the tool's `Reconcile.Check` with the operation id and resource identity; `found` → `succeeded`, `not_found` → `failed`, error → retry after 2^(n−1) minutes |
| `unresolved` | the reconciler gave up: `error_code` = `not_reconcilable` (the tool declares `Reconcile{Kind: none}` or is not registered), `reconcile_exhausted` (`GATEWAY_LEDGER_MAX_RECONCILE_ATTEMPTS`, 6) or `reconcile_expired` (`GATEWAY_LEDGER_MAX_RECONCILE_AGE`, 24 h) | **a person**; the block on the idempotency key is lifted so a deliberate retry is a new operation |

While an operation is `in_progress` or `unknown`, the same write (same user, account, tool, canonical arguments inside the window; or the same approval) answers `-32033 pending verification` with `error.data.operation_id`. `failed` and `unresolved` do not block.

Which tools can never be reconciled (always `not_reconcilable` after an unknown outcome): every write declared `Reconcile{Kind: none}` — in v1 `fake.post_note`, Slack `post_message` / `reply_in_thread` unless `marker_reconcile=true` is set on the Slack vendor app, `jira.transition_issue`, Google `docs.append_text` / `sheets.append_rows`, Microsoft Teams `post_channel_message` (see each `docs/connectors/*.md` "Reconciliation" table). Those go straight to `unresolved` on the next reconciler run.

## Preconditions

- Admin role in the portal (for `/admin/audit`); `JOBS_URL` and `psql` for the views; the operation id (from the alert's time window, the log line or the user).
- Never ask the user for, and never look up, the arguments of the write: they are not stored (only `digest` and the resource identity). The vendor's own UI / API is the source of truth.

## Steps

1. **List what is unresolved** (metadata only):

   ```bash
   psql "$JOBS_URL" -c "
     SELECT id, user_id, tool, error_code, reconcile_attempts, created_at, finished_at, result_ids
     FROM admin_ledger_operations
     WHERE state = 'unresolved' AND finished_at > now() - interval '24 hours'
     ORDER BY finished_at DESC;"
   ```

   Also `state = 'unknown'` ordered by `created_at`: those are still being retried; many of them with the same `tool` and recent `created_at` is a vendor outage or an expired vendor app secret ([vendor-app-secret-rotation.md](vendor-app-secret-rotation.md)) rather than individual problems.

2. **Find the context in the audit trail.** In the portal, `/admin/audit?tool=<app.tool>&outcome=unresolved&since=<date>` (admins; filters `tool`, `decision`, `outcome`, `since`, `until`, `user_id`, `page`; `internal/audit/handlers.go` `parseQuery`) lists the verdict events the reconciler recorded (`outcome=unresolved`, error class `not_reconcilable` / `reconcile_exhausted` / `reconcile_expired`, `operation_id` set). The original `tool_call` row (same `operation_id`; its `outcome` is `failed` with error class `tool_error`, because the audit stage only knows the call returned an error — `internal/mcp/stages.go`; the ledger row's `error_code` is what says `outcome_unknown`, `timeout`, `canceled` or `connection_reset`, `internal/mcp/pipeline_ledger.go` `classifyOutcome`) carries the **resource identity** (repo, channel, site, folder …), the account label and the request id. The same from SQL:

   ```bash
   psql "$JOBS_URL" -c "
     SELECT created_at, event_type, outcome, decision, tool, account_label, resource, details->>'error_class' AS class, details->>'request_id' AS request_id
     FROM admin_audit_events WHERE operation_id = '<operation id>' ORDER BY created_at;"
   ```

3. **Check the app.** With the resource identity and the operation id, look in the vendor for the side effect. Marker-reconciled writes carry the operation id in what they created (GitHub: HTML comment `<!-- mcp-gateway op:<id> -->` in the body; Atlassian: a visible `mcp-gateway op:<id>` paragraph; Google Drive/Docs creates: `appProperties[mcp-gateway-op]`; Slack with `marker_reconcile`: message metadata), so a search for the id in the vendor settles it even when the reconciler could not (search indexes lag). For `none` tools there is no marker: look at the resource (the Jira issue's status, the channel's recent messages, the document's tail) around `created_at`.

   The reconciler's own reason is in the logs: `kubectl -n $NS logs deploy/$RELEASE --since=24h | grep -E 'ledger\.(reconcile_retry|reconcile_failed|unresolved)' | grep <operation id>` (`vendor_error`/`error` fields are class-level, redacted).

4. **Tell the user** (what they need, nothing more):
   - *The write took effect*: "Your `<tool>` write at `<time>` did go through (`<link or id from the app>`). Nothing to redo; `/operations` will keep showing it as unresolved, that is expected." Optionally close it in the ledger (step 5).
   - *It did not*: "Your `<tool>` write at `<time>` did not reach `<app>`. You can run it again; the gateway treats it as a new write (it will ask for approval again if the tool needs one)."
   - *Cannot tell*: say so, and ask them to check the resource themselves before retrying; a retry of a marker-reconciled tool is safe to verify afterwards by the new operation id.

5. **(Optional) close the row.** There is no admin page or endpoint to settle an unresolved operation; v1 leaves it as a record. If the team wants the ledger to reflect what you found, record it in the change log and update the row through the jobs role (the audit trail already has the verdict event; this does not add one):

   ```sql
   UPDATE ledger_operations SET state = 'succeeded', result_ids = '{"id": "<vendor id>"}'::jsonb, updated_at = now()
     WHERE id = '<operation id>' AND state = 'unresolved';   -- or state = 'failed'
   ```

   Keep this rare; the point of `unresolved` is that a human looked.

## Verification

- The user confirms the outcome matches what they see in the app.
- `psql "$JOBS_URL" -c "SELECT state, count(*) FROM admin_ledger_operations WHERE created_at > now() - interval '1 day' GROUP BY 1"` shows `unknown` draining (not growing) after the next reconciler runs; `ledger_operations_total{state="unresolved"}` stops increasing.
- If several users were hit by the same cause, `connection_refresh_failures_total` / `vendor_rate_limited_total` and the vendor status page explain it; fix the cause ([vendor-app-secret-rotation.md](vendor-app-secret-rotation.md)) before telling people to retry.

## Rollback

Nothing to roll back: triage is read-only except step 5, which is reversible by the inverse `UPDATE` (state back to `unresolved`). Never delete ledger rows; approvals and audit rows reference them.

## Tuning (pilot)

`GATEWAY_LEDGER_MAX_RECONCILE_ATTEMPTS` (6 → attempts at 1, 2, 4, 8, 16, 32 minutes ≈ one hour) and `GATEWAY_LEDGER_MAX_RECONCILE_AGE` (24 h) bound how long an `unknown` write blocks duplicates; `GATEWAY_LEDGER_STALE_AFTER` (2 m) must stay above the longest tool call (connector timeouts are 30 s by default). Lower attempts if users complain about `-32033` on legitimate retries; raise the age only if a vendor's search index needs longer to show the marker. Record changes in `docs/pilot-checklist.md`.
