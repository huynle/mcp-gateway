# Audit export

Getting audit rows out of the gateway for an investigation, a compliance request or a user's data request. Background: [`docs/observability.md`](../observability.md) "Audit events", decision `v6piaxdb` (admins see metadata, never content). Checked against `internal/audit/{handlers.go,event.go,recorder.go,purge.go}`, `internal/store/repo_audit_query.go`, `internal/store/migrations/{00006_audit_keys_jobs.sql,00007_admin_views.sql}`.

## What exists, and what does not

- **`/admin/audit`** (`audit.AdminSearchHandler`): an HTML page for admins over the `admin_audit_events` view with filters `tool`, `decision`, `outcome`, `since`, `until` (RFC 3339 or `YYYY-MM-DD`), `user_id` (uuid) and `page` (1-based, **50 rows per page**, `audit.DefaultPageSize`; there is no page-size parameter), newest first. `/activity` is the same for a user's own rows.
- **There is no export endpoint** (no CSV/JSON route, no `Accept` negotiation: `grep -rn "csv\|export" internal/audit internal/portal` finds nothing). Brain draft task **`trpz0p16`** adds `GET /admin/audit/export`. Until then the supported export is the **database-level query against the `admin_audit_events` view** below, run through the `gateway_jobs` role.
- **Self-service export**: a user's own rows (newest 10 000) are part of *Download my data* on My account (`internal/account`, audited `user.data_exported`, once per 10 minutes). For "what did my harness do" or "send me my data" point the user there first; this runbook is for anything wider or longer.
- **Retention**: the `audit.purge` job (daily, one replica) deletes rows older than `GATEWAY_AUDIT_RETENTION` (default `8760h` = 365 days, minimum `720h`) in batches through `app.audit_purge` (the only DELETE the append-only trigger admits); each run that deleted rows leaves a `system` event `action=audit.purged` with the count and cutoff ([observability.md](../observability.md) "Retention purge"). Rows older than the retention are gone: an export for an older period is impossible, so check `SELECT min(created_at) FROM admin_audit_events` before promising one, and export what an investigation needs **before** it ages out (or raise the retention first).
- **Deleted users**: their rows stay (pseudonymous uuid, no name left: the `admin_users` tombstone has `status = deleted` and an empty display name; see [user-offboarding.md](user-offboarding.md) "What delete does"). Joining `admin_users` for names yields `''` for them.

What a row contains (and nothing else — `audit.Event` is reflection-guarded against new fields): `created_at`, `event_type` (`tool_call` | `user` | `system`), `user_id`, `actor_user_id` (the admin for admin actions), `token_id` (generated token id or OAuth refresh family id), `tool`, `connection_id` + `account_label`, `resource` (the connector's resource identity, ≤ 8 keys × 128 bytes: repo, channel, `action=…` for user events), `decision`, `policy_version_id`, `approval_id`, `operation_id`, `outcome`, `latency_ms`, `details` = `{request_id, error_class}` only. **Never** arguments, results, message text, file names beyond what the resource identity carries, or secrets. The view is `security_invoker` and projects exactly those columns.

## Preconditions

- A ticket that names the requester, the purpose, the time range and the recipient; exports contain pseudonymous-enough metadata but still tie people to tools and resources.
- `JOBS_URL` (README conventions) and `psql`; a place to write the file that is not a shared chat.
- For a per-user export you need the user id: `psql "$JOBS_URL" -c "SELECT id, display_name FROM admin_users WHERE display_name ILIKE '%<name>%';"` (display name only; emails are not stored).

## Steps

1. **Scope the query.** Always bound `created_at`; prefer the narrowest filter the ticket allows.

   ```bash
   SINCE='2026-10-01'; UNTIL='2026-10-09'; OUT=audit-$SINCE-$UNTIL.csv
   psql "$JOBS_URL" -v ON_ERROR_STOP=1 -c "\copy (
     SELECT created_at, event_type, user_id, actor_user_id, token_id, tool, connection_id, account_label,
            resource, decision, policy_version_id, approval_id, operation_id, outcome, latency_ms,
            details->>'request_id' AS request_id, details->>'error_class' AS error_class
     FROM admin_audit_events
     WHERE created_at >= '$SINCE' AND created_at < '$UNTIL'
       -- AND user_id = '<uuid>'
       -- AND tool LIKE 'github.%'
       -- AND outcome = 'denied'
     ORDER BY created_at, id
   ) TO '$OUT' WITH (FORMAT csv, HEADER true)"
   wc -l $OUT
   ```

   JSON lines instead of CSV: replace the `\copy ... TO` with `-At -c "SELECT row_to_json(e) FROM (SELECT ... ) e" > $OUT`.

2. **Join the names the reader needs**, without widening what is exported: `admin_users (id, display_name, status)` for user ids, `admin_tokens (id, user_id, name, read_only, scope, expires_at, revoked_at)` for `token_id`, `admin_connections (id, display_name, label, status)` for `connection_id`, `policy_versions (id, version_hash, created_at, created_by)` for the policy in force. Do not join `tokens`, `connection_secrets`, `vendor_apps` base tables.

3. **Check the file before it leaves** ([incident-redaction-check.md](incident-redaction-check.md) patterns): `grep -cE 'mgw_[A-Za-z0-9]{8}_[A-Za-z0-9]{43}|xox[abopsre]-|gh[posur]_|github_pat_|eyJ[A-Za-z0-9_-]+\.eyJ|AIza' $OUT` must print `0`. The schema makes a hit impossible, but the check is cheap and the ticket should say it was done.

4. **Hand over** through the ticket's agreed channel; record the query (filters, range), row count and recipient in the ticket. Delete the local file when the ticket closes.

5. **Record the export itself.** Until `trpz0p16` writes an audit event for exports, add a note to the ticket; there is no gateway-side trace of a read through `psql`.

## Verification

- The row count matches `/admin/audit` for the same filters (page through, or `SELECT count(*)` with the same `WHERE`).
- The export opens as CSV with 17 columns and `created_at` in UTC (`timestamptz` rendered by psql in the session time zone: add `-c "SET TIME ZONE 'UTC'"` first if the reader expects UTC).
- No match from the step-3 grep.

## Rollback

Nothing changes in the database (the view is read-only for `gateway_jobs`; the trigger blocks `UPDATE` for everyone and `DELETE` without the purge flag). If a file was sent to the wrong recipient, treat it as an incident: the rows name users, tools and resources.

## Notes for the user-facing case

A coworker asking "what did my harness do last week" needs no export: `/activity` shows their own rows with the same filters. A manager asking about someone else's activity goes through the admin page or this runbook, with the ticket.
