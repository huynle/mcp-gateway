# Incident redaction check

How to verify that logs and audit rows contain no secrets or app content, before sharing them during an incident, and what to do if something slipped through. Background: [`docs/observability.md`](../observability.md) "What is and is not logged", decision `v6piaxdb`, report `ixu4ai2s` (security review). Checked against `internal/observability/{redact.go,redact_test.go,logger.go}`, `internal/audit/event.go`, `internal/tokens/format.go` (`ScanPattern`), `test/security/{redaction_test.go,world_test.go}` (`scanForLeaks`), `test/e2e/world_test.go`.

## When to use

- Before attaching gateway logs, audit exports or database excerpts to an incident ticket or sending them to a vendor.
- After a suspected leak: a developer logged a new field, a connector relays vendor text, a hostile vendor answer (report `ixu4ai2s` finding 3).
- Alert `MCPGatewayAuthFailureSpike`: you will be reading auth-failure lines and must know what they can and cannot contain.

## What the code guarantees (so you know what to look for)

1. **There is no unredacted logger.** `observability.NewLogger` wraps every handler in `RedactingHandler` (`internal/observability/logger.go`); `slog.SetDefault` makes it the process logger. The handler redacts the message, every attribute, every nested value reachable through `slog.Any` (maps, slices, structs by exported field and `json` tag, pointers, error chains, `Stringer`, `LogValuer`, `[]byte`) in three layers (`redact.go`):
   - **key denylist** (case-insensitive, separators ignored, also as suffix): `token, secret, password, passwd, code (exact), authorization, cookie, set-cookie, arguments, args, body, content, payload, refresh_token, access_token, id_token, client_secret, private_key, signing_secret, api_key` → the whole value becomes `[REDACTED]`;
   - **value patterns** on every string: PEM blocks, `Bearer …`/`Basic …`, `mgw_…`, JWT shape (`eyJ….eyJ…`), Slack `xox[abopsre]-…`, GitHub `gh[posur]_…` / `github_pat_…`, Google `AIza…`, `?code=…&token=…`-style query parameters, `key=value` / `key: value` / `"key":"value"` where the key is secret-ish;
   - **shape rules**: `user`, `user_id`, `*_user_id` values are hashed (HMAC with `GATEWAY_LOG_SALT`, 16 hex), `error` values are rendered, redacted and cut to 200 bytes, nesting deeper than 8 is cut.
2. **Audit rows cannot carry content**: `audit.Event` has exactly 15 fields and `event_test.go` fails the build's tests if a field named like arguments/args/content/body/payload appears; `ResourceIdentity` is capped at 8 keys × 128 bytes and `ErrorClass` at 64 bytes after redaction; `details` holds only `request_id` and `error_class`.
3. **Tests that keep it so**: `internal/observability/redact_test.go` runs a ≥ 30-case adversarial corpus (51 cases at v1) through JSON and text sinks and asserts zero leaks (`TestRedactingHandlerLeaksNothing`), with a control proving the plain handler leaks (`TestRedactionControlLeaksWithoutHandler`); `test/security` `TestSecurityRedactionUnderLoad` fires 50 concurrent calls with a "secret soup" and hostile vendor 5xx/HTML answers and scans MCP answers, audit, ledger, portal and the log; every e2e and security world ends with `scanForLeaks()`, which greps the captured gateway log and every audit row for every secret the world registered (vendor tokens, client secrets, `mgw_` token secrets).
4. **Limits you must know**: the redactor matches *shapes and key names*. A secret with no recognisable shape under a harmless key name (a random hex API key logged as `vendor_ref=…`, a password inside free text) is **not** caught. Connectors therefore relay only class-level vendor errors to the model and the log (finding 3), and new log lines must not carry vendor text.

## Preconditions

- The logs to check (`kubectl -n $NS logs deploy/$RELEASE --since=<window> > gateway.log`, every pod: `-l app.kubernetes.io/instance=$RELEASE --all-containers --prefix`) and/or an audit export ([audit-export.md](audit-export.md)).
- A copy of the project at the deployed tag (for the tests and the patterns).

## Steps

1. **Pattern scan** of whatever is about to leave. The patterns mirror `redact.go` and `tokens.ScanPattern`; a hit on a *redacted* marker is fine, a hit on a real value is not.

   ```bash
   F=gateway.log   # or the audit export
   grep -nE 'mgw_[A-Za-z0-9]{8}_[A-Za-z0-9]{43}' $F                                 # generated token (full form)
   grep -nE '\bxox[abopsre]-[A-Za-z0-9-]+' $F                                         # Slack tokens
   grep -nE '\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{10,}|github_pat_[A-Za-z0-9_]{10,}' $F  # GitHub
   grep -nE '\bAIza[0-9A-Za-z_-]{20,}' $F                                             # Google API keys
   grep -nE '\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}' $F                             # JWTs (access/id tokens)
   grep -niE '\b(bearer|basic) [A-Za-z0-9._~+/=-]{8,}' $F                           # Authorization header values
   grep -nE -- '-----BEGIN [A-Z ]+-----' $F                                           # PEM
   grep -niE '(client_secret|signing_secret|refresh_token|access_token|password)["=: ]+[^"\[ ]{6,}' $F   # key=value with a non-redacted value
   grep -nE '"(arguments|args|body|content|payload)"\s*:' $F                           # argument/content keys (should only ever be [REDACTED])
   grep -c '\[REDACTED\]' $F                                                          # how often the redactor acted (informational)
   ```

   Also look for **raw user ids** (uuids under a `user`/`user_id` key: the redactor hashes them, so a uuid there means a code path bypassed the logger) and for **vendor response text** (HTML tags, stack frames, internal hostnames) in `error` fields.

2. **Audit rows**: on an export, the step-3 grep in [audit-export.md](audit-export.md); additionally `SELECT count(*) FROM admin_audit_events WHERE jsonb_typeof(details) = 'object' AND (details ? 'arguments' OR details ? 'body' OR details ? 'content')` must be `0` (the Event type cannot produce such keys; a non-zero count means a foreign writer).

3. **Run the gates at the deployed tag** when the incident involves a code change or a new connector version, to prove the guarantees still hold there:

   ```bash
   git checkout <deployed tag>
   go test -race -count=1 ./internal/observability/ -run 'Redact'      # corpus + control
   go test -race -count=1 ./internal/audit/ -run 'Event'               # field guard
   export GATEWAY_TEST_DATABASE_URL=...; make test-security            # TestSecurityRedactionUnderLoad + scanForLeaks (needs PostgreSQL)
   make test-e2e                                                       # every e2e world scans for leaks too
   ```

4. **Reproduce the suspected leak as a corpus case** when the scan found something: add the exact shape to `corpus()` in `internal/observability/redact_test.go` (a distinctive fake value, never the real one), watch `TestRedactingHandlerLeaksNothing` fail, then fix (`redact.go` pattern or denylist, or the call site that logged vendor text) and ship a patch release. The fix is not done until the corpus case passes and the security suite is green.

## If a secret was found

1. **Contain**: rotate what leaked — a generated token: revoke it on `/tokens` (or disable the user, [user-offboarding.md](user-offboarding.md)); an OAuth access token: it is bounded by its 1-hour `exp`, revoke the family (`/harnesses` → *Disconnect*, or disable); a vendor user token: the user disconnects and reconnects on `/connections` (disconnect revokes at the vendor where supported); a vendor app secret or the Slack bot token / signing secret: [vendor-app-secret-rotation.md](vendor-app-secret-rotation.md); the Vault token or database password: [key-rotation.md](key-rotation.md).
2. **Purge the copies**: log aggregator retention/deletion for the affected window, the ticket attachments, local files. Audit rows cannot be edited (trigger); if an audit row carried a secret (only possible through a foreign writer), that is an incident of its own.
3. **Fix the cause** (step 4 above) and note the finding in Brain as a `quirk` with the pattern, never the value.
4. **Record** in the incident ticket: what leaked (shape, not value), where, for how long, what was rotated and when, which pattern now catches it.

## Verification

- All step-1 greps print nothing but `[REDACTED]`-bearing lines; the `[REDACTED]` count is non-zero on any log that contains auth or connector activity (the redactor is clearly running).
- Step-3 tests pass at the deployed tag.
- For the alert case: `auth_failures_total{reason}` explains the spike (`unknown`/`malformed` = scanning; `signin_stale` = inactive users; `revoked`/`user_disabled` after an offboarding) and the corresponding `tokens.auth_failed reason=… public_id=…` lines carry only the 8-character public id, never the secret.

## Rollback

Not applicable; the check is read-only. A pattern added to `redact.go` is itself covered by the corpus; if it over-redacts something harmless, add a `TestRedactingHandlerKeepsHarmlessAttributes` case and narrow it.
