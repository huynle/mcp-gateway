# Audit, logging and metrics

`internal/audit` and `internal/observability` are the one way every module audits, logs and measures. They are built so that secrets and content *cannot* reach a sink: the audit event type has no field for arguments or content, the logger redacts every record before it is written, and the metric helpers accept only fixed vocabularies. Design: Brain plan `36bakiw8` sections 3 (step 9) and 6; decisions `v6piaxdb` (redacted logs, private metrics, no content), `dovthftx` (audit carries resource identity, never arguments; ledger states as metrics), `9z5sdzsm` (WithUser for a user's own rows, WithJobs for admin cross-user reads and system events).

## Wiring in `cmd/gateway/main.go`

```go
log, err := observability.NewLogger(os.Stdout, cfg.LogLevel, cfg.LogFormat) // already redacting
slog.SetDefault(log)

metrics := observability.NewMetrics()
go func() {
    // Private port; "" means GATEWAY_METRICS_ADDR or 127.0.0.1:19090.
    if err := observability.ServeMetrics(ctx, "", metrics.Handler()); err != nil {
        log.Error("metrics server", "error", err) // bind failure: decide whether to abort
    }
}()

var recorder audit.Recorder = audit.NopRecorder{}      // foundation-only mode (no database)
var reader audit.Reader                                 // nil until the store exists
if st != nil {
    sr := audit.NewStoreRecorder(st)                    // *store.Store satisfies audit.Scopes
    recorder, reader = sr, sr
}

mux := http.NewServeMux()
mux.Handle("GET /healthz", observability.Liveness())
mux.Handle("GET /readyz", readiness)
// who is supplied by the portal/identity module: session -> (userID, isAdmin).
if reader != nil {
    mux.Handle("GET /activity", audit.ActivityHandler(reader, who))
    mux.Handle("GET /admin/audit", audit.AdminSearchHandler(reader, who))
}

// Order matters: the metrics middleware must wrap the mux directly so it can
// read the matched route pattern; RequestID goes outside it.
handler := observability.RequestID(metrics.HTTPMiddleware(mux))
srv := server.New(handler, cfg.DrainTimeout, log)
```

Pass `metrics` and `recorder` to the modules that need them (identity, tokens, policy, approvals, ledger, connections, connectors). Nothing else needs the registry.

### Environment variables (read inside the helpers, not by `config`)

| Variable | Default | Used by |
|---|---|---|
| `GATEWAY_METRICS_ADDR` | `127.0.0.1:19090` | `observability.MetricsAddr()` / `ServeMetrics(ctx, "", h)` |
| `GATEWAY_LOG_SALT` | *(unset: random per process)* | `observability.UserAttr`, `HashUserID`, and the redactor's `user_id` hashing |

Set `GATEWAY_LOG_SALT` to a long random string per deployment and keep it with the other secrets. Without it user hashes are still pseudonymous but change on every restart, so lines from different replicas or restarts cannot be correlated.

## Exported API

### `internal/observability`

| Symbol | Purpose |
|---|---|
| `NewLogger(w, level, format)` | Process logger; the returned logger is already wrapped by `RedactingHandler`. There is no unredacted path. |
| `NewRedactingHandler(inner)` | Wrap any other `slog.Handler` by hand. |
| `Redact(s)`, `RedactError(err)` | Apply the value patterns to a string / render an error redacted and truncated to `MaxErrorLen` (200). Use for strings that leave the process by a path other than the logger (audit `ErrorClass`, error pages). |
| `UserAttr(userID)`, `HashUserID(userID)` | Pseudonymous user attribute: key `user`, value HMAC-SHA256(`GATEWAY_LOG_SALT`, id) first 16 hex. |
| `RequestID(next)` | Middleware: accept incoming `X-Request-Id` only if it matches `^[A-Za-z0-9._-]{8,64}$`, otherwise generate 32 hex; put it in the context and echo it in the response. |
| `RequestIDFromContext(ctx)`, `WithRequestID(ctx, id)`, `RequestIDAttr(ctx)` | Context helpers and the `request_id` log attribute. |
| `NewMetrics()`, `(*Metrics).Handler()`, `(*Metrics).Registry()` | Private Prometheus registry (no default collectors) and its scrape handler. |
| `(*Metrics).HTTPMiddleware(next)` | Records `http_request_duration_seconds` labelled by the `ServeMux` pattern (`GET /things/{id}`), never the raw path; `unmatched` for 404s. Preserves `http.ResponseController` (Flush) for streaming handlers. |
| Typed helpers | `ObserveHTTP(route, method, status, d)`, `AuthFailure(reason)`, `PolicyDecision(decision)`, `Approval(state)`, `LedgerOperation(state)`, `ConnectionRefreshFailure(app)`, `VendorRateLimited(app)`. |
| `ServeMetrics(ctx, addr, handler)` | Serves `/metrics` on a separate listener until ctx is cancelled; returns bind errors immediately. |
| `MetricsAddr()`, `EnvMetricsAddr`, `DefaultMetricsAddr`, `EnvLogSalt` | Env plumbing. |

### `internal/audit`

| Symbol | Purpose |
|---|---|
| `Event` | Exactly: `Time, UserID, TokenID, Tool, AccountID, AccountLabel, ResourceIdentity map[string]string, Decision, PolicyVersion, ApprovalID, OperationID, Outcome, Latency, RequestID, ErrorClass`. `event_test.go` fails if the set changes or a field named like arguments/args/content/body/payload/... appears. |
| `(*Event).Normalize()` | Caps `ResourceIdentity` to `MaxResourceKeys` (8) entries, `MaxResourceValueLen` (128) bytes per value, `MaxResourceKeyLen` (32) per key; fills `Time`. |
| `Recorder` | `Record(ctx, Event) error`. |
| `Reader` | `ListForUser(ctx, userID, Filter, Page)` and `AdminSearch(ctx, Filter, Page)` returning `[]Record` (`ID`, `EventType` + `Event`). |
| `NewStoreRecorder(st)` | Store-backed `Recorder` + `Reader`. Events with a `UserID` insert through `WithUser` (RLS proves the row is that user's); events without one (failed auth, jobs) through `WithJobs`. `ListForUser` reads through `WithUser` and ignores `Filter.UserID`; `AdminSearch` reads the `admin_audit_events` view through `WithJobs`. |
| `NopRecorder` | Discards; foundation-only mode and tests. |
| `Identity` | `func(*http.Request) (userID string, isAdmin bool)`; the portal supplies it. |
| `ActivityHandler(reader, who)` | "My activity": 401 when not signed in; always the session user's rows, whatever the query says. |
| `AdminSearchHandler(reader, who)` | 401 / 403 / metadata of all users with a `user_id` filter. |
| `Filter`, `Page`, `DefaultPageSize` (50), `MaxPageSize` (200) | Query parameters `tool`, `decision`, `outcome`, `since`, `until` (RFC 3339 or `YYYY-MM-DD`), `page` (1-based), `user_id` (admin only, uuid). |

`store.ListAuditEvents(ctx, q, admin, store.AuditFilter, store.AuditPage)` in `internal/store/repo_audit_query.go` is the query behind both readers; it is package-level so the `AuditRepository` interface did not need to change.

## What is and is not logged

**Never:** generated tokens (`mgw_...`), OAuth codes and tokens (JWTs, bearer/basic headers, refresh/access/id tokens, client secrets), vendor tokens (Slack `xox*`, GitHub `ghp_`/`gho_`/`github_pat_`, Google `AIza...`), PEM blocks, cookies, API keys, private keys, signing secrets, passwords, tool arguments, request/response bodies, content or payloads. Raw user IDs are never written as-is under `user`/`user_id`/`*_user_id` keys.

**Always safe:** route patterns, methods, status codes, request IDs, tool names, account labels, decision/outcome/state words, error classes, token/approval/operation/policy IDs (uuids), hashed user IDs.

The `RedactingHandler` enforces this in three layers, applied to the message, every attribute, every group and every value reachable through `slog.Any` (maps, slices, structs via exported fields and `json` tags, pointers, `error` chains incl. `fmt.Errorf("%w")` and `errors.Join`, `fmt.Stringer`, `slog.LogValuer`, `[]byte`):

1. **Key denylist** (case-insensitive; `-`, `_`, `.` and spaces ignored; also as suffix, e.g. `github_token`, `x-api-key`, `request_body`): `token, secret, password, passwd, code, authorization, cookie, set-cookie, arguments, args, body, content, payload, refresh_token, access_token, id_token, client_secret, private_key, signing_secret, api_key`. The whole value is replaced with `[REDACTED]`, whatever its type. `code` matches exactly only, so `error_code` and `status_code` survive.
2. **Value patterns** on every string: `mgw_…`, JWT shape, `Bearer …` / `Basic …`, `xox[abopsre]-…`, `gh[posur]_…`, `github_pat_…`, `AIza…`, PEM blocks (terminated or not), `?code=…&token=…`-style query parameters, `key=value` / `key: value` / `"key":"value"` where key is a secret-ish name.
3. **Shape rules:** values under `user`, `user_id`, `*_user_id` are hashed (same transform as `UserAttr`, idempotent); `error` values are rendered with `Error()`, redacted and truncated to 200 bytes; nesting deeper than 8 levels is cut off; structs are walked by exported fields, so a `String()` or `MarshalJSON()` method can never reintroduce a secret.

`redact_test.go` runs a 51-case adversarial corpus through JSON and text sinks and asserts zero leaks; a control run through a plain handler shows 49/51 cases leak without the redactor.

## Audit events

One row per tool call (`event_type = tool_call`), per user action without a tool (`user`: token created, connection revoked) and per system event (`system`: failed authentication, job runs). The columns are the `Event` fields; `RequestID` and `ErrorClass` live in `details` and nothing else is ever written there. `AccountID` is the connection ID, `PolicyVersion` the `policy_versions.id`; both must be uuids. `AccountLabel` is `company` or `personal`. `ErrorClass` is redacted and cut to 64 bytes on write: pass a classification (`token_expired`, `vendor_rate_limited`, `timeout`), never vendor text. `created_at` is set by the database at insert; `Event.Time` is informational on write and carries `created_at` on read.

Users see their own rows (`/activity`), admins see metadata for everyone (`/admin/audit`). Retention purge (`AuditRepository.Purge`, one year by default) belongs to the jobs module.

## Metric catalogue

All on the private registry; no user, token, account or request identifiers as labels (`TestMetricsHaveNoUserIdentifyingLabels` enforces the vocabulary).

| Metric | Type | Labels | Incremented by |
|---|---|---|---|
| `http_request_duration_seconds` | histogram | `route` (mux pattern), `method`, `status` | `HTTPMiddleware` |
| `auth_failures_total` | counter | `reason` | tokens (`malformed`, `unknown`, `revoked`, `expired`, `user_disabled`, `signin_stale`, `rate_limited`) / authserver later |
| `policy_decisions_total` | counter | `decision` (`allow`, `deny`, `confirm`) | policy |
| `approvals_total` | counter | `state` (`pending`, `approved`, `denied`, `consumed`, `expired`) | approvals |
| `ledger_operations_total` | counter | `state` (`in_progress`, `succeeded`, `failed`, `unknown`, `unresolved`) | ledger / reconciler |
| `connection_refresh_failures_total` | counter | `app` | connections |
| `vendor_rate_limited_total` | counter | `app` | connectors (429 / Retry-After) |
| `tunnel_relay_requests_total` | counter | `side` (`forward`, `serve`), `result` (fixed words, see docs/tunnel.md) | tunnel relay (only when `GATEWAY_RELAY_*` is set) |

Scrape `http://127.0.0.1:19090/metrics` inside the pod or via the Helm-defined private port; never expose it on the public listener.

## Testing

- `make test`: unit tests incl. the redaction corpus, the `Event` field guard, metrics label vocabulary and handler tests with a fake reader.
- `make test-integration` with `GATEWAY_TEST_DATABASE_URL` set to a superuser URL: `internal/audit/integration_test.go` creates and migrates its own database `gateway_audit` on the same server (so it cannot race with the store package's table resets), then proves two users see only their own rows, that a filter cannot widen a user's view, that RLS rejects an event filed under another user, and that admin search sees every user with filters and paging.
