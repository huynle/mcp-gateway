# Pilot checklist

A pilot with a few coworkers before the gateway is opened to the whole team (Brain plan `36bakiw8` section 9 step "pilot", task `pn4voyen`). It exists to find out what the docs and defaults got wrong while the blast radius is small. Do not open to the team before sign-off (section 5).

## 1. Entry criteria

- [ ] Staging is up from `deploy/helm/values-staging.example.yaml` with the staging vendor apps, and the real-harness conformance rows in [`docs/conformance.md`](conformance.md) are ticked for OpenCode and Claude Code (Brain task `6a5khoph`; draft `5yosafvz`).
- [ ] Production is deployed per [`docs/deploy.md`](deploy.md) "Production": 3 replicas, Vault, production IdP client, production vendor apps entered on `/admin/vendor-apps`, alerts firing into a channel someone reads.
- [ ] Each runbook in [`docs/runbooks/`](runbooks/README.md) drilled once on staging; **deploy-and-rollback** (an upgrade with a migration, then a rollback with `migrate down-to`) and **key-rotation** (transit rotate; note that re-wrap is a known gap, `nsyw7xml`) at minimum. Drill notes recorded in the Brain task.
- [ ] Backups: a production database restore rehearsed; the restore time is known.
- [ ] Roles: `/admin/roles` has a pilot role with reads **allow**, writes **confirm**, personal accounts **confirm_writes** (or **deny**) per app; the default role grants nothing. Pilot users are assigned the pilot role on `/admin/users`.
- [ ] 3–6 pilot users across at least two harnesses (OpenCode with a token, Claude Code or Claude Desktop with OAuth) and at least three vendors between them; one of them has a company Slack connection (approval DMs).
- [ ] A feedback channel (Slack channel or form) and a weekly 20-minute check-in on the calendar; one owner for triage.

## 2. What pilot users do (and what you watch)

Give each user [`docs/user-guide.md`](user-guide.md) and nothing else: **the docs are under test**. Ask them to:

1. Sign in, mint a token or connect via OAuth, get `tools/list` to show tools — **without help**. Record where they got stuck.
2. Connect a company account and, if the role allows, a personal one; note the vendor consent screens that confused them (Google's unverified-app warning, GitHub App install, Slack admin approval).
3. Use reads for a week in their normal work.
4. Do at least five confirmed writes: approve in the portal, approve from Slack, let one expire, deny one, retry one with `approval_id`.
5. Trigger the error table in the user guide at least once each: a hidden tool, a denied resource, a missing scope (*Grant more access*), a rate limit, a disconnected account.
6. Report every message they did not understand, verbatim (the harness's rendering of `-32032` and `-32035` especially).

## 3. What to collect

Per user, per week (a short form; no tool arguments or content):

| Collect | Where it comes from |
|---|---|
| Setup time and the step they got stuck on | user report |
| Which harness, version, token vs OAuth | user report; `/harnesses` and `/tokens` show the gateway side |
| Calls per day, by tool and outcome; denied/hidden calls they expected to work | `/admin/audit?user_id=…` (metadata), `policy_decisions_total{decision}` |
| Approvals: how many completed inside the 30 s wait vs needed a retry; how many expired; how long a decision took | `approvals_total{state}` (`waited_through` vs `created`), `/approvals/history`, `admin_approvals` (`created_at` → `decided_at`) |
| Replays and pending-verification answers they hit (`-32033`, `_ledger: replayed`) and whether they were right | `admin_ledger_operations` (`state`, `idempotency_key` reuse), user report |
| Unknown/unresolved writes and what they turned out to be | [`docs/runbooks/unresolved-operations.md`](runbooks/unresolved-operations.md) triage notes |
| Reconnects (`needs_reconnect`) per vendor and why | `connection_refresh_failures_total{app}`, `connections.refresh_failed` log lines (class only) |
| Vendor rate limits hit | `vendor_rate_limited_total{app}`, `-32029` reports |
| Messages/errors quoted verbatim that were unclear | user report |
| Anything that felt like the gateway *should* have asked, or asked when it should not | user report (policy tuning input) |
| Alert noise: alerts fired, true/false positives | the alert channel |

Never collect what people typed or what tools returned; the gateway does not store it and the pilot must not either.

## 4. Defaults to tune (and the evidence that says so)

All live in Helm values (`gateway.*`), env names in brackets. Change one at a time, record the before/after and why in the Brain plan's open items.

| Default | Value | Raise when | Lower when |
|---|---|---|---|
| Approval TTL (`approvals.ttl`, `GATEWAY_APPROVAL_TTL`) | 15m | approvals expire before people see the DM/portal (expired ≫ denied in `approvals_total`) | people approve stale requests they no longer remember |
| Bounded wait (`approvals.wait`, `GATEWAY_APPROVAL_WAIT`, max 5m) | 30s | most approvals are decided within a minute and harnesses tolerate the wait (check each harness's request timeout first: Claude Code / OpenCode defaults are above 30 s but not unlimited) | harnesses time out and show nothing; `waited_through` is near zero anyway |
| Idempotency window (`ledger.idempotencyWindow`, `GATEWAY_LEDGER_IDEMPOTENCY_WINDOW`) | 24h | duplicates slip through after the window in normal retries (rare) | users legitimately repeat the same write the same day (daily reports, repeated reactions) and get `_ledger: replayed` |
| Reconcile limits (`ledger.maxReconcileAttempts` 6, `ledger.maxReconcileAge` 24h) | ≈ 1 h of attempts | a vendor's search index needs longer to show markers (unresolved that later prove `found`) | `-32033` blocks real retries for too long |
| Stale after (`ledger.staleAfter`) | 2m | tool calls legitimately exceed 2 minutes (large PR file lists) → false `stale` | never below the longest connector timeout (30 s) |
| Rate limits (`rateLimits.userPerMinute` 60, `appPerMinute` 600) | | `-32029` without any vendor 429 (`vendor_rate_limited_total` flat) | the vendor rate-limits the gateway (`MCPGatewayVendorRateLimited`) |
| Sign-in freshness (`tokens.signinMaxAge`) | 30d | `signin_stale` failures annoy active users who rarely open the portal (consider 45d; offboarding relies on it, do not exceed 60d) | the company's leaver process is slow and relies on this cutoff |
| Token max expiry (fixed at 90 days, default 30 in `/tokens`) | | not tunable in v1 | |
| Audit retention | 1 year by design; **no purge job yet** (`mjdzepbx`) | | decide the retention before the job lands; export needs ([`runbooks/audit-export.md`](runbooks/audit-export.md)) |
| OAuth refresh TTL / client idle (`oauth.refreshTokenTTL` 30d, `oauth.clientIdle` 30d) | | harnesses used less than monthly must re-register and sign in again (complaints) | — |
| Alert thresholds (`metrics.prometheusRule.*`) | see values | false positives (auth spike from one misconfigured harness; refresh failures during a vendor outage) | an incident was missed |

Per-role tuning is in the portal, not values: which tools are `confirm` vs `allow`, conditional rules by resource (`repo` prefix, `channel`), personal-account allowance per app. Expect to loosen reads and keep writes on confirm.

## 5. Sign-off criteria

Open the gateway to the team only when all of these hold for the last pilot week:

- [ ] Every pilot user completed harness setup and account connection from the user guide alone; every point of confusion found is fixed in the docs (or in the message the gateway sends).
- [ ] No unresolved write whose cause was a gateway defect; every unresolved operation was triaged with the runbook and the user told.
- [ ] No secret, argument or content found in logs or audit rows ([`runbooks/incident-redaction-check.md`](runbooks/incident-redaction-check.md) run on a week of production logs).
- [ ] No cross-user exposure reported or observed (`/admin/audit` review of denied/not-found events naming other users' ids: none unexplained).
- [ ] Approvals: ≥ 90 % of approvals decided inside the TTL; the Slack DM path worked for the user who had it; `approval_id` retries worked in every harness used.
- [ ] Alerts: each production alert either fired for a real reason or was tuned; the on-call person knows the runbooks.
- [ ] Runbooks: each drilled at least once; deltas fixed.
- [ ] Defaults: the tuned values are in the production values file and recorded in Brain plan `36bakiw8` "Open items".
- [ ] The team-wide default role and the per-app personal-account policy are agreed with whoever owns security.
- [ ] Open follow-ups are Brain tasks with owners (at least: `nsyw7xml` re-wrap, `trpz0p16` audit export, `mjdzepbx` audit purge, `fire4u3k` CSP, `jni63atp` test databases, `5yosafvz` conformance run; `6br0isjh` Slack id→name is landed), and none of them is a blocker for the team.

Record the sign-off (date, pilot users count, tuned defaults, open items) as the outcome on Brain task `pn4voyen` and in the plan's open items.
