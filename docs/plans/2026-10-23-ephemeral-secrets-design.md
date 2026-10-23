# Ephemeral secrets: agents use secrets they cannot read

Status: design agreed 2026-10-23 (user, interactive brainstorm). Not implemented.

## Problem

Agent harnesses sometimes need a password or other secret from the user: an upstream API credential, `sudo` on a
remote box, an SSH passphrase, a database login. Today the only paths are pasting the secret into the chat (it then
lives in the model context, transcripts and provider logs) or editing config files by hand. We want a standard
gateway feature, available to every user, where:

- the user enters the secret on an ephemeral gateway URL, never in the chat;
- the agent can *use* the secret but never *read* it;
- the same mechanism covers secrets for upstream servers and for commands on the user's own machines.

## Core idea

The model only ever holds a **handle** (`sec_…`). The gateway substitutes the plaintext at the last moment, only
for the target the secret is bound to, and scrubs it from results.

"Usable but unreadable" only holds when the code that consumes the secret is fixed. A secret handed to an arbitrary
shell is readable (`echo $PW | base64`). Every secret is therefore bound to **where** it may be used (a server, tool
and argument, or a machine action), not just to the agent.

Approaches considered:

1. **Handle + gateway-side substitution (chosen).** The model never sees the value; policy, audit and approvals
   apply per use; reuses approvals, crypto, the pipeline and machines.
2. **Ephemeral URL that hands the plaintext to the agent once.** Simplest, but the secret enters model context,
   transcripts and provider logs irreversibly. Rejected (possible explicit opt-in later).
3. **Long-lived named secrets vault** (`op://`-style). Same mechanism as 1 with a larger scope; overlaps the existing
   per-user header credentials (`header_config.per_user`). Deferred; can grow out of 1.

Machine servers are already reached through the gateway (tool call → machine WebSocket → `mcp-gateway up`), so one
substitution stage in the gateway covers both upstream and machine use. No separate delivery channel.

## 1. Lifecycle and data flow

```
 USER (browser)            AGENT HARNESS                     MCP GATEWAY                         TARGET
      │                          │                                │                                  │
      │                ① secrets.request                          │                                  │
      │                  {label, use:{server,tool,arg},           │                                  │
      │                   ttl:15m, uses:1}                        │                                  │
      │                          │───────────────────────────────▶│ store PENDING request            │
      │                          │◀───────────────────────────────│ -32042 URL elicitation           │
      │                          │   url: /s/<one-time id>        │ + handle sec_…                   │
      │◀──── shows link ─────────│                                │                                  │
 ② open /s/<id> ─────────────────┼───────────────────────────────▶│ signed in? owner? unused? <10min?│
      │◀── entry page (who asked, label, binding, TTL, uses) ─────│                                  │
      │── Save (CSRF) ───────────┼───────────────────────────────▶│ ③ envelope-encrypt, AAD          │
      │                          │                                │   {user,"secret",id,server};     │
      │                          │                                │   audit secret.provided (label)  │
      │                ④ real call with {"$secret":"sec_…"}       │                                  │
      │                          │───────────────────────────────▶│ authenticate → resolve → policy  │
      │                          │                                │ → SECRET STAGE: owner, TTL, uses,│
      │                          │                                │   binding match; decrypt; swap;  │
      │                          │                                │   uses-- in the ledger tx        │
      │                          │                                │──────────── plaintext ──────────▶│
      │                          │                                │◀──────────── result ─────────────│
      │                          │◀───────────────────────────────│ ⑤ scrub (raw/base64/url forms)   │
      │                          │                                │ ⑥ used up / TTL → wipe ciphertext│
      │── /secrets → Revoke ─────┼───────────────────────────────▶│                                  │
```

1. **Request.** Built-in tool `secrets.request {label, use:{server, tool, arg} | use:{machine, action}, ttl, uses}`
   (defaults: 15 min, 1 use). The gateway stores a pending request bound to the caller (user + harness family or
   token id) and answers `-32042` (URL elicitation required) with `<base>/s/<one-time id>` and the handle.
   Harnesses with URL elicitation open it; others show the link.
2. **Entry.** `/s/<id>`: signed-in portal page (company sign-in, CSRF, `X-Frame-Options: DENY`, CSP). Shows the
   requesting harness, label, exact binding, TTL, uses and a 4-word fingerprint the agent also prints. One password
   field (`autocomplete="off"`), **Save** / **Deny**. Owner only, single use, link valid 10 minutes.
3. **Store.** Envelope encryption with AAD `{user, "secret", id, server}`, `expires_at`, `uses_left`; registered with
   `/migrate rewrap`. Never logged. Audit `secret.provided` / `secret.denied` / `secret.used` / `secret.revoked` with
   label and handle id only.
4. **Use.** The agent passes `{"<arg>": {"$secret": "sec_…"}}`. A pipeline stage after the policy decision and
   before dispatch checks owner, expiry, uses and binding, decrypts, substitutes and decrements `uses_left` inside the
   ledger transaction (nothing is consumed if dispatch never happens). Approval payloads and ledger rows store the
   handle, never the value.
5. **Return.** Results (including streamed SSE chunks) are scrubbed of the value and its base64 / URL-encoded forms,
   replaced with `[secret]`.
6. **End.** The expiry job wipes ciphertext when uses reach 0 or the TTL passes. `/secrets` lists live secrets and
   pending requests with **Revoke**.

## 2. Machine side: actions

The agent chooses *which* action runs; the user's `config.yaml` decides *what* it does with the secret.

```yaml
actions:
  sudo-apt-upgrade:
    run: sudo -S apt-get upgrade -y        # fixed argv, no shell
    secret: stdin                          # stdin | askpass | fd | env:NAME
  ssh-prod:
    run: ssh -o BatchMode=no prod uptime
    secret: askpass                        # via SSH_ASKPASS / SUDO_ASKPASS helper
  psql-report:
    run: psql -h db -U report -f ~/q/report.sql
    secret: env:PGPASSWORD                 # child env only; weakest, flagged on the entry page
    params:
      host: '^[a-z0-9-]+$'                 # agent may fill only declared, pattern-checked params
```

```
 GATEWAY (secret stage)  ══ machine WebSocket ══▶  `mcp-gateway up`
   tool <machine>/actions.run {action, secret}       ① action exists in config.yaml?
                                                     ② spawn fixed argv (no shell, no free-form args)
                                                     ③ deliver via stdin / askpass / fd, zero the buffer
                                                     ④ scrub output locally
                         ◀════════ result ════════   (gateway scrubs again)
```

- Secrets bind to `<machine>/actions.run` + action name; a secret for `ssh-prod` cannot reach another action.
- Never in argv (`/proc/<pid>/cmdline`). `env:` only in the child's environment.
- The harness's own shell tool never receives the secret; only the `mcp-gateway up` process does.
- New or changed actions appear as a review on the Machines page, like new tools today.
- Not covered: an action whose command prints the secret or runs a script the agent can edit. Point actions at files
  the agent cannot write.

## 3. Errors, limits and abuse

| Threat | Defense |
|---|---|
| Phishing link from the agent or a prompt injection | Entry only on the gateway origin behind sign-in; shows harness, binding and a fingerprint the agent also prints; docs: type secrets only at `<base>/s/…` |
| Injection requests a secret bound to an attacker's server | Bindings only to servers/actions the user owns or that are published to them, and that policy allows |
| Request spam | ≤ 5 pending per user, 20/hour, `-32029` beyond; pending links expire in 10 min |
| Handle replay by another harness or user | Handle checked against user + harness family/token id; any mismatch is the generic error |
| Guessing `/s/<id>` or handles | 256-bit random ids, SHA-256 at rest, per-address failure rate limit |
| Leak through results | Two scrub passes (machine + gateway); values shorter than 8 characters refused |
| Leak through logs / audit / ledger / approvals | Plaintext only inside the secret stage; redacting slog; handle ids only |
| Gateway compromise | Envelope encryption under the OpenBao root key, as for stored credentials; short TTLs |

| Situation | Agent receives |
|---|---|
| Not entered yet | `-32042` again, same link |
| User pressed Deny | `-32030 secret request denied` |
| Expired, used up, revoked, wrong binding, not yours | `-32036 secret unavailable` (identical for all) |
| Machine offline | existing tunnel error; use not consumed |

Policy: `secrets.*` is a built-in app like `gateway.*` (universal Cedar layer); admins can deny it per role;
read-only tokens cannot request secrets.

## 4. Testing and rollout

- `make test`: `internal/secrets` state machine, TTL/uses, binding match, byte-identical generic errors, scrubber
  (raw/base64/url, split across SSE chunks); `internal/machineclient` actions (fixed argv, stdin/askpass/fd, param
  patterns, nothing in cmdline, local scrub).
- `make test-integration`: RLS on secret tables, single use under 10 concurrent consumers, expiry wipes ciphertext,
  cross-replica consume.
- `make test-e2e`: request → `-32042` → entry page → retry with handle → fake connector gets plaintext, agent result
  scrubbed; same through an enrolled machine action.
- `make test-security`: cross-user/cross-harness handles, wrong binding, id guessing, CSRF and framing, approval
  payload holds only the handle, and a search of logs/audit/ledger/DB for the plaintext finds nothing.

Rollout behind `GATEWAY_SECRETS_ENABLED`, one merge per step:

1. Schema + store: `secret_requests`, `secrets` (RLS, envelope columns registered for rewrap), expiry job.
2. Portal: `/s/<id>` entry page, `/secrets` list and revoke.
3. Pipeline: `secrets.request`, `$secret` substitution stage, scrubber, `-32036`.
4. Machine actions: `actions:` in `config.yaml`, `actions.run`, Machines page review.
5. Docs, flag on for gateway.huynle.com, dogfood `sudo` on a devbox.

Steps 1–3 deliver upstream secrets; step 4 adds machines.
