# Public sign-up

By default the gateway is a company gateway: every identity provider has an
allow-list (`ALLOWED_DOMAINS` / `ALLOWED_TENANTS`) and an account from inside it
is active, with the default role, the moment it first signs in. A public
gateway lets anyone with an account at a provider sign up, and decides how new
accounts become usable.

## Any-domain providers

`GATEWAY_OIDC_<NAME>_ALLOWED_DOMAINS="*"` admits **every** account of that
provider, on one condition: the ID token carries an email address with a
domain **and** `email_verified: true`. Accounts without a verified email are
refused (`identity.signin_rejected`, `reason=no_verified_email`). For Google this
means any Google account (gmail.com and Workspace) whose email Google verified.

`*` must be the only entry and cannot be combined with `ALLOWED_TENANTS` or
`DOMAIN_CLAIM` (startup fails). Every other allow-list keeps its exact
behaviour.

Identity stays issuer + subject (never the email; no cross-provider linking).

## Sign-up modes

`GATEWAY_SIGNUP_MODE` decides what happens to an account that signs in for the
first time:

| Mode | New account | Default |
|---|---|---|
| `open` | active at once with the [default role](#default-role) | when no provider uses `*` (today's behaviour for every existing configuration) |
| `approval` | created **pending**, without any role, until an admin approves it | when any provider uses `ALLOWED_DOMAINS="*"` |
| `invite` | needs a valid single-use invite code; without one nothing is created | |

Never affected by the mode: users that already exist (whatever mode they were
created in) and bootstrap admins (`GATEWAY_BOOTSTRAP_ADMINS`), who are always
active, also when they first signed up pending. Changing the mode never
changes existing users.

### Approval

A pending account can sign in, but only to `/pending` ("Waiting for
approval", with a sign-out button). Its session never becomes a signed-in
user, so:

- every portal page, module page (`/tokens`, `/connections`, `/connect/...`,
  `/oauth/authorize`, harnesses, tunnels, servers) and admin page sends it to
  `/pending`; it can submit no form except sign-out;
- it holds no role, so the policy grants it nothing;
- generated tokens, OAuth codes and refresh tokens, OAuth access tokens on
  `/mcp` and tunnel tokens on `/tunnel/connect` are refused for any user that
  is not active (it could not create any of them anyway).

Admins see **Pending approval** (with a count) at the top of `/admin/users`:

- **Approve**: active, plus the default role (the role flagged on
  `/admin/settings/default-role`, else `GATEWAY_DEFAULT_ROLE`). The user's
  existing session works at once.
- **Reject**: disabled, exactly like Disable (sessions end, the disable hooks
  revoke tokens, OAuth grants and connections). Enable re-activates a rejected
  account later if needed (without a role change: assign one).

Enable and the role select refuse a pending account (`409`): approval is the
only way in. Each new pending account is logged as `identity.signup_pending`.
There is no admin notification beyond the log and the Users page.

### Invites

In invite mode the Users page has an **Invites** section. **Create invite**
(optional note, valid 1, 7 or 30 days) shows the invite link once:
`<GATEWAY_BASE_URL>/signin?invite=mgwi_...`. Only the code's SHA-256 is stored;
the list shows note, state (unused, used, revoked, expired) and dates, never
the code. Unused invites can be revoked.

The sign-in page carries the code to the provider buttons; the code stays in
the gateway (HttpOnly sign-in cookie), never in the request to the identity
provider. Without a code a new account sees "This gateway is invite-only"
(`403`); an unknown, used, revoked or expired code is refused the same way
("invalid, expired or already used"). A valid code is consumed in the same
transaction that creates the account, which is active with the default role.

## New-account rate limit

Account creation is limited per client IP and globally, over a rolling hour:
`GATEWAY_SIGNUP_RATE_IP_PER_HOUR` (default 10) and
`GATEWAY_SIGNUP_RATE_GLOBAL_PER_HOUR` (default 100). Over the limit the
sign-in gets a `429` page with `Retry-After: 3600`, nothing is created, and the
refusal is logged (`identity.signup_rate_limited`, `scope=ip|global`) and audited
(`signup.rate_limited`, system event). Sign-ins of existing users and of
bootstrap admins are never limited. The count is shared by every replica
(PostgreSQL, serialised by an advisory lock) and stores a (domain-separated) SHA-256 of the
IP, never the address.

The client IP is the TCP peer (`RemoteAddr`), as for the other per-IP limits of
the gateway. Behind a load balancer or ingress every request may come from the
same peer, so the per-IP limit then acts as a second global limit: size
`GATEWAY_SIGNUP_RATE_IP_PER_HOUR` accordingly until the gateway learns
trusted-proxy client IPs.

## Default role

New active accounts (open mode, invite mode, and approval mode on approval)
get the role flagged on `/admin/settings/default-role`, else
`GATEWAY_DEFAULT_ROLE` (default `member`, created empty when missing). An empty
role grants nothing: for a public gateway, give it a baseline.

**Apply public member baseline** on `/admin/settings/default-role` is an
explicit admin action (the gateway never edits roles on its own). It adds
`<app>.*: allow` to the `member` role (creating it when missing) for every
built-in app registered at that moment (github, slack, jira, confluence, the
Google apps, the Microsoft apps, ...; not user-added MCP servers, not the
`gateway` management app), keeps every rule already there (a deny or confirm
still wins over allow; vendor apps' Ask approvals still apply), and turns on
**May add MCP servers**. It is idempotent, audited (`member_baseline_applied`)
and does not make `member` the default role: flag it as default separately if
that is what new users should get.

## Audit events

All under `user` events (`action` in the resource identity), never with an
email, invite code, invite note or IP:

| Action | Actor | Keys |
|---|---|---|
| `user.signed_up` | the new user | `mode`, `status` (`active` / `pending`), `provider` |
| `user.approved` | the admin | `target_user_id`, `role` |
| `user.rejected` | the admin | `target_user_id` |
| `signup_invite.created` | the admin | `invite_id`, `expires_at` |
| `signup_invite.revoked` | the admin | `invite_id` |
| `signup.rate_limited` | system | `scope`, `provider` |
| `member_baseline_applied` | the admin | `role`, `apps` (count), `may_add_servers`, `policy_version_id` |

## Storage

Migration 00027: `users.status` may be `pending`; `signup_invites` (code hash,
note, creator, expiry, used / revoked); `signup_events` (hashed client key,
time; rows older than the window are pruned on insert). Both tables are only
reachable by `gateway_jobs` and have row-level security forced with no policy.
Going down disables every pending user.
