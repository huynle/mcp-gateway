# User guide

For coworkers using the gateway from an AI harness. Replace `https://gw.example.com` with your company's gateway address (the one the portal is at). Setup details per harness are in [`docs/harness-setup.md`](harness-setup.md); this page is the short version plus what to expect day to day (routes and messages checked against the portal and `internal/mcp/errors.go` at v1).

## 1. Sign in to the portal

Open `https://gw.example.com` and press *Continue with <your company provider>*. You sign in with your normal company account; the gateway never sees your password. The first sign-in creates your user with the default role; an admin assigns other roles on `/admin/users`. The *Light / System / Dark* switch at the top right of every page sets the colour theme for this browser (*System* follows your operating system). On a public gateway an administrator may have to approve your account first (you see *Waiting for approval* until then; sign in again later), or new accounts may need an invite link (open the link, then sign in); see [public-signup.md](public-signup.md). You will need to sign in again at least every **30 days**: every harness token you own stops working until you do (the harness shows *"sign in to the portal to reactivate your tokens"*), and signing in reactivates all of them at once.

## 2. Connect a harness

One endpoint for everything: `https://gw.example.com/mcp`. Two ways to authenticate; both go through the same roles, approvals and audit.

| | Generated token | MCP OAuth sign-in |
|---|---|---|
| Works with | OpenCode, scripts, `curl`, anything that can send a header | Claude Code, Claude Desktop, the MCP inspector, most SDK clients |
| Setup | `/tokens` → *New token* → copy it once | add the server; the harness opens your browser; press *Allow* |
| Lifetime | up to 90 days (you choose; default 30), no renewal — make a new one | 1-hour access tokens, renewed automatically for 30 days of inactivity |
| Stop it | `/tokens` → *Revoke* | `/harnesses` → *Disconnect* |

### Generated token (OpenCode, scripts)

1. `/tokens` → *New token*: name it after the harness/machine (`laptop opencode`), pick an expiry, optionally restrict it to some apps/tools or make it **read-only**.
2. Copy the token from the page that follows — it is shown **once**. It looks like `mgw_<8 chars>_<43 chars>`.
3. Paste the snippet the page shows for your harness:

```jsonc
// OpenCode: opencode.json (project or ~/.config/opencode/opencode.json)
{ "$schema": "https://opencode.ai/config.json",
  "mcp": { "gateway": { "type": "remote", "url": "https://gw.example.com/mcp", "enabled": true,
                        "headers": { "Authorization": "Bearer mgw_<id>_<secret>" } } } }
```

```bash
# Claude Code with a token instead of OAuth
claude mcp add --transport http gateway https://gw.example.com/mcp --header "Authorization: Bearer mgw_<id>_<secret>"
# quick check from a shell
curl -sS https://gw.example.com/mcp -H "Authorization: Bearer mgw_<id>_<secret>" -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

Treat the token like a password: do not commit `opencode.json` with it inside (add the secret-scanning pattern `mgw_[A-Za-z0-9]{8}_[A-Za-z0-9]{43}` to your repo's scanner), and revoke it on `/tokens` if it leaks. `/tokens` lists your tokens as `mgw_<id>_…` with last use.

### MCP OAuth sign-in (Claude Code, Claude Desktop)

```bash
claude mcp add --transport http gateway https://gw.example.com/mcp
```

Claude Desktop: *Settings → Connectors → Add custom connector*, name `gateway`, URL `https://gw.example.com/mcp`, leave client id/secret empty, *Connect*.

The first call answers *unauthorized*; the harness discovers the gateway's sign-in, registers itself and opens your browser at `/oauth/authorize`. Sign in if asked, read what the harness asks for (`mcp` = everything your role allows, `mcp:read` = read tools only), press **Allow**; the browser bounces back to the harness (`http://localhost:<port>/callback`) and it is connected. `/harnesses` lists every connected harness with its last use; *Disconnect* there ends it (the harness has to sign in again). If a harness keeps asking you to sign in, somebody may have reused its refresh token — the gateway revokes the whole family on reuse; disconnect it on `/harnesses` and sign in again.

### What you see

- **Tools**: `tools/list` shows only what your role allows (hidden tools do not exist from the harness's point of view). A fresh deployment shows nothing until an admin grants tools to your role. Every tool has two extra optional arguments the gateway owns: `account` (which connected account to use when you have several) and `approval_id` (retry after an approval). Harnesses re-list tools on reconnect; after a role change restart the harness or run `/mcp` → reconnect.
- **Accounts**: every app has `<app>.list_accounts` (`github.list_accounts`, `slack.list_accounts`, …) returning your connected accounts with their label (`company` / `personal`). With one account the gateway uses it; with several, the model must pass `account`.

## 3. Connect your app accounts

`/connections` lists each vendor your admins registered (GitHub, Slack, Atlassian, Google, Microsoft) with your connected accounts (name, **company** or **personal** label, granted scopes, status) and a *Connect* button. *Connect* sends you to the vendor's consent screen, then back; the gateway stores the vendor's tokens encrypted and never shows them. Each connection is bound to the vendor's permanent account id, so the same account reconnects to the same row.

**Company vs personal** is decided by the gateway from the vendor's answer, not by you:

| Vendor | Company when | Notes |
|---|---|---|
| GitHub | you are an active member of one of the company organizations the admin listed | install the GitHub App on your personal account for personal repos ([`docs/connectors/github.md`](connectors/github.md)) |
| Slack | the workspace is the company workspace | only a **company** Slack connection receives approval DMs; Slack needs the workspace admin's approval of the app once ([`docs/connectors/slack.md`](connectors/slack.md)) |
| Atlassian | the site (`acme.atlassian.net`) is a company site | one connection per site; connect again for another site ([`docs/connectors/atlassian.md`](connectors/atlassian.md)) |
| Google | you signed in with a Workspace account of the company domain (the *Internal* app) | personal Gmail accounts go through the *External* app, which shows Google's "unverified app" warning — press *Advanced* → *Go to …*; it is expected ([`docs/connectors/google.md`](connectors/google.md)) |
| Microsoft | your account is in the company tenant | personal Microsoft accounts cannot use the Teams tools ([`docs/connectors/microsoft.md`](connectors/microsoft.md)) |

Whether you may use a **personal** account at all, and whether its writes always need approval, is a role setting: if your role denies personal accounts for an app, the connect flow refuses with *"That is a personal account and your role does not allow personal accounts for this app"* and nothing is stored.

**Scopes.** *Connect* asks for what the **read** tools your role shows need (reads first). When an account lacks scopes for tools your role shows (writes, or tools added since you connected), its row on `/connections` shows **Grant more access** with what it unlocks ("Unlocks 25 functions: slack.archive_channel, …"). Press it, approve the extra scopes at the vendor, and the tools work; the connection keeps the union of everything granted. A tool you call before that answers `scope_required` naming the missing scopes, and `<app>.list_accounts` shows `locked_tools` and a `grant_more_access` link for such an account. Personal Microsoft accounts are never asked for Teams permissions (they cannot grant them).

**Reconnect** appears when the vendor stopped accepting the gateway's refresh token (password change, revoked app, long inactivity): tools on that account fail until you reconnect; nothing else changes. **Disconnect** revokes the gateway's access at the vendor (where supported) and deletes the stored tokens; your history stays.

## 3a. Connect a stdio or private MCP server (tunnel)

The gateway never runs programs on your machine and never dials into your network. To use an MCP server that speaks stdio (most `npx …` / `uvx …` servers), or one on `localhost` or your home network, you run a small client next to it that connects **out** to the gateway.

1. Install the client once (the portal's **Install CLI** page, `/cli`, has copyable commands): `brew install huynle/tap/mcp-gateway`, or `curl -fsSL https://gateway.huynle.com/install | sh` (installs into `~/.local/bin`, verifies the download's checksum, no sudo). Archives for macOS, Linux and Windows are on [GitHub Releases](https://github.com/huynle/mcp-gateway/releases).
2. In the portal, open **Servers → Tunnels**, name the tunnel (e.g. `laptop`) and press **Create tunnel**. Copy the token now: it is shown only once.
3. Copy the run command from the page and replace `<your server command>`, e.g. `MCP_GATEWAY_TUNNEL_TOKEN=mgt_… mcp-gateway tunnel --gateway https://gateway.example.com --stdio "npx -y @modelcontextprotocol/server-everything"`. For an HTTP server on your network use `--http http://localhost:8080/mcp` instead.
4. Add a server with the address `tunnel://<tunnel id>` (copy it from the same page).

Keep the command running while you use the server; it reconnects on its own. If you lose the token, revoke the tunnel and create a new one. `mcp-gateway tunnel --help` lists every option; details are in [tunnel.md](tunnel.md).

## 3b. Connect several local servers from one machine (`mcp-gateway login` / `up`)

If you run more than one local MCP server, or want them served while you are away (a headless box), enroll the machine once instead of creating a tunnel per server:

1. Install the client (see 3a) and list your servers in `~/.config/mcp-gateway/config.yaml`:

   ```yaml
   gateway: https://gateway.example.com
   servers:
     fusion360:
       http: http://127.0.0.1:27182/mcp
     everything:
       stdio: npx -y @modelcontextprotocol/server-everything
   ```

2. Run `mcp-gateway login`. It prints a code and opens `/activate`; check that the page shows this machine's name and the same fingerprint as your terminal, then **Approve**. On a machine without a browser, create an enrollment code on the portal's **Machines** page and run `MCP_GATEWAY_ENROLL_CODE=mge_… mcp-gateway login` there.
3. Run `mcp-gateway up`. Each server appears in your servers list; `up` prints a review link per new server: open it and approve the tools you want, as for any server.
4. Optional: `mcp-gateway service install` keeps `up` running in the background (and after a reboot). `mcp-gateway status` checks everything; after editing the config, restart the service or send `up` a SIGHUP.

Stdio servers started this way see only a minimal environment (`PATH`, `HOME`, `USER`, language settings) plus what you list under `env` / `inherit_env`, never your other shell variables. To retire a machine run `mcp-gateway logout`, or revoke it on the **Machines** page (from any device). Details: [machines-cli.md](machines-cli.md).

**Machines** (`/machines`) shows your machines and their servers. **Revoke** cuts one off at once. For a headless host create a one-time **enrollment code** there and run `mcp-gateway login --enroll-code mge_…`.

## 3c. Giving your agent a password

When the gateway has ephemeral secrets turned on, an agent that needs a password (a server's API key, `sudo` on your machine, an SSH passphrase) asks for it with `secrets.request` and shows you a link and four check words, for example `oak-river-mint-amber`. Then:

1. **Only ever type a secret at `<your gateway>/s/…`.** Never paste it into the chat, and never type it on a page someone sent you.
2. Open the link (sign in if asked). The page shows which agent asked, the label, exactly which server, tool and argument the secret is for, how long it stays usable and how many times. **Check that the words match what your agent shows.** If they differ, or you did not expect the request, press **Deny**.
3. Type the secret and press **Save**, then tell the agent to go on. The agent can use the secret for that one tool, for the time and number of uses shown, but never sees it; the gateway removes it from the results.

**Secrets** (`/secrets`) lists your pending and live secrets; **Revoke** ends one at once. Links expire after 10 minutes. For commands on your own machine, the secret goes only to the fixed commands you listed under `actions:` in the machine's config ([machines-cli.md](machines-cli.md#actions)). Details: [secrets.md](secrets.md).

## 3d. A server asks you to open a page

Some MCP servers need more than sign-in (a second API key, a consent screen) and ask for it on their own web page. When the gateway relays such a request, your agent shows a link `<your gateway>/elicit/…` saying "*<server> asks you to open a page*". Then:

1. Open the link (sign in if asked). Only you can open it; it expires after 10 minutes.
2. The page shows which server and agent asked, the **full address** you would go to, with its domain highlighted, and the server's own message. **Check the domain is the service you expect.** A warning appears for look-alike (punycode) names.
3. Press **Continue** to go to the server's page and finish there, or **Cancel**. Then tell your agent to retry.

The gateway only forwards pages on the server's own domain or on origins the server's owner allowed (server settings → *Allowed elicitation origins*). Otherwise the agent gets *"asked you to open a page that is not allowed"*; if it is your server, add the page's origin there. Details: [elicitation.md](elicitation.md).

## 4. Approvals: when a tool call waits for you

Some tools (writes, or anything your role marks *confirm*, or every write on a personal account when the role says so, or a write tool an admin set to *Ask* under Settings → Vendor apps, or a server write set to *Ask*) need your explicit OK per call. What happens:

1. The harness calls the tool. The gateway stores the call (arguments encrypted), notifies you, and **waits up to 30 s** for your decision.
2. You get the request in two places: the portal page **`/approvals`** (tool, account, resource such as the repo or channel, a summary of the arguments, a countdown; the page refreshes itself) and, if you have a **company Slack** connection, a **Slack DM** from the gateway's app with *Approve* / *Deny* buttons (the DM updates to "Approved by you at …" once you press).
3. Approve within the wait and the call completes in the same round trip — the model just sees the result.
4. If you were slower, the harness gets *approval required* with an `approval_id` and the instruction "ask the user to approve, then call this tool again with `approval_id=<id>`". Approve on `/approvals` or in Slack, then tell the model to retry. The retry runs the **stored** arguments (what you approved), even if the model reworded them; the approval is single-use.
5. An approval expires after **15 minutes**; a denied, used or expired one makes the retry fail with a message saying which, and the model should ask again (a new approval). `/approvals/history` shows your last 50 decisions.

Only you can approve your own calls (another person's Slack account pressing the button is refused and audited). An admin changing your role between approval and retry invalidates the approval (*approval does not match this call*): ask again.

## 5. What is audited (and what is not)

`/activity` shows every tool call made with your tokens or harnesses, plus your own actions (token created/revoked, account connected/disconnected, approvals decided, harness connected/disconnected), with filters by tool, decision, outcome and date. Each row has: time, tool, which account (label), the **resource identity** (repo, channel, site, folder … as the connector extracts it), the policy decision (allow / confirm / deny), the policy version, the approval and operation ids, the outcome (succeeded / failed / denied / replayed), latency, a request id and a short error class.

Admins see the same **metadata for everyone** on `/admin/audit`; they do not see more than that.

**Never recorded, anywhere**: the arguments you send, the results, message or file contents, your tokens, the vendor's tokens. The one exception is the pending approval's arguments, kept encrypted for the 15 minutes it lives and deleted when it is approved-and-used, denied or expired. Secrets you enter on `/s/…` pages are kept encrypted only until they expire, are used up or revoked; audit shows their label, never the value. Logs are redacted before they are written. The write ledger (`/operations`) keeps only the identifiers of what a write produced (issue number, message timestamp, file id, URL).

`/operations` lists your last 50 writes with their state. **succeeded** / **failed** are final; **unknown** means the vendor did not confirm and the gateway is checking (a duplicate call meanwhile answers *pending verification*); **unresolved** means it could not find out — *verify in the app* before retrying; the next identical call is a new write.

## 6. Common errors

JSON-RPC error codes the harness surfaces (the message says what to do; `error.data` carries ids and retry hints):

| Code / message | Meaning | What to do |
|---|---|---|
| HTTP `401` *invalid_token* (no JSON-RPC answer) | no token, revoked, expired, you are disabled, or you have not signed in for 30 days (*sign in to the portal to reactivate your tokens*) | sign in at the portal; if that does not help, make a new token or reconnect the harness |
| HTTP `429` + `Retry-After` | too many failed authentications from your address | fix the token; wait |
| sign-in page *Waiting for approval* | your new account needs an admin's approval | wait; sign in again later |
| sign-in page *This gateway is invite-only* / *This invite is invalid, expired or already used* (`403`) | new accounts need a valid invite link | ask an administrator for a (new) invite link |
| sign-in page `429` *Too many new accounts were created recently* | the gateway's new-account limit is reached | try again in an hour |
| `-32602 unknown tool "x"` | the tool does not exist **or** your role hides it | `tools/list`; ask an admin if you expected it |
| `-32602 account required: … set "account" to one of: …` | you have several accounts for the app | tell the model which account (or pass `account=<id>`); `<app>.list_accounts` shows them |
| `-32602 unknown account` | the `account` is not yours / not for this app | use one from `<app>.list_accounts` |
| `-32029 rate limited; retry in Ns` | your per-minute budget (60 calls across apps) or the app's shared budget is spent, or the vendor is rate limiting the gateway (`<app> is rate limiting this gateway`) | wait `retry_after` seconds |
| `-32030 denied by policy` | your role (or a token restriction) denies this tool on this resource/account | ask an admin; or use a company account / the right repo |
| `-32030 approval does not match this call` / `already used` / `was denied` / `expired` | the `approval_id` is not valid for this exact call | call again **without** `approval_id` to get a new approval |
| `-32031 no connected account for <app>` | you have not connected that app | `/connections` → *Connect* |
| `-32032 approval required` (`error.data.approval_id`, `portal_url`, `expires_at`) | the call waits for you | approve on `/approvals` or in Slack, then retry with `approval_id` |
| `-32033 pending verification` (`error.data.operation_id`) | the same write is already running or being verified | wait a minute, check `/operations`; do not fire it again |
| `-32034 authentication required` | a call reached the pipeline without a principal (fail-closed guard; you should only ever see the HTTP `401`) | as for `401`; report it if it persists |
| `-32042` with a link `<gateway>/s/…` and check words | the agent asked you for a secret | check the words, enter it on that page (section 3c), then let the agent retry |
| `-32042` with a link `<gateway>/servers/…` | (credential links) you need to connect, reconnect or fill in your values for that server | open the link, fix it, then retry |
| `-32042` with a link `<gateway>/elicit/…` | the server asks you to open its own page | check the address on the gateway's page, Continue, finish there, retry (section 3d) |
| `-32037 secret unavailable` | the secret expired, was used up or revoked, or is not for this tool | let the agent ask again (a new link) |
| `-32030 secret request denied` | you pressed Deny on the secret page | nothing; the agent asks again only if you want |
| `-32035 scope_required` (`error.data.missing_scopes`, `portal_url`) | the connected account has not granted a scope the tool needs | `/connections` → *Grant more access* on that account, approve at the vendor, retry |
| tool result with `isError: true` | the vendor refused or failed (class only: `reconnect_required`, `not_found`, `forbidden`, `invalid_argument`, `vendor_error`) | `reconnect_required` → *Reconnect* on `/connections`; `forbidden` → the app is not installed on that org/repo/site; otherwise fix the arguments or retry later |
| status **needs reconnect** on `/connections` | the vendor no longer accepts the stored refresh token | *Reconnect* |
| `/connections` says *That is a personal account and your role does not allow personal accounts for this app* | your role denies personal accounts for this app | connect the company account instead, or ask an admin |

Read results can carry a marker (`empty`, `partial`, `unavailable`) that tells the model "nothing found" from "could not look" — `partial` means a page or size limit was hit; ask for a narrower query.

## 7. Your data: download it, delete your account

**Download my data** (My account → *Your data*): one JSON file (`mcp-gateway-export-<date>.json`, format `mcp-gateway.user-export.v1`) with your profile and sign-in identities, roles, app connections, harness tokens and harness sign-ins, the MCP servers you own and your connections to servers, tunnels, approvals, write operations, your audit events and your rate-limit settings. It is metadata only: **never** tokens, vendor credentials, server credentials, approval arguments or anything stored encrypted; server URLs lose any `user:password@` and `?query`. Each section is capped (audit events 10 000, operations and approvals 5 000, the rest 1 000; newest first) and a capped section says `"truncated": true` with a note; ask an admin for a complete audit export ([runbook](runbooks/audit-export.md)). You can download once every **10 minutes**; earlier you get *Export limit* with the wait. Every download is in your activity (`user.data_exported`).

**Delete my account** (My account → *Delete my account…*): for safety this needs a company sign-in from the **last 10 minutes** (the page offers *Sign in with …* and brings you back) and typing `delete my account`. Deletion, in one step:

- signs you out everywhere, revokes every harness token and harness sign-in;
- disconnects every app account (revoked at the vendor where it supports that) and deletes the stored credentials;
- deletes your tunnels, your **private** MCP servers and your connections to MCP servers, and drops the arguments of any open approval;
- clears your name and your sign-in identity: signing in again later creates a **new, empty** account.

What stays: your audit events, write operations and approval records (without arguments), under an anonymous id — the gateway's legal record; they leave with the normal retention (one year by default). Deletion is refused, with the reason on the page, while you own **published** MCP servers (other people use them: ask an admin to unpublish or delete them first — the gateway does not transfer ownership), while you are the **last admin**, or for a bootstrap admin account (configured by the operators). Deletion cannot be undone.

## 8. Leaving, or losing a device

- Lost laptop: `/tokens` → *Revoke* the token(s) on it, `/harnesses` → *Disconnect* its harnesses, `/machines` → *Revoke* it if it was an enrolled machine. Nothing else is needed; vendor accounts stay connected.
- Leaving the team: an admin disables you; every token, harness and app connection is revoked at once. Your activity history stays for the audit trail.
- Leaving for good: delete your account (section 7), or ask an admin to delete it.
