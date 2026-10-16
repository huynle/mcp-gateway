# Vendor app registration runbook (Team MCP Gateway v1)

Status: ready to execute. Written 2026-10-08 against the Team MCP Gateway v1 design
(Brain plan `36bakiw8`, sections 5 and 10) and the app-connections decision (`mh7c6z3v`).
Every scope, permission and console step below was checked against the vendor's current
documentation on 2026-10-08; the sources are listed at the end.

The database also contains a disabled `mcp/federation` **system app**. It is
not an OAuth integration: user-added MCP servers use it only for tokenless
connection anchors referenced by approvals, the write ledger and audit. The
Vendor apps page shows it in a read-only System apps disclosure. It cannot be
configured or enabled, never appears on the user Connections page, and its
anchors are excluded from token keep-alive.

Why now: vendor registrations and company admin approvals are the longest lead-time
item in the build order. They can and should start before the gateway can accept them.

## 0. Read this first

### 0.1 Hosts and callback paths

The gateway owns these paths. Use the placeholder hosts until the real hostnames exist,
then edit the registrations (every vendor lets you change redirect URIs later).

| Environment | Base URL |
| --- | --- |
| local | `http://localhost:8080` |
| staging | `https://mcp-gateway-staging.example.com` |
| production | `https://mcp-gateway.example.com` |

| Purpose | Path | Vendor values |
| --- | --- | --- |
| App connection callback (per user) | `/connect/{vendor}/callback` | `google`, `microsoft`, `atlassian`, `github`, `slack` |
| Company sign-in callback | `/auth/{provider}/callback` | `google`, `microsoft`, `okta` (only the providers the company uses) |
| Slack Approve/Deny buttons | `/slack/interactions` | n/a |

So, for example, the production GitHub callback is
`https://mcp-gateway.example.com/connect/github/callback`.

### 0.2 One registration per environment

Register **separate apps for staging and production** at every vendor. It keeps a
compromised staging secret away from production and lets you point staging at test
accounts. Local development reuses the **staging** registration where the vendor accepts
`http://localhost` redirect URIs (Google, Microsoft, GitHub, Atlassian). Slack requires
HTTPS redirect and request URLs, so local Slack work needs an HTTPS tunnel and ideally a
personal dev Slack app (see 2.6).

### 0.3 What the admin hands back, and where it goes

| Vendor | Hand back | Secret? |
| --- | --- | --- |
| GitHub App | App ID, app slug (public install URL), Client ID, Client secret | Client secret |
| Slack | App ID, Client ID, Client secret, Signing secret, Bot User OAuth token (`xoxb-...`) for the company workspace | Client secret, Signing secret, bot token |
| Atlassian | Client ID, Secret | Secret |
| Google Internal | Project ID, OAuth Client ID, Client secret | Client secret |
| Google External | Project ID, OAuth Client ID, Client secret | Client secret |
| Microsoft Entra | Application (client) ID, Directory (tenant) ID of the registering tenant, Client secret **value** and its expiry date | Client secret |

How they are entered:

- Admin portal -> **Settings -> Vendor apps -> \<vendor\>**. Secrets are stored
  envelope-encrypted with the gateway's key provider (design sections 5 and 6). Nothing
  is read from environment variables, Helm values or files in production.
- **Never** commit, paste into tickets, Slack messages or email, or store in the Brain.
  Hand secrets over through the company password manager (one-time share) or in person.
  If a secret ever travelled over a weaker channel, rotate it at the vendor after entry.
- Local development: use the same admin portal on `localhost`. If a dev-only values file
  is used, it must be git-ignored and contain only staging/dev credentials.
- Record non-secret identifiers (App IDs, Client IDs, project IDs) in the checklist table
  (section 6). Client IDs are not secrets.

### 0.4 Read/write separation

The gateway grants tool access per role and asks for scopes incrementally (reads first,
writes on "grant more access"). Where the vendor supports distinct read and write scopes
(Google, Microsoft, Atlassian, Slack user scopes) register **both** sets at the vendor; the
gateway requests only what the role needs. GitHub App permissions are declared once for the
whole app (no per-user split); the gateway's policy layer enforces read vs write there.

How the gateway asks (`internal/connections/access.go`):

- **Base scopes** in the vendor app editor only need the identity scopes (and
  `offline_access` where the vendor wants it). Tool scopes come from the tools themselves
  (`RequiredScopes`, plus `OptionalScopes` such as Slack's `im:read` that widen a tool).
- **Connect** asks for the base scopes plus the scopes of the **read** tools the user's
  role shows, leaving out any scope a write tool also needs (Slack's `chat:write`) and any
  scope some account cannot grant (Microsoft's Teams permissions, which personal accounts
  cannot grant).
- **Grant more access** on `/connections` appears on a connection that lacks scopes for
  tools the user's role shows ("Unlocks N functions: ..."). It asks for the base scopes,
  everything the connection already holds and the missing scopes; the connection keeps the
  union. A connection that **needs reconnect** gets the missing scopes on its *Reconnect*.
- The `scopes` query of `/connect/{vendor}/start` is filtered: only base scopes and scopes
  some tool of the vendor requires or uses are requested; anything else is dropped and
  logged (`connections.scopes_ignored`). Google requests carry `include_granted_scopes=true`
  even if the app's extras omit it.
- `<app>.list_accounts` tells a harness `locked_tools` (how many of that app's tools the
  account cannot run yet) and `grant_more_access` (the `/connections` URL).
- Existing apps whose base scopes were hand-filled with tool scopes keep working: those
  scopes are simply asked for on every connect.

### 0.5 Company admin consent summary

| Vendor | Admin action required for company accounts |
| --- | --- |
| GitHub | An **org owner** must install the GitHub App on the company organization (installation = consent). Personal accounts: each user installs on their own account. |
| Slack | If the workspace restricts app installs ("Admin-approved apps"), a Slack admin must approve the app. The bot token is created when an admin installs the app into the company workspace. |
| Atlassian | No admin consent step in the 3LO flow; users consent per site. Confirm with the Atlassian org admin that third-party OAuth apps are not blocked for the company sites. |
| Google | Internal app: Workspace admin may need to allow the app / scopes under Admin console -> Security -> API controls. If the company is **not** a Workspace org there is no Internal app and company users share the External app's 100-user cap. |
| Microsoft | `ChannelMessage.Read.All` (delegated; `teams_read_channel_messages`, `teams_read_channel_replies`) **requires admin consent**. Every other delegated permission in 5.2, including the ones added for the mail / calendar / OneDrive / Teams chat / To Do / contacts / people / directory tools, is user-consentable. Tenants that disable user consent need an admin to consent to the whole permission set. |

---

## 1. GitHub App

- Console: `https://github.com/settings/apps` (personal) or
  `https://github.com/organizations/<ORG>/settings/apps` (recommended: owned by the
  company org so ownership survives staff changes) -> **New GitHub App**.
- App type: **GitHub App** (not an OAuth App). Users authorize it (user access tokens)
  and install it on their personal accounts for personal repos; the org owner installs
  it on the company org.

### 1.1 Registration values

| Field | Value |
| --- | --- |
| GitHub App name | `MCP Gateway` (staging: `MCP Gateway Staging`) |
| Homepage URL | the environment base URL |
| Callback URL | `http://localhost:8080/connect/github/callback` (staging app only), `https://mcp-gateway-staging.example.com/connect/github/callback`, `https://mcp-gateway.example.com/connect/github/callback` (production app only). Up to 10 callback URLs are allowed per app. |
| Expire user authorization tokens | **leave selected** (GitHub's recommended default; the gateway handles refresh tokens) |
| Request user authorization (OAuth) during installation | **select** |
| Setup URL | leave empty (not available once the option above is selected) |
| Webhook -> Active | **unselect** (no v1 tool needs events; no Webhook URL/secret needed) |
| Where can this GitHub App be installed? | **Any account** |

### 1.2 Permissions

Repository permissions (verified per endpoint in the GitHub REST docs):

| Permission | Access | Tools |
| --- | --- | --- |
| Metadata | Read (mandatory, set automatically) | all; alone: `github.list_tags` |
| Issues | Read and write | read: `github.get_issue`, `github.list_issues`, `github.list_issue_comments`; write: `github.create_issue`, `github.add_issue_comment`, `github.update_issue` |
| Pull requests | Read and write | read: `github.get_pull_request`, `github.list_pull_request_files`, `github.list_pull_requests`, `github.get_pull_request_diff`, `github.get_pull_request_status`, `github.list_pull_request_reviews`, `github.list_pull_request_review_comments`; write: `github.create_pull_request`, `github.update_pull_request`, `github.create_pull_request_review`, `github.request_reviewers`, `github.add_issue_comment` (on PRs) |
| Contents | Read and write | read: `github.get_file_contents`, `github.list_branches`, `github.list_commits`, `github.get_commit`, `github.list_releases`, `github.get_release`; write: `github.create_branch` (`POST /repos/{owner}/{repo}/git/refs`), `github.create_or_update_file`, `github.merge_pull_request` |
| **Actions** (new) | Read and write | read: `github.list_workflow_runs`, `github.get_workflow_run`, `github.list_workflow_jobs`, `github.get_job_logs`; write: `github.run_workflow`, `github.rerun_workflow_run`, `github.cancel_workflow_run` |
| **Checks** (new) | Read | `github.get_pull_request_status` (check runs) |
| **Commit statuses** (new) | Read | `github.get_pull_request_status` (combined status) |
| Workflows (optional) | Read and write | only `github.create_or_update_file` on files under `.github/workflows`; leave off to keep the gateway from editing CI definitions |

Organization permissions: none required (Members: read optional, see
[connectors/github.md](connectors/github.md#setup)). Account permissions: none.

`github.get_me` (`GET /user`), `github.search_issues`, `github.search_code`,
`github.search_repositories` and `github.search_users` (`GET /search/...`) require no
permissions; search results are limited to repositories the installation and the user
can see.

**Upgrading an existing app (operator step).** The tool-gap release adds three repository
permissions: **Actions: read and write**, **Checks: read** and **Commit statuses: read**
(and optionally Workflows: read and write). Issues, Pull requests and Contents stay as
before. After saving the new permissions on the app's **Permissions & events** page,
GitHub e-mails every owner of an installation to **review and accept the updated
permissions**: the org owner for the company organization (org **Settings → GitHub Apps →
Configure** on the app → *Review request*), each user for their personal account. Until an installation accepts, the new tools answer `forbidden` on its
repositories; the existing tools keep working. Users do not need to reconnect: GitHub App
user tokens carry the app's permissions intersected with the installation's.

The new GitHub writes default to **Ask** (migration 24, see section 9).

GitHub's notifications API only accepts classic personal access tokens, so the gateway
has no notification tools; no notifications permission exists to add.

Subscribe to events: **none**.

### 1.3 After creation

1. Note the **App ID** and the public link (`https://github.com/apps/<slug>`).
2. Under **Client secrets** click **Generate a new client secret**; copy it once.
3. Do **not** generate a private key. v1 only uses user access tokens (client ID +
   client secret). If one is generated later for installation tokens, store it in the
   admin portal, never in the repo.
4. Install the app: org owner -> **Install App** -> company org -> choose
   "All repositories" or a curated list (this is the company's consent decision).
   Users install on their own accounts for personal repos.

---

## 2. Slack app

- Console: `https://api.slack.com/apps` -> **Create New App** -> **From a manifest**
  (paste 2.5) or **From scratch**.
- One app plays two roles:
  - **Per-user connector**: user token scopes; each user authorizes it from the portal.
  - **Approval bot**: bot token scopes `chat:write` + `im:write` to DM Approve/Deny
    buttons; interactivity posts to `/slack/interactions`, verified with the signing secret.

### 2.1 OAuth & Permissions -> Redirect URLs

Slack requires **HTTPS** for every redirect URL, so `localhost` cannot be registered.

| App | Redirect URLs |
| --- | --- |
| staging | `https://mcp-gateway-staging.example.com/connect/slack/callback` |
| production | `https://mcp-gateway.example.com/connect/slack/callback` |
| dev (personal, optional) | `https://<your-tunnel-host>/connect/slack/callback` |

### 2.2 User token scopes (per-user connector)

| Scope | Read/write | Tools |
| --- | --- | --- |
| `channels:read` | read | `slack.list_channels` (public channels) |
| `groups:read` | read | `slack.list_channels` (private channels the user is in) |
| `channels:history` | read | `slack.read_channel_history`, `slack.get_thread` (public) |
| `groups:history` | read | `slack.read_channel_history`, `slack.get_thread` (private) |
| `search:read` | read | `slack.search_messages` (user token only; Slack has no bot equivalent) |
| `users:read` | read | `slack.get_user` |
| `chat:write` | write | `slack.post_message`, `slack.reply_in_thread` |
| `im:write` | write | `slack.post_message`, `slack.reply_in_thread` to a user id: opens the direct message (`conversations.open`), e.g. a note to yourself. Optional: without it only channels work |
| `reactions:write` | write | `slack.add_reaction` |
| `channels:write` | write | `slack.create_channel` (public), `slack.rename_channel`, `slack.archive_channel`, `slack.unarchive_channel`, `slack.set_channel_topic`, `slack.set_channel_purpose`, `slack.join_channel`, `slack.leave_channel`, `slack.invite_to_channel`, `slack.remove_from_channel` (public channels; `channels:manage` is the bot-token equivalent and does not apply to user tokens) |
| `groups:write` | write | the same channel tools on **private** channels, and `slack.create_channel` with `is_private` |
| `pins:read` | read | `slack.list_pins` |
| `pins:write` | write | `slack.pin_message`, `slack.unpin_message` |
| `files:write` | write | `slack.upload_file` |
| `users.profile:write` | write | `slack.set_status`, `slack.clear_status` (the user's own status) |
| `dnd:read` | read | `slack.get_dnd` |
| `dnd:write` | write | `slack.set_dnd`, `slack.end_dnd` (the user's own Do Not Disturb snooze) |
| `im:read`, `mpim:read` | read | `slack.list_conversations` lists DMs / group DMs only when granted; group-DM ids resolve for policy (`mpim:<id>`) with `mpim:read` |
| `im:history`, `mpim:history` | read | `slack.read_channel_history`, `slack.get_thread` with a DM (`D…`) or group-DM id |
| `reactions:read` | read | `slack.get_reactions` |
| `files:read` | read | `slack.read_file` (metadata and content, at most 5 MiB) |
| `emoji:read` | read | `slack.search_emojis` (the workspace's custom emoji) |
| `canvases:read` | read | `slack.read_canvas`; optional for `slack.update_canvas` (find a section by its text) |
| `canvases:write` | write | `slack.create_canvas`, `slack.update_canvas` |
| `lists:read` | read | `slack.read_list`; also needed by `slack.add_list_item`, `slack.update_list_item` (they read the columns first) |
| `lists:write` | write | `slack.create_list`, `slack.update_list`, `slack.add_list_item`, `slack.update_list_item` |

`chat:write` also covers `slack.update_message`, `slack.delete_message`,
`slack.schedule_message`, `slack.list_scheduled_messages` and
`slack.delete_scheduled_message`.
`search:read` also covers `slack.search_files`; `users:read` covers
`slack.search_users`; `channels:read` / `groups:read` cover `slack.search_channels` and
`slack.list_channel_members` (plus `im:read` / `mpim:read` for a DM's members).

**Operator step for the search, file, canvas and list tools (Brain plan `5soa9785`).**
Add these seven **user token scopes** to the Slack app (**OAuth & Permissions -> User
Token Scopes**, or the manifest in 2.5) before rolling out the build that ships them:
`reactions:read`, `files:read`, `emoji:read`, `canvases:read`, `canvases:write`,
`lists:read`, `lists:write`. Then re-approve the app if the workspace uses
Admin-approved apps; users get them with **Grant more access** on `/connections`. Canvas
and List writes also need a paid plan for standalone canvases and Slack Lists (Slack
answers `free_teams_cannot_create_standalone_canvases` and similar, reported as
`forbidden`). The six new writes start as **Ask** (section 9).

Everything above acts **as the connected user** through the user token (Brain decision
`aud38ptd`): a user can only do what Slack already lets that user do (create a channel
when the workspace allows members to, archive one they may archive, remove members only
where they may). The gateway never requests Slack's `admin.*` scopes and offers no
workspace administration.

**Base scopes.** The vendor app's *Base scopes* field may stay **empty** for Slack: user
scopes are requested per user from the tools (0.4): *Connect* asks for the read scopes
above, *Grant more access* for the rest (Slack user scopes accumulate, so each new token
carries everything granted before). Apps whose base scopes were hand-filled with the nine
original user scopes keep working; those nine are then asked for on every connect.

**Adding scopes to an existing app.** Every scope a tool needs must be in the app's user
token scopes (2.5), or Slack refuses the request (`invalid_scope`). Users who connected
before a scope was added keep their old grant until they press **Grant more access** on
`/connections` (shown on every Slack connection that lacks scopes for tools their role
shows); until then the scope stage answers `scope_required` for the tools that need the
missing scopes and every other tool keeps working.
Workspaces with **Admin-approved apps** must re-approve the app after its scope list
changes (Slack treats new scopes as a new request), before anyone can grant them.

**Token shape.** The code exchange (`oauth.v2.access`) of an app with bot *and* user
scopes answers with the bot token as the top-level `access_token` and the user's own
token under `authed_user.access_token`; a user-scope-only app answers with no top-level
`access_token` at all. The gateway's connect flow reads the answer itself for vendor
`slack` and stores the **user token** (`authed_user`) in the connection; the bot token
the approval notifier uses is the one the admin pastes (2.6), never the one from a
user's connect. Token rotation (off in the manifest) would add `refresh_token` /
`expires_in` under `authed_user`; the flow keeps those too.

### 2.3 Bot token scopes (approval bot)

| Scope | Purpose |
| --- | --- |
| `chat:write` | post the approval message (`chat.postMessage`) |
| `im:write` | open the DM with the user (`conversations.open`) |

Enable the bot user under **App Home** (display name `MCP Gateway`).

### 2.4 Interactivity

**Interactivity & Shortcuts** -> toggle **Interactivity** on -> **Request URL**
`https://mcp-gateway.example.com/slack/interactions` (staging app: the staging host).
The URL can be saved before the gateway exists; re-save it once the endpoint responds.
The gateway verifies `X-Slack-Signature` with the **Signing Secret** from
**Basic Information -> App Credentials**.

Socket Mode: **off**. Event Subscriptions: **off**. Token rotation: off for v1
(optional later).

### 2.5 Manifest (copy, adjust hosts, paste)

```yaml
display_information:
  name: MCP Gateway
  description: Team MCP gateway - connects your Slack account to approved AI harness tools and delivers write approvals.
features:
  bot_user:
    display_name: MCP Gateway
    always_online: false
oauth_config:
  redirect_urls:
    - https://mcp-gateway.example.com/connect/slack/callback
  scopes:
    user:
      - channels:read
      - groups:read
      - channels:history
      - groups:history
      - search:read
      - users:read
      - chat:write
      - im:write
      - reactions:write
      - channels:write
      - groups:write
      - pins:read
      - pins:write
      - files:write
      - users.profile:write
      - dnd:read
      - dnd:write
      - im:read
      - mpim:read
      - im:history
      - mpim:history
      - reactions:read
      - files:read
      - emoji:read
      - canvases:read
      - canvases:write
      - lists:read
      - lists:write
    bot:
      - chat:write
      - im:write
settings:
  interactivity:
    is_enabled: true
    request_url: https://mcp-gateway.example.com/slack/interactions
  org_deploy_enabled: false
  socket_mode_enabled: false
  token_rotation_enabled: false
```

### 2.6 Distribution and install

1. **Manage Distribution** -> complete the checklist (remove hard-coded secrets, add
   redirect URL) -> **Activate Public Distribution**. Required so every team member's
   account can authorize the app, not just the creator's.
2. **Install to Workspace** on the company workspace (Slack admin if installs are
   restricted). Copy the **Bot User OAuth Token** (`xoxb-...`) from
   **OAuth & Permissions**. This is the token the approval notifier uses.
3. Hand back: App ID, Client ID, Client Secret, Signing Secret, bot token. They go
   into **Admin portal -> Vendor apps -> Slack**: client ID and client secret as for
   every vendor, plus the *Bot User OAuth token* and *Signing secret* fields (all
   three secrets are write-only and stored encrypted together; leave a field blank
   to keep the stored value). Without the bot token no approval DM is sent; without
   the signing secret `/slack/interactions` answers 401 to everything.
   In **Extra parameters**, `scope_param=user_scope` (default) makes the flow send the
   user scopes as `user_scope`; `company_team_id=T0...` and/or `company_team_domain=acme`
   label the company workspace's accounts *company*; `marker_reconcile=true` is the
   opt-in of `docs/connectors/slack.md`. These four are gateway hints: they are never
   forwarded to Slack's authorize URL. Any other key is sent as an authorization
   parameter.
4. For local work, developers create a personal dev Slack app from the same manifest in
   a sandbox workspace with a tunnel URL. Never point a dev app at the company workspace.

---

## 3. Atlassian OAuth 2.0 (3LO)

- Console: `https://developer.atlassian.com/console/myapps/` -> **Create** ->
  **OAuth 2.0 integration**. Create it with a company-owned Atlassian account.
- App type: OAuth 2.0 (3LO). Users consent per Atlassian site; the gateway binds the
  connection to Atlassian account ID + site (`cloudId` from
  `https://api.atlassian.com/oauth/token/accessible-resources`).

### 3.1 Authorization -> OAuth 2.0 (3LO) -> Configure

| Field | Value |
| --- | --- |
| Callback URL | staging app: `https://mcp-gateway-staging.example.com/connect/atlassian/callback`; production app: `https://mcp-gateway.example.com/connect/atlassian/callback`; dev: `http://localhost:8080/connect/atlassian/callback` on a developer's own app |

The console takes one callback URL per app; that is the main reason for separate apps per
environment. The gateway's `redirect_uri` must match exactly.

### 3.2 Permissions -> Jira API (classic scopes)

| Scope | Read/write | Tools |
| --- | --- | --- |
| `read:jira-work` | read | `jira.search_issues`, `jira.get_issue`, `jira.list_transitions` |
| `read:jira-user` | read | user fields (assignee, reporter) inside `jira.get_issue` / search results |
| `write:jira-work` | write | `jira.create_issue`, `jira.add_comment`, `jira.transition_issue` |

### 3.3 Permissions -> Confluence API

Classic scopes (v1 REST endpoints):

| Scope | Read/write | Tools |
| --- | --- | --- |
| `search:confluence` | read | `confluence.search` |
| `read:confluence-content.all` | read | `confluence.get_page` (content body) |
| `read:confluence-space.summary` | read | space fields returned by search and page reads |
| `write:confluence-content` | write | `confluence.create_page` |

Granular scopes (Confluence **v2** REST endpoints list only granular scopes). Register
them too so the connector can use v2 `GET /pages/{id}` and `POST /pages`:

| Scope | Read/write | Tools |
| --- | --- | --- |
| `read:page:confluence` | read | `confluence.get_page` |
| `write:page:confluence` | write | `confluence.create_page` |

### 3.4 Refresh tokens and sharing

- The gateway adds `offline_access` to the authorization request to receive refresh
  tokens; no console setting is needed, but keep the scope count well under Atlassian's
  recommended 50.
- **Distribution** -> set **Sharing** (fill vendor name, privacy policy URL, etc.).
  Without sharing, only the app creator can authorize it.
- **Settings** -> copy **Client ID** and **Secret**; hand back.
- Scopes do not override Jira/Confluence permissions: users only ever see what their own
  site permissions allow.

---

## 4. Google (Internal client + External app)

Google's user type is set per Cloud project, so an Internal app and an External app need
**two projects** (plus staging copies). Console: Google Auth Platform at
`https://console.cloud.google.com/auth/overview` (pages: **Branding**, **Audience**,
**Clients**, **Data Access**, **Verification Center**). Enable the APIs under
**APIs & Services -> Library** in each project: Google Calendar API, Tasks API, Gmail API,
Google Drive API, Google Docs API, Google Sheets API, People API.

### 4.1 Which app is which

| App | Exists when | Audience page | Who connects through it |
| --- | --- | --- | --- |
| Google **Internal** client | only if the company is a Google Workspace / Cloud Identity org, and the project is owned by that org | User type **Internal** | company Workspace accounts |
| Google **External** app | always | User type **External**, publishing status **In production**, **unverified** | personal Google accounts; also company accounts if there is no Internal app |

Open item from the design (section 10): confirm whether the company is a Google
Workspace org. If not, skip the Internal client and note that company users consume the
External app's cap.

### 4.2 Redirect URIs (Clients page -> Web application)

Add the authorized domains first (`example.com` placeholder; must be a domain the project
owner has verified in Search Console before verification is ever requested).

| Project | Authorized redirect URIs |
| --- | --- |
| staging (Internal and External) | `http://localhost:8080/connect/google/callback`, `https://mcp-gateway-staging.example.com/connect/google/callback` |
| production (Internal and External) | `https://mcp-gateway.example.com/connect/google/callback` |

If the gateway also uses Google for company sign-in, add
`/auth/google/callback` on the same hosts to the **Internal** client.

### 4.3 Scopes (Data Access page). Identical list in both apps.

Always requested (non-sensitive): `openid`, `https://www.googleapis.com/auth/userinfo.email`
(the connection is bound to the Google `sub`; the email domain labels company vs personal).

Increment 1 (Calendar, Tasks, Gmail):

| Scope | Read/write | Tools | Classification |
| --- | --- | --- | --- |
| `https://www.googleapis.com/auth/calendar.events.readonly` | read | `calendar.list_events`, `calendar.get_event` | sensitive |
| `https://www.googleapis.com/auth/tasks.readonly` | read | `tasks.list` | sensitive |
| `https://www.googleapis.com/auth/gmail.readonly` | read | `gmail.search`, `gmail.get_message`, `gmail.list_labels` | **restricted** |
| `https://www.googleapis.com/auth/gmail.labels` | read | `gmail.list_labels` only (non-sensitive alternative so labels work without `gmail.readonly`) | non-sensitive |
| `https://www.googleapis.com/auth/calendar.events` | write | `calendar.create_event` | sensitive |
| `https://www.googleapis.com/auth/tasks` | write | `tasks.create` | sensitive |
| `https://www.googleapis.com/auth/gmail.send` | write | `gmail.send` | sensitive |
| `https://www.googleapis.com/auth/gmail.compose` | write | `gmail.create_draft` (`drafts.create` accepts only `gmail.compose`, `gmail.modify` or `mail.google.com`) | **restricted** |

Increment 2 (Drive, Docs, Sheets, Contacts):

| Scope | Read/write | Tools | Classification |
| --- | --- | --- | --- |
| `https://www.googleapis.com/auth/drive.metadata.readonly` | read | `drive.search`, `drive.get_file_metadata` | **restricted** |
| `https://www.googleapis.com/auth/documents.readonly` | read | `docs.get_text` | sensitive |
| `https://www.googleapis.com/auth/spreadsheets.readonly` | read | `sheets.read_range` | sensitive |
| `https://www.googleapis.com/auth/contacts.readonly` | read | `contacts.search` | sensitive |
| `https://www.googleapis.com/auth/drive.file` | write | `drive.create_folder`, `docs.create` (per-file access: only folders/files the gateway created or the user opened with it). Alone it also admits every `drive.*`, `docs.*` and `sheets.*` tool on those files, so a deployment may leave `drive.metadata.readonly` out (see `docs/connectors/google.md`, "Increment 2 notes") | non-sensitive |
| `https://www.googleapis.com/auth/documents` | write | `docs.append_text` | sensitive |
| `https://www.googleapis.com/auth/spreadsheets` | write | `sheets.append_rows` | sensitive |

Increment 3 (management tools, `docs/connectors/google.md` "Increment 3"). **Operator step:
add these four scopes on the Data Access page of both the Internal and the External project**
(Google shows the unverified-app screen when requested scopes differ from the declared ones);
the gateway asks for them only through *Grant more access* when a role shows the tools:

| Scope | Read/write | Tools | Classification |
| --- | --- | --- | --- |
| `https://www.googleapis.com/auth/calendar.calendarlist.readonly` | read | `calendar.list_calendars` (`calendar.readonly` also covers it) | sensitive (confirm on the Data Access page) |
| `https://www.googleapis.com/auth/calendar.freebusy` | read | `calendar.free_busy` (`calendar.readonly` also covers it) | sensitive (confirm on the Data Access page) |
| `https://www.googleapis.com/auth/gmail.modify` | write | `gmail.modify_labels`, `gmail.trash` (`messages.modify` / `trash` accept only `gmail.modify` or `mail.google.com`). It also covers `gmail.readonly`, `gmail.compose`, `gmail.send`, `gmail.labels` | **restricted** |
| `https://www.googleapis.com/auth/drive.readonly` | read | `drive.get_content`, `drive.list_comments` (`files.export`, `alt=media` and `comments.list` do not accept `drive.metadata.readonly`). Also covers `drive.metadata.readonly`, `documents.readonly`, `spreadsheets.readonly` | **restricted** |

The other increment-3 tools reuse registered scopes: `calendar.events` (update, delete,
respond), `tasks.readonly` / `tasks` (task lists, get, update, complete, delete),
`gmail.readonly` (`get_thread`, `list_drafts`, `get_attachment`), `gmail.compose`
(`send_draft`), `drive.metadata.readonly` (`list_folder`, `list_permissions`), `drive.file`
(`create_file`, `update_file`, `share`, `add_comment`, `sheets.create`), `documents`
(`docs.replace_text`), `spreadsheets.readonly` / `spreadsheets` (`sheets.get_metadata`,
`update_range`), `contacts.readonly` (`contacts.get`, `contacts.list`). A deployment that
does not want the two new restricted scopes leaves them out: `drive.get_content` and
`drive.list_comments` then work only per file through `drive.file`, and the Gmail label /
trash tools stay locked.

"Classification" follows Google's published restricted-scope list and the Gmail/Drive
scope pages; the Data Access page shows the same labels when you add a scope. Request
only scopes the connector actually sends: Google shows the unverified-app screen whenever
the requested scopes differ from the declared ones.

### 4.4 The External app: 100-user cap and the CASA trigger

- Publish the External app (**Audience -> Publish app**) **without** requesting
  verification. Google: a published, unverified External app that requests sensitive or
  restricted scopes shows the unverified-app warning and is **capped at 100 total users
  for its lifetime**; the cap cannot be reset.
- Do **not** leave it in Testing: Testing mode caps at 100 test users and expires refresh
  tokens after 7 days.
- Restricted scopes in the list above (`gmail.readonly`, `gmail.compose`,
  `drive.metadata.readonly`, and with increment 3 `gmail.modify` and `drive.readonly`) are what trigger the heavier path if the app is ever
  submitted for verification: restricted-scope verification plus an **annual CASA security
  assessment** by a Google-approved assessor, because the gateway stores restricted-scope
  data (tokens) on a server. The design explicitly defers this; revisit when personal
  Google users approach 100 (plan section 10).
- Branding (app name, support email, privacy policy and homepage links on a verified
  domain) is still required to publish. Without brand verification the consent screen
  shows the domain instead of the name/logo; that is acceptable for v1.

### 4.5 Internal client and Workspace admin

- Internal apps are not subject to verification or the cap, but Workspace admins control
  them: Admin console -> **Security -> Access and data control -> API controls**. Ask the
  admin to allow (or mark **Trusted**) the gateway's Internal app and to confirm the
  restricted Gmail/Drive scopes are not blocked for the org.
- If there is no Workspace org, ask whether the company accounts' admin (if any) must
  trust the External app instead.

### 4.6 Hand back

Per project: Project ID, OAuth **Client ID**, **Client secret** (download once from the
Clients page). Keep the OAuth consent screen's support and developer contact addresses on
a shared mailbox so Google's notices reach the team.

---

## 5. Microsoft Entra (Microsoft 365)

- Console: `https://entra.microsoft.com` -> **Entra ID -> App registrations -> New
  registration** (register in the company tenant).
- App type: web app registration, **multi-tenant + personal accounts**.

### 5.1 Registration

| Field | Value |
| --- | --- |
| Name | `MCP Gateway` (staging: `MCP Gateway Staging`) |
| Supported account types | **Any Entra ID tenant + personal Microsoft accounts** (multitenant + Skype/Xbox/Live/Hotmail) |
| Redirect URI (platform **Web**) | staging app: `http://localhost:8080/connect/microsoft/callback`, `https://mcp-gateway-staging.example.com/connect/microsoft/callback`; production app: `https://mcp-gateway.example.com/connect/microsoft/callback` |

Redirect URIs must be HTTPS except `http://localhost` paths, and are case-sensitive.
If Microsoft is also a company sign-in provider, add `/auth/microsoft/callback` on the
same hosts. The gateway authenticates against the `common` authority and enforces the
allowed tenant list itself; the registration does not restrict tenants.

**Certificates & secrets -> New client secret**: choose the longest lifetime the company
policy allows (max 24 months), copy the **Value** immediately, and put the expiry date in
the checklist. Rotation is an admin-portal change plus a new secret here.

### 5.2 API permissions -> Microsoft Graph -> Delegated permissions

| Permission | Read/write | Tools | Admin consent (delegated) |
| --- | --- | --- | --- |
| `User.Read` | read | identity binding (object ID + tenant) | No |
| `offline_access` | n/a | refresh tokens | No |
| `Mail.Read` | read | `mail.search`, `mail.get_message` | No |
| `Calendars.Read` | read | `calendar.list_events` | No |
| `Files.Read.All` | read | `drive.search` (OneDrive and SharePoint the user can access) | No |
| `Channel.ReadBasic.All` | read | `teams.list_channels` | No |
| `Team.ReadBasic.All` | read | `teams.list_channels` (enumerate the user's joined teams) | No |
| `ChannelMessage.Read.All` | read | `teams.read_channel_messages` | **Yes** |
| `Mail.Send` | write | `mail.send` | No |
| `Calendars.ReadWrite` | write | `calendar.create_event` (superset of `Calendars.Read`; requested only when writes are enabled) | No |
| `Files.ReadWrite` | write | `drive.create_folder` in the user's own OneDrive (use `Files.ReadWrite.All` instead if folders must be created in SharePoint libraries) | No |
| `ChannelMessage.Send` | write | `teams.post_channel_message`, `teams_reply_channel_message` | No |
| `Mail.ReadWrite` | write | `mail_create_draft`, `mail_move`, `mail_mark_read`, `mail_delete` (`Mail.Send` also covers `mail_send_draft`, `mail_reply`, `mail_forward`; `Mail.Read` covers `mail_list_folders`, `mail_list_attachments`, `mail_get_attachment`) | No |
| `Calendars.Read.Shared` | read | `calendar_find_meeting_times` (work accounts only) | No |
| `Chat.ReadBasic` | read | `teams_list_chats` (work accounts only; `Chat.Read` covers it) | No |
| `Chat.Read` | read | `teams_read_chat_messages` (work accounts only) | No |
| `ChatMessage.Send` | write | `teams_send_chat_message` (work accounts only) | No |
| `Tasks.Read` | read | `todo_list_lists`, `todo_list_tasks` | No |
| `Tasks.ReadWrite` | write | `todo_create_task`, `todo_update_task`, `todo_complete_task` | No |
| `Contacts.Read` | read | `contacts_search` | No |
| `People.Read` | read | `people_search` | No |
| `User.ReadBasic.All` | read | `users_search` (directory search; work accounts only) | No |

`Calendars.ReadWrite` also covers `calendar_list_calendars`, `calendar_get_event`,
`calendar_update_event`, `calendar_delete_event` and `calendar_respond_event`;
`Files.Read.All` covers `drive_list_children` and `drive_get_file_content`;
`Files.ReadWrite` covers `drive_upload_file` and `drive_create_share_link`;
`ChannelMessage.Read.All` covers `teams_read_channel_replies`.

**Operator step (tool-gap release, migration 23).** Add the ten delegated permissions
above that are new -- `Mail.ReadWrite`, `Calendars.Read.Shared`, `Chat.ReadBasic`,
`Chat.Read`, `ChatMessage.Send`, `Tasks.Read`, `Tasks.ReadWrite`, `Contacts.Read`,
`People.Read`, `User.ReadBasic.All` -- under **API permissions -> Add a permission ->
Microsoft Graph -> Delegated permissions** of the existing registration. None needs admin
consent; tenants with user consent disabled need an admin to re-consent to the full list.
Do **not** add them to the vendor app's base **Scopes**: users get them through **Grant
more access** on `/connections` for the tools their role shows.

No application permissions. Teams chat, SharePoint, directory (`User.ReadBasic.All`)
and shared-calendar (`Calendars.Read.Shared`) permissions are **not supported for
personal Microsoft accounts** (`microsoft.WorkOnlyScope`): Connect and Grant more access
never ask personal accounts for them, the binder strips them, and the tools that need
them answer `scope_required` for those connections.

### 5.3 Admin consent

- `ChannelMessage.Read.All` needs a Global Administrator or Privileged Role Administrator
  of the **company tenant** to consent. Do it from **API permissions -> Grant admin
  consent for \<tenant\>** in the registering tenant, or send the admin the tenant-wide
  consent link
  `https://login.microsoftonline.com/<company-tenant-id>/adminconsent?client_id=<application-id>`.
- If the company tenant has user consent disabled, the same admin consent covers the
  whole list above.

### 5.4 Hand back

Application (client) ID, Directory (tenant) ID, client secret value, secret expiry date.

---

## 6. Checklist

Update this table as registrations land. "Owner" is the human doing the registration;
"Approver" is the company admin who must consent/install. Status values: `not started`,
`registered`, `approved`, `entered in gateway`, `verified end-to-end`.

| Vendor / app | Environment | Owner | Approver (company admin) | Admin action | Status | Non-secret IDs recorded |
| --- | --- | --- | --- | --- | --- | --- |
| GitHub App | staging | | GitHub org owner | install on company org | not started | App ID: , slug: , Client ID: |
| GitHub App | production | | GitHub org owner | install on company org | not started | App ID: , slug: , Client ID: |
| Slack app | staging (sandbox workspace) | | Slack workspace admin | approve + install (bot token) | not started | App ID: , Client ID: |
| Slack app | production | | Slack workspace admin | approve + install (bot token) | not started | App ID: , Client ID: |
| Atlassian 3LO | staging | | Atlassian org admin | confirm third-party apps allowed | not started | Client ID: |
| Atlassian 3LO | production | | Atlassian org admin | confirm third-party apps allowed | not started | Client ID: |
| Google Internal client | staging | | Workspace admin | allow/trust app, confirm scopes | not started (or n/a if not a Workspace org) | Project: , Client ID: |
| Google Internal client | production | | Workspace admin | allow/trust app, confirm scopes | not started (or n/a) | Project: , Client ID: |
| Google External app | staging | | none | publish unverified | not started | Project: , Client ID: |
| Google External app | production | | none | publish unverified | not started | Project: , Client ID: |
| Microsoft Entra | staging | | Entra Global Admin | consent `ChannelMessage.Read.All` | not started | App ID: , Tenant ID: , secret expires: |
| Microsoft Entra | production | | Entra Global Admin | consent `ChannelMessage.Read.All` | not started | App ID: , Tenant ID: , secret expires: |

Prerequisites to close before production registrations: real staging and production
hostnames (replace `example.com`), a verified company domain for Google's authorized
domains, a public privacy-policy URL (Google External, Atlassian sharing, Slack
distribution all ask for one), and the answer to "is the company a Google Workspace org".

## 7. Scope-to-tool coverage check

Every v1 tool in plan section 5 maps to at least one registered scope above:

- GitHub: see the table in 1.2 (every row names its tools).
- Slack: `list_channels` (`channels:read`, `groups:read`), `read_channel_history`,
  `get_thread` (`channels:history`, `groups:history`), `search_messages` (`search:read`),
  `get_user` (`users:read`), `post_message`, `reply_in_thread` (`chat:write`),
  `add_reaction` (`reactions:write`); channel and member management
  (`channels:write`, `groups:write`), `update_message`, `delete_message`,
  `schedule_message`, `list_scheduled_messages`, `delete_scheduled_message`
  (`chat:write`), `list_pins` (`pins:read`), `pin_message`, `unpin_message`
  (`pins:write`), `upload_file` (`files:write`), `set_status`, `clear_status`
  (`users.profile:write`), `get_dnd` (`dnd:read`), `set_dnd`, `end_dnd` (`dnd:write`),
  `list_conversations` (`channels:read`, `groups:read`, plus `im:read` / `mpim:read`
  for DMs; DM history `im:history` / `mpim:history`); `get_reactions` (`reactions:read`),
  `list_channel_members`, `search_channels` (`channels:read`, `groups:read`),
  `search_files` (`search:read`), `search_users` (`users:read`), `search_emojis`
  (`emoji:read`), `read_file` (`files:read`), `read_canvas` (`canvases:read`),
  `create_canvas`, `update_canvas` (`canvases:write`), `read_list` (`lists:read`),
  `create_list`, `update_list`, `add_list_item`, `update_list_item` (`lists:write`,
  item writes also `lists:read`). Approval DMs: bot `chat:write`, `im:write`.
- Atlassian: `jira.search_issues`, `jira.get_issue`, `jira.list_transitions`
  (`read:jira-work`, `read:jira-user`), `confluence.search` (`search:confluence`),
  `confluence.get_page` (`read:confluence-content.all` / `read:page:confluence`),
  `jira.create_issue`, `jira.add_comment`, `jira.transition_issue` (`write:jira-work`),
  `confluence.create_page` (`write:confluence-content` / `write:page:confluence`).
- Google: see the tables in 4.3 (every row names its tools).
- Microsoft: see the table in 5.2 (every row names its tools).

No registered scope is unused by a v1 tool except `openid`/`userinfo.email`,
`User.Read` and `offline_access`, which exist for identity binding and refresh.

## 8. Sources checked on 2026-10-08

- Google: OAuth 2.0 scopes list (`developers.google.com/identity/protocols/oauth2/scopes`);
  OAuth app state overview (`.../production-readiness/overview`: Testing vs Published,
  100-user cap); restricted scope verification (`.../restricted-scope-verification`: CASA,
  annual reassessment); Restricted Scopes list (`support.google.com/cloud/answer/13464325`);
  Unverified apps (`support.google.com/cloud/answer/7454865`); Manage OAuth App Branding
  (`support.google.com/cloud/answer/10311615`); Gmail scopes
  (`developers.google.com/workspace/gmail/api/auth/scopes`) and `drafts.create`,
  `messages.send`, `messages.list`, `labels.list` references; Drive scopes
  (`developers.google.com/workspace/drive/api/guides/api-specific-auth`) and `files.create`,
  `files.list` references; Calendar `events.list` / `events.insert`; Tasks `tasks.list` /
  `tasks.insert`; Docs `documents.batchUpdate`; Sheets `spreadsheets.values.append`;
  People `people.searchContacts`.
- Microsoft: Graph permissions reference (`learn.microsoft.com/graph/permissions-reference`,
  AdminConsentRequired column); API pages for `user: list messages`, `sendMail`,
  `list events`, `create event`, `driveItem: search`, `create folder`, `channel: list`,
  `list channel messages`, `send chatMessage`, `list joinedTeams`; app registration
  quickstart (`learn.microsoft.com/entra/identity-platform/quickstart-register-app`);
  redirect URI rules (`.../reply-url`).
- GitHub: REST reference "Fine-grained access tokens" sections for `GET /user`,
  `GET /search/issues`, `GET/POST /repos/{owner}/{repo}/issues`,
  `POST .../issues/{n}/comments`, `GET .../pulls/{n}`, `GET .../pulls/{n}/files`,
  `POST .../pulls`, `POST .../git/refs`; "Registering a GitHub App"
  (`docs.github.com/apps/creating-github-apps/registering-a-github-app/registering-a-github-app`).
- Slack: method references `conversations.list`, `conversations.history`,
  `conversations.replies`, `search.messages`, `users.info`, `chat.postMessage`,
  `reactions.add`, `conversations.open`, and (2026-10-15) `conversations.create`,
  `.rename`, `.archive`, `.unarchive`, `.setTopic`, `.setPurpose`, `.join`, `.leave`,
  `.invite`, `.kick`, `.info`, `.members`, `users.conversations`, `chat.update`,
  `chat.delete`, `chat.scheduleMessage`, `chat.scheduledMessages.list`,
  `chat.deleteScheduledMessage`, `pins.add` / `.remove` / `.list`,
  `files.getUploadURLExternal`, `files.completeUploadExternal`, `users.profile.set`,
  `dnd.info`, `dnd.setSnooze`, `dnd.endSnooze` (`docs.slack.dev/reference/methods/...`);
  "Installing with OAuth" (HTTPS redirect requirement); "Handling user interaction"
  (Interactivity & Shortcuts -> Request URL); "Verifying requests from Slack".
- Atlassian: Jira scopes for OAuth 2.0 (3LO)
  (`developer.atlassian.com/cloud/jira/platform/scopes-for-oauth-2-3LO-and-forge-apps/`);
  Confluence scopes (`developer.atlassian.com/cloud/confluence/scopes-for-oauth-2-3LO-and-forge-apps/`);
  OAuth 2.0 (3LO) apps guide (`developer.atlassian.com/cloud/jira/platform/oauth-2-3lo-apps/`:
  console, callback URL, `offline_access`, accessible-resources, distribution/sharing);
  Confluence v2 `GET /pages/{id}` and `POST /pages` scope lines; Jira v3 issue search
  scope line.

## 9. Tool approvals (Ask / Auto)

Once a vendor is configured, its page (**Settings → Vendor apps → <vendor>**,
`/admin/vendor-apps/<vendor>`, admins only) has a **Tool approvals** section: every
**write** tool of every connector app that uses this vendor's accounts, grouped by app
(GitHub: `github`; Slack: `slack`; Atlassian: `jira`, `confluence`; Google: `gmail`,
`calendar`, `drive`, …; Microsoft: `microsoft`). Each tool has an **Ask / Auto** switch;
"Ask for all" and "Run all without asking" set every write of one app; a counts line shows
`N write tools · A auto · K ask`.

- **Auto** (the default for most tools, and the behaviour before this setting existed):
  the tool runs as the user's roles say.
- **Ask**: every call of the tool needs the user's approval first (`/approvals` or Slack),
  for every user, org-wide.

The setting only ever **adds** a confirmation: a role *allow* + Ask confirms, a role
*confirm* stays confirm (Auto never lifts it), and role *deny*, user restrictions and
token narrowing (read-only, allow-list) still win. It grants nothing: a user without a
role grant still cannot call the tool. Read tools are never affected. User-added MCP
servers keep their own per-server modes (servers portal / `/admin/servers/{id}`).

| Role rule for the tool | Auto | Ask |
|---|---|---|
| allow | allow | **confirm** |
| confirm | confirm | confirm |
| deny / hidden | deny / hidden | deny / hidden |
| no rule | hidden | hidden |

**Seeded Ask defaults (Microsoft).** Migration 23 (`00023_microsoft_default_ask.sql`)
stores Ask for every Microsoft write added to close the gap with the reference
Microsoft 365 connectors: `mail_create_draft`, `mail_send_draft`, `mail_reply`,
`mail_forward`, `mail_move`, `mail_mark_read`, `mail_delete`, `calendar_update_event`,
`calendar_delete_event`, `calendar_respond_event`, `drive_upload_file`,
`drive_create_share_link`, `teams_send_chat_message`, `teams_reply_channel_message`,
`todo_create_task`, `todo_update_task`, `todo_complete_task`. `mail_send`,
`calendar_create_event`, `drive_create_folder` and `teams_post_channel_message` stay Auto.
`TestMicrosoftNewWritesAreSeededAsAsk` (`cmd/gateway`) fails when a new Microsoft write
ships without a seed.

**Seeded Ask defaults.** Migration 20 (`00020_slack_default_ask.sql`) stores Ask for
every Slack write added with Brain decision `aud38ptd`: `create_channel`,
`rename_channel`, `archive_channel`, `unarchive_channel`, `set_channel_topic`,
`set_channel_purpose`, `join_channel`, `leave_channel`, `invite_to_channel`,
`remove_from_channel`, `update_message`, `delete_message`, `schedule_message`,
`delete_scheduled_message`, `pin_message`, `unpin_message`, `upload_file`, `set_status`,
`clear_status`, `set_dnd`, `end_dnd`. They need a confirmation on every call until an
admin switches them to Auto; `post_message`, `reply_in_thread` and `add_reaction` stay
Auto. A row an admin already wrote is kept (`ON CONFLICT DO NOTHING`); the migration's
Down removes exactly those rows. Migration 21 (`00021_slack_docs_default_ask.sql`) does
the same for the canvas and Slack List writes of Brain plan `5soa9785`: `create_canvas`,
`update_canvas`, `create_list`, `update_list`, `add_list_item`, `update_list_item`.
`TestSlackNewWritesAreSeededAsAsk` (`cmd/gateway`) fails when a new Slack write ships
without a seed in one of them.

Migration 22 (`00022_google_default_ask.sql`) does the same for the Google writes added
after increments 1 and 2: `calendar.update_event`, `delete_event`, `respond_to_event`;
`tasks.update`, `complete`, `delete`; `gmail.modify_labels`, `trash`, `send_draft`;
`drive.create_file`, `update_file`, `share`, `add_comment`; `docs.replace_text`;
`sheets.update_range`, `create`. `calendar.create_event`, `tasks.create`, `gmail.send`,
`gmail.create_draft`, `drive.create_folder`, `docs.create`, `docs.append_text` and
`sheets.append_rows` stay Auto. `TestGoogleNewWritesAreSeededAsAsk` guards the list.

Migration 24 (`00024_github_default_ask.sql`) does the same for the GitHub writes added to
close the gap with github-mcp-server: `create_or_update_file`, `update_issue`,
`update_pull_request`, `create_pull_request_review`, `request_reviewers`,
`merge_pull_request`, `run_workflow`, `rerun_workflow_run`, `cancel_workflow_run`.
`create_issue`, `add_issue_comment`, `create_pull_request` and `create_branch` stay Auto.
`TestGitHubNewWritesAreSeededAsAsk` (`cmd/gateway`) keeps the list equal to the
connector's writes.

Storage and policy: only the tools set to Ask are stored (`vendor_tool_approvals`,
migration 19: `app`, `tool`, `updated_by`, `updated_at`; the `gateway` app is refused).
The policy service compiles them into the Cedar set as one
`@id("app/<app>/ask_writes")` confirm permit per app (`policy.AppApproval`); a change
recompiles at once and records a new policy version under the admin. Each change is
audited as `vendor_app.approval_modes_changed` (`app`, `changed`, `ask`, `auto` counts;
no tool names). The form posts to `POST /admin/vendor-apps/<vendor>/approvals` (`app`,
`mode_<tool>` = `ask|auto` or `all` = `ask|auto`; CSRF; a bad mode is 422 "Choose Ask or
Auto for each tool."; members get the admin pages' 404).

Over MCP, an admin can read and change the same setting with
`gateway.get_tool_approvals` / `gateway.set_tool_approval` (see
[gateway-management.md](gateway-management.md)); every change through
`set_tool_approval` needs the admin's own approval first.

