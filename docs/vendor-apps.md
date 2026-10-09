# Vendor app registration runbook (Team MCP Gateway v1)

Status: ready to execute. Written 2026-10-08 against the Team MCP Gateway v1 design
(Brain plan `36bakiw8`, sections 5 and 10) and the app-connections decision (`mh7c6z3v`).
Every scope, permission and console step below was checked against the vendor's current
documentation on 2026-10-08; the sources are listed at the end.

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
(Google, Microsoft, Atlassian, Slack user scopes) register **both** sets; the gateway
requests only what the role needs. GitHub App permissions are declared once for the
whole app (no per-user split); the gateway's policy layer enforces read vs write there.

### 0.5 Company admin consent summary

| Vendor | Admin action required for company accounts |
| --- | --- |
| GitHub | An **org owner** must install the GitHub App on the company organization (installation = consent). Personal accounts: each user installs on their own account. |
| Slack | If the workspace restricts app installs ("Admin-approved apps"), a Slack admin must approve the app. The bot token is created when an admin installs the app into the company workspace. |
| Atlassian | No admin consent step in the 3LO flow; users consent per site. Confirm with the Atlassian org admin that third-party OAuth apps are not blocked for the company sites. |
| Google | Internal app: Workspace admin may need to allow the app / scopes under Admin console -> Security -> API controls. If the company is **not** a Workspace org there is no Internal app and company users share the External app's 100-user cap. |
| Microsoft | `ChannelMessage.Read.All` (delegated) **requires admin consent**. Tenants that disable user consent need an admin to consent to the whole permission set. |

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
| Metadata | Read (mandatory, set automatically) | all |
| Issues | Read and write | read: `github.get_issue`; write: `github.create_issue`, `github.add_issue_comment` |
| Pull requests | Read and write | read: `github.get_pull_request`, `github.list_pull_request_files`; write: `github.create_pull_request`, `github.add_issue_comment` (on PRs) |
| Contents | Read and write | write: `github.create_branch` (`POST /repos/{owner}/{repo}/git/refs`); read also satisfies `github.get_pull_request` |

Organization permissions: none. Account permissions: none.

`github.get_me` (`GET /user`) and `github.search_issues` (`GET /search/issues`) require
no permissions; search results are limited to repositories the installation and the user
can see.

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
| `reactions:write` | write | `slack.add_reaction` |

Optional, only if DMs/group DMs should be readable through the gateway: `im:read`,
`mpim:read`, `im:history`, `mpim:history`. Not in v1 by default.

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
      - reactions:write
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
  `drive.metadata.readonly`) are what trigger the heavier path if the app is ever
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
| `ChannelMessage.Send` | write | `teams.post_channel_message` | No |

No application permissions. Teams permissions are **not supported for personal
Microsoft accounts**; the gateway hides the Teams tools for those connections (design
section 5).

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

- GitHub: `get_me`, `search_issues` (no permission), `get_issue` (Issues R),
  `get_pull_request`, `list_pull_request_files` (Pull requests R), `create_issue`,
  `add_issue_comment` (Issues W), `create_pull_request` (Pull requests W),
  `create_branch` (Contents W).
- Slack: `list_channels` (`channels:read`, `groups:read`), `read_channel_history`,
  `get_thread` (`channels:history`, `groups:history`), `search_messages` (`search:read`),
  `get_user` (`users:read`), `post_message`, `reply_in_thread` (`chat:write`),
  `add_reaction` (`reactions:write`). Approval DMs: bot `chat:write`, `im:write`.
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
  `reactions.add`, `conversations.open` (`docs.slack.dev/reference/methods/...`);
  "Installing with OAuth" (HTTPS redirect requirement); "Handling user interaction"
  (Interactivity & Shortcuts -> Request URL); "Verifying requests from Slack".
- Atlassian: Jira scopes for OAuth 2.0 (3LO)
  (`developer.atlassian.com/cloud/jira/platform/scopes-for-oauth-2-3LO-and-forge-apps/`);
  Confluence scopes (`developer.atlassian.com/cloud/confluence/scopes-for-oauth-2-3LO-and-forge-apps/`);
  OAuth 2.0 (3LO) apps guide (`developer.atlassian.com/cloud/jira/platform/oauth-2-3lo-apps/`:
  console, callback URL, `offline_access`, accessible-resources, distribution/sharing);
  Confluence v2 `GET /pages/{id}` and `POST /pages` scope lines; Jira v3 issue search
  scope line.
