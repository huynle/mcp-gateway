# Third-party notices

This file lists third-party source that was copied or adapted into this repository, and states the policy that governs what may be reused. Go module dependencies declared in `go.mod` are covered by their own licenses in the module cache and are not listed here unless their code was copied into the tree. The policy is an engineering policy agreed for this project (Brain decision `0sod196t`), not legal advice.

## Policy

| License family | Examples | What we may do |
|---|---|---|
| **MIT, BSD, Apache-2.0** | Obot, ToolHive, ContextForge, agentgateway, github/github-mcp-server, korotovsky/slack-mcp-server, taylorwilsdon/google_workspace_mcp, sooperset/mcp-atlassian, Softeria/ms-365-mcp-server, docker/mcp-gateway, mcp-gateway-registry | Copy and adapt. Keep the original copyright and license header in every copied file, add a line stating the file was modified, keep any Apache `NOTICE` content, and add a row to the table below. |
| **MPL-2.0** | MCPJungle | Reference only, by preference. If a file is copied anyway it stays under MPL-2.0, is listed below, and changes to it must be published. |
| **AGPL-3.0, BSL 1.1, ELv2** | Archestra core (AGPL), ThinkWatch (BSL), Nango including `providers.yaml` (ELv2) | Never copy code or data. Documentation may be read for ideas only. |
| **Archestra enterprise code** | files matching `*.ee.*`, directories named `ee/`, or carrying the enterprise SPDX header | Do not open, read, or feed to any AI agent; its license forbids AI-system use. |

Before adapting anything: confirm the upstream license at the exact commit you copy from, record that commit below, and keep the adapted file's header intact.

## Sources

| Path in this repository | Upstream project | Upstream path / commit | License | Modifications |
|---|---|---|---|---|
| `internal/portal/static/htmx.min.js` (+ `htmx.LICENSE`) | [htmx](https://htmx.org) | `dist/htmx.min.js` from the v2.0.8 release (unpkg `htmx.org@2.0.8`) | Zero-Clause BSD | unmodified, embedded into the gateway binary and served at `/static/htmx.min.js` |
| `internal/connectors/github/tools_read.go` | [github/github-mcp-server](https://github.com/github/github-mcp-server) | `pkg/github/context_tools.go`, `issues.go`, `pullrequests.go`, `search_utils.go`, `params.go` at commit `eb47a99ddb866ca2b8a162920e6bda9521f33ebb` | MIT (Copyright (c) 2025 GitHub) | tool descriptions, argument shapes and search query handling adapted: one tool per read, snake_case `page`/`per_page` clamped to the gateway's bounds, resource identity, `connectors.Result` markers, no GraphQL enrichment; header in the file |
| `internal/connectors/github/minimal.go` | [github/github-mcp-server](https://github.com/github/github-mcp-server) | `pkg/github/minimal_types.go` at commit `eb47a99ddb866ca2b8a162920e6bda9521f33ebb` | MIT (Copyright (c) 2025 GitHub) | minimal result types and converters adapted: flattened (logins, `repo` as `owner/name`, `url`), page metadata and truncation flags added, unused fields dropped; header in the file |
| `internal/connectors/github/tools_write.go` | [github/github-mcp-server](https://github.com/github/github-mcp-server) | `pkg/github/issues.go` (`issue_write`, `add_issue_comment`), `pullrequests.go` (`create_pull_request`), `repositories.go` (`create_branch`) at commit `eb47a99ddb866ca2b8a162920e6bda9521f33ebb` | MIT (Copyright (c) 2025 GitHub) | tool descriptions and argument shapes adapted: one tool per write, snake_case arguments, no method switch / reactions / milestones / reviewers / interactive forms, the ledger operation id embedded as a hidden marker, result ids instead of full objects, the connector's error vocabulary with unknown outcomes reported; header in the file |
| `internal/connectors/microsoft/**` (design only; no code copied) | [Softeria/ms-365-mcp-server](https://github.com/Softeria/ms-365-mcp-server) | tool catalogue and Graph endpoint choices (mail search/get/send, calendar view/create with `transactionId`, drive search/create folder, Teams channels/messages) consulted at the design level in October 2026 | MIT (Copyright (c) Softeria) | nothing copied: the connector is a hand-written Go port over the gateway's own thin Graph client; tool names, schemas, result shapes, bounds, markers and reconciliation are the gateway's (decision `0sod196t`: TypeScript sources are design-level only) |
