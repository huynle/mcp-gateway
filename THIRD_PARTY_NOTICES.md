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
| _none yet_ | | | | |
