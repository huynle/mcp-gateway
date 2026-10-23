// Package machineclient is the client side of machine enrollment (Brain
// decision ldjix4y1, docs/machines-cli.md): it enrolls the user's machine
// with the gateway and serves the local MCP servers of config.yaml through
// one connection.
//
//   - config.yaml (Config, LoadConfig): the gateway, the machine name and the
//     servers (http URL or stdio command); unknown keys are rejected.
//   - The machine key (Ed25519) lives in the macOS keychain or a 0600 file
//     (KeyStore); machine.json (State) records the gateway and machine id.
//   - Login: the OAuth device flow (RFC 8628) approved by the user at
//     /activate, or a one-time enrollment code for headless machines.
//   - TokenSource signs short EdDSA assertions (RFC 7523) and caches the
//     10-minute machine access token; MachineAPI calls /machine/v1/*.
//   - Up registers every server (idempotent PUT), starts stdio servers with
//     a clean environment (BuildStdioSpec), runs the Connector (the
//     multiplexed WebSocket), refreshes new servers and prints their review
//     links, reconnects with backoff and reloads on SIGHUP.
//   - Actions (actions_config.go, actions.go): `actions:` in config.yaml
//     are fixed commands (no shell) that receive an ephemeral secret by
//     stdin, fd 3, a one-shot askpass helper or one environment variable,
//     never argv. Up serves them as the in-process http server
//     "<machine>-actions", one tool per action (input: the declared
//     params and "secret"), and scrubs the secret from the output
//     (docs/plans/2026-10-23-ephemeral-secrets-design.md).
//   - ServiceInstall / ServiceUninstall / ServiceStatus manage the launchd
//     LaunchAgent or systemd user unit running `mcp-gateway up`.
//
// Keys, tokens, assertions, device and enrollment codes are never logged,
// printed or put in errors or process arguments.
package machineclient
