# Machines: the client CLI (`mcp-gateway login` / `up`, `internal/machineclient`)

Enroll a vetted machine once, then serve every local MCP server listed in a config file through one outbound
connection, headless if you like. This page is the **client side**; the gateway side (endpoints, `/activate`, the
Machines page, caps, audit, the multiplexed WebSocket) is [machines.md](machines.md). Design: Brain decision
`ldjix4y1`. The per-tunnel token flow ([tunnel.md](tunnel.md), `mcp-gateway tunnel`) is unchanged and keeps working.

## Quick start

```sh
brew install huynle/tap/mcp-gateway              # or: curl -fsSL https://gateway.huynle.com/install | sh

mkdir -p ~/.config/mcp-gateway
cat > ~/.config/mcp-gateway/config.yaml <<'EOF'
gateway: https://gateway.huynle.com
servers:
  fusion360:
    http: http://127.0.0.1:27182/mcp
  everything:
    stdio: npx -y @modelcontextprotocol/server-everything
EOF

mcp-gateway login            # approve the machine in the browser (check its name and fingerprint)
mcp-gateway up               # registers both servers, connects, prints review links
mcp-gateway service install  # optional: keep `up` running in the background (launchd / systemd)
```

Approve the tools of each new server on the review link `up` prints (tool approval always stays in the browser).

## Commands

| Command | What it does |
|---|---|
| `mcp-gateway login [--gateway URL] [--name N] [--enroll-code mge_…] [--key-store keychain\|file] [--no-browser] [--config P]` | Creates an Ed25519 key and enrolls it. Without a code: the device flow (RFC 8628) — prints a code and `<gateway>/activate`, opens the browser when stdout is a terminal (not with `--no-browser`), polls at the server's interval (`slow_down` adds 5 s for good; `access_denied` and `expired_token` stop). With an enrollment code from the Machines page: enrolls without a browser (headless). Refuses when already logged in. |
| `mcp-gateway status [--config P]` | Validates `config.yaml`, shows the machine, its key store and fingerprint, checks the credentials (`GET /machine/v1/self`) and lists the servers with status, approved tool count and review link; configured servers not registered yet are marked. Exit 1 on any problem. |
| `mcp-gateway up [--config P] [--register-only]` | See [`up`](#up). |
| `mcp-gateway logout` | `POST /machine/v1/logout` (self-revoke), then deletes the key and `machine.json`. If the gateway cannot be reached, the local credentials are still deleted and you are told to revoke the machine on the Machines page. |
| `mcp-gateway service install\|uninstall\|status [--config P]` | See [Background service](#background-service). |

Every command takes `--help`; `--verbose` turns on debug logging (requests are logged as method, path and status only).

Defaults: `--gateway` from `gateway:` in the config; `--name` from `machine:`, else the short hostname lowercased with other
characters replaced by `-` (1–63 of `[a-z0-9_-]`, starting with a letter or digit); `--key-store` is `keychain` on macOS,
`file` elsewhere. The enrollment code can come from `$MCP_GATEWAY_ENROLL_CODE` instead of the flag (flags are visible to
other local users in the process list); codes are single-use and short-lived either way.

## Files

Config path: `--config` > `$MCP_GATEWAY_CONFIG` > `$XDG_CONFIG_HOME/mcp-gateway/config.yaml` (when absolute) >
`~/.config/mcp-gateway/config.yaml`. State (`machine.json`, `machine.key`) always lives in
`$XDG_CONFIG_HOME/mcp-gateway` or `~/.config/mcp-gateway`, whatever `--config` says.

### config.yaml

```yaml
gateway: https://gateway.huynle.com   # optional once logged in; must match the logged-in gateway
machine: huy-macbook                  # optional; the name requested at login
servers:
  fusion360:                          # the gateway server name: 1-63 of [a-z0-9_-], not a built-in app name
    http: http://127.0.0.1:27182/mcp  # http(s) only; loopback and private addresses are fine (your machine)
  everything:
    stdio: npx -y @modelcontextprotocol/server-everything   # split like a shell, but no expansion, no shell
    env: {NODE_ENV: production, API_KEY: "${MY_API_KEY}"}   # extra variables; ${VAR} comes from mcp-gateway's environment
    cwd: ~/work                       # absolute or ~/…
    inherit_env: [LANG, AWS_PROFILE]  # names copied from mcp-gateway's environment
  listed:
    command: [python3, -m, my_server] # argv form instead of stdio:
```

Rules: exactly one of `http`, `stdio` or `command` per server; `env`, `cwd`, `inherit_env` only for stdio servers;
unknown and duplicate keys are errors, and so is more than one YAML document. `http` URLs must not carry credentials.
A `${VAR}` that is not set is an error naming the variable (never the values). `gateway` must be https (http only for
`localhost`/loopback).

### Clean environment for stdio servers

A stdio server gets **only** `PATH`, `HOME`, `USER`, `LANG`, every `LC_*`, `TMPDIR` (when set), the `inherit_env`
names and the `env` entries, in that order of precedence. Nothing else from your shell — no `AWS_*`, tokens,
`MCP_GATEWAY_*` or the like — reaches it. This replaces the tunnel client's "everything but the tunnel token".

### machine.json and the key

`machine.json` (0600): `{"gateway", "machine_id", "name", "key_store"}` — no secret. It is refused when other users
can access it or another user owns it, and unknown fields are errors.

The private key never leaves the machine and is never an argument, a log line or part of an error:

- **`keychain`** (macOS default): a generic password in the login keychain (service `mcp-gateway`, account = machine
  id) holding the base64url Ed25519 seed, managed through `/usr/bin/security`. Why not a library: the release binaries
  are built with `CGO_ENABLED=0`, and the Security framework bindings (e.g. `keybase/go-keychain`) need cgo. The secret
  never goes on the command line: `security add-generic-password … -w` with `-w` last makes `security` prompt for the
  password, and the client runs it in a new session (setsid, no controlling terminal) so the prompt reads the secret
  from stdin; `find-generic-password -w` returns it on stdout. Without setsid, `security` would read the prompt from
  the terminal. The item's access list trusts `/usr/bin/security`, so the headless service reads it without a
  keychain prompt. Like a 0600 file, other processes of the same user can read it; unlike the file it is encrypted at
  rest with the login keychain and stays out of plain-file backups.
- **`file`**: `machine.key`, PKCS#8 PEM, mode 0600 in a 0700 directory, written atomically. Loading refuses a file
  that group or others can access in any way (`chmod 600` fixes it), a file owned by another user, a symlink and a
  non-regular file.

Machine login is not supported on Windows yet (owner and mode checks fail closed); `mcp-gateway tunnel` works there.

## Authentication

1. Login sends the public key as a JWK (`{"kty":"OKP","crv":"Ed25519","x":…}`) with the name and client version.
   The fingerprint shown at login and on `/activate` is the first 16 characters of the RFC 7638 thumbprint, in
   groups of 4. The gateway's `machine_id`/`name`/`gateway` answer is checked; a gateway that names a different host
   is refused (`--gateway` must be the gateway's own URL: it is the assertion audience).
2. Every API call uses a machine access token (`mgm_…`, 10 minutes) from `POST /machine/token` with a JWT assertion
   signed by the key (RFC 7523: `alg` EdDSA, `iss` = `sub` = machine id, `aud` = `<gateway>/machine/token`, 60 s
   lifetime, random `jti`). The token is cached in memory only and refreshed a minute before it expires (at most
   half its lifetime). One `401 invalid_token` is retried with a fresh token; `403 revoked` and `invalid_grant` stop
   with a message to log in again.
3. HTTP requests never follow redirects, time out after 30 s and read at most 1 MiB; server error descriptions are
   bounded and stripped of control characters before they are shown.

## `up`

1. Loads `machine.json`, the key and `config.yaml` (the config's `gateway`, if set, must equal the logged-in one).
2. `PUT /machine/v1/servers/{name}` for every server, sorted (`{"kind","path":""}`; idempotent). `409 name_taken`
   (you already have a server with that name that is not this machine's), `409 cap_exceeded` and other 4xx answers
   skip that server with a message; network and 5xx errors retry the registration with backoff.
3. Starts each stdio server with the clean environment (stdin/stdout bridged exactly like `mcp-gateway tunnel
   --stdio`; stderr to `up`'s stderr) and builds the HTTP forwarder for each http server. A server that cannot start
   is skipped with a message. A stdio server that exits on its own is restarted with backoff (1 s doubling to 1 min,
   reset after a minute of uptime); meanwhile its tunnel answers 503.
4. Runs the `Connector` (one WebSocket, `GET /machine/v1/connect`) with the map tunnel id → target. After the first
   connection it refreshes (`POST …/refresh`) every server that was just created or has no approved tools, once per
   process (retrying `409 offline` twice, 2 s apart, then on the next connection), and prints
   `server "x": N tools found …; review and approve them at <review_url>`.
5. When the connection ends it reconnects with backoff (1 s doubling to 1 min, ±20 % jitter, reset after a
   successful connection); a connection that failed before the handshake gets a fresh access token. A revoked
   machine (close 4003 / `403 revoked` / `invalid_grant`) or a replaced connection (close 4001: another `up` of the
   same machine) stops `up` with exit status 1.
6. `SIGHUP` reloads the config: an invalid file is reported and the running servers stay up; a valid one stops the
   stdio servers, registers again and reconnects. `SIGINT`/`SIGTERM` stop the stdio servers gracefully (close stdin,
   then SIGTERM, then SIGKILL, a few seconds apart) and exit 0.

`--register-only` does steps 1–2 and prints each server's review link without connecting or starting anything.
Servers removed from the config stay registered on the gateway (offline) until you delete them in the portal.

The `Connector` interface (`internal/machineclient/up.go`) is implemented by `machineclient.NewTunnelConnector`
(`tunnelconnector.go`), an adapter over `tunnel.NewMachineAgent`: `Run(ctx, gateway, token, targets, onConnected)
error`, with `Target{Kind, URL, Stdio, Handler}`. `up` builds each target's `http.Handler` (stdio bridge or HTTP
forwarder), so the adapter only routes requests by tunnel id. It returns on the first disconnect (so `up` owns
reconnecting and the status lines) and maps close code 4003 to `ErrRevoked` and 4001 to `ErrReplaced`.
`cmd/gateway`'s `TestIntegrationMachineCLIEndToEnd` runs the real `Login` + `Up` against a real gateway.

## Background service

`mcp-gateway service install` first checks that the machine is logged in and the config has servers, then:

- **macOS**: writes `~/Library/LaunchAgents/com.huynle.mcp-gateway.plist` (`ProgramArguments` = this executable,
  `up --config <absolute path>`; `RunAtLoad`, `KeepAlive`, `ThrottleInterval` 10 s; stdout and stderr to
  `~/Library/Logs/mcp-gateway.log`) and runs `launchctl bootout gui/<uid>/com.huynle.mcp-gateway` (ignored when not
  loaded) and `launchctl bootstrap gui/<uid> <plist>`.
- **Linux**: writes `~/.config/systemd/user/mcp-gateway.service` (`$XDG_CONFIG_HOME/systemd/user` when set;
  `Restart=on-failure`, `ExecReload` sends SIGHUP) and runs `systemctl --user daemon-reload`, `enable` and `restart`.
  For a headless machine that should serve while nobody is logged in: `loginctl enable-linger $USER`.

The service gets `PATH`, `LANG` and `XDG_CONFIG_HOME` of the shell that installed it (so `npx`/`uvx` resolve under
launchd's and systemd's minimal `PATH`), nothing else. The executable path is not resolved through symlinks, so a
Homebrew upgrade keeps working. `uninstall` stops and removes it (`launchctl bootout` / `systemctl --user disable
--now`, then `daemon-reload`); `status` shows whether it is installed and its state. Every command run is printed
as `$ …`. Reload after editing the config: `launchctl kickstart -k gui/$(id -u)/com.huynle.mcp-gateway` or
`systemctl --user reload mcp-gateway`.

## Tests

`go test -race ./internal/machineclient/ ./cmd/mcp-gateway/` — an in-memory fake of the gateway contract (verifies
assertion signatures, audience, lifetime and `jti` replay; scripted device-flow answers), a fake clock, a fake
`Connector`, fake stdio processes and an injected `exec` for launchctl/systemctl: nothing touches the real system.
Each flow also checks that no device code, enrollment code, access token or assertion reaches the output, the log
(captured at debug level) or an error. Opt-in, against the real login keychain:
`MCP_GATEWAY_TEST_KEYCHAIN=1 go test -run TestKeychainReal ./internal/machineclient/`. On macOS the rendered plist is
checked with `plutil -lint`.
