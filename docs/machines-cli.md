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

## Actions

`actions:` in `config.yaml` are fixed commands on this machine that receive an **ephemeral secret** the user entered on
the gateway ([secrets.md](secrets.md)), so an agent can run `sudo`, `ssh` or `psql` with a password it never sees. The
agent chooses *which* action runs and fills the declared params; the config decides *what* runs and how the secret is
handed over. Never through argv, never through a shell.

```yaml
actions:
  apt-upgrade:                                   # tool name: 1-63 of [a-z0-9_-], starting with a letter or digit
    run: sudo -A apt-get upgrade -y              # sudo -A asks the askpass helper
    secret: askpass
    timeout: 10m                                 # 1s-30m, default 2m
    description: Upgrade the packages on this box   # optional, up to 500 characters
  prod-uptime:
    run: ssh prod uptime                         # OpenSSH >= 8.4 (SSH_ASKPASS_REQUIRE)
    secret: askpass
  sudo-restart-nginx:
    run: sudo -S -p "" systemctl restart nginx   # sudo -S reads the password from stdin
    secret: stdin
  decrypt-notes:
    run: gpg --batch --pinentry-mode loopback --passphrase-fd 3 -d /home/huy/notes.gpg
    secret: fd
  report:
    run: psql -h {host} -U report -f /home/huy/q/report.sql
    secret: env:PGPASSWORD                       # weakest mode, see below
    params:
      host: '[a-z0-9.-]+'                        # the agent may only fill declared, pattern-checked params
```

Rules (checked when the config is loaded; unknown keys are errors, as everywhere in the file):

- `run` is split into words like `stdio:` (quotes and backslashes, **no expansion**: `~`, `$VAR` and globs are literal,
  so use absolute paths). The program must be an absolute path or a name found on `PATH` at load time; it is resolved
  to an absolute path then and cannot contain a placeholder.
- `{name}` in a later word is a param placeholder; `{{` and `}}` are literal braces. Every declared param must be used
  in `run`, and every placeholder must be declared. Param names are 1-32 of `[a-z0-9_]` starting with a letter;
  `secret` is reserved. A pattern is anchored (`^(?:…)$`). A call must give every declared param and nothing else,
  each matching its pattern, or nothing runs.
- `secret` is one of `stdin`, `fd`, `askpass` or `env:NAME` (`NAME` of `[A-Z0-9_]`, not starting with a digit).
- An empty secret, a NUL byte, and a line break with `stdin` or `askpass` are refused before anything runs.

| `secret:` | Delivery | Limits |
|---|---|---|
| `stdin` | the secret and `\n` on stdin (a pipe), then EOF | for programs that read a password from stdin (`sudo -S`, `passwd --stdin`, …) |
| `fd` | the secret on file descriptor 3 (a pipe), then EOF | for `--passphrase-fd 3`-style options. Not on Windows |
| `askpass` | `SUDO_ASKPASS` and `SSH_ASKPASS` point at a one-shot helper in a private 0700 temporary directory; it prints the secret from a FIFO **once** (the FIFO is removed at the first read). `SSH_ASKPASS_REQUIRE=force`, and `DISPLAY=:0` when unset | `sudo` uses it only with **`-A`**; OpenSSH honours `SSH_ASKPASS_REQUIRE` from **8.4** on; a second prompt (a wrong password, a second host) gets nothing. Until the first read a process of the same user could open the FIFO. Not on Windows |
| `env:NAME` | `NAME=<secret>` in the command's environment only | **weakest**: everything the command starts can read it, and on Linux so can same-user processes through `/proc/<pid>/environ`. The tool description says so |

How an action runs: the minimal environment of stdio servers ([above](#clean-environment-for-stdio-servers)) plus the
delivery variables; a new session (`setsid`: no controlling terminal, so nothing can prompt on your terminal); the whole
process group is killed at the timeout or when the call is cancelled (Windows kills the process only). The result is
`{exit_code, duration_ms, timed_out, stdout, stderr, stdout_truncated, stderr_truncated}`, each stream capped at
64 KiB and **scrubbed of the secret** (raw, base64, URL, JSON and hex forms; the gateway scrubs again). A non-zero exit
or a timeout is an error result (`isError`). The `[]byte` copies of the secret are zeroed after the run; Go strings
cannot be.

**Serving.** `up` serves all actions as one in-process MCP server named **`<machine>-actions`**, registered like an
`http` server (it appears in `status`, `--register-only` and the review links). Each action is one tool named after
it: the description holds the fixed command (`Runs (fixed command, no shell): …`), the delivery mode and the timeout;
the input schema is the declared params (with their patterns) plus the required `secret` argument. The name must fit
the server-name limit of 63 characters, so a machine with actions needs a name of at most 55 characters; a configured
server called `<machine>-actions` is an error. A config with only `actions:` and no `servers:` is valid (`up` and
`service install` accept it). Older CLIs refuse a config with `actions:`.

**Review.** The actions server's tools are disabled until you approve them on the review link `up` prints, like any
server's: the review shows each action's command. `up` refreshes the snapshot only for a server that was just created
or has no approved tool. After adding an action press **Refresh** on the server page and approve the new tool (until
then it is refused). **After changing an existing action** (`run`, `secret`, `params`, `timeout`), rename it: the
gateway checks calls against the reviewed snapshot, not against what the machine serves now, so a changed action
under an already approved name can run its new command without a new review. A renamed action is a new tool that
needs approval, and the old name stops working.

**Using one.** The agent asks for a secret bound to the action and calls it with the handle:

```json
{"name": "secrets.request", "arguments": {"label": "sudo password on devbox", "tool": "devbox-actions.apt-upgrade", "arg": "secret"}}
{"name": "devbox-actions.apt-upgrade", "arguments": {"secret": {"$secret": "sec_…"}}}
```

A secret bound to one action cannot reach another, nor the harness's own shell tool. Not covered: an action whose
command prints the secret in a form the scrubber does not know, or that runs a script the agent can edit. Point actions
at programs and files the agent cannot write.

## Background service

`mcp-gateway service install` first checks that the machine is logged in and the config has servers or actions, then:

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

Actions: `actions_config_test.go` (parsing, placeholders, patterns, timeouts, program resolution, the actions server
name), `actions_test.go` (Unix; every delivery mode against a helper process that reports hashes, the secret never in
the helper's argv or environment, bad params never run, scrubbed and capped output, the process group killed at the
timeout, one tool per action over MCP) and `up_actions_test.go` (registration as `<machine>-actions`, actions-only
configs, name collisions, `--register-only`, `status`). `cmd/gateway`'s `TestIntegrationSecretThroughMachineAction`
delivers a secret to an action through a real gateway and tunnel.
