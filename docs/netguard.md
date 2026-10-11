# Outbound SSRF guard (`internal/netguard`)

Every call the gateway makes to a **user-supplied URL** (federated MCP servers, their OAuth endpoints, tunnels) goes through one HTTP stack, `netguard.Guard`. No other package may build its own `http.Client` / `http.Transport` for such URLs; `TestFederationUsesOnlyTheGuard` fails if anything under `internal/federation` does. Design: Brain plan `0omkv2e1` §4, decision `yhd5kcaz`, task `qm82mfer`.

Vendor connectors (GitHub, Slack, Google, ...) talk to fixed vendor hosts and are not affected.

## Wiring

```go
pm, err := netguard.NewPrometheusMetrics(metrics.Registry()) // blocked_dials_total{reason}
if err != nil { return err }
guard := netguard.New(netguard.Options{
    AllowList:        allowList,          // nil = nothing allow-listed; production: netguard.NewCachedAllowList over netguard_allow_hosts
    Timeout:          30 * time.Second,   // default
    MaxResponseBytes: 10 << 20,           // default
    Metrics:          pm,
    Log:              log,                // receives host + reason only
})
client := guard.Client() // share it; safe for concurrent use

// When a user saves a server URL, reject it early (no network access):
if err := guard.CheckURL(ctx, u); err != nil { /* errors.As(err, &blocked) with blocked *netguard.BlockedError */ }
```

## What it enforces

| Stage | Rule |
|---|---|
| URL (`CheckURL`, every request and every redirect hop) | scheme `https`; `http` only with `AllowHTTP` or an allow-listed host; no `user:pass@`; any port |
| Host literal | canonical IPv4/IPv6 literals are classified (table below); `localhost` / `*.localhost` refused; **non-canonical numeric hosts** (`2130706433`, `0x7f.1`, `017700000001`, `127.1`, `010.8.8.8`, ...) are refused outright, whatever they decode to, because Go treats them as names while browsers/libc treat them as addresses; zoned IPv6 refused; hosts outside `[A-Za-z0-9._-]` refused (use punycode) |
| Dial | resolve once with the configured resolver; refuse when **any** answer is internal and not allow-listed; dial the checked IP itself (DNS-rebinding safe). TLS SNI and `Host` keep the original name. TCP only. No proxy (environment proxies are ignored) |
| Redirects (`Client`) | at most `MaxRedirects` (5); never https→http (not even for allow-listed hosts); each hop re-validated and re-dialled through the checks |
| Response | the `Client` timeout covers the whole request; every body is wrapped in `LimitedBody`, which fails with `ErrResponseTooLarge` past `MaxResponseBytes` (measured after decompression) |

### Blocked address ranges

| Reason | Ranges |
|---|---|
| `loopback` | 127.0.0.0/8, ::1 |
| `unspecified` | 0.0.0.0, :: |
| `this_network` | 0.0.0.0/8 |
| `private` | 10/8, 172.16/12, 192.168/16, fc00::/7, fec0::/10, 64:ff9b:1::/48 |
| `metadata` | 169.254.169.254, fd00:ec2::254 (checked first, also inside embedded forms) |
| `link_local` | 169.254.0.0/16, fe80::/10 |
| `cgnat` | 100.64.0.0/10 |
| `multicast` | 224.0.0.0/4, ff00::/8 |
| `broadcast` | 255.255.255.255 |
| `reserved` | 240/4, 192.0.0/24, 192.0.2/24, 198.18/15, 198.51.100/24, 203.0.113/24, 192.88.99/24, 100::/64, 2001:db8::/32, 2001:2::/48, 2001:10::/28, 3fff::/20, and every IPv4-compatible `::a.b.c.d` |
| *(embedded)* | `::ffff:a.b.c.d` (mapped), `64:ff9b::/96` (NAT64), `2002::/16` (6to4), `2001::/32` (Teredo server and client) are judged by the embedded IPv4 |

Request-level reasons: `scheme`, `userinfo`, `network`, `ambiguous_ip_literal`, `invalid_host`, `ipv6_zone`, `invalid_address`, `too_many_redirects`, `redirect_downgrade`.

### Allow list

`CachedAllowList` (production, wired by `connector.Wire`) loads the entries from `netguard_allow_hosts` through a loader (`connector.AllowHostsLoader`), keeps them for 30 s (`Invalidate` after an admin edit), fails closed when the load fails and skips entries `NewStaticAllowList` refuses.

`AllowList.Allowed(ctx, host, ip)` opens a destination: an exact host name (case-insensitive, no wildcards) or a CIDR/IP. `StaticAllowList` is the in-memory implementation (`NewStaticAllowList("mcp.internal.example", "10.20.0.0/16")`). An allow-listed host may use plain http. Ambiguous numeric hosts, zoned IPv6 and https→http redirects can never be allow-listed. A CIDR entry matches at dial time (or for IP-literal URLs); to permit `http` for a *name*, the name itself must be listed.

## Errors, logs, metrics

- Refusals return `*netguard.BlockedError{Reason, Host}` (wrapped by `net/http` in a `*url.Error`; use `errors.As`). The message names the host and the reason only, never the path, query or credentials. The outer `*url.Error` from `http.Client` *does* include the URL (minus any password): log it with `observability.RedactError`, or log the `BlockedError` alone.
- Each refusal logs `netguard: blocked outbound request` at warn with `host` and `reason` and increments `blocked_dials_total{reason}`.

## Testing hooks

`Options.Resolver` (anything with `LookupNetIP`, default `net.DefaultResolver`) and `Options.Dial` (receives only checked `ip:port` addresses) let tests route "public" addresses to local `httptest` servers without the internet. Tests that must reach a `127.0.0.1` test server allow-list it.
