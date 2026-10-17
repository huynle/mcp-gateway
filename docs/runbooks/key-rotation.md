# Key rotation

Rotating the secrets that protect the gateway's stored data and its own credentials. Background: [`docs/crypto.md`](../crypto.md) (envelope encryption, providers), [`docs/deploy.md`](../deploy.md) "Key rotation". Checked against `internal/crypto/{vault.go,file.go,rewrap.go,migrate.go}`, `internal/rewrap`, `cmd/migrate/rewrap.go`, `internal/authserver/service.go` (`KeyRotationJob`), `cmd/gateway/main.go`, `deploy/helm/mcp-gateway/templates/_helpers.tpl`.

What is encrypted under the root key (four `*_key_id`, `*_wrapped_key`, `*_nonce`, `*_ciphertext` columns each; migrations `00004`, `00005`, `00006`, `00014`; the authoritative list is `rewrap.Columns`, table in [`docs/crypto.md`](../crypto.md) "Re-wrap"): vendor app secrets (`vendor_apps.secret_*`), connection token bundles (`connection_secrets.secret_*`), pending approval payloads (`approvals.payload_*`, NULL once consumed/denied/expired), the OAuth signing private keys (`signing_keys.private_*`) and federated MCP server credentials (`mcp_server_shared_secrets.secret_*`, `mcp_server_user_connections.secret_*`, `mcp_server_oauth_clients.secret_*`, NULL for public clients). Every envelope records the key version that wrapped its data key.

Moving from the file provider to Vault/OpenBao is a separate procedure: [`docs/crypto.md`](../crypto.md) "Moving from file to Vault/OpenBao".

## When to use

- Scheduled rotation of the Vault transit key (policy; yearly is typical) or after a suspected compromise of Vault or a database dump.
- The Vault **token** expires or leaks (static token in v1, `docs/crypto.md` "v1 limitation").
- Database passwords or OIDC client secrets rotate (same mechanism: Secret + restart).
- The OAuth **signing keys** need no operator action: `authserver.rotate_keys` (hourly) replaces the active key after `GATEWAY_OAUTH_KEY_ROTATION` (30 days), keeps the previous one for `GATEWAY_OAUTH_KEY_GRACE` (2 h) and deletes it after. To force one, see the end.

## Re-wrap

`/migrate rewrap` (in the gateway image; [`docs/crypto.md`](../crypto.md) "Re-wrap") moves every envelope to the provider's current key: `--dry-run` counts per table and key ID, the default re-wraps in batches (idempotent, resumable, safe while serving), `--verify` unwraps everything and reports failures by key ID. Raising `min_decryption_version` (or deleting a file key) before `--verify` reports `0 not under the current key, 0 failed` makes every remaining old envelope fail with `crypto.ErrUnknownKeyID`: tool calls on those connections fail before any vendor call (the connection is **not** marked `needs_reconnect`, so the user gets an error, not a reconnect prompt), vendor app secrets stop loading, signing keys inside their grace period stop verifying, and pending approvals cannot be summarised.

## Preconditions

- Vault CLI or API access with `update` on `<mount>/keys/<key>/rotate` and `read` on `<mount>/keys/<key>` (the gateway's own token only has encrypt/decrypt/read; use an operator token).
- `kubectl exec` into a gateway pod (it has the key provider variables and `GATEWAY_JOBS_DATABASE_URL`, which `/migrate rewrap` uses).
- A maintenance note to the team is not needed: rotation is online and no pod restart is required for the transit key.

## Steps: rotate the Vault transit key

```bash
export VAULT_ADDR=https://vault.internal.example.com:8200   # keyProvider.vault.addr
MOUNT=transit; KEY=mcp-gateway                               # keyProvider.vault.mount / transitKey
# 1. Current state.
vault read $MOUNT/keys/$KEY | grep -E 'latest_version|min_decryption_version|min_encryption_version'
# 2. Rotate. New wraps use the new version immediately; the gateway reads latest_version per call (crypto.VaultProvider.CurrentKeyID), no restart.
vault write -f $MOUNT/keys/$KEY/rotate
vault read $MOUNT/keys/$KEY | grep latest_version                # N+1
# 3. Prove the gateway writes under the new version: connect or reconnect ONE test account on /connections, or save a vendor app on /admin/vendor-apps (re-entering the same secret).
# 4. Count envelopes per table and key version (no changes):
kubectl -n $NS exec deploy/$RELEASE -- /migrate rewrap --dry-run
# 5. Re-wrap; repeat until "total: 0 rewrapped, 0 conflicts, 0 failed".
kubectl -n $NS exec deploy/$RELEASE -- /migrate rewrap
# 6. Verify: must print "0 not under the current key, 0 failed".
kubectl -n $NS exec deploy/$RELEASE -- /migrate rewrap --verify
# 7. Only then retire the old versions:
vault write $MOUNT/keys/$KEY/config min_decryption_version=<N+1>
```

Record the rotation (date, versions before/after, the step 4 and step 6 output) in the change log.

## Steps: rotate the Vault token

The token is read from Secret `mcp-gateway-vault` key `token` into `GATEWAY_VAULT_TOKEN` at pod start (`_helpers.tpl` `mcp-gateway.env`); env vars are not re-read, so a restart is required.

```bash
# 1. Issue a new token with the policy from docs/crypto.md (encrypt/decrypt on the key, read on keys/<key>).
vault token create -policy=mcp-gateway -orphan -period=720h -display-name=mcp-gateway-prod
# 2. Replace the Secret value (never via helm values) and restart.
kubectl -n $NS create secret generic mcp-gateway-vault --from-literal=token='hvs....' --dry-run=client -o yaml | kubectl apply -f -
kubectl -n $NS rollout restart deploy/$RELEASE && kubectl -n $NS rollout status deploy/$RELEASE
# 3. Revoke the old token only after every pod is ready (readiness includes the key-provider check).
vault token revoke <old accessor or token>
```

The migrate Job does not use Vault.

## Steps: database passwords, OIDC client secrets, log salt

Same pattern: change it at the source (PostgreSQL `ALTER ROLE ... PASSWORD`, the IdP console), update the Secret (`mcp-gateway-database` keys `app-url` / `jobs-url` / `migrate-url`; `mcp-gateway-oidc` key `<provider>-client-secret`), `kubectl rollout restart deploy/$RELEASE`. Keep the old database password valid until the rollout finishes (pods start with the new one while old ones still hold connections with the old). Changing `GATEWAY_LOG_SALT` changes every pseudonymous user hash in the logs: lines before and after cannot be correlated, which is the point if the salt leaked; otherwise leave it.

The OIDC client secret also keys the HMAC of the in-flight sign-in cookie (`internal/identity`, decision `k2qwqd3k`): sign-ins started before the rollout fail once with "state mismatch" and succeed on retry.

## Steps: the file provider (local clusters and Compose only)

`crypto.LoadKeyFile` loads the file at start, so rotation is add key → move `current` → restart → `/migrate rewrap` and `--verify` → remove the old key:

```bash
# keys.json: add {"id":"2026-10","key":"<base64 32 bytes>"} to keys, set "current":"2026-10"; keep the old entry.
kubectl -n $NS create secret generic mcp-gateway-keys --from-file=keys.json --dry-run=client -o yaml | kubectl apply -f -
kubectl -n $NS rollout restart deploy/$RELEASE    # the init container copies the file at pod start (decision 4o8myker)
```

Then `kubectl -n $NS exec deploy/$RELEASE -- /migrate rewrap` until it reports `0 rewrapped`, and `--verify` until `0 not under the current key, 0 failed`. Never delete a key id that any envelope still references (`--dry-run` lists envelopes per key id).

## Verification

- `curl /readyz` on every pod shows `key-provider` ok (Vault: the key is readable with the token in use).
- `kubectl -n $NS logs deploy/$RELEASE | grep -iE 'unknown key|decrypt'` shows nothing new. Note that a decrypt failure is **not** a refresh failure: `connections.Service.token` (`internal/connections/tokens.go`) returns it before any vendor call, so `connection_refresh_failures_total` stays flat and the connection is not marked `needs_reconnect`; the user sees the tool fail with an error and the only trace is the log line. That is why `/migrate rewrap --verify`, not the metric, is the evidence.
- A user can run a read tool on an existing connection (decrypts an old envelope) and connect a new account (encrypts under the new version).
- `/migrate rewrap --verify` reports `0 not under the current key, 0 failed`.

## Rollback

- Transit key: there is no un-rotate; the previous version keeps decrypting as long as `min_decryption_version` is below it. If you raised it too early, lower it again (`vault write $MOUNT/keys/$KEY/config min_decryption_version=<old>`): Vault allows lowering unless the version was deleted (`deletion_allowed` is off by default; leave it off).
- Vault token: re-apply the previous Secret value and restart (do this before revoking the old token).
- File provider: restore the previous `keys.json` Secret **with every key id that envelopes still reference** (after a re-wrap that is the new key, so keep both until the rollback window closes) and restart.

## Forcing an OAuth signing-key rotation

`authserver.rotate_keys` only rotates a key older than `GATEWAY_OAUTH_KEY_ROTATION`. To rotate now (suspected private key exposure): lower `gateway.oauth.keyRotation` to `1m` in values, `helm upgrade`, wait for the job (runs hourly; or restart to run it at start, then check `kubectl logs | grep authserver.key_rotated`), then restore the value and upgrade again. Access tokens signed by the retired key verify for the grace period (2 h) and then fail with `401 invalid_token`; harnesses refresh and continue. To invalidate everything at once instead, also revoke refresh-token families (user-offboarding.md shows the per-user mechanism; there is no "revoke all" button: `UPDATE oauth_refresh_tokens SET revoked_at = now() WHERE revoked_at IS NULL` through `JOBS_URL` is the manual equivalent, and every harness has to sign in again).
