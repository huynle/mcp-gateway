# Key rotation

Rotating the secrets that protect the gateway's stored data and its own credentials. Background: [`docs/crypto.md`](../crypto.md) (envelope encryption, providers), [`docs/deploy.md`](../deploy.md) "Key rotation". Checked against `internal/crypto/{vault.go,file.go,rewrap.go}`, `internal/authserver/service.go` (`KeyRotationJob`), `cmd/gateway/main.go`, `deploy/helm/mcp-gateway/templates/_helpers.tpl`.

What is encrypted under the root key (four `*_key_id`, `*_wrapped_key`, `*_nonce`, `*_ciphertext` columns each; migrations `00004`, `00005`, `00006`): vendor app secrets (`vendor_apps.secret_*`), connection token bundles (`connection_secrets.secret_*`), pending approval payloads (`approvals.payload_*`, NULL once consumed/denied/expired) and the OAuth signing private keys (`signing_keys.private_key_*`). Every envelope records the key version that wrapped its data key.

## When to use

- Scheduled rotation of the Vault transit key (policy; yearly is typical) or after a suspected compromise of Vault or a database dump.
- The Vault **token** expires or leaks (static token in v1, `docs/crypto.md` "v1 limitation").
- Database passwords or OIDC client secrets rotate (same mechanism: Secret + restart).
- The OAuth **signing keys** need no operator action: `authserver.rotate_keys` (hourly) replaces the active key after `GATEWAY_OAUTH_KEY_ROTATION` (30 days), keeps the previous one for `GATEWAY_OAUTH_KEY_GRACE` (2 h) and deletes it after. To force one, see the end.

## Known gap: no re-wrap command yet

`crypto.Rewrap` and `crypto.RewrapEach` (`internal/crypto/rewrap.go`) implement re-wrapping a batch of envelopes under the current key version, and they are tested, but **nothing in the binaries calls them**: there is no CLI, job or admin page that walks the four tables (`grep -rn RewrapEach cmd internal/jobs internal/store` finds nothing). `docs/crypto.md` step 3 ("run the re-wrap job") describes the intended design, not something you can run. Until Brain draft task **`nsyw7xml`** lands, a Vault transit rotation is safe but **incomplete**:

- new envelopes use the new version at once (`WrapDataKey` encrypts under `latest_version`);
- old envelopes keep decrypting as long as `min_decryption_version` is **not raised**;
- raising `min_decryption_version` with old envelopes still present makes every one of them fail with `crypto.ErrUnknownKeyID`: tool calls on those connections fail before any vendor call (the connection is **not** marked `needs_reconnect`, so the user gets an error, not a reconnect prompt), vendor app secrets stop loading (every new connect flow of that vendor fails), signing keys still inside their grace period stop verifying, and pending approvals cannot be summarised.

So: rotate, verify, and **do not raise `min_decryption_version`** until the re-wrap command exists and reports zero rows under the old version. Step 5 below shows how to count them.

## Preconditions

- Vault CLI or API access with `update` on `<mount>/keys/<key>/rotate` and `read` on `<mount>/keys/<key>` (the gateway's own token only has encrypt/decrypt/read; use an operator token).
- `JOBS_URL` (README conventions) for the count queries; `psql`.
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
# 3. Prove the gateway writes under the new version: create and revoke a harness token is not enough (tokens are hashed, not encrypted);
#    instead connect or reconnect ONE test account on /connections, or save a vendor app on /admin/vendor-apps (re-entering the same secret).
# 4. Count envelopes per key version (metadata only; the views do not expose the ciphertext columns, so this reads the base tables' key-id column through the jobs role):
psql "$JOBS_URL" -c "
  SELECT 'vendor_apps' t, secret_key_id k, count(*) FROM vendor_apps GROUP BY 2
  UNION ALL SELECT 'connection_secrets', secret_key_id, count(*) FROM connection_secrets GROUP BY 2
  UNION ALL SELECT 'approvals', payload_key_id, count(*) FROM approvals WHERE payload_key_id IS NOT NULL GROUP BY 2
  UNION ALL SELECT 'signing_keys', private_key_id, count(*) FROM signing_keys GROUP BY 2
  ORDER BY 1,2;"
# 5. Re-wrap: NOT AVAILABLE YET (draft task nsyw7xml). When it exists it will run until the query above shows only v<N+1>.
# 6. Only after step 5 reports zero rows under old versions:
#    vault write $MOUNT/keys/$KEY/config min_decryption_version=<N+1>
```

Record the rotation (date, versions before/after, the count from step 4) in the change log. Until the re-wrap exists, add a reminder to re-run step 4 after `nsyw7xml` lands and then do step 6.

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

`crypto.LoadKeyFile` loads the file at start, so rotation is add key → move `current` → restart → (re-wrap, see gap) → remove the old key:

```bash
# keys.json: add {"id":"2026-10","key":"<base64 32 bytes>"} to keys, set "current":"2026-10"; keep the old entry.
kubectl -n $NS create secret generic mcp-gateway-keys --from-file=keys.json --dry-run=client -o yaml | kubectl apply -f -
kubectl -n $NS rollout restart deploy/$RELEASE    # the init container copies the file at pod start (decision 4o8myker)
```

Never delete a key id that any envelope still references (step 4 query above: the key id column holds the file key id); without the re-wrap command that means never deleting it.

## Verification

- `curl /readyz` on every pod shows `key-provider` ok (Vault: the key is readable with the token in use).
- `kubectl -n $NS logs deploy/$RELEASE | grep -iE 'unknown key|decrypt'` shows nothing new. Note that a decrypt failure is **not** a refresh failure: `connections.Service.token` (`internal/connections/tokens.go`) returns it before any vendor call, so `connection_refresh_failures_total` stays flat and the connection is not marked `needs_reconnect`; the user sees the tool fail with an error and the only trace is the log line. That is why the step-4 count, not the metric, is the evidence.
- A user can run a read tool on an existing connection (decrypts an old envelope) and connect a new account (encrypts under the new version).
- The step-4 query shows new rows under the new version.

## Rollback

- Transit key: there is no un-rotate; the previous version keeps decrypting as long as `min_decryption_version` is below it. If you raised it too early, lower it again (`vault write $MOUNT/keys/$KEY/config min_decryption_version=<old>`): Vault allows lowering unless the version was deleted (`deletion_allowed` is off by default; leave it off).
- Vault token: re-apply the previous Secret value and restart (do this before revoking the old token).
- File provider: restore the previous `keys.json` Secret and restart; nothing was re-wrapped, so every envelope still decrypts.

## Forcing an OAuth signing-key rotation

`authserver.rotate_keys` only rotates a key older than `GATEWAY_OAUTH_KEY_ROTATION`. To rotate now (suspected private key exposure): lower `gateway.oauth.keyRotation` to `1m` in values, `helm upgrade`, wait for the job (runs hourly; or restart to run it at start, then check `kubectl logs | grep authserver.key_rotated`), then restore the value and upgrade again. Access tokens signed by the retired key verify for the grace period (2 h) and then fail with `401 invalid_token`; harnesses refresh and continue. To invalidate everything at once instead, also revoke refresh-token families (user-offboarding.md shows the per-user mechanism; there is no "revoke all" button: `UPDATE oauth_refresh_tokens SET revoked_at = now() WHERE revoked_at IS NULL` through `JOBS_URL` is the manual equivalent, and every harness has to sign in again).
