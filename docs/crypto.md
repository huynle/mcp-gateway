# Key provider and envelope encryption

`internal/crypto` protects everything the gateway stores that must never leak in a database dump: app connection tokens, pending approval payloads, vendor app client secrets, the authorization server's signing keys, federated MCP server credentials, ephemeral secrets and the Web Push key and subscriptions (the full column inventory is `rewrap.Columns`, see "Re-wrap"). Design: Brain plan `36bakiw8` sections 2, 5 and 6; decisions `p91c25vb` (cloud-neutral, pluggable key provider), `mh7c6z3v` (envelope per record, AAD binds user/connection/app, rotation by re-wrap), `s0p05diu` (approval payloads encrypted) and `a5tgebwa` (Vault transit as the first real provider).

## How a record is encrypted

```
plaintext ──AES-256-GCM(data key, nonce, AAD)──▶ ciphertext
data key  ──KeyProvider.WrapDataKey──────────────▶ (key ID, wrapped data key)
```

- A fresh random 32-byte **data key** per record, wiped from memory after use.
- **AES-256-GCM** with a random 96-bit nonce; the GCM tag travels inside the ciphertext.
- **Associated data** `AAD{UserID, Kind, RecordID, App}` is serialized canonically (version tag + length-prefixed fields) and authenticated with the ciphertext. Changing any component, or moving the ciphertext to another row, makes decryption fail with `ErrDecrypt`. `Kind` and `RecordID` are required; `UserID` and `App` are empty for system records (vendor app secrets, signing keys).
- The provider **wraps** the data key under its current root key. The root key never leaves the provider.
- Stored as four columns: `key_id`, `wrapped_data_key`, `nonce`, `ciphertext` = `crypto.Envelope`.

Errors: `ErrDecrypt` (wrong AAD, tampered bytes, wrong key: the cause is deliberately not distinguished), `ErrUnknownKeyID` (the provider no longer holds that root key: operator action, not a retry), `ErrInvalidDataKey`. Error strings and debug logs never contain key material, plaintext or the Vault token; `TestNoKeyMaterialInLogsOrErrors` checks this with a capturing `slog` handler.

## Root key rotation

Rotation never touches ciphertext. `Rewrap` unwraps the data key under the old key ID and wraps it again under the current one; `RewrapEach` drives a batch and hands each updated envelope to a callback so the store can persist it in a transaction. Envelopes already under the current key are skipped.

Operator sequence, both providers:

1. Make a new root key current (see below). Old keys stay available for unwrapping.
2. Restart the gateway (file provider) or do nothing (Vault reads the latest version per call).
3. Run `/migrate rewrap` (see "Re-wrap") until it reports `0 rewrapped, 0 conflicts, 0 failed`, then `/migrate rewrap --verify`.
4. Retire the old key: remove it from the key file, or raise `min_decryption_version` in Vault. Any envelope still referencing it then fails with `ErrUnknownKeyID`.

## Re-wrap (`/migrate rewrap`)

`internal/rewrap` drives `RewrapEach` over every envelope column group in the schema; the `migrate` binary (shipped in the image as `/migrate`) exposes it:

```
migrate rewrap [--dry-run | --verify] [--batch N]
```

- **Provider**: built from the same variables as the gateway (`GATEWAY_KEY_PROVIDER`, `GATEWAY_KEY_FILE`, `GATEWAY_VAULT_*`); `GATEWAY_KEY_PROVIDER` must be set explicitly. Envelopes move to that provider's `CurrentKeyID`.
- **Database**: `GATEWAY_MIGRATE_DATABASE_URL` (owner), else `GATEWAY_JOBS_DATABASE_URL` (`gateway_jobs`). Both bypass row-level security; the command refuses a role that does not (`rewrap.ErrRowLevelSecurity`), because under `FORCE ROW LEVEL SECURITY` it would see no user rows and report success. `GATEWAY_DATABASE_URL` (`gateway_app`) is never used.
- **Default (re-wrap)**: table by table, pages of `--batch` rows (default 100) by primary key, one transaction per page. Only `<prefix>_key_id` and `<prefix>_wrapped_key` change; nonce and ciphertext are untouched and no plaintext is produced. Each update is a compare-and-swap on the old key ID and wrapped key, so a secret the running gateway rewrote meanwhile is never overwritten (counted as a *conflict*; a later run picks it up). Idempotent and resumable: rows already under the current key are skipped, so an interrupted run is simply started again. An envelope that cannot be unwrapped (unknown key ID, corrupt blob) is counted as *failed* and skipped, the run continues and exits non-zero; any other error (database, provider unreachable) stops it.
- `--dry-run`: counts envelopes per table and key ID and how many would move; changes nothing.
- `--verify`: unwraps every envelope's data key with the configured provider (the key is wiped immediately) and reports per table how many are under the current key and how many fail, by key ID. Exits non-zero on any failure.
- Output is counts and key IDs only; never key material, wrapped keys, plaintext or the Vault token.

Encrypted column groups (`rewrap.Columns`; four columns `<prefix>_key_id`, `_wrapped_key`, `_nonce`, `_ciphertext` each):

| Table | Prefix | What | NULL allowed |
|---|---|---|---|
| `vendor_apps` | `secret` | vendor app client secret bundle | no |
| `connection_secrets` | `secret` | app connection token bundle | no |
| `approvals` | `payload` | stored call arguments of pending/approved approvals | yes (cleared once consumed) |
| `signing_keys` | `private` | OAuth signing private key | no |
| `mcp_server_shared_secrets` | `secret` | federated server shared credentials | no |
| `mcp_server_user_connections` | `secret` | federated server per-user credentials | no |
| `mcp_server_oauth_clients` | `secret` | federated server OAuth client secret | yes (public clients) |
| `secrets` | `value` | ephemeral secret value entered on `/s/<id>` (AAD `{owner, "secret", id, server id}`) | yes (set only while provided; wiped by the expiry job) |
| `webpush_keys` | `private` | Web Push VAPID private key (AAD `{"webpush_key", id}`; [push-notifications.md](push-notifications.md)) | no |
| `push_subscriptions` | `sub` | a browser's push subscription: endpoint, p256dh and auth (AAD `{owner, "push_subscription", id}`) | no |

`internal/rewrap` tests fail when a migration adds a `*_wrapped_key` column group the registry does not list (a scan of the embedded migrations, plus an integration check against `information_schema`), so a new encrypted column cannot be left behind at the next rotation. The ledger, audit events, tokens and sessions store no envelopes (tokens and codes are hashed).

## Moving from file to Vault/OpenBao

The `migrate` provider makes the cutover possible without users reconnecting or admins re-entering secrets. It wraps **new** data keys with Vault transit and unwraps existing envelopes by key ID: transit versions (`v1`, `v2`, ...) go to Vault, every other ID to the key file, never falling back from one to the other. It refuses a key file whose IDs look like transit versions (`v<N>`, any case, including `v0`/`v01`): rename such a key (add a new file key, re-wrap with `GATEWAY_KEY_PROVIDER=file`, remove the old one) before starting. Its readiness check is Vault's (no new record can be written without it).

**OpenBao** is API-compatible for everything the gateway uses (transit `encrypt`, `decrypt`, `keys` read; `X-Vault-Token`); point `GATEWAY_VAULT_ADDR` at OpenBao. Everything below applies unchanged; read `vault` as `bao` for the CLI.

Prerequisites: the transit engine and key exist (`bao secrets enable transit`, `bao write -f transit/keys/<key>`), the gateway token has the policy above, and a **tested backup of OpenBao** exists: from the cutover on, losing the transit key makes every stored secret unreadable.

1. **Deploy with `GATEWAY_KEY_PROVIDER=migrate`**, keeping `GATEWAY_KEY_FILE` mounted and adding `GATEWAY_VAULT_ADDR`, `GATEWAY_VAULT_TOKEN`, `GATEWAY_VAULT_TRANSIT_KEY` (and `GATEWAY_VAULT_MOUNT` if not `transit`). `/readyz` must show `key-provider` ok. From now on new secrets are written under `v<N>`; old ones still read from the file. During the rolling update, a pod still on `file` cannot read a secret a `migrate` pod has just written (it fails with `ErrUnknownKeyID` until it is replaced); keep the rollout short and avoid admin edits while it runs.
2. **Dry run.** The image carries `/migrate`, and a gateway pod already has the key provider variables and `GATEWAY_JOBS_DATABASE_URL`, so run it in place (distroless has no shell; `kubectl exec` runs the binary directly; if the pod has no `GATEWAY_JOBS_DATABASE_URL`, use a one-off pod from the same image with `GATEWAY_MIGRATE_DATABASE_URL` instead):

   ```bash
   kubectl -n $NS exec deploy/$RELEASE -- /migrate rewrap --dry-run
   ```

   Expect every table of the inventory above, counts under the file key ID(s), and `current key v<N>`.
3. **Re-wrap**: `kubectl -n $NS exec deploy/$RELEASE -- /migrate rewrap` (optionally `--batch 50`). It is safe while the gateway serves traffic. Run it again until it prints `total: 0 rewrapped, 0 conflicts, 0 failed`. A non-zero `failed` means envelopes under a key ID neither provider holds; investigate with `--verify` (failures by key ID) before continuing.
4. **Verify**: `kubectl -n $NS exec deploy/$RELEASE -- /migrate rewrap --verify` must print `0 not under the current key, 0 failed`: every envelope is then under the current Vault version and unwraps through Vault, which is exactly what the `vault` provider will need. (For a check with the Vault-only configuration before switching, run a one-off pod from the same image with the same environment minus `GATEWAY_KEY_FILE` and `GATEWAY_KEY_PROVIDER=vault`.)
5. **Switch the gateway to `GATEWAY_KEY_PROVIDER=vault`** (remove nothing else yet) and roll out. Check `/readyz`, run `kubectl -n $NS exec deploy/$RELEASE -- /migrate rewrap --verify` again (now Vault only: `0 failed`), and check that a user can use an existing connection (reads a re-wrapped token) and that saving a vendor app works.
6. **Keep `keys.json`** (the Secret and an offline copy) until a database backup taken **after** the switch has been restored and verified (`/migrate rewrap --verify` with `vault` against the restored copy). Backups taken before the cutover still need the file key to be read.
7. **Retire the file key**: delete the Secret, its SOPS source and the mount; remove `GATEWAY_KEY_FILE`. From here on, root key rotation is the Vault procedure under "Root key rotation" (`rotate`, `/migrate rewrap`, `--verify`, raise `min_decryption_version`).

Rollback: from any step, go back to `GATEWAY_KEY_PROVIDER=migrate`, which reads both kinds of envelope as long as the key file and Vault are both available. Going back to `file` alone is only possible while nothing has been written or re-wrapped under Vault (before step 1's rollout served writes); otherwise those secrets would be unreadable.

The Helm chart in `deploy/helm` renders `keyProvider.type` `file` or `vault` only; a deployment that needs `migrate` sets the environment itself (or extends the chart).

## Providers

Selected by `GATEWAY_KEY_PROVIDER` (`file`, `vault`, or `migrate` for the cutover between them, see "Moving from file to Vault/OpenBao"); `crypto.NewProviderFromEnv(os.Getenv)` builds it and `crypto.ReadinessCheck(p)` is the `/readyz` check to register (suggested name `key-provider`).

### `file` (local development and Compose only)

A JSON file with one or more 32-byte keys and a `current` marker:

```json
{
  "current": "2026-01",
  "keys": [
    {"id": "2026-01", "key": "<base64 of 32 random bytes>"},
    {"id": "2025-07", "key": "<base64 of 32 random bytes>"}
  ]
}
```

- Data keys are wrapped with AES-256-GCM under the current key, with the key ID as associated data.
- The file must be mode `0600` (group/world access is rejected), keys must be exactly 32 bytes, IDs unique, and no two keys may share material. Unknown JSON fields are errors.
- Rotate by adding a key and moving `current`; retire by deleting the entry after re-wrap.
- `crypto.GenerateKeyFile(path, id)` writes a fresh file with mode 0600 and refuses to overwrite an existing one (that would orphan every envelope).
- Readiness: the file loaded at startup and its current key is present.

Not for production: anyone who can read the file can decrypt every secret.

### `vault` (staging and production)

HashiCorp Vault (or OpenBao) **transit** secrets engine over its HTTP API; no Vault SDK dependency.

- `WrapDataKey` → `POST <mount>/encrypt/<key>`; `UnwrapDataKey` → `POST <mount>/decrypt/<key>`; `CurrentKeyID` → `GET <mount>/keys/<key>` (`latest_version`).
- The transit **key version is the envelope key ID**: `v1`, `v2`, ... The wrapped data key is Vault's `vault:v<N>:...` ciphertext. The provider checks that the stored key ID and the ciphertext version agree.
- Rotation: `vault write -f <mount>/keys/<key>/rotate`. New wraps use the new version immediately; old versions decrypt until `min_decryption_version` is raised (`vault write <mount>/keys/<key>/config min_decryption_version=N`), after which they map to `ErrUnknownKeyID`.
- Token policy needed:

  ```hcl
  path "transit/encrypt/gateway" { capabilities = ["update"] }
  path "transit/decrypt/gateway" { capabilities = ["update"] }
  path "transit/keys/gateway"    { capabilities = ["read"] }
  ```

- Readiness: the key is readable with the configured token.
- Requests honor the caller's context and a 10 s client timeout; debug logs carry operation, key name, status and duration only.
- v1 limitation: a static token from the cluster secret store. Token renewal and Kubernetes/AppRole auth are follow-ups.

## Environment variables

| Variable | Provider | Required | Meaning |
|---|---|---|---|
| `GATEWAY_KEY_PROVIDER` | all | no | `file` (default when unset), `vault`, or `migrate` (file keys read, Vault wraps; cutover only). |
| `GATEWAY_KEY_FILE` | file, migrate | yes | Path to the JSON key file, mode 0600. |
| `GATEWAY_VAULT_ADDR` | vault, migrate | yes | Vault / OpenBao base URL, e.g. `https://vault.internal:8200`. |
| `GATEWAY_VAULT_TOKEN` | vault, migrate | yes | Token with encrypt/decrypt/read on the transit key. Never logged. |
| `GATEWAY_VAULT_TRANSIT_KEY` | vault, migrate | yes | Transit key name (single path segment). |
| `GATEWAY_VAULT_MOUNT` | vault, migrate | no | Transit mount path. Default `transit`. |

The unset-means-`file` default exists so local runs only need `GATEWAY_KEY_FILE`; production manifests should set `GATEWAY_KEY_PROVIDER=vault` explicitly.

## Testing

- `go test -race ./internal/crypto/...` runs everything offline: round trips, per-component AAD failures, tamper cases, rotation with a two-key file, the Vault provider against an in-process fake, and the provider contract suite against the file, Vault (fake) and migrating providers.
- `cryptotest.NewFakeVault` is the in-process transit double (AES-GCM per key version, rotation, `min_decryption_version`, token checks); other packages use it too (`cmd/migrate`'s file-to-Vault cutover test).
- `make test-integration` covers the re-wrap: `internal/rewrap` (every table, NULL groups, batching, idempotence, conflicts, unreadable envelopes, RLS refusal, registry vs. schema) and `cmd/migrate` (`TestIntegrationRewrapFileToVault`: data written under the file provider, `rewrap --dry-run`, `rewrap`, `--verify` with Vault only, then the connections service and the authorization server read everything back with Vault only).
- `internal/crypto/cryptotest.ProviderContract(t, Harness{Provider, Rotate})` is the contract every provider must pass; new providers (cloud KMS) call it from their own tests.
- The Vault contract test runs against a real transit engine when `GATEWAY_VAULT_ADDR` is set and is skipped otherwise. It creates and **rotates** the key named by `GATEWAY_VAULT_TRANSIT_KEY` (default `mcp-gateway-contract-test`), so only point it at a dev Vault:

  ```bash
  docker run -d --name vault-dev -p 18200:8200 -e VAULT_DEV_ROOT_TOKEN_ID=root hashicorp/vault:1.17
  curl -s -X POST -H 'X-Vault-Token: root' -d '{"type":"transit"}' http://127.0.0.1:18200/v1/sys/mounts/transit
  GATEWAY_VAULT_ADDR=http://127.0.0.1:18200 GATEWAY_VAULT_TOKEN=root go test -race -run TestVaultProviderContract ./internal/crypto/
  docker rm -f vault-dev
  ```

## API summary

```go
type KeyProvider interface {
    WrapDataKey(ctx, plaintextKey []byte) (keyID string, wrapped []byte, err error)
    UnwrapDataKey(ctx, keyID string, wrapped []byte) ([]byte, error)
    CurrentKeyID(ctx) (string, error)
}
type AAD struct{ UserID, Kind, RecordID, App string }   // Validate(), Bytes()
type Envelope struct{ KeyID string; WrappedDataKey, Nonce, Ciphertext []byte }

func Encrypt(ctx, p KeyProvider, aad AAD, plaintext []byte) (Envelope, error)
func Decrypt(ctx, p KeyProvider, aad AAD, env Envelope) ([]byte, error)
func Rewrap(ctx, p KeyProvider, env Envelope) (Envelope, error)
func RewrapEach(ctx, p KeyProvider, envs []Envelope, apply func(ctx, i int, updated Envelope) error) (RewrapStats, error)

func NewStaticProvider(currentID string, keys map[string][]byte) (*StaticProvider, error)
func LoadKeyFile(path string) (*StaticProvider, error)
func GenerateKeyFile(path, keyID string) error
func NewVaultProvider(cfg VaultConfig) (*VaultProvider, error)   // (*VaultProvider).Ready(ctx)
func NewMigratingProvider(legacy *StaticProvider, target *VaultProvider) (*MigratingProvider, error)
func NewProviderFromEnv(getenv func(string) string) (KeyProvider, error)
func ReadinessCheck(p KeyProvider) func(ctx context.Context) error

// internal/rewrap
var Columns []Column                                              // every envelope column group
func Plan(ctx, db, p) ([]TableReport, error)                      // counts by key ID (dry run)
func Run(ctx, db, p, Options{BatchSize}) ([]TableReport, error)   // ErrIncomplete on unreadable envelopes
func Verify(ctx, db, p) ([]TableReport, error)                    // ErrVerifyFailed on any failure
```
