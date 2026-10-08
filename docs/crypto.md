# Key provider and envelope encryption

`internal/crypto` protects everything the gateway stores that must never leak in a database dump: app connection tokens, pending approval payloads, vendor app client secrets and the authorization server's signing keys. Design: Brain plan `36bakiw8` sections 2, 5 and 6; decisions `p91c25vb` (cloud-neutral, pluggable key provider), `mh7c6z3v` (envelope per record, AAD binds user/connection/app, rotation by re-wrap), `s0p05diu` (approval payloads encrypted) and `a5tgebwa` (Vault transit as the first real provider).

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
3. Run the re-wrap job (store task) until every row carries the current key ID.
4. Retire the old key: remove it from the key file, or raise `min_decryption_version` in Vault. Any envelope still referencing it then fails with `ErrUnknownKeyID`.

## Providers

Selected by `GATEWAY_KEY_PROVIDER`; `crypto.NewProviderFromEnv(os.Getenv)` builds it and `crypto.ReadinessCheck(p)` is the `/readyz` check to register (suggested name `key-provider`).

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
| `GATEWAY_KEY_PROVIDER` | all | no | `file` (default when unset) or `vault`. |
| `GATEWAY_KEY_FILE` | file | yes | Path to the JSON key file, mode 0600. |
| `GATEWAY_VAULT_ADDR` | vault | yes | Vault base URL, e.g. `https://vault.internal:8200`. |
| `GATEWAY_VAULT_TOKEN` | vault | yes | Token with encrypt/decrypt/read on the transit key. Never logged. |
| `GATEWAY_VAULT_TRANSIT_KEY` | vault | yes | Transit key name (single path segment). |
| `GATEWAY_VAULT_MOUNT` | vault | no | Transit mount path. Default `transit`. |

The unset-means-`file` default exists so local runs only need `GATEWAY_KEY_FILE`; production manifests should set `GATEWAY_KEY_PROVIDER=vault` explicitly.

## Testing

- `go test -race ./internal/crypto/...` runs everything offline: round trips, per-component AAD failures, tamper cases, rotation with a two-key file, the Vault provider against an in-process fake, and the provider contract suite against the file provider.
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
func NewProviderFromEnv(getenv func(string) string) (KeyProvider, error)
func ReadinessCheck(p KeyProvider) func(ctx context.Context) error
```
