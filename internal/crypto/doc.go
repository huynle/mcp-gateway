// Package crypto owns the pluggable root-key provider and per-record envelope
// encryption used for connection secrets, approval payloads, vendor app
// secrets and signing keys.
//
// A KeyProvider wraps and unwraps per-record data keys under a root key it
// never reveals. Two implementations ship: a dev key file (LoadKeyFile, local
// only) and HashiCorp Vault transit (NewVaultProvider, the first production
// provider; cloud KMS providers follow behind the same interface and the
// contract suite in cryptotest). Encrypt and Decrypt seal a record with a
// random data key and AES-256-GCM, authenticating the canonical AAD (user,
// record kind, record ID, app) so ciphertext cannot be moved between rows.
// Rewrap and RewrapEach rotate root keys by re-wrapping data keys without
// touching ciphertext. NewProviderFromEnv and ReadinessCheck wire the chosen
// provider into main and /readyz.
//
// Operator documentation, including environment variables and rotation
// procedures, is in docs/crypto.md.
//
// Design: Brain plan 36bakiw8 sections 2, 5, 6; decisions p91c25vb, mh7c6z3v,
// s0p05diu, a5tgebwa.
package crypto
