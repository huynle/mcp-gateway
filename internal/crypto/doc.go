// Package crypto owns the key provider interface (dev key file, AWS KMS,
// Google Cloud KMS, Azure Key Vault, Vault) and envelope encryption: per-record
// data keys wrapped by the provider, AEAD associated data binding user,
// connection and app, and master key rotation by re-wrap.
//
// Design: Brain plan 36bakiw8 section 5; decision mh7c6z3v.
package crypto
