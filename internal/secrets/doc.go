// Package secrets owns ephemeral secrets: agents use secrets they cannot
// read (docs/plans/2026-10-23-ephemeral-secrets-design.md, including its
// "Corrections after code validation").
//
// A harness requests a secret for one target (Binding: server id, tool and
// argument; no argument for a machine action). Request stores a pending row
// and returns a one-time request id (the /s/<id> entry link, valid
// LinkTTL) and a handle (sec_...) the model holds instead of the value.
// Only SHA-256 hashes of both are stored. The owner enters the value on the
// entry page (LookupRequest, Provide, Deny); it is envelope-encrypted with
// AAD {owner, "secret", record id, server id} and usable for TTL from then
// on, at most UsesTotal times. Consume is the dispatch-time step: one
// conditional UPDATE that takes a use only when handle, owner, harness and
// binding all match and the secret is provided, unexpired and has uses
// left; every other case is the single ErrUnavailable (ErrPending and
// ErrDenied only for the caller's own matching request). Refund gives a use
// back when the call never reached its target. Revoke ends a secret at once;
// the ExpiryJob ("secrets.expire", every 30 s) wipes values that ran out and
// deletes ended rows after Retention. OnDisableUser revokes a disabled
// user's secrets inside the identity transaction.
//
// Plaintext values, request ids and handles are never logged; logs carry
// the record id and label only.
package secrets
