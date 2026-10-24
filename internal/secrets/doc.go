// Package secrets owns ephemeral secrets: agents use secrets they cannot
// read (docs/secrets.md; design docs/plans/2026-10-23-ephemeral-secrets-design.md,
// including its "Corrections after code validation").
//
// A harness requests a secret for one target (Binding: server id, upstream
// tool and top-level argument; "secret" for a machine action). Request
// stores a pending row and returns a one-time request id (the /s/<id>
// entry link, valid LinkTTL) and a handle (sec_...) the model holds
// instead of the value. Only SHA-256 hashes of both are stored. The owner
// enters the value on the entry page (LookupRequest, Provide, Deny); it is
// envelope-encrypted with AAD {owner, "secret", record id, server id} and
// usable for TTL from then on, at most UsesTotal times. Consume is the
// dispatch-time step: one conditional UPDATE that takes a use only when
// handle, owner, harness and binding all match and the secret is provided,
// unexpired and has uses left; every other case is the single
// ErrUnavailable (ErrPending and ErrDenied only for the caller's own
// matching request). Refund gives a use back when the call never reached
// its target. Revoke ends a secret at once; the ExpiryJob
// ("secrets.expire", every 30 s) wipes values that ran out and deletes
// ended rows after Retention. OnDisableUser revokes a disabled user's
// secrets inside the identity transaction.
//
// Files:
//
//   - config.go: GATEWAY_SECRETS_ENABLED (ConfigFromEnv) and the limits
//     and defaults (TTL, uses, link lifetime, per-user request limits,
//     value and label lengths, retention), constants by design.
//   - service.go: Service, the state machine above (Request,
//     LookupRequest, Provide, Deny, Revoke, Status, Consume, Refund, List,
//     Expire, OnDisableUser), handles, request ids derived from them,
//     Binding and the errors.
//   - store.go: the Store/Tx persistence interface and NewPostgresStore
//     over internal/store (row-level security as the owner, the jobs scope
//     for the expiry job and the disable hook); secretstest.MemStore is
//     the in-memory implementation for tests.
//   - expiry.go: ExpiryJob, the jobs.Job that runs Expire.
//   - fingerprint.go: FingerprintForRequest / FingerprintForHandle, the
//     4-word check both the agent and the entry page show.
//   - tools.go: Connector, the built-in "secrets" app with
//     secrets.request: validates the target (visible to the caller, a tool
//     of a user-added or machine server through Targets, the argument in
//     its schema), stores the request and answers -32042 with the link,
//     handle and fingerprint.
//   - stage.go: NewStage, the pipeline stage immediately before dispatch:
//     finds {"$secret": handle} refs, checks status and binding, consumes,
//     substitutes the plaintext, scrubs result and error, restores the
//     handle-form arguments, refunds calls that never reached the target
//     and reports uses (UseHook, audit secret.used).
//   - portal.go and templates/: the pages GET/POST /s/{id} (entry, save,
//     deny) and GET /secrets, POST /secrets/{id}/revoke, with audit
//     secret.provided, secret.denied and secret.revoked.
//   - limiter.go: AddressLimiter, the per-address budget for failed
//     /s/{id} lookups (EntryFailureBurst per EntryFailureWindow, per
//     process).
//   - ref/: handle format, {"$secret": handle} references (find,
//     replace with plaintext or handle string, top-level binding) and the
//     word-list fingerprint.
//   - scrub/: the Scrubber that removes a value and its base64, URL,
//     JSON and hex forms from results and error text.
//
// Plaintext values, request ids and handles are never logged; logs carry
// the record id and label only.
package secrets
