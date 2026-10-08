// Package policy owns structured roles and their compilation to versioned Cedar
// policies (cedar-go): per-tool allow / confirm / deny / hidden, argument rules
// on resource identity, personal-account allowance. Deny wins, confirm is a
// separate action namespace, users and tokens can only narrow what a role
// grants. Hidden and nonexistent tools are indistinguishable to callers.
//
// Pieces: the role model and its JSON definition (model.go), the compiler to
// canonical Cedar text with a SHA-256 version (compile.go, golden files under
// testdata), evaluation with cedar-go (decide.go), the Service that loads,
// compiles, caches and persists versions and applies admin changes
// (service.go), the PostgreSQL Store (store.go; policytest has the in-memory
// one) and the admin role pages (handlers.go, templates/). The /mcp policy
// stage and visibility live in internal/mcp (pipeline_policy.go).
//
// Design: Brain plan 36bakiw8 sections 3 and 4; decisions 490o45d0, 0ft3v5mh,
// uamxx6ba, mh7c6z3v and m4ggt9j9 (compiler semantics).
package policy
