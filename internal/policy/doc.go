// Package policy owns structured roles and their compilation to versioned Cedar
// policies (cedar-go): per-tool allow / confirm / deny / hidden, argument rules
// on resource identity, personal-account allowance. Deny wins, confirm is a
// separate action namespace, users and tokens can only narrow what a role
// grants. Hidden and nonexistent tools are indistinguishable to callers.
//
// Design: Brain plan 36bakiw8 sections 3 and 4; decision 490o45d0.
package policy
