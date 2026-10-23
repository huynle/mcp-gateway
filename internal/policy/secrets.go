package policy

import (
	"fmt"
	"strconv"
)

// SecretsApp is the app of the built-in ephemeral secrets tools
// (secrets.request; internal/secrets, design
// docs/plans/2026-10-23-ephemeral-secrets-design.md correction 6).
const SecretsApp = "secrets"

// secrets emits the implicit secrets layer, part of every policy set
// beside the gateway layer: every user may list and call the secrets.*
// tools without a role grant, except with a read-only token, which can
// never request a secret although secrets.request is a read (the
// token/read_only forbid only covers writes). Like the gateway layer it is
// compiled into the same Cedar set, so the token allow-list, user
// restrictions and role denials still apply: an admin can deny the app per
// role.
func (w *writer) secrets() {
	resource := fmt.Sprintf(`resource in %s::%s`, EntityApp, strconv.Quote(SecretsApp))
	w.policy("secrets/request", "permit", "principal", actions(ActionCall, ActionList), resource, nil, nil)
	w.policy("secrets/read_only", "forbid", "principal", actions(ActionCall, ActionList), resource,
		[]string{`context.token.read_only`}, nil)
}
