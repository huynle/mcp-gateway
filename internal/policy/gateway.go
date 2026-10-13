package policy

import (
	"fmt"
	"strconv"
)

// GatewayApp is the app of the built-in gateway.* management tools (Brain
// task 99b5yzdb, decision bnneszc1): list, inspect, detect, add, refresh
// and delete the caller's MCP servers over /mcp.
const GatewayApp = "gateway"

const GatewayConfirmTool = "delete_server"

// GatewayConfirmTools are management writes that always require approval.
var GatewayConfirmTools = []string{"delete_server", "set_my_rate_limit", "set_org_rate_limits", "set_app_rate_limit", "set_user_rate_limit"}

// gateway emits the implicit gateway layer, part of every policy set:
// every user may list and call the gateway.* tools without a role grant,
// and gateway.delete_server needs a confirmation. Like the owner layer of
// private servers (OwnerGrant) it is compiled into the same Cedar set, so
// the token-narrowing forbids, user restrictions and role denials still
// apply, a role allow cannot lift the delete confirmation, and the admin
// role gets nothing extra. Who actually sees the tools is decided in front
// of the policy by the gateway tools' gate (permitted to add MCP servers
// AND the "Gateway management tools" setting on, evaluated per request);
// this layer only spares admins from granting the tools in every role.
func (w *writer) gateway() {
	resource := fmt.Sprintf(`resource in %s::%s`, EntityApp, strconv.Quote(GatewayApp))
	w.policy("gateway/management", "permit", "principal", actions(ActionCall, ActionList), resource, nil, nil)
	for _, tool := range GatewayConfirmTools {
		w.policy("gateway/management/confirm_"+tool, "permit", "principal", actions(ActionConfirm), resource,
			[]string{`resource.name == ` + strconv.Quote(GatewayApp+"."+tool)}, nil)
	}
}
