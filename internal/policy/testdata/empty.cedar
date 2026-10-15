// mcp-gateway policy set, compiled from structured roles (decision 490o45d0).
// Generated: do not edit. Actions: call (may run), confirm (needs approval), list (visible).
// assignments: none

@id("token/read_only")
forbid (
    principal,
    action in [Action::"call", Action::"list"],
    resource
)
when { context.token.read_only && resource.kind == "write" };

@id("token/allow_list")
forbid (
    principal,
    action in [Action::"call", Action::"list"],
    resource
)
when { context.token.restricted && !(context.token.apps.contains(resource.app) || context.token.tools.contains(resource.name)) };

@id("gateway/management")
permit (
    principal,
    action in [Action::"call", Action::"list"],
    resource in App::"gateway"
);

@id("gateway/management/confirm_delete_server")
permit (
    principal,
    action == Action::"confirm",
    resource in App::"gateway"
)
when { resource.name == "gateway.delete_server" };

@id("gateway/management/confirm_set_my_rate_limit")
permit (
    principal,
    action == Action::"confirm",
    resource in App::"gateway"
)
when { resource.name == "gateway.set_my_rate_limit" };

@id("gateway/management/confirm_set_org_rate_limits")
permit (
    principal,
    action == Action::"confirm",
    resource in App::"gateway"
)
when { resource.name == "gateway.set_org_rate_limits" };

@id("gateway/management/confirm_set_app_rate_limit")
permit (
    principal,
    action == Action::"confirm",
    resource in App::"gateway"
)
when { resource.name == "gateway.set_app_rate_limit" };

@id("gateway/management/confirm_set_user_rate_limit")
permit (
    principal,
    action == Action::"confirm",
    resource in App::"gateway"
)
when { resource.name == "gateway.set_user_rate_limit" };

@id("gateway/management/confirm_set_tool_approval")
permit (
    principal,
    action == Action::"confirm",
    resource in App::"gateway"
)
when { resource.name == "gateway.set_tool_approval" };

