// mcp-gateway policy set, compiled from structured roles (decision 490o45d0).
// Generated: do not edit. Actions: call (may run), confirm (needs approval), list (visible).
// assignment: u1 = reader

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

@id("role/reader/github.*/allow")
permit (
    principal in Role::"reader",
    action == Action::"call",
    resource in App::"github"
)
when { (context.resource has "org" && context.resource["org"] == "acme") };

@id("role/reader/github.*/allow/list")
permit (
    principal in Role::"reader",
    action == Action::"list",
    resource in App::"github"
);

@id("role/reader/jira.*/deny")
forbid (
    principal in Role::"reader",
    action in [Action::"call", Action::"confirm", Action::"list"],
    resource in App::"jira"
)
unless { ["jira.search"].contains(resource.name) };

@id("role/reader/jira.search/allow")
permit (
    principal in Role::"reader",
    action in [Action::"call", Action::"list"],
    resource == Tool::"jira.search"
);

