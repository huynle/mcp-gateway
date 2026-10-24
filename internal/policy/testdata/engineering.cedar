// mcp-gateway policy set, compiled from structured roles (decision 490o45d0).
// Generated: do not edit. Actions: call (may run), confirm (needs approval), list (visible).
// assignment: u-alice = admin, engineer
// assignment: u-bob = member
// assignment: u-carol = engineer

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

@id("gateway/management/confirm_set_org_limits")
permit (
    principal,
    action == Action::"confirm",
    resource in App::"gateway"
)
when { resource.name == "gateway.set_org_limits" };

@id("gateway/management/confirm_set_user_limits")
permit (
    principal,
    action == Action::"confirm",
    resource in App::"gateway"
)
when { resource.name == "gateway.set_user_limits" };

@id("secrets/request")
permit (
    principal,
    action in [Action::"call", Action::"list"],
    resource in App::"secrets"
);

@id("secrets/read_only")
forbid (
    principal,
    action in [Action::"call", Action::"list"],
    resource in App::"secrets"
)
when { context.token.read_only };

@id("role/engineer/github.*/allow")
permit (
    principal in Role::"engineer",
    action == Action::"call",
    resource in App::"github"
)
unless { (resource.name == "github.create_issue" && (context.resource has "repo" && context.resource["repo"] like "acme/*")) || resource.name == "github.create_issue" || resource.name == "github.delete_repo" };

@id("role/engineer/github.*/allow/list")
permit (
    principal in Role::"engineer",
    action == Action::"list",
    resource in App::"github"
)
unless { ["github.create_issue", "github.delete_repo"].contains(resource.name) };

@id("role/engineer/github.create_issue/allow")
permit (
    principal in Role::"engineer",
    action in [Action::"call", Action::"list"],
    resource == Tool::"github.create_issue"
);

@id("role/engineer/github.create_issue/confirm")
permit (
    principal in Role::"engineer",
    action in [Action::"call", Action::"confirm"],
    resource == Tool::"github.create_issue"
)
when { (context.resource has "repo" && context.resource["repo"] like "acme/*") };

@id("role/engineer/github.create_issue/confirm/list")
permit (
    principal in Role::"engineer",
    action == Action::"list",
    resource == Tool::"github.create_issue"
);

@id("role/engineer/github.merge_pr/deny")
forbid (
    principal in Role::"engineer",
    action in [Action::"call", Action::"confirm"],
    resource == Tool::"github.merge_pr"
)
when { (context.resource has "repo" && context.resource["repo"] == "acme/prod") };

@id("role/engineer/slack.*/confirm")
permit (
    principal in Role::"engineer",
    action in [Action::"call", Action::"confirm"],
    resource in App::"slack"
)
unless { resource.name == "slack.list_channels" };

@id("role/engineer/slack.*/confirm/list")
permit (
    principal in Role::"engineer",
    action == Action::"list",
    resource in App::"slack"
)
unless { ["slack.list_channels"].contains(resource.name) };

@id("role/engineer/slack.list_channels/allow")
permit (
    principal in Role::"engineer",
    action in [Action::"call", Action::"list"],
    resource == Tool::"slack.list_channels"
);

@id("role/engineer/slack.post_message/deny")
forbid (
    principal in Role::"engineer",
    action in [Action::"call", Action::"confirm"],
    resource == Tool::"slack.post_message"
)
when { (context.resource has "channel" && context.resource["channel"] like "#exec-*") };

@id("role/engineer/github/personal/confirm_writes")
permit (
    principal in Role::"engineer",
    action == Action::"confirm",
    resource in App::"github"
)
when { context.account.label == "personal" && resource.kind == "write" };

@id("role/engineer/slack/personal/deny")
forbid (
    principal in Role::"engineer",
    action in [Action::"call", Action::"confirm"],
    resource in App::"slack"
)
when { context.account.label == "personal" };

@id("role/member/fake.*/deny")
forbid (
    principal in Role::"member",
    action in [Action::"call", Action::"confirm"],
    resource in App::"fake"
)
unless { resource.name == "fake.get_item" || resource.name == "fake.list_accounts" || resource.name == "fake.list_items" };

@id("role/member/fake.*/deny/list")
forbid (
    principal in Role::"member",
    action == Action::"list",
    resource in App::"fake"
)
unless { ["fake.get_item", "fake.list_accounts", "fake.list_items"].contains(resource.name) };

@id("role/member/fake.get_item/allow")
permit (
    principal in Role::"member",
    action in [Action::"call", Action::"list"],
    resource == Tool::"fake.get_item"
);

@id("role/member/fake.list_accounts/allow")
permit (
    principal in Role::"member",
    action in [Action::"call", Action::"list"],
    resource == Tool::"fake.list_accounts"
);

@id("role/member/fake.list_items/allow")
permit (
    principal in Role::"member",
    action in [Action::"call", Action::"list"],
    resource == Tool::"fake.list_items"
);

@id("restriction/u-carol/github.create_issue/confirm")
permit (
    principal == User::"u-carol",
    action == Action::"confirm",
    resource == Tool::"github.create_issue"
);

@id("restriction/u-carol/github.list_issues/deny")
forbid (
    principal == User::"u-carol",
    action in [Action::"call", Action::"confirm"],
    resource == Tool::"github.list_issues"
)
when { (context.resource has "repo" && context.resource["repo"] like "secret/*") };

@id("restriction/u-carol/github.merge_pr/deny")
forbid (
    principal == User::"u-carol",
    action in [Action::"call", Action::"confirm", Action::"list"],
    resource == Tool::"github.merge_pr"
);

@id("restriction/u-carol/slack.*/deny")
forbid (
    principal == User::"u-carol",
    action in [Action::"call", Action::"confirm", Action::"list"],
    resource in App::"slack"
);

