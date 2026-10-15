package slack

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	goslack "github.com/slack-go/slack"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Channel-management write tool names (Brain decision aud38ptd: all
// through the user's own token, never Slack's admin.* APIs).
const (
	ToolCreateChannel     = "create_channel"
	ToolRenameChannel     = "rename_channel"
	ToolArchiveChannel    = "archive_channel"
	ToolUnarchiveChannel  = "unarchive_channel"
	ToolSetChannelTopic   = "set_channel_topic"
	ToolSetChannelPurpose = "set_channel_purpose"
	ToolJoinChannel       = "join_channel"
	ToolLeaveChannel      = "leave_channel"
	ToolInviteToChannel   = "invite_to_channel"
	ToolRemoveFromChannel = "remove_from_channel"
)

// Slack user-token scopes of the channel-management tools. A user token
// manages public channels with channels:write and private ones with
// groups:write (channels:manage is a bot-token scope; user tokens use
// channels:write for conversations.create, rename, archive, unarchive,
// setTopic, setPurpose, join, leave, invite and kick).
const (
	ScopeChannelsWrite = "channels:write"
	ScopeGroupsWrite   = "groups:write"
)

// MaxInviteUsers bounds one invite_to_channel call (Slack accepts up to
// 1000 ids; a conversational harness never needs that many and a typo
// should not invite a department).
const MaxInviteUsers = 30

// ClassConflict: the request collides with existing state (name_taken:
// a channel with that name already exists, perhaps archived or private).
const ClassConflict = "conflict"

// channelNewNameRE is what Slack accepts as a channel name: lower-case
// letters, digits, hyphens and underscores, at most 80 characters.
var channelNewNameRE = regexp.MustCompile(`^[a-z0-9_-]{1,80}$`)

// ChannelChange is the result of the channel-management writes: the
// channel id, what was done (Action) and, where it applies, the new name,
// topic, purpose or the users invited / removed. Already says the
// desired state already held (already_archived, not_archived,
// already_in_channel, not_in_channel on leave): the call succeeded
// without changing anything.
type ChannelChange struct {
	Channel   string   `json:"channel"`
	Name      string   `json:"name,omitempty"`
	IsPrivate bool     `json:"is_private,omitempty"`
	Action    string   `json:"action"`
	Already   bool     `json:"already,omitempty"`
	Topic     string   `json:"topic,omitempty"`
	Purpose   string   `json:"purpose,omitempty"`
	Users     []string `json:"users,omitempty"`
	User      string   `json:"user,omitempty"`
}

// channelTools declares the channel-management writes. Each reconciles
// by stable id: the channel (and the name, topic hash, users) are known
// before the call, so Check reads the channel's state back.
func (c *Connector) channelTools() []connectors.Tool {
	single := connectors.Bounds{MaxResultBytes: c.bounds.MaxResultBytes}
	stable := func(check func(context.Context, connectors.ReconcileInput) (connectors.ReconcileResult, error)) connectors.Reconciliation {
		return connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: check}
	}
	scopes := []string{ScopeChannelsWrite}
	tool := func(name, desc string, props []property, required []string, ident func(map[string]any) map[string]string, check func(context.Context, connectors.ReconcileInput) (connectors.ReconcileResult, error)) connectors.Tool {
		return connectors.Tool{
			App: App, Name: name, Kind: connectors.KindWrite, Description: desc,
			InputSchema: objectSchema(props, required), RequiredScopes: scopes,
			ResourceIdentity: ident, Reconcile: stable(check), ResultIDs: channelChangeIDs, Bounds: single,
		}
	}
	nameProp := func(desc string) property { return property{"name", "string", desc, nil} }
	return []connectors.Tool{
		tool(ToolCreateChannel, "Create a Slack channel as the connected user (who becomes its first member). Public by default; "+
			"is_private creates a private channel (needs the groups:write scope). Returns the new channel's id and name.",
			[]property{
				nameProp("Channel name: lower-case letters, digits, hyphens and underscores, at most 80 characters (a leading # is ignored)."),
				{"is_private", "boolean", "Create a private channel instead of a public one. Default: false.", nil},
			}, []string{"name"}, createIdentity, c.checkCreated),
		tool(ToolRenameChannel, "Rename a Slack channel the connected user may manage. Returns the channel id and its new name.",
			[]property{channelProperty, nameProp("The new channel name (lower-case letters, digits, hyphens, underscores; at most 80 characters).")},
			[]string{"channel", "name"}, identityWith(newNameIdentity), c.checkRenamed),
		tool(ToolArchiveChannel, "Archive a Slack channel. Idempotent: an already archived channel is reported with already: true.",
			[]property{channelProperty}, []string{"channel"}, identity(), c.checkArchived(true)),
		tool(ToolUnarchiveChannel, "Unarchive a Slack channel. Idempotent: a channel that is not archived is reported with already: true.",
			[]property{channelProperty}, []string{"channel"}, identity(), c.checkArchived(false)),
		tool(ToolSetChannelTopic, "Set the topic of a Slack channel (an empty topic clears it).",
			[]property{channelProperty, {"topic", "string", "The new topic (plain text, at most 250 characters; empty clears it).", nil}},
			[]string{"channel", "topic"}, identityWith(hashIdentity("topic")), c.checkTopic("topic")),
		tool(ToolSetChannelPurpose, "Set the purpose (description) of a Slack channel (an empty purpose clears it).",
			[]property{channelProperty, {"purpose", "string", "The new purpose (plain text, at most 250 characters; empty clears it).", nil}},
			[]string{"channel", "purpose"}, identityWith(hashIdentity("purpose")), c.checkTopic("purpose")),
		tool(ToolJoinChannel, "Join a public Slack channel as the connected user. A name is looked up among the workspace's public, "+
			"unarchived channels. Idempotent: already being a member is reported with already: true.",
			[]property{{"channel", "string", "Public channel id (C...) or name (with or without #).", nil}}, []string{"channel"}, identity(), c.checkMember(true)),
		tool(ToolLeaveChannel, "Leave a Slack channel. Idempotent: not being a member is reported with already: true.",
			[]property{channelProperty}, []string{"channel"}, identity(), c.checkMember(false)),
		tool(ToolInviteToChannel, fmt.Sprintf("Invite users (by id) to a Slack channel the connected user is a member of; at most %d per call.", MaxInviteUsers),
			[]property{channelProperty, {"users", "array", fmt.Sprintf("User ids to invite (U... or W..., or <@U...> mentions), 1-%d.", MaxInviteUsers), nil}},
			[]string{"channel", "users"}, identityWith(usersIdentity), c.checkInvited),
		tool(ToolRemoveFromChannel, "Remove a user (by id) from a Slack channel (conversations.kick); the workspace may restrict who can.",
			[]property{channelProperty, {"user", "string", "The user id to remove (U... or W..., with or without <@...>).", nil}},
			[]string{"channel", "user"}, identityWith(userKeyIdentity), c.checkRemoved),
	}
}

// channelHandlers maps the channel-management writes to their implementation.
func (c *Connector) channelHandlers() map[string]handler {
	return map[string]handler{
		ToolCreateChannel:     c.createChannel,
		ToolRenameChannel:     c.renameChannel,
		ToolArchiveChannel:    c.archiveChannel,
		ToolUnarchiveChannel:  c.unarchiveChannel,
		ToolSetChannelTopic:   c.setTopic,
		ToolSetChannelPurpose: c.setPurpose,
		ToolJoinChannel:       c.joinChannel,
		ToolLeaveChannel:      c.leaveChannel,
		ToolInviteToChannel:   c.inviteToChannel,
		ToolRemoveFromChannel: c.removeFromChannel,
	}
}

// --- identity -----------------------------------------------------------------------

// identityWith extends the channel identity with fn's keys.
func identityWith(fn func(args map[string]any, out map[string]string)) func(map[string]any) map[string]string {
	base := identity()
	return func(args map[string]any) map[string]string {
		out := base(args)
		if args != nil {
			fn(args, out)
		}
		return out
	}
}

// createIdentity: the channel to be created is named by the arguments
// (channel = channel_name = the normalised name) plus is_private when given.
func createIdentity(args map[string]any) map[string]string {
	out := map[string]string{}
	if name, ok := normalizeChannelName(args["name"]); ok {
		out["channel"], out["channel_name"] = name, name
	}
	if b, ok := args["is_private"].(bool); ok {
		out["is_private"] = fmt.Sprint(b)
	}
	return out
}

func newNameIdentity(args map[string]any, out map[string]string) {
	if name, ok := normalizeChannelName(args["name"]); ok {
		out["new_name"] = name
	}
}

// hashIdentity records the SHA-256 of a text argument (key_sha256): the
// reconciliation compares it with the channel's state without the text
// itself reaching policy, audit or the ledger.
func hashIdentity(key string) func(map[string]any, map[string]string) {
	return func(args map[string]any, out map[string]string) {
		if v, ok := args[key].(string); ok {
			out[key+"_sha256"] = sha256Hex(v)
		}
	}
}

func usersIdentity(args map[string]any, out map[string]string) {
	if users := parseUsers(args["users"]); len(users) > 0 {
		out["users"] = strings.Join(users, ",")
	}
}

func userKeyIdentity(args map[string]any, out map[string]string) {
	raw, _ := args["user"].(string)
	if id := parseUserRef(raw); id != "" {
		out["user"] = id
	}
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// normalizeChannelName lower-cases a new channel name without its "#"
// and reports whether it is one Slack accepts.
func normalizeChannelName(v any) (string, bool) {
	s, _ := v.(string)
	s = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(s), "#"))
	return s, channelNewNameRE.MatchString(s)
}

// parseUsers returns the sorted, de-duplicated user ids of a users
// argument (ids that do not parse are left out).
func parseUsers(v any) []string {
	var out []string
	switch list := v.(type) {
	case []any:
		for _, u := range list {
			if s, ok := u.(string); ok {
				if id := parseUserRef(s); id != "" {
					out = append(out, id)
				}
			}
		}
	case []string:
		for _, s := range list {
			if id := parseUserRef(s); id != "" {
				out = append(out, id)
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// --- result ids ---------------------------------------------------------------------

func channelChangeIDs(res connectors.Result) map[string]string {
	v, ok := res.Content.(ChannelChange)
	if !ok || v.Channel == "" {
		return nil
	}
	out := map[string]string{"channel": v.Channel}
	if v.Name != "" {
		out["name"] = v.Name
	}
	if len(v.Users) > 0 {
		out["users"] = strings.Join(v.Users, ",")
	}
	if v.User != "" {
		out["user"] = v.User
	}
	return out
}

// --- argument helpers -----------------------------------------------------------------

func newNameArg(args map[string]any) (string, error) {
	name, ok := normalizeChannelName(args["name"])
	if !ok {
		return "", invalid("name is required: lower-case letters, digits, hyphens and underscores, at most 80 characters")
	}
	return name, nil
}

// textArgAllowEmpty reads a required string argument that may be empty.
func textArgAllowEmpty(args map[string]any, key string) (string, error) {
	v, ok := args[key]
	if !ok || v == nil {
		return "", invalid("%s is required (an empty string clears it)", key)
	}
	s, ok := v.(string)
	if !ok {
		return "", invalid("%s must be a string", key)
	}
	return s, nil
}

func usersArg(args map[string]any) ([]string, error) {
	list, ok := args["users"].([]any)
	if !ok {
		if strs, ok2 := args["users"].([]string); ok2 {
			for _, s := range strs {
				list = append(list, s)
			}
		} else {
			return nil, invalid("users is required: an array of user ids (U...)")
		}
	}
	if len(list) == 0 {
		return nil, invalid("users is required: an array of 1-%d user ids", MaxInviteUsers)
	}
	for _, u := range list {
		s, _ := u.(string)
		if parseUserRef(s) == "" {
			return nil, invalid("users must be user ids such as U0123ABCDEF (names are not accepted), got %q", s)
		}
	}
	users := parseUsers(list)
	if len(users) > MaxInviteUsers {
		return nil, invalid("users: at most %d per call, got %d", MaxInviteUsers, len(users))
	}
	return users, nil
}

func userArg(args map[string]any) (string, error) {
	raw, _ := args["user"].(string)
	id := parseUserRef(raw)
	if id == "" {
		return "", invalid("user is required: a Slack user id such as U0123ABCDEF")
	}
	return id, nil
}

// slackCode returns the ok:false error code behind err, "" when none.
func slackCode(err error) string {
	var ser goslack.SlackErrorResponse
	if errors.As(err, &ser) {
		return ser.Err
	}
	return ""
}

// channelTarget reads the channel argument and resolves it among the
// account's conversations (a read: its failure is a known outcome).
func (c *Connector) channelTarget(ctx context.Context, api *goslack.Client, args map[string]any) (string, error) {
	id, name, err := channelArg(args)
	if err != nil {
		return "", err
	}
	id, _, err = c.resolveChannel(ctx, api, id, name)
	return id, err
}

// --- handlers -------------------------------------------------------------------------

func (c *Connector) createChannel(ctx context.Context, api *goslack.Client, call connectors.Call) (connectors.Result, error) {
	name, err := newNameArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	private := false
	if v, ok := call.Args["is_private"]; ok && v != nil {
		b, ok := v.(bool)
		if !ok {
			return connectors.Result{}, invalid("is_private must be a boolean")
		}
		private = b
	}
	ch, err := api.CreateConversationContext(ctx, goslack.CreateConversationParams{ChannelName: name, IsPrivate: private})
	if err := ClassifyWrite("create channel", err); err != nil {
		return connectors.Result{}, err
	}
	out := ChannelChange{Name: name, IsPrivate: private, Action: "created"}
	if ch != nil {
		out.Channel = ch.ID
		if ch.Name != "" {
			out.Name = ch.Name
		}
		out.IsPrivate = ch.IsPrivate || private
	}
	return connectors.Result{Content: out}, nil
}

func (c *Connector) renameChannel(ctx context.Context, api *goslack.Client, call connectors.Call) (connectors.Result, error) {
	id, name, err := channelArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	newName, err := newNameArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	if id, _, err = c.resolveChannel(ctx, api, id, name); err != nil {
		return connectors.Result{}, err
	}
	ch, err := api.RenameConversationContext(ctx, id, newName)
	if err := ClassifyWrite("rename channel", err); err != nil {
		return connectors.Result{}, err
	}
	out := ChannelChange{Channel: id, Name: newName, Action: "renamed"}
	if ch != nil && ch.Name != "" {
		out.Name = ch.Name
	}
	return connectors.Result{Content: out}, nil
}

// archiveLike runs archive / unarchive: alreadyCode is the Slack code
// saying the desired state already holds.
func (c *Connector) archiveLike(ctx context.Context, api *goslack.Client, call connectors.Call, action, alreadyCode string, run func(context.Context, string) error) (connectors.Result, error) {
	id, err := c.channelTarget(ctx, api, call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	err = run(ctx, id)
	already := false
	if err != nil && slackCode(err) == alreadyCode {
		err, already = nil, true
	}
	if err := ClassifyWrite(action+" channel", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: ChannelChange{Channel: id, Action: action + "d", Already: already}}, nil
}

func (c *Connector) archiveChannel(ctx context.Context, api *goslack.Client, call connectors.Call) (connectors.Result, error) {
	return c.archiveLike(ctx, api, call, "archive", "already_archived", api.ArchiveConversationContext)
}

func (c *Connector) unarchiveChannel(ctx context.Context, api *goslack.Client, call connectors.Call) (connectors.Result, error) {
	return c.archiveLike(ctx, api, call, "unarchive", "not_archived", api.UnArchiveConversationContext)
}

func (c *Connector) setTopic(ctx context.Context, api *goslack.Client, call connectors.Call) (connectors.Result, error) {
	topic, err := textArgAllowEmpty(call.Args, "topic")
	if err != nil {
		return connectors.Result{}, err
	}
	id, err := c.channelTarget(ctx, api, call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	ch, err := api.SetTopicOfConversationContext(ctx, id, topic)
	if err := ClassifyWrite("set channel topic", err); err != nil {
		return connectors.Result{}, err
	}
	out := ChannelChange{Channel: id, Action: "topic_set", Topic: topic}
	if ch != nil && ch.Topic.Value != "" {
		out.Topic = ch.Topic.Value
	}
	return connectors.Result{Content: out}, nil
}

func (c *Connector) setPurpose(ctx context.Context, api *goslack.Client, call connectors.Call) (connectors.Result, error) {
	purpose, err := textArgAllowEmpty(call.Args, "purpose")
	if err != nil {
		return connectors.Result{}, err
	}
	id, err := c.channelTarget(ctx, api, call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	ch, err := api.SetPurposeOfConversationContext(ctx, id, purpose)
	if err := ClassifyWrite("set channel purpose", err); err != nil {
		return connectors.Result{}, err
	}
	out := ChannelChange{Channel: id, Action: "purpose_set", Purpose: purpose}
	if ch != nil && ch.Purpose.Value != "" {
		out.Purpose = ch.Purpose.Value
	}
	return connectors.Result{Content: out}, nil
}

func (c *Connector) joinChannel(ctx context.Context, api *goslack.Client, call connectors.Call) (connectors.Result, error) {
	id, name, err := channelArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	if id == "" {
		if id, err = c.resolvePublic(ctx, api, name); err != nil {
			return connectors.Result{}, err
		}
	}
	ch, warning, warnings, err := api.JoinConversationContext(ctx, id)
	if err := ClassifyWrite("join channel", err); err != nil {
		return connectors.Result{}, err
	}
	out := ChannelChange{Channel: id, Name: name, Action: "joined",
		Already: warning == "already_in_channel" || slices.Contains(warnings, "already_in_channel")}
	if ch != nil && ch.Name != "" {
		out.Name = ch.Name
	}
	return connectors.Result{Content: out}, nil
}

func (c *Connector) leaveChannel(ctx context.Context, api *goslack.Client, call connectors.Call) (connectors.Result, error) {
	id, err := c.channelTarget(ctx, api, call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	notIn, err := api.LeaveConversationContext(ctx, id)
	if err := ClassifyWrite("leave channel", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: ChannelChange{Channel: id, Action: "left", Already: notIn}}, nil
}

func (c *Connector) inviteToChannel(ctx context.Context, api *goslack.Client, call connectors.Call) (connectors.Result, error) {
	users, err := usersArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	id, err := c.channelTarget(ctx, api, call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	_, err = api.InviteUsersToConversationContext(ctx, id, users...)
	already := false
	if err != nil && slackCode(err) == "already_in_channel" {
		if len(users) > 1 {
			// Slack does not say which of the users were members already
			// nor whether the others were invited: a known failure the
			// harness resolves by inviting the users one by one.
			return connectors.Result{}, &Error{Class: ClassInvalidArgument, Err: err,
				Message: "invite to channel: at least one of the users is already in the channel (already_in_channel); invite the others one by one"}
		}
		err, already = nil, true
	}
	if err := ClassifyWrite("invite to channel", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: ChannelChange{Channel: id, Action: "invited", Users: users, Already: already}}, nil
}

func (c *Connector) removeFromChannel(ctx context.Context, api *goslack.Client, call connectors.Call) (connectors.Result, error) {
	user, err := userArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	id, err := c.channelTarget(ctx, api, call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	err = api.KickUserFromConversationContext(ctx, id, user)
	if err := ClassifyWrite("remove from channel", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: ChannelChange{Channel: id, Action: "removed", User: user}}, nil
}

// --- resolution -------------------------------------------------------------------------

// resolvePublic looks a name up among the workspace's public, unarchived
// channels (conversations.list, pages of resolveLimit, at most
// MaxResolvePages): the channels a user can join.
func (c *Connector) resolvePublic(ctx context.Context, api *goslack.Client, name string) (string, error) {
	params := &goslack.GetConversationsParameters{Types: []string{"public_channel"}, ExcludeArchived: true, Limit: resolveLimit}
	for page := 1; page <= MaxResolvePages; page++ {
		channels, next, err := api.GetConversationsContext(ctx, params)
		if err := classify("resolve channel", err); err != nil {
			return "", err
		}
		for _, ch := range channels {
			if strings.EqualFold(ch.Name, name) || strings.EqualFold(ch.NameNormalized, name) {
				return ch.ID, nil
			}
		}
		if next == "" {
			break
		}
		params.Cursor = next
	}
	return "", &Error{Class: ClassNotFound, Message: fmt.Sprintf("channel #%s not found among the workspace's public channels (first %d pages); pass the channel id instead", name, MaxResolvePages)}
}

// --- reconciliation ---------------------------------------------------------------------

// reconcileClient checks the input carries an operation id and an
// account and builds the account's client.
func (c *Connector) reconcileClient(ctx context.Context, in connectors.ReconcileInput) (*goslack.Client, error) {
	if in.OperationID == "" && in.Call.OperationID == "" {
		return nil, fmt.Errorf("%w: no operation id", ErrNotReconcilable)
	}
	if in.Call.Account == "" {
		return nil, fmt.Errorf("%w: no account", ErrNotReconcilable)
	}
	return c.client(ctx, in.Call)
}

// identityChannelRef returns the channel the identity names (channel_id
// first, then channel_name, then channel parsed).
func identityChannelRef(in connectors.ReconcileInput) (id, name string, err error) {
	id, name = in.ResourceIdentity["channel_id"], in.ResourceIdentity["channel_name"]
	if id == "" && name == "" {
		id, name = parseChannelRef(in.ResourceIdentity["channel"])
	}
	if id == "" && name == "" {
		return "", "", fmt.Errorf("%w: resource identity has no channel", ErrNotReconcilable)
	}
	return id, name, nil
}

// checkTarget builds the client and resolves the identity's channel: a
// name among the account's conversations, then (when public is set)
// among the workspace's public channels, for checks that run after the
// account may have left the channel.
func (c *Connector) checkTarget(ctx context.Context, in connectors.ReconcileInput, public bool) (*goslack.Client, string, error) {
	id, name, err := identityChannelRef(in)
	if err != nil {
		return nil, "", err
	}
	api, err := c.reconcileClient(ctx, in)
	if err != nil {
		return nil, "", err
	}
	if id != "" {
		return api, id, nil
	}
	ch, err := c.findConversation(ctx, api, defaultChanType, func(ch goslack.Channel) bool {
		return strings.EqualFold(ch.Name, name) || strings.EqualFold(ch.NameNormalized, name)
	})
	if err != nil {
		return nil, "", err
	}
	if ch != nil {
		return api, ch.ID, nil
	}
	if !public {
		return nil, "", fmt.Errorf("slack: reconcile: channel #%s not found; cannot tell yet", name)
	}
	id, err = c.resolvePublic(ctx, api, name)
	if err != nil {
		return nil, "", err
	}
	return api, id, nil
}

// channelInfo reads conversations.info (a read: every failure is
// "cannot tell yet").
func channelInfo(ctx context.Context, api *goslack.Client, id string) (*goslack.Channel, error) {
	ch, err := api.GetConversationInfoContext(ctx, &goslack.GetConversationInfoInput{ChannelID: id})
	if err := classify("reconcile: channel info", err); err != nil {
		return nil, err
	}
	if ch == nil {
		return nil, errors.New("slack: reconcile: conversations.info returned no channel")
	}
	return ch, nil
}

// verdict turns a boolean state check into found (resource: id) or not_found.
func verdict(ok bool, id string) connectors.ReconcileResult {
	if ok {
		return found(id)
	}
	return notFound
}

// checkCreated: the account's conversations (it is the creator's first
// member) list a channel with the name: found (its id); the end of the
// listing without it: not_found; the page bound: cannot tell yet.
func (c *Connector) checkCreated(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	name := in.ResourceIdentity["channel_name"]
	if name == "" {
		return connectors.ReconcileResult{}, fmt.Errorf("%w: resource identity has no channel name", ErrNotReconcilable)
	}
	api, err := c.reconcileClient(ctx, in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	ch, exhausted, err := c.walkConversations(ctx, api, defaultChanType, func(ch goslack.Channel) bool { return strings.EqualFold(ch.Name, name) })
	switch {
	case err != nil:
		return connectors.ReconcileResult{}, err
	case ch != nil:
		return found(ch.ID), nil
	case exhausted:
		return notFound, nil
	}
	return connectors.ReconcileResult{}, fmt.Errorf("slack: reconcile: more than %d pages of conversations without #%s; cannot tell yet", MaxResolvePages, name)
}

// checkRenamed: conversations.info names the channel new_name. A channel
// identified by its old name is looked up by the old name, then by the
// new one (the rename took effect when only the new one resolves).
func (c *Connector) checkRenamed(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	newName := in.ResourceIdentity["new_name"]
	if newName == "" {
		return connectors.ReconcileResult{}, fmt.Errorf("%w: resource identity has no new name", ErrNotReconcilable)
	}
	id, name, err := identityChannelRef(in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	api, err := c.reconcileClient(ctx, in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	if id == "" {
		for _, n := range []string{name, newName} {
			ch, err := c.findConversation(ctx, api, defaultChanType, func(ch goslack.Channel) bool { return strings.EqualFold(ch.Name, n) })
			if err != nil {
				return connectors.ReconcileResult{}, err
			}
			if ch != nil {
				id = ch.ID
				break
			}
		}
		if id == "" {
			return connectors.ReconcileResult{}, fmt.Errorf("slack: reconcile: neither #%s nor #%s found; cannot tell yet", name, newName)
		}
	}
	ch, err := channelInfo(ctx, api, id)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	return verdict(strings.EqualFold(ch.Name, newName), id), nil
}

// checkArchived: conversations.info says is_archived == want.
func (c *Connector) checkArchived(want bool) func(context.Context, connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	return func(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
		ctx, cancel := context.WithTimeout(ctx, c.timeout)
		defer cancel()
		api, id, err := c.checkTarget(ctx, in, false)
		if err != nil {
			return connectors.ReconcileResult{}, err
		}
		ch, err := channelInfo(ctx, api, id)
		if err != nil {
			return connectors.ReconcileResult{}, err
		}
		return verdict(ch.IsArchived == want, id), nil
	}
}

// checkTopic: the channel's topic (purpose) hashes to <key>_sha256.
func (c *Connector) checkTopic(key string) func(context.Context, connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	return func(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
		want := in.ResourceIdentity[key+"_sha256"]
		if want == "" {
			return connectors.ReconcileResult{}, fmt.Errorf("%w: resource identity has no %s hash", ErrNotReconcilable, key)
		}
		ctx, cancel := context.WithTimeout(ctx, c.timeout)
		defer cancel()
		api, id, err := c.checkTarget(ctx, in, false)
		if err != nil {
			return connectors.ReconcileResult{}, err
		}
		ch, err := channelInfo(ctx, api, id)
		if err != nil {
			return connectors.ReconcileResult{}, err
		}
		value := ch.Topic.Value
		if key == "purpose" {
			value = ch.Purpose.Value
		}
		return verdict(sha256Hex(value) == want, id), nil
	}
}

// checkMember: conversations.info says is_member == want (join: true,
// leave: false).
func (c *Connector) checkMember(want bool) func(context.Context, connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	return func(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
		ctx, cancel := context.WithTimeout(ctx, c.timeout)
		defer cancel()
		api, id, err := c.checkTarget(ctx, in, true)
		if err != nil {
			return connectors.ReconcileResult{}, err
		}
		ch, err := channelInfo(ctx, api, id)
		if err != nil {
			return connectors.ReconcileResult{}, err
		}
		return verdict(ch.IsMember == want, id), nil
	}
}

// members walks conversations.members (pages of reconcilePerPage, at
// most MaxReconcilePages) and reports which of users are members; an
// error when the bound is hit before the end.
func members(ctx context.Context, api *goslack.Client, channel string, users []string) (map[string]bool, error) {
	want := map[string]bool{}
	for _, u := range users {
		want[u] = true
	}
	in := map[string]bool{}
	params := &goslack.GetUsersInConversationParameters{ChannelID: channel, Limit: reconcilePerPage}
	for page := 1; page <= MaxReconcilePages; page++ {
		ids, next, err := api.GetUsersInConversationContext(ctx, params)
		if err := classify("reconcile: channel members", err); err != nil {
			return nil, err
		}
		for _, id := range ids {
			if want[id] {
				in[id] = true
			}
		}
		if next == "" {
			return in, nil
		}
		params.Cursor = next
	}
	return nil, fmt.Errorf("slack: reconcile: more than %d pages of members in %s; cannot tell yet", MaxReconcilePages, channel)
}

// checkInvited: every invited user is a member.
func (c *Connector) checkInvited(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	users := parseUsers(strings.Split(in.ResourceIdentity["users"], ","))
	if len(users) == 0 {
		return connectors.ReconcileResult{}, fmt.Errorf("%w: resource identity has no users", ErrNotReconcilable)
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	api, id, err := c.checkTarget(ctx, in, false)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	in2, err := members(ctx, api, id, users)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	return verdict(len(in2) == len(users), id), nil
}

// checkRemoved: the removed user is not a member.
func (c *Connector) checkRemoved(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	user := parseUserRef(in.ResourceIdentity["user"])
	if user == "" {
		return connectors.ReconcileResult{}, fmt.Errorf("%w: resource identity has no user", ErrNotReconcilable)
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	api, id, err := c.checkTarget(ctx, in, false)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	in2, err := members(ctx, api, id, []string{user})
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	return verdict(!in2[user], id), nil
}
