package slack

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	goslack "github.com/slack-go/slack"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Own-profile tool names: the connected user's status and Do Not Disturb.
const (
	ToolSetStatus   = "set_status"
	ToolClearStatus = "clear_status"
	ToolGetDND      = "get_dnd"
	ToolSetDND      = "set_dnd"
	ToolEndDND      = "end_dnd"
)

// Slack user-token scopes of the own-profile tools.
const (
	ScopeUsersProfileWrite = "users.profile:write"
	ScopeDNDRead           = "dnd:read"
	ScopeDNDWrite          = "dnd:write"
)

// MaxSnoozeMinutes bounds set_dnd (24 hours).
const MaxSnoozeMinutes = 1440

// maxStatusText is Slack's limit on status_text.
const maxStatusText = 100

// Status is the result of set_status and clear_status. Expiration is
// RFC 3339 UTC, empty when the status does not expire.
type Status struct {
	Text       string `json:"status_text"`
	Emoji      string `json:"status_emoji"`
	Expiration string `json:"expiration,omitempty"`
	Action     string `json:"action"`
}

// DND is the connected user's Do Not Disturb state (get_dnd) and the
// result of set_dnd / end_dnd. Times are RFC 3339 UTC.
type DND struct {
	DNDEnabled             bool   `json:"dnd_enabled"`
	NextStart              string `json:"next_dnd_start,omitempty"`
	NextEnd                string `json:"next_dnd_end,omitempty"`
	SnoozeEnabled          bool   `json:"snooze_enabled"`
	SnoozeEnd              string `json:"snooze_end,omitempty"`
	SnoozeRemainingSeconds int    `json:"snooze_remaining_seconds,omitempty"`
	Action                 string `json:"action,omitempty"`
	Already                bool   `json:"already,omitempty"`
}

func (c *Connector) profileTools() []connectors.Tool {
	single := connectors.Bounds{MaxResultBytes: c.bounds.MaxResultBytes}
	empty := func(map[string]any) map[string]string { return map[string]string{} }
	return []connectors.Tool{
		{
			App: App, Name: ToolSetStatus, Kind: connectors.KindWrite,
			Description: "Set the connected user's Slack status: text and/or emoji, optionally expiring at a time or after some minutes.",
			InputSchema: objectSchema([]property{
				{"text", "string", fmt.Sprintf("Status text, at most %d characters.", maxStatusText), nil},
				{"emoji", "string", "Status emoji name, with or without colons (calendar, :palm_tree:). Slack defaults to :speech_balloon: when only text is set.", nil},
				{"expiration", "string", "Optional: when the status clears: an RFC 3339 time, or a number of minutes from now. Default: never.", nil},
			}, nil),
			RequiredScopes: []string{ScopeUsersProfileWrite}, ResourceIdentity: statusIdentity,
			Reconcile: stableID(c.checkStatus(false)), ResultIDs: statusIDs, Bounds: single,
		},
		{
			App: App, Name: ToolClearStatus, Kind: connectors.KindWrite,
			Description: "Clear the connected user's Slack status (text, emoji and expiration).",
			InputSchema: objectSchema(nil, nil), RequiredScopes: []string{ScopeUsersProfileWrite}, ResourceIdentity: empty,
			Reconcile: stableID(c.checkStatus(true)), ResultIDs: statusIDs, Bounds: single,
		},
		{
			App: App, Name: ToolGetDND, Kind: connectors.KindRead,
			Description: "Get the connected user's Do Not Disturb state: whether DND is on, the next scheduled DND window and any snooze.",
			InputSchema: objectSchema(nil, nil), RequiredScopes: []string{ScopeDNDRead}, ResourceIdentity: empty, Bounds: single,
		},
		{
			App: App, Name: ToolSetDND, Kind: connectors.KindWrite,
			Description:    fmt.Sprintf("Turn on Do Not Disturb (snooze notifications) for the connected user for 1-%d minutes.", MaxSnoozeMinutes),
			InputSchema:    objectSchema([]property{{"minutes", "integer", fmt.Sprintf("How long to snooze, 1-%d minutes.", MaxSnoozeMinutes), nil}}, []string{"minutes"}),
			RequiredScopes: []string{ScopeDNDWrite}, ResourceIdentity: minutesIdentity,
			Reconcile: stableID(c.checkSnooze(true)), ResultIDs: dndIDs, Bounds: single,
		},
		{
			App: App, Name: ToolEndDND, Kind: connectors.KindWrite,
			Description: "End the connected user's Do Not Disturb snooze now. Idempotent: no active snooze is reported with already: true.",
			InputSchema: objectSchema(nil, nil), RequiredScopes: []string{ScopeDNDWrite}, ResourceIdentity: empty,
			Reconcile: stableID(c.checkSnooze(false)), ResultIDs: dndIDs, Bounds: single,
		},
	}
}

func (c *Connector) profileReadHandlers() map[string]handler {
	return map[string]handler{ToolGetDND: c.getDND}
}

func (c *Connector) profileWriteHandlers() map[string]handler {
	return map[string]handler{ToolSetStatus: c.setStatus, ToolClearStatus: c.clearStatus, ToolSetDND: c.setDND, ToolEndDND: c.endDND}
}

// --- identity, result ids, arguments --------------------------------------------------

// statusIdentity: the text's SHA-256 (the text is content) and the emoji.
func statusIdentity(args map[string]any) map[string]string {
	out := map[string]string{}
	if text, ok := args["text"].(string); ok {
		out["status_text_sha256"] = sha256Hex(text)
	}
	if emoji, err := emojiArg(args); err == nil && emoji != "" {
		out["status_emoji"] = emoji
	}
	return out
}

func minutesIdentity(args map[string]any) map[string]string {
	out := map[string]string{}
	if m, err := minutesArg(args); err == nil {
		out["minutes"] = strconv.Itoa(m)
	}
	return out
}

func statusIDs(res connectors.Result) map[string]string {
	v, ok := res.Content.(Status)
	if !ok || v.Action == "" {
		return nil
	}
	out := map[string]string{"status": v.Action}
	if v.Emoji != "" {
		out["status_emoji"] = v.Emoji
	}
	return out
}

func dndIDs(res connectors.Result) map[string]string {
	v, ok := res.Content.(DND)
	if !ok || v.Action == "" {
		return nil
	}
	if v.SnoozeEnd != "" {
		return map[string]string{"snooze_end": v.SnoozeEnd}
	}
	return map[string]string{"dnd": v.Action}
}

// emojiArg reads an optional emoji name as Slack stores it (":name:").
func emojiArg(args map[string]any) (string, error) {
	v, ok := args["emoji"]
	if !ok || v == nil {
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", invalid("emoji must be a string")
	}
	s = strings.ToLower(strings.Trim(strings.TrimSpace(s), ":"))
	if s == "" {
		return "", nil
	}
	if !reactionRE.MatchString(s) {
		return "", invalid("emoji must be an emoji name such as calendar or :palm_tree:")
	}
	return ":" + s + ":", nil
}

// expirationArg reads expiration: an RFC 3339 time or minutes from now
// (a number or a numeric string); 0 when absent.
func expirationArg(args map[string]any, now time.Time) (int64, error) {
	v, ok := args["expiration"]
	if !ok || v == nil {
		return 0, nil
	}
	bad := invalid("expiration must be an RFC 3339 time (2030-01-02T15:04:05Z) or a positive number of minutes")
	if s, ok := v.(string); ok {
		s = strings.TrimSpace(s)
		if s == "" {
			return 0, nil
		}
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			return t.Unix(), nil
		}
	}
	m, err := toInt(v)
	if err != nil || m <= 0 {
		return 0, bad
	}
	return now.Add(time.Duration(m) * time.Minute).Unix(), nil
}

func minutesArg(args map[string]any) (int, error) {
	m, err := toInt(args["minutes"])
	if err != nil || m < 1 || m > MaxSnoozeMinutes {
		return 0, invalid("minutes is required: 1-%d", MaxSnoozeMinutes)
	}
	return m, nil
}

func toDND(s *goslack.DNDStatus) DND {
	if s == nil {
		return DND{}
	}
	return DND{
		DNDEnabled: s.Enabled, NextStart: unixTime(int64(s.NextStartTimestamp)), NextEnd: unixTime(int64(s.NextEndTimestamp)),
		SnoozeEnabled: s.SnoozeEnabled, SnoozeEnd: unixTime(int64(s.SnoozeEndTime)), SnoozeRemainingSeconds: s.SnoozeRemaining,
	}
}

// --- handlers ---------------------------------------------------------------------------

func (c *Connector) setStatus(ctx context.Context, api *goslack.Client, call connectors.Call) (connectors.Result, error) {
	text, err := optionalString(call.Args, "text")
	if err != nil {
		return connectors.Result{}, err
	}
	text = strings.TrimSpace(text)
	if utf8.RuneCountInString(text) > maxStatusText {
		return connectors.Result{}, invalid("text is longer than %d characters", maxStatusText)
	}
	emoji, err := emojiArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	if text == "" && emoji == "" {
		return connectors.Result{}, invalid("text or emoji is required (clear_status clears the status)")
	}
	exp, err := expirationArg(call.Args, time.Now())
	if err != nil {
		return connectors.Result{}, err
	}
	err = api.SetUserCustomStatusContext(ctx, text, emoji, exp)
	if err := ClassifyWrite("set status", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: Status{Text: text, Emoji: emoji, Expiration: unixTime(exp), Action: "set"}}, nil
}

func (c *Connector) clearStatus(ctx context.Context, api *goslack.Client, _ connectors.Call) (connectors.Result, error) {
	err := api.UnsetUserCustomStatusContext(ctx)
	if err := ClassifyWrite("clear status", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: Status{Action: "cleared"}}, nil
}

func (c *Connector) getDND(ctx context.Context, api *goslack.Client, _ connectors.Call) (connectors.Result, error) {
	s, err := api.GetDNDInfoContext(ctx, nil)
	if err := classify("get do not disturb", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: toDND(s)}, nil
}

func (c *Connector) setDND(ctx context.Context, api *goslack.Client, call connectors.Call) (connectors.Result, error) {
	m, err := minutesArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	s, err := api.SetSnoozeContext(ctx, m)
	if err := ClassifyWrite("set do not disturb", err); err != nil {
		return connectors.Result{}, err
	}
	out := toDND(s)
	out.Action = "snoozed"
	return connectors.Result{Content: out}, nil
}

func (c *Connector) endDND(ctx context.Context, api *goslack.Client, _ connectors.Call) (connectors.Result, error) {
	s, err := api.EndSnoozeContext(ctx)
	already := false
	if err != nil && slackCode(err) == "snooze_not_active" {
		err, already = nil, true
	}
	if err := ClassifyWrite("end do not disturb", err); err != nil {
		return connectors.Result{}, err
	}
	out := toDND(s)
	out.Action, out.Already = "ended", already
	return connectors.Result{Content: out}, nil
}

// --- reconciliation ---------------------------------------------------------------------

// checkStatus reads the account's own profile (auth.test for the user
// id, users.info with the users:read scope the reads already need): for
// set_status the text hashes to status_text_sha256 and, when the
// identity has one, the emoji matches; for clear_status both are empty.
// Resource id: the user id.
func (c *Connector) checkStatus(clear bool) func(context.Context, connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	return func(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
		wantHash, wantEmoji := in.ResourceIdentity["status_text_sha256"], in.ResourceIdentity["status_emoji"]
		if !clear && wantHash == "" {
			return connectors.ReconcileResult{}, fmt.Errorf("%w: resource identity has no status text hash", ErrNotReconcilable)
		}
		api, err := c.reconcileClient(ctx, in)
		if err != nil {
			return connectors.ReconcileResult{}, err
		}
		ctx, cancel := context.WithTimeout(ctx, c.timeout)
		defer cancel()
		me, err := api.AuthTestContext(ctx)
		if err := classify("reconcile: identify account", err); err != nil {
			return connectors.ReconcileResult{}, err
		}
		u, err := api.GetUserInfoContext(ctx, me.UserID)
		if err := classify("reconcile: read profile", err); err != nil {
			return connectors.ReconcileResult{}, err
		}
		text, emoji := u.Profile.StatusText, u.Profile.StatusEmoji
		if clear {
			return verdict(text == "" && emoji == "", me.UserID), nil
		}
		return verdict(sha256Hex(text) == wantHash && (wantEmoji == "" || emoji == wantEmoji), me.UserID), nil
	}
}

// checkSnooze: dnd.info says snooze_enabled == want (set_dnd: true,
// end_dnd: false). Resource id: "dnd".
func (c *Connector) checkSnooze(want bool) func(context.Context, connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	return func(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
		api, err := c.reconcileClient(ctx, in)
		if err != nil {
			return connectors.ReconcileResult{}, err
		}
		ctx, cancel := context.WithTimeout(ctx, c.timeout)
		defer cancel()
		s, err := api.GetDNDInfoContext(ctx, nil)
		if err := classify("reconcile: do not disturb", err); err != nil {
			return connectors.ReconcileResult{}, err
		}
		return verdict(s.SnoozeEnabled == want, "dnd"), nil
	}
}
