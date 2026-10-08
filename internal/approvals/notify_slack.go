package approvals

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/slack-go/slack"

	"github.com/huynle/mcp-gateway/internal/observability"
)

// Slack DM notifier (decision s0p05diu): a user who has connected their
// company Slack account gets the pending approval as a direct message
// with Approve / Deny buttons; the button press reaches
// /slack/interactions (internal/slack), which resolves the approval. A
// user without a Slack connection is portal-only and the notifier does
// nothing for them. Failures are returned to the service, which logs them
// redacted and never fails the approval.

// Slack vendor app secret keys and Block Kit action IDs shared with
// internal/slack. The values are the connections package's secret keys
// (SecretSlackBotToken, SecretSlackSigningSecret), repeated here so this
// package does not import connections.
const (
	SlackVendor               = "slack"
	SlackSecretBotToken       = "bot_token"
	SlackSecretSigningSecret  = "signing_secret"
	SlackActionApprove        = "approve"
	SlackActionDeny           = "deny"
	slackBlockIDPrefix        = "approval:"
	slackMaxBlockText         = 2900 // Slack caps a text object at 3000
	slackMaxSummaryFieldValue = 300
)

// DefaultSlackTimeout bounds the conversations.open + chat.postMessage
// pair; the confirm handler is waiting behind it.
const DefaultSlackTimeout = 5 * time.Second

// SlackIdentitySource answers which Slack user and workspace a gateway
// user is connected as (connections.Service.SlackIdentity: the active,
// company-labelled Slack connection). ok is false when there is none.
type SlackIdentitySource interface {
	SlackIdentity(ctx context.Context, userID string) (slackUserID, teamID string, ok bool, err error)
}

// SlackSecretSource returns the Slack vendor app's secrets
// (connections.Service.VendorSecrets): the bot token for the notifier and
// the signing secret for the interactions endpoint.
type SlackSecretSource interface {
	VendorSecrets(ctx context.Context, vendor, variant string, keys ...string) (map[string]string, error)
}

// SlackArgumentSource renders the stored arguments of an approval for the
// DM; *Service implements it (Summary). It is set after construction
// because the service is built with the notifier already in place.
type SlackArgumentSource interface {
	Summary(ctx context.Context, userID, id string) ([]Field, error)
}

// SlackNotifierOptions configures NewSlackNotifier.
type SlackNotifierOptions struct {
	// Identity and Secrets are required.
	Identity SlackIdentitySource
	Secrets  SlackSecretSource
	// PortalURL is linked from the DM (Service.PortalURL).
	PortalURL string
	// APIURL overrides the Slack Web API base (tests); "" means
	// slack.APIURL.
	APIURL string
	// HTTPClient sends the API calls; nil means a client bounded by Timeout.
	HTTPClient *http.Client
	// Timeout bounds one notification; 0 means DefaultSlackTimeout.
	Timeout time.Duration
	Log     *slog.Logger
}

// SlackNotifier implements Notifier over the Slack Web API.
type SlackNotifier struct {
	identity SlackIdentitySource
	secrets  SlackSecretSource
	portal   string
	apiURL   string
	client   *http.Client
	timeout  time.Duration
	log      *slog.Logger

	mu   sync.RWMutex
	args SlackArgumentSource
}

// NewSlackNotifier builds the notifier.
func NewSlackNotifier(opts SlackNotifierOptions) (*SlackNotifier, error) {
	if opts.Identity == nil || opts.Secrets == nil {
		return nil, errors.New("approvals: slack notifier needs an identity and a secret source")
	}
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultSlackTimeout
	}
	if opts.APIURL == "" {
		opts.APIURL = slack.APIURL
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{Timeout: opts.Timeout}
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	return &SlackNotifier{
		identity: opts.Identity, secrets: opts.Secrets, portal: opts.PortalURL, apiURL: opts.APIURL,
		client: opts.HTTPClient, timeout: opts.Timeout, log: opts.Log,
	}, nil
}

// SetArguments installs the argument renderer (the approvals service).
func (n *SlackNotifier) SetArguments(src SlackArgumentSource) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.args = src
}

func (n *SlackNotifier) arguments() SlackArgumentSource {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.args
}

// Notify implements Notifier: no Slack connection means nothing to do;
// otherwise open the DM and post the approval message. The error, when
// any, never names the token.
func (n *SlackNotifier) Notify(ctx context.Context, a Approval) error {
	slackUser, _, ok, err := n.identity.SlackIdentity(ctx, a.UserID)
	if err != nil {
		return fmt.Errorf("slack: identity: %w", err)
	}
	if !ok {
		return nil
	}
	secrets, err := n.secrets.VendorSecrets(ctx, SlackVendor, "", SlackSecretBotToken)
	if err != nil {
		return fmt.Errorf("slack: secrets: %w", err)
	}
	token := secrets[SlackSecretBotToken]
	if token == "" {
		return errors.New("slack: the Slack vendor app has no bot token; approval DMs are off")
	}
	ctx, cancel := context.WithTimeout(ctx, n.timeout)
	defer cancel()
	var summary []Field
	if src := n.arguments(); src != nil {
		if summary, err = src.Summary(ctx, a.UserID, a.ID); err != nil {
			// The DM is still useful without the arguments.
			n.log.Warn("slack DM without argument summary", "event", "approvals.slack_summary_failed", "approval_id", a.ID,
				"error", observability.RedactError(err), observability.RequestIDAttr(ctx))
			summary = nil
		}
	}
	api := slack.New(token, slack.OptionAPIURL(n.apiURL), slack.OptionHTTPClient(n.client))
	channel, _, _, err := api.OpenConversationContext(ctx, &slack.OpenConversationParameters{Users: []string{slackUser}})
	if err != nil {
		return fmt.Errorf("slack: conversations.open: %w", err)
	}
	blocks := SlackApprovalBlocks(a, summary, n.portal)
	_, ts, err := api.PostMessageContext(ctx, channel.ID,
		slack.MsgOptionText(slackFallbackText(a), false),
		slack.MsgOptionBlocks(blocks...),
		slack.MsgOptionDisableLinkUnfurl(),
	)
	if err != nil {
		return fmt.Errorf("slack: chat.postMessage: %w", err)
	}
	n.log.Info("approval DM sent", "event", "approvals.slack_notified", "approval_id", a.ID, "user_id", a.UserID,
		"channel", channel.ID, "ts", ts, observability.RequestIDAttr(ctx))
	return nil
}

// Summary returns the display summary of one of the user's approvals'
// stored arguments (empty when the payload is gone). It implements
// SlackArgumentSource.
func (s *Service) Summary(ctx context.Context, userID, id string) ([]Field, error) {
	var fields []Field
	err := s.st.AsUser(ctx, userID, func(tx Tx) error {
		rec, err := tx.GetApproval(ctx, id)
		if err != nil {
			return err
		}
		if rec.Payload == nil {
			return nil
		}
		args, err := s.decrypt(ctx, rec)
		if err != nil {
			return err
		}
		fields = Summarize(args)
		return nil
	})
	if err != nil {
		return nil, mapNotFound(err)
	}
	return fields, nil
}

// Lookup reads an approval by id across all users (the bypass scope):
// what /slack/interactions needs to find the owner of the approval a
// button press names before it checks that the presser is that owner.
func (s *Service) Lookup(ctx context.Context, id string) (*Approval, error) {
	var a Approval
	err := s.st.Bypass(ctx, func(tx Tx) error {
		rec, err := tx.GetApproval(ctx, id)
		if err != nil {
			return err
		}
		a = fromRecord(rec)
		return nil
	})
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &a, nil
}

// SlackApprovalBlocks renders the DM: header, the call (tool, account,
// resource identity, expiry), the argument summary and the Approve /
// Deny buttons whose value is the approval id. portalURL, when set, is
// linked for users who prefer the portal.
func SlackApprovalBlocks(a Approval, summary []Field, portalURL string) []slack.Block {
	account := a.AccountLabel
	if a.AccountName != "" {
		account = strings.TrimSpace(account + " · " + a.AccountName)
	}
	if account == "" {
		account = "—"
	}
	fields := []*slack.TextBlockObject{
		slack.NewTextBlockObject(slack.MarkdownType, "*Tool*\n`"+slackEscape(a.Tool)+"`", false, false),
		slack.NewTextBlockObject(slack.MarkdownType, "*Account*\n"+slackEscape(account), false, false),
		slack.NewTextBlockObject(slack.MarkdownType, "*Resource*\n"+slackResource(a.ResourceIdentity), false, false),
		slack.NewTextBlockObject(slack.MarkdownType, fmt.Sprintf("*Expires*\n<!date^%d^{date_short_pretty} {time}|%s>", a.ExpiresAt.Unix(), a.ExpiresAt.UTC().Format("15:04 UTC")), false, false),
	}
	blocks := []slack.Block{
		slack.NewHeaderBlock(slack.NewTextBlockObject(slack.PlainTextType, "Approval required", false, false)),
		slack.NewSectionBlock(nil, fields, nil),
	}
	if text := slackSummary(summary); text != "" {
		blocks = append(blocks, slack.NewSectionBlock(slack.NewTextBlockObject(slack.MarkdownType, "*Arguments*\n"+text, false, false), nil, nil))
	}
	meta := "Approval `" + slackEscape(a.ID) + "`"
	if portalURL != "" {
		meta += " · <" + portalURL + "|Open in the portal>"
	}
	blocks = append(blocks,
		slack.NewContextBlock("", slack.NewTextBlockObject(slack.MarkdownType, meta, false, false)),
		slack.NewActionBlock(slackBlockIDPrefix+a.ID,
			slack.NewButtonBlockElement(SlackActionApprove, a.ID, slack.NewTextBlockObject(slack.PlainTextType, "Approve", false, false)).WithStyle(slack.StylePrimary),
			slack.NewButtonBlockElement(SlackActionDeny, a.ID, slack.NewTextBlockObject(slack.PlainTextType, "Deny", false, false)).WithStyle(slack.StyleDanger),
		),
	)
	return blocks
}

// slackFallbackText is the notification text clients without Block Kit
// show.
func slackFallbackText(a Approval) string {
	return fmt.Sprintf("Approval required: %s (approval %s)", a.Tool, a.ID)
}

// slackResource renders the resource identity as "key: value" lines,
// keys sorted.
func slackResource(res map[string]string) string {
	if len(res) == 0 {
		return "—"
	}
	keys := make([]string, 0, len(res))
	for k := range res {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(slackEscape(k) + ": " + slackEscape(res[k]))
	}
	return slackCut(b.String(), 1000)
}

// slackSummary renders the argument summary as a code block, each value
// cut at slackMaxSummaryFieldValue and the whole at slackMaxBlockText.
func slackSummary(summary []Field) string {
	if len(summary) == 0 {
		return ""
	}
	var b strings.Builder
	for _, f := range summary {
		v := f.Value
		if f.Truncated && !strings.HasSuffix(v, "…") {
			v += "…"
		}
		b.WriteString(slackEscape(f.Key) + ": " + slackEscape(slackCut(v, slackMaxSummaryFieldValue)) + "\n")
	}
	body := slackCut(strings.TrimRight(b.String(), "\n"), slackMaxBlockText-20)
	return "```" + strings.ReplaceAll(body, "```", "` ` `") + "```"
}

// slackCut truncates s to at most max bytes on a rune boundary, marking
// the cut with an ellipsis.
func slackCut(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && cut < len(s) && (s[cut]&0xC0) == 0x80 {
		cut--
	}
	return s[:cut] + "…"
}

// slackEscape escapes the characters Slack's mrkdwn treats specially.
func slackEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}
