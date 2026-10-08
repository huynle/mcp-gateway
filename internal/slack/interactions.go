// Package slack owns the gateway's Slack interactivity endpoint
// (/slack/interactions): it verifies Slack's request signature, maps an
// Approve / Deny button press to the approval it names, checks that the
// Slack user pressing it is the approval owner's connected company Slack
// user, decides the approval through approvals.Service with the same
// single-use semantics as the portal, and replaces the buttons in the
// original DM with the outcome.
//
// Design: Brain plan 36bakiw8 section 3; decision s0p05diu. The DM itself
// is sent by approvals.SlackNotifier.
package slack

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	slackapi "github.com/slack-go/slack"

	"github.com/huynle/mcp-gateway/internal/approvals"
	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/observability"
)

// Signature headers and the v0 signing scheme (docs.slack.dev, "Verifying
// requests from Slack"): X-Slack-Signature is
// "v0=" + hex(HMAC-SHA256(signing secret, "v0:" + timestamp + ":" + body)).
const (
	HeaderSignature  = "X-Slack-Signature"
	HeaderTimestamp  = "X-Slack-Request-Timestamp"
	signatureVersion = "v0"
)

// Defaults.
const (
	// DefaultMaxSkew is how far the request timestamp may be from now
	// before the request is treated as a replay.
	DefaultMaxSkew = 5 * time.Minute
	// DefaultUpdateTimeout bounds the chat.update that replaces the
	// buttons: Slack gives the endpoint 3 s to answer.
	DefaultUpdateTimeout = 2 * time.Second
	// MaxBody bounds the request body.
	MaxBody = 1 << 20
)

// Verification errors.
var (
	// ErrStaleTimestamp: the timestamp header is missing, malformed or
	// outside the replay window.
	ErrStaleTimestamp = errors.New("slack: request timestamp is stale")
	// ErrBadSignature: the signature header is missing, malformed or
	// does not match.
	ErrBadSignature = errors.New("slack: bad request signature")
)

// VerifySignature checks Slack's v0 signature over body: the timestamp
// must be within maxSkew of now (replay window; checked first, before any
// HMAC work) and signature must equal the HMAC under secret. It never
// parses the body.
func VerifySignature(secret, timestamp, signature string, body []byte, now time.Time, maxSkew time.Duration) error {
	if secret == "" {
		return errors.New("slack: signing secret is not configured")
	}
	ts, err := strconv.ParseInt(strings.TrimSpace(timestamp), 10, 64)
	if err != nil {
		return ErrStaleTimestamp
	}
	if skew := now.Sub(time.Unix(ts, 0)); skew > maxSkew || skew < -maxSkew {
		return ErrStaleTimestamp
	}
	version, hexMAC, ok := strings.Cut(signature, "=")
	if !ok || version != signatureVersion {
		return ErrBadSignature
	}
	got, err := hex.DecodeString(hexMAC)
	if err != nil || len(got) != sha256.Size {
		return ErrBadSignature
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = io.WriteString(mac, signatureVersion+":"+strconv.FormatInt(ts, 10)+":")
	_, _ = mac.Write(body)
	if !hmac.Equal(mac.Sum(nil), got) {
		return ErrBadSignature
	}
	return nil
}

// Options configures NewInteractionsHandler.
type Options struct {
	// Approvals resolves and decides approvals (required).
	Approvals *approvals.Service
	// Identity says which Slack user a gateway user is connected as
	// (connections.Service; required).
	Identity approvals.SlackIdentitySource
	// Secrets supplies the signing secret and the bot token
	// (connections.Service; required).
	Secrets approvals.SlackSecretSource
	// Audit records refused presses; nil means none.
	Audit audit.Recorder
	// APIURL overrides the Slack Web API base (tests).
	APIURL string
	// HTTPClient sends chat.update; nil means one bounded by UpdateTimeout.
	HTTPClient *http.Client
	// UpdateTimeout bounds chat.update; 0 means DefaultUpdateTimeout.
	UpdateTimeout time.Duration
	// MaxSkew is the replay window; 0 means DefaultMaxSkew.
	MaxSkew time.Duration
	// Now is the clock (tests).
	Now func() time.Time
	Log *slog.Logger
}

// InteractionsHandler serves POST /slack/interactions.
type InteractionsHandler struct {
	svc      *approvals.Service
	identity approvals.SlackIdentitySource
	secrets  approvals.SlackSecretSource
	audit    audit.Recorder
	apiURL   string
	client   *http.Client
	timeout  time.Duration
	maxSkew  time.Duration
	now      func() time.Time
	log      *slog.Logger
}

// NewInteractionsHandler builds the handler.
func NewInteractionsHandler(opts Options) (*InteractionsHandler, error) {
	if opts.Approvals == nil || opts.Identity == nil || opts.Secrets == nil {
		return nil, errors.New("slack: interactions handler needs the approvals service, an identity and a secret source")
	}
	if opts.Audit == nil {
		opts.Audit = audit.NopRecorder{}
	}
	if opts.APIURL == "" {
		opts.APIURL = slackapi.APIURL
	}
	if opts.UpdateTimeout <= 0 {
		opts.UpdateTimeout = DefaultUpdateTimeout
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{Timeout: opts.UpdateTimeout}
	}
	if opts.MaxSkew <= 0 {
		opts.MaxSkew = DefaultMaxSkew
	}
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Now().UTC() }
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	return &InteractionsHandler{
		svc: opts.Approvals, identity: opts.Identity, secrets: opts.Secrets, audit: opts.Audit, apiURL: opts.APIURL,
		client: opts.HTTPClient, timeout: opts.UpdateTimeout, maxSkew: opts.MaxSkew, now: opts.Now, log: opts.Log,
	}, nil
}

// payload is the part of a block_actions interaction the handler reads.
type payload struct {
	Type string `json:"type"`
	Team struct {
		ID string `json:"id"`
	} `json:"team"`
	User struct {
		ID     string `json:"id"`
		TeamID string `json:"team_id"`
	} `json:"user"`
	Container struct {
		ChannelID string `json:"channel_id"`
		MessageTs string `json:"message_ts"`
	} `json:"container"`
	Channel struct {
		ID string `json:"id"`
	} `json:"channel"`
	Message struct {
		Ts string `json:"ts"`
	} `json:"message"`
	Actions []struct {
		ActionID string `json:"action_id"`
		Value    string `json:"value"`
	} `json:"actions"`
}

// ServeHTTP implements http.Handler.
func (h *InteractionsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ctx := r.Context()
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBody+1))
	if err != nil || len(body) > MaxBody {
		http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
		return
	}
	// Verify before parsing anything.
	secrets, err := h.secrets.VendorSecrets(ctx, approvals.SlackVendor, "", approvals.SlackSecretSigningSecret, approvals.SlackSecretBotToken)
	if err != nil {
		// No Slack vendor app (or no store): nothing can be verified, so
		// the answer is the same 401 as a bad signature.
		h.log.Error("slack secrets unavailable", "event", "slack.secrets_failed", "error", observability.RedactError(err), observability.RequestIDAttr(ctx))
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err := VerifySignature(secrets[approvals.SlackSecretSigningSecret], r.Header.Get(HeaderTimestamp), r.Header.Get(HeaderSignature), body, h.now(), h.maxSkew); err != nil {
		h.log.Warn("slack request rejected", "event", "slack.signature_rejected", "error", observability.RedactError(err), observability.RequestIDAttr(ctx))
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	p, err := parsePayload(body)
	if err != nil {
		http.Error(w, "bad payload", http.StatusBadRequest)
		return
	}
	if p.Type != "block_actions" {
		w.WriteHeader(http.StatusOK)
		return
	}
	action, id := pressed(p)
	if action == "" {
		w.WriteHeader(http.StatusOK)
		return
	}
	channel, ts := p.Container.ChannelID, p.Container.MessageTs
	if channel == "" {
		channel = p.Channel.ID
	}
	if ts == "" {
		ts = p.Message.Ts
	}
	api := slackapi.New(secrets[approvals.SlackSecretBotToken], slackapi.OptionAPIURL(h.apiURL), slackapi.OptionHTTPClient(h.client))
	update := func(blocks []slackapi.Block, text string) {
		if channel == "" || ts == "" {
			return
		}
		uctx, cancel := context.WithTimeout(ctx, h.timeout)
		defer cancel()
		if _, _, _, err := api.UpdateMessageContext(uctx, channel, ts, slackapi.MsgOptionText(text, false), slackapi.MsgOptionBlocks(blocks...)); err != nil {
			h.log.Warn("slack message update failed", "event", "slack.update_failed", "approval_id", id,
				"error", observability.RedactError(err), observability.RequestIDAttr(ctx))
		}
	}

	a, err := h.svc.Lookup(ctx, id)
	if err != nil {
		if !errors.Is(err, approvals.ErrNotFound) {
			h.log.Error("approval lookup failed", "event", "slack.lookup_failed", "approval_id", id, "error", observability.RedactError(err), observability.RequestIDAttr(ctx))
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		update(resolvedBlocks(approvals.Approval{ID: id}, "This approval has expired."), "Approval expired")
		w.WriteHeader(http.StatusOK)
		return
	}
	// The presser must be the owner's connected company Slack user, in the
	// same workspace (decision s0p05diu).
	slackUser, team, ok, err := h.identity.SlackIdentity(ctx, a.UserID)
	if err != nil {
		h.log.Error("slack identity lookup failed", "event", "slack.identity_failed", "approval_id", id, "error", observability.RedactError(err), observability.RequestIDAttr(ctx))
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if !ok || p.User.ID == "" || p.User.ID != slackUser || p.Team.ID != team {
		h.refuse(ctx, a, p.User.ID, p.Team.ID)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var decided *approvals.Approval
	switch action {
	case approvals.SlackActionApprove:
		decided, err = h.svc.Approve(ctx, a.UserID, id)
	default:
		decided, err = h.svc.Deny(ctx, a.UserID, id)
	}
	switch {
	case err == nil:
		when := h.now()
		if decided.DecidedAt != nil {
			when = *decided.DecidedAt
		}
		if decided.Status == approvals.StatusApproved {
			update(resolvedBlocks(*decided, fmt.Sprintf("✅ Approved by you at %s. The tool call will run when the harness retries.", when.UTC().Format("15:04 UTC"))), "Approved")
		} else {
			update(resolvedBlocks(*decided, fmt.Sprintf("⛔ Denied by you at %s.", when.UTC().Format("15:04 UTC"))), "Denied")
		}
	case errors.Is(err, approvals.ErrNotPending):
		update(resolvedBlocks(*a, notPendingText(a, h.now())), "Approval already decided")
	case errors.Is(err, approvals.ErrNotFound):
		update(resolvedBlocks(*a, "This approval has expired."), "Approval expired")
	default:
		h.log.Error("approval decision failed", "event", "slack.decide_failed", "approval_id", id, "error", observability.RedactError(err), observability.RequestIDAttr(ctx))
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	h.log.Info("slack interaction handled", "event", "slack.interaction", "approval_id", id, "action", action, "user_id", a.UserID, observability.RequestIDAttr(ctx))
	w.WriteHeader(http.StatusOK)
}

// refuse audits a press by someone other than the owner's Slack user as
// a denied event of the owner.
func (h *InteractionsHandler) refuse(ctx context.Context, a *approvals.Approval, slackUser, team string) {
	h.log.Warn("slack interaction from another user refused", "event", "slack.user_mismatch", "approval_id", a.ID, "user_id", a.UserID,
		"slack_user", slackUser, "slack_team", team, observability.RequestIDAttr(ctx))
	ev := audit.Event{
		Time:             h.now(),
		UserID:           a.UserID,
		Tool:             a.Tool,
		AccountID:        a.AccountID,
		AccountLabel:     a.AccountLabel,
		ResourceIdentity: map[string]string{"action": "approval_slack_rejected", "tool": a.Tool, "slack_user": slackUser, "slack_team": team},
		Decision:         "deny",
		PolicyVersion:    a.PolicyVersionID,
		ApprovalID:       a.ID,
		Outcome:          "denied",
		ErrorClass:       "slack_user_mismatch",
		RequestID:        observability.RequestIDFromContext(ctx),
	}
	if err := h.audit.Record(ctx, ev); err != nil {
		h.log.Error("slack refusal not audited", "event", "slack.audit_failed", "approval_id", a.ID, "error", observability.RedactError(err), observability.RequestIDAttr(ctx))
	}
}

// parsePayload decodes the form-encoded "payload" JSON.
func parsePayload(body []byte) (*payload, error) {
	form, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, fmt.Errorf("slack: form: %w", err)
	}
	raw := form.Get("payload")
	if raw == "" {
		return nil, errors.New("slack: no payload")
	}
	var p payload
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return nil, fmt.Errorf("slack: payload: %w", err)
	}
	return &p, nil
}

// pressed returns the approve/deny action and the approval id it names,
// or "" when no known button was pressed.
func pressed(p *payload) (action, id string) {
	for _, a := range p.Actions {
		switch a.ActionID {
		case approvals.SlackActionApprove, approvals.SlackActionDeny:
			if a.Value != "" {
				return a.ActionID, a.Value
			}
		}
	}
	return "", ""
}

// notPendingText says why a press changed nothing.
func notPendingText(a *approvals.Approval, now time.Time) string {
	switch {
	case a.Status == approvals.StatusApproved:
		return "This approval was already approved."
	case a.Status == approvals.StatusDenied:
		return "This approval was already denied."
	case a.Status == approvals.StatusConsumed:
		return "This approval was already used."
	case a.Status == approvals.StatusExpired || !a.ExpiresAt.After(now):
		return "This approval has expired."
	}
	return "This approval was already decided."
}

// resolvedBlocks is the DM without its buttons: the call, then the
// outcome line.
func resolvedBlocks(a approvals.Approval, outcome string) []slackapi.Block {
	var blocks []slackapi.Block
	for _, b := range approvals.SlackApprovalBlocks(a, nil, "") {
		if b.BlockType() == slackapi.MBTAction {
			continue
		}
		blocks = append(blocks, b)
	}
	return append(blocks, slackapi.NewSectionBlock(slackapi.NewTextBlockObject(slackapi.MarkdownType, outcome, false, false), nil, nil))
}
