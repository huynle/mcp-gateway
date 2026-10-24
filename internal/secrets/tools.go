package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/secrets/ref"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

// App is the built-in secrets app (policy.SecretsApp): its tools are
// "secrets.<name>", the name is reserved for user-added servers, and the
// policy's secrets layer lets every user call them except with a
// read-only token (design correction 6).
const App = "secrets"

// ToolRequest is secrets.request.
const ToolRequest = "request"

// MaxToolLabelLen bounds the label secrets.request accepts, in characters
// (the service allows MaxLabelLen; the tool keeps it short for the entry
// page and the agent's message).
const MaxToolLabelLen = 80

// limitedRetryAfter is how long a harness over the request limits is told
// to wait: a pending request's link ends within LinkTTL.
const limitedRetryAfter = LinkTTL

// Targets resolves a registered tool to what a secret binds to: the id of
// its server and the tool's upstream name. Only the tools of user-added
// MCP servers and machines have one (v1); built-in apps return false.
// *connector.Manager (internal/federation/connector) implements it.
type Targets interface {
	SecretTarget(app, tool string) (serverID, upstream string, ok bool)
}

// ToolLookup finds a registered tool by its full name
// (*connectors.Registry).
type ToolLookup interface {
	Get(name string) (connectors.Tool, bool)
}

// ConnectorDeps are the secrets app's collaborators; all but Log are
// required. Visibility must be the one the /mcp pipeline uses, so a
// secret can only be requested for a tool the caller can see. BaseURL is
// GATEWAY_BASE_URL (the entry links are <BaseURL>/s/<request id>).
type ConnectorDeps struct {
	Service    *Service
	Tools      ToolLookup
	Visibility mcp.Visibility
	Targets    Targets
	BaseURL    string
	Log        *slog.Logger
}

// Connector is the secrets app: secrets.request.
type Connector struct {
	d    ConnectorDeps
	base string
}

// NewConnector builds the app.
func NewConnector(d ConnectorDeps) (*Connector, error) {
	if d.Service == nil || d.Tools == nil || d.Visibility == nil || d.Targets == nil {
		return nil, errors.New("secrets: Service, Tools, Visibility and Targets are required")
	}
	base := strings.TrimRight(strings.TrimSpace(d.BaseURL), "/")
	if base == "" {
		return nil, errors.New("secrets: the base URL is required (entry links)")
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
	return &Connector{d: d, base: base}, nil
}

// App implements connectors.Connector.
func (c *Connector) App() string { return App }

// Register adds the tools to reg. Unlike connectors.RegisterConnector it
// adds no secrets.list_accounts: the app needs no account.
func (c *Connector) Register(reg *connectors.Registry) error {
	for _, t := range c.Tools() {
		if err := reg.Register(t); err != nil {
			return err
		}
	}
	return nil
}

// Call implements connectors.Connector.
func (c *Connector) Call(ctx context.Context, call connectors.Call) (connectors.Result, error) {
	if call.Tool != App+"."+ToolRequest {
		return connectors.Result{}, connectors.ErrUnknownTool
	}
	return c.request(ctx, call)
}

// fullNameRE is the shape of a registered tool's full name.
var fullNameRE = regexp.MustCompile(`^[a-z0-9_-]{1,63}\.[a-z0-9_-]{1,64}$`)

const requestSchema = `{"type":"object","properties":{` +
	`"label":{"type":"string","minLength":1,"maxLength":80,"description":"What the secret is, as the user will see it on the entry page (\"vault password\")."},` +
	`"tool":{"type":"string","description":"The full name of the tool the secret is for, as in tools/list (\"<server>.<tool>\"; a machine action is \"<machine>-actions.<action>\")."},` +
	`"arg":{"type":"string","description":"The top-level argument of that tool the secret goes into (\"secret\" for a machine action)."},` +
	`"ttl":{"type":"string","description":"How long the secret stays usable once entered, as a Go duration (default 15m, 1m to 1h)."},` +
	`"uses":{"type":"integer","minimum":1,"maximum":10,"description":"How many calls may use it (default 1)."}` +
	`},"required":["label","tool","arg"],"additionalProperties":false}`

// Tools implements connectors.Connector.
func (c *Connector) Tools() []connectors.Tool {
	return []connectors.Tool{{
		App: App, Name: ToolRequest, Kind: connectors.KindRead, NoAccount: true,
		Description: "Ask the user for a secret (password, API key, passphrase) without it ever entering this chat. " +
			"The secret is bound to one tool and argument; the answer is an error with a link for the user and a handle. " +
			"Show the user the link and the check words, never ask them to paste the secret here; once they entered it, " +
			"call the tool with {\"<arg>\": {\"$secret\": \"<handle>\"}}: the gateway puts the value in for that tool only " +
			"and removes it from the result. v1: tools of MCP servers and machines only.",
		InputSchema:      json.RawMessage(requestSchema),
		ResourceIdentity: requestIdentity,
		Bounds:           connectors.Bounds{MaxResultBytes: connectors.DefaultMaxResultBytes},
		Handler:          c.request,
	}}
}

// requestIdentity is the audit/policy identity: the target tool's name
// when it is well formed, else "invalid".
func requestIdentity(args map[string]any) map[string]string {
	name, _ := args["tool"].(string)
	if !fullNameRE.MatchString(name) {
		name = "invalid"
	}
	return map[string]string{"tool": name}
}

func invalidParams(msg string) *mcp.ToolError {
	return mcp.NewToolError(mcp.CodeInvalidParams, "invalid_params", msg)
}

// unknownTarget is the one answer for a target that does not exist or
// that the caller cannot see.
func unknownTarget(name string) *mcp.ToolError {
	return mcp.NewToolError(mcp.CodeInvalidParams, "secret_target_unknown", fmt.Sprintf("unknown tool %q", name))
}

type requestArgs struct {
	label, tool, arg string
	ttl              time.Duration
	uses             int
}

func parseRequestArgs(args map[string]any) (requestArgs, *mcp.ToolError) {
	var out requestArgs
	label, ok := args["label"].(string)
	label = strings.TrimSpace(label)
	if !ok || label == "" || utf8.RuneCountInString(label) > MaxToolLabelLen {
		return out, invalidParams(fmt.Sprintf("label must be 1 to %d characters", MaxToolLabelLen))
	}
	out.label = label
	if out.tool, ok = args["tool"].(string); !ok || out.tool == "" {
		return out, invalidParams("tool must be the full name of a tool (\"<server>.<tool>\")")
	}
	if out.arg, ok = args["arg"].(string); !ok || !validArgName(out.arg) {
		return out, invalidParams("arg must name a top-level argument of the tool")
	}
	if out.arg == mcp.ArgAccount || out.arg == mcp.ArgApprovalID {
		return out, invalidParams(fmt.Sprintf("arg %q is set by the gateway and cannot take a secret", out.arg))
	}
	out.ttl = DefaultTTL
	if v, present := args["ttl"]; present && v != nil {
		s, ok := v.(string)
		d, err := time.ParseDuration(strings.TrimSpace(s))
		if !ok || err != nil || d < MinTTL || d > MaxTTL {
			return out, invalidParams(fmt.Sprintf("ttl must be a duration from %s to %s (\"15m\")", MinTTL, MaxTTL))
		}
		out.ttl = d
	}
	out.uses = DefaultUses
	if v, present := args["uses"]; present && v != nil {
		n, ok := intArg(v)
		if !ok || n < 1 || n > MaxUses {
			return out, invalidParams(fmt.Sprintf("uses must be a whole number from 1 to %d", MaxUses))
		}
		out.uses = n
	}
	return out, nil
}

// validArgName accepts 1-200 characters without control characters.
func validArgName(s string) bool {
	if s == "" || len(s) > 200 || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// intArg reads a JSON integer (float64 from encoding/json, json.Number or
// an int).
func intArg(v any) (int, bool) {
	switch n := v.(type) {
	case float64:
		if n != math.Trunc(n) || n < math.MinInt32 || n > math.MaxInt32 {
			return 0, false
		}
		return int(n), true
	case json.Number:
		i, err := n.Int64()
		if err != nil || i < math.MinInt32 || i > math.MaxInt32 {
			return 0, false
		}
		return int(i), true
	case int:
		return n, true
	}
	return 0, false
}

// schemaHasArg reports whether a tool's input schema allows the
// top-level argument arg: a schema that declares properties must list it;
// one without a properties object is taken as open.
func schemaHasArg(schema json.RawMessage, arg string) bool {
	var s struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(schema, &s); err != nil {
		return false
	}
	if s.Properties == nil {
		return true
	}
	_, ok := s.Properties[arg]
	return ok
}

// request is secrets.request: validate, store the pending request, and
// answer -32042 with the entry link and the handle.
func (c *Connector) request(ctx context.Context, call connectors.Call) (connectors.Result, error) {
	a, terr := parseRequestArgs(call.Args)
	if terr != nil {
		return connectors.Result{}, terr
	}
	owner, harness := call.Principal.UserID, call.Principal.TokenID
	p := tokens.PrincipalFrom(ctx)
	target, ok := c.d.Tools.Get(a.tool)
	if !ok || p == nil || p.UserID != owner || owner == "" || !c.d.Visibility.Visible(ctx, p, target) {
		return connectors.Result{}, unknownTarget(a.tool)
	}
	if target.App == App {
		return connectors.Result{}, invalidParams("a secret cannot be bound to a secrets tool")
	}
	serverID, upstream, ok := c.d.Targets.SecretTarget(target.App, target.Name)
	if !ok {
		return connectors.Result{}, invalidParams(a.tool + " is a built-in tool; secrets can only be bound to tools of MCP servers and machines")
	}
	if !schemaHasArg(target.InputSchema, a.arg) {
		return connectors.Result{}, invalidParams(fmt.Sprintf("%s has no argument %q", a.tool, a.arg))
	}
	req, err := c.d.Service.Request(ctx, owner, harness, a.label, Binding{ServerID: serverID, Tool: upstream, Arg: a.arg}, a.ttl, a.uses)
	switch {
	case errors.Is(err, ErrLimited):
		return connectors.Result{}, mcp.ErrSecretsLimited(limitedRetryAfter)
	case errors.Is(err, ErrInvalid):
		return connectors.Result{}, invalidParams("invalid secret request")
	case err != nil:
		c.d.Log.Error("secret request failed", "event", "secrets.request_failed", "error", err.Error())
		return connectors.Result{}, mcp.NewToolError(mcp.CodeInternal, "secrets_unavailable", "the secret request could not be stored")
	}
	return connectors.Result{}, secretRequired(c.base, req.Handle, a.arg, req.Secret)
}

// secretRequired is the -32042 answer for the pending request behind
// handle (sec is its record): the entry link, the fingerprint the entry
// page shows, and how to retry. The same answer is given again while the
// request is pending.
func secretRequired(base, handle, arg string, sec Secret) *mcp.ToolError {
	requestID := RequestIDForHandle(handle)
	link := base + "/s/" + requestID
	fp := ref.Fingerprint(requestID)
	key, _ := json.Marshal(arg)
	msg := fmt.Sprintf("Ask the user to open %s and enter the secret (check the words: %s). Then retry the call with {%s: {\"$secret\": %q}}.",
		link, fp, key, handle)
	elicit := fmt.Sprintf("Enter the secret %q on the gateway (check the words: %s).", sec.Label, fp)
	return mcp.NewSecretRequired(msg, map[string]any{
		"elicitations": []any{map[string]any{"mode": "url", "elicitationId": sec.ID, "url": link, "message": elicit}},
		"url":          link,
		"handle":       handle,
		"fingerprint":  fp,
		"expires_at":   sec.LinkExpiresAt.UTC().Format(time.RFC3339),
	})
}
