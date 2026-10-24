package secrets

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/secrets/ref"
	"github.com/huynle/mcp-gateway/internal/secrets/scrub"
)

// StageName is the secret stage's pipeline name. It belongs immediately
// before dispatch, after policy, ledger and rate limit (design correction
// 3):
//
//	p.Insert(mcp.Before, mcp.StageDispatch, stage)
const StageName = "secrets"

// Use is one use of a secret, as the stage reports it: record id and
// label, never the value or the handle.
type Use struct {
	UserID    string
	HarnessID string
	SecretID  string
	Label     string
	// Tool is the full gateway name of the tool the secret was used for.
	Tool string
}

// UseHook is told about every use that stays consumed after the call
// (audit "secret.used"). It must not fail the call.
type UseHook interface {
	SecretUsed(ctx context.Context, u Use)
}

// StageOptions configure the stage. Service and Targets are required;
// BaseURL is GATEWAY_BASE_URL (the entry link of a pending request); Hook
// and Log are optional.
type StageOptions struct {
	Service *Service
	Targets Targets
	BaseURL string
	Hook    UseHook
	Log     *slog.Logger
}

// refundClasses are the error classes of a call that failed before it
// reached its target, so the use it took is given back: gateway refusals
// at dispatch (the federation connector's review, credential and client
// checks) and an offline or unavailable tunnel. Anything else (upstream
// errors, timeouts, unclassed errors) keeps the use: the value may have
// been delivered. A failure whose outcome is unknown never refunds.
var refundClasses = map[string]bool{
	"tunnel_offline": true, "tunnel_unavailable": true,
	"tool_not_found": true, "server_unavailable": true, "tool_disabled": true, "tool_not_reviewed": true,
	"tool_changed": true, "args_invalid": true, "snapshot_unavailable": true, "server_not_configured": true,
	"credentials_unavailable": true, "client_unavailable": true,
	// A declared per-user header without a value (credential links):
	// refused before the upstream.
	"user_header_missing": true,
}

type secretStage struct {
	o    StageOptions
	base string
}

// NewStage builds the secret stage. For a call whose arguments hold
// {"$secret": handle} references it:
//
//  1. resolves the called tool to its binding (Targets: server id and
//     upstream tool; built-in tools have none) and requires every ref to
//     be exactly the value of a top-level argument;
//  2. checks every handle's Status first: pending answers -32042 with the
//     same link, denied -32030; nothing is consumed unless all are usable;
//  3. consumes one use per handle (Service.Consume) and substitutes the
//     plaintext into a copy of the arguments;
//  4. runs the call, then scrubs the value from the result and the error
//     (including a *mcp.ToolError's Message and Data), restores the
//     handle-form arguments for audit, wipes the plaintext buffers and
//     refunds the uses when the call failed before reaching its target.
//
// Every other refusal is mcp.ErrSecretUnavailable, the same for every
// cause. Calls without refs pass through untouched.
func NewStage(o StageOptions) (mcp.Stage, error) {
	if o.Service == nil || o.Targets == nil {
		return nil, errors.New("secrets: the stage needs Service and Targets")
	}
	base := strings.TrimRight(strings.TrimSpace(o.BaseURL), "/")
	if base == "" {
		return nil, errors.New("secrets: the stage needs the base URL (entry links)")
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	return &secretStage{o: o, base: base}, nil
}

func (s *secretStage) Name() string { return StageName }

// handleUse is one distinct handle of a call and the argument it sits in.
type handleUse struct {
	handle string
	arg    string
	status StatusResult
	used   Consumed
}

func (s *secretStage) Run(ctx context.Context, cc *mcp.CallContext, next mcp.Next) (connectors.Result, error) {
	locs := ref.FindWithPaths(cc.Call.Args)
	if len(locs) == 0 {
		return next(ctx)
	}
	if cc.Tool == nil || cc.Principal == nil || cc.Principal.UserID == "" {
		return connectors.Result{}, mcp.ErrSecretUnavailable()
	}
	owner, harness := cc.Principal.UserID, cc.Principal.TokenID
	serverID, upstream, ok := s.o.Targets.SecretTarget(cc.Tool.App, cc.Tool.Name)
	if !ok {
		return connectors.Result{}, mcp.ErrSecretUnavailable()
	}
	var uses []*handleUse
	byHandle := map[string]*handleUse{}
	for _, l := range locs {
		if !l.BoundTo(l.Arg) {
			return connectors.Result{}, mcp.ErrSecretUnavailable()
		}
		if u, seen := byHandle[l.Handle]; seen {
			if u.arg != l.Arg {
				return connectors.Result{}, mcp.ErrSecretUnavailable()
			}
			continue
		}
		u := &handleUse{handle: l.Handle, arg: l.Arg}
		byHandle[l.Handle] = u
		uses = append(uses, u)
	}
	bindingOf := func(u *handleUse) Binding { return Binding{ServerID: serverID, Tool: upstream, Arg: u.arg} }

	// Status first, for every handle: nothing is consumed while one of
	// them is pending, denied or unusable.
	for _, u := range uses {
		st, err := s.o.Service.Status(ctx, owner, harness, u.handle)
		if err != nil {
			s.o.Log.Error("secret status failed", "event", "secrets.status_failed", "error", err.Error())
			return connectors.Result{}, mcp.ErrSecretUnavailable()
		}
		u.status = st
		if st.Status == StatusUnavailable || st.Secret == nil || st.Secret.Binding != bindingOf(u) {
			return connectors.Result{}, mcp.ErrSecretUnavailable()
		}
		switch st.Status {
		case StatusPending:
			return connectors.Result{}, secretRequired(s.base, u.handle, u.arg, *st.Secret)
		case StatusDenied:
			return connectors.Result{}, mcp.ErrSecretDenied()
		}
	}

	defer func() {
		for _, u := range uses {
			wipe(u.used.Value)
		}
	}()
	values := make(map[string]string, len(uses))
	for i, u := range uses {
		c, err := s.o.Service.Consume(ctx, owner, harness, u.handle, bindingOf(u))
		if err != nil {
			s.refund(ctx, owner, uses[:i])
			switch {
			case errors.Is(err, ErrPending):
				return connectors.Result{}, secretRequired(s.base, u.handle, u.arg, *u.status.Secret)
			case errors.Is(err, ErrDenied):
				return connectors.Result{}, mcp.ErrSecretDenied()
			case !errors.Is(err, ErrUnavailable):
				s.o.Log.Error("secret consume failed", "event", "secrets.consume_failed", "error", err.Error())
			}
			return connectors.Result{}, mcp.ErrSecretUnavailable()
		}
		u.used = c
		values[u.handle] = string(c.Value)
	}
	substituted, err := ref.ReplaceArgs(cc.Call.Args, values)
	if err != nil {
		s.refund(ctx, owner, uses)
		return connectors.Result{}, mcp.ErrSecretUnavailable()
	}

	plain := make([]string, 0, len(values))
	for _, v := range values {
		plain = append(plain, v)
	}
	scr := scrub.New(plain...)
	clear(values)

	orig := cc.Call.Args
	cc.Call.Args = substituted
	res, callErr := func() (connectors.Result, error) {
		defer func() { cc.Call.Args = orig }()
		return next(ctx)
	}()

	res.Content = scr.Any(res.Content)
	callErr = scrubError(scr, callErr)

	if refundable(callErr) {
		s.refund(ctx, owner, uses)
		return res, callErr
	}
	if s.o.Hook != nil {
		for _, u := range uses {
			s.o.Hook.SecretUsed(ctx, Use{UserID: owner, HarnessID: harness, SecretID: u.used.SecretID, Label: u.used.Label, Tool: cc.Tool.FullName()})
		}
	}
	return res, callErr
}

// refund gives back the uses taken; a failure is logged (the use stays
// consumed, the safe side).
func (s *secretStage) refund(ctx context.Context, owner string, uses []*handleUse) {
	for _, u := range uses {
		if u.used.SecretID == "" {
			continue
		}
		if err := s.o.Service.Refund(ctx, owner, u.used.SecretID); err != nil {
			s.o.Log.Warn("secret refund failed", "event", "secrets.refund_failed", "secret_id", u.used.SecretID, "error", err.Error())
		}
	}
}

// refundable reports whether err says the call never reached its target.
func refundable(err error) bool {
	if err == nil || errors.Is(err, connectors.ErrOutcomeUnknown) {
		return false
	}
	var te *mcp.ToolError
	if errors.As(err, &te) {
		return refundClasses[te.Class()]
	}
	var ce mcp.ClassedError
	if errors.As(err, &ce) {
		return refundClasses[ce.ErrorClass()]
	}
	return false
}

// scrubError scrubs err's text. A *mcp.ToolError in the chain is what the
// endpoint renders (Message and Data), and scrub.Error cannot reach its
// fields through errors.As, so it is rebuilt with both scrubbed and
// returned in place of the chain; any other error keeps its chain
// (errors.Is / ClassedError) behind a scrubbed message.
func scrubError(s *scrub.Scrubber, err error) error {
	if err == nil {
		return nil
	}
	var te *mcp.ToolError
	if errors.As(err, &te) {
		out := mcp.NewToolError(te.Code, te.Class(), s.String(te.Message))
		out.RetryAfter = te.RetryAfter
		if te.Data != nil {
			if m, ok := s.Any(te.Data).(map[string]any); ok {
				out.Data = m
			}
		}
		return out
	}
	return s.Error(err)
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
