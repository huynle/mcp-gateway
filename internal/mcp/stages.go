package mcp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/observability"
)

// Stage names, the anchors for Pipeline.Insert. The default order is
// authenticate, audit, resolve, strip, [account,] ratelimit, dispatch:
// audit sits right after authenticate so it wraps every later stage and
// records the outcome whether the call was denied, rate limited or
// dispatched; account (StageAccount, account.go) is present when an
// AccountSource is configured. The policy, confirm and ledger tasks insert
// themselves between account and dispatch.
const (
	StageAuthenticate = "authenticate"
	StageAudit        = "audit"
	StageResolve      = "resolve"
	StageStrip        = "strip"
	StageRateLimit    = "ratelimit"
	StageDispatch     = "dispatch"
)

// Gateway-injected argument names. tools/list adds them to every tool's
// schema; the strip stage removes them before the tool's handler runs
// (decisions dovthftx, s0p05diu).
const (
	ArgAccount    = "account"
	ArgApprovalID = "approval_id"
)

// RateLimiter is the per-user hook the ratelimit stage consults before
// dispatch. Allow reports whether the call may proceed now and, when it may
// not, how long the harness should wait. The rate-limiting task supplies the
// real implementation (per user and per vendor app, decision dovthftx).
type RateLimiter interface {
	Allow(ctx context.Context, userID, tool string) (ok bool, retryAfter time.Duration)
}

// NopRateLimiter allows everything.
type NopRateLimiter struct{}

// Allow implements RateLimiter.
func (NopRateLimiter) Allow(context.Context, string, string) (bool, time.Duration) { return true, 0 }

// PipelineDeps is what DefaultPipeline needs. Registry is required;
// Visibility defaults to ScopeVisibility, RateLimiter to NopRateLimiter,
// Audit to audit.NopRecorder and Log to slog.Default(). Accounts enables
// the account stage; without it the account argument passes through to
// the connector unchecked (only acceptable in tests).
type PipelineDeps struct {
	Registry    *connectors.Registry
	Visibility  Visibility
	RateLimiter RateLimiter
	Accounts    connectors.AccountSource
	Audit       audit.Recorder
	// Metrics counts vendor rate limits (vendor_rate_limited_total); nil
	// counts nothing.
	Metrics *observability.Metrics
	Log     *slog.Logger
}

func (d *PipelineDeps) defaults() error {
	if d.Registry == nil {
		return errors.New("mcp: registry is required")
	}
	if d.Visibility == nil {
		d.Visibility = ScopeVisibility{}
	}
	if d.RateLimiter == nil {
		d.RateLimiter = NopRateLimiter{}
	}
	if d.Audit == nil {
		d.Audit = audit.NopRecorder{}
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
	return nil
}

// DefaultPipeline builds the standard pipeline: authenticate, audit,
// resolve, strip, account (when deps.Accounts is set), ratelimit,
// dispatch.
func DefaultPipeline(deps PipelineDeps) (*Pipeline, error) {
	if err := deps.defaults(); err != nil {
		return nil, err
	}
	stages := []Stage{
		AuthenticateStage(),
		AuditStage(deps.Audit, deps.Log),
		ResolveStage(deps.Registry, deps.Visibility),
		StripStage(),
	}
	if deps.Accounts != nil {
		stages = append(stages, AccountStage(deps.Accounts, deps.Log))
	}
	stages = append(stages, RateLimitStage(deps.RateLimiter, deps.Metrics), DispatchStage())
	return NewPipeline(stages...)
}

// stage is a named function.
type stage struct {
	name string
	run  func(ctx context.Context, cc *CallContext, next Next) (connectors.Result, error)
}

func (s stage) Name() string { return s.name }
func (s stage) Run(ctx context.Context, cc *CallContext, next Next) (connectors.Result, error) {
	return s.run(ctx, cc, next)
}

// AuthenticateStage requires a principal on the CallContext (the HTTP
// bearer middleware put it in the request context; the handler copies it).
// It fails closed with CodeUnauthenticated so a misconfigured mount can
// never dispatch anonymously.
func AuthenticateStage() Stage {
	return stage{StageAuthenticate, func(ctx context.Context, cc *CallContext, next Next) (connectors.Result, error) {
		if cc.Principal == nil || cc.Principal.UserID == "" {
			return connectors.Result{}, errUnauthenticated
		}
		cc.Call.Principal = connectors.Principal{UserID: cc.Principal.UserID, TokenID: cc.Principal.TokenID}
		return next(ctx)
	}}
}

// ResolveStage looks the requested name up in the registry and checks the
// caller may see it. A missing tool and a hidden tool return the very same
// error value.
func ResolveStage(reg *connectors.Registry, vis Visibility) Stage {
	return stage{StageResolve, func(ctx context.Context, cc *CallContext, next Next) (connectors.Result, error) {
		tool, ok := reg.Get(cc.Name)
		if !ok || !vis.Visible(ctx, cc.Principal, tool) {
			return connectors.Result{}, ErrToolNotFound(cc.Name)
		}
		cc.Tool = &tool
		cc.Call.Tool = tool.FullName()
		return next(ctx)
	}}
}

// StripStage moves the gateway-injected arguments out of the argument map:
// account to Call.Account, approval_id to Call.ApprovalID. The handler
// never sees them. Call.Args is always a non-nil map.
func StripStage() Stage {
	return stage{StageStrip, func(ctx context.Context, cc *CallContext, next Next) (connectors.Result, error) {
		args := make(map[string]any, len(cc.RawArgs))
		for k, v := range cc.RawArgs {
			switch k {
			case ArgAccount, ArgApprovalID:
				s, ok := v.(string)
				if !ok && v != nil {
					return connectors.Result{}, NewToolError(CodeInvalidParams, "invalid_params", fmt.Sprintf("argument %q must be a string", k))
				}
				if k == ArgAccount {
					cc.Call.Account = s
				} else {
					cc.Call.ApprovalID = s
					cc.ApprovalID = s
				}
			default:
				args[k] = v
			}
		}
		cc.Call.Args = args
		return next(ctx)
	}}
}

// RateLimitStage asks the limiter before continuing and turns a refusal
// into CodeRateLimited carrying the wait. After the call it watches for a
// connectors.RateLimited from the connector (a vendor 429): the error
// becomes CodeRateLimited with the vendor's Retry-After, the app's bucket
// is paused for that long when the limiter is an AppPauser, and
// vendor_rate_limited_total{app} is incremented.
func RateLimitStage(l RateLimiter, metrics *observability.Metrics) Stage {
	if l == nil {
		l = NopRateLimiter{}
	}
	pauser, _ := l.(AppPauser)
	return stage{StageRateLimit, func(ctx context.Context, cc *CallContext, next Next) (connectors.Result, error) {
		ok, wait := l.Allow(ctx, cc.Principal.UserID, cc.Call.Tool)
		if !ok {
			cc.Decision = "deny"
			te := NewToolError(CodeRateLimited, "rate_limited", fmt.Sprintf("rate limited; retry in %s", wait.Round(time.Second)))
			te.RetryAfter = wait
			return connectors.Result{}, te
		}
		res, err := next(ctx)
		var rl *connectors.RateLimited
		if !errors.As(err, &rl) {
			return res, err
		}
		app := rl.App
		if app == "" && cc.Tool != nil {
			app = cc.Tool.App
		}
		if pauser != nil {
			pauser.Pause(app, rl.RetryAfter)
		}
		if metrics != nil {
			metrics.VendorRateLimited(app)
		}
		cc.Decision = "deny"
		te := NewToolError(CodeRateLimited, "vendor_rate_limited",
			fmt.Sprintf("%s is rate limiting this gateway; retry in %s", app, rl.RetryAfter.Round(time.Second)))
		te.RetryAfter = rl.RetryAfter
		return connectors.Result{}, te
	}}
}

// DispatchStage runs the resolved tool's handler. It is terminal: it never
// calls next.
func DispatchStage() Stage {
	return stage{StageDispatch, func(ctx context.Context, cc *CallContext, _ Next) (connectors.Result, error) {
		if cc.Tool == nil {
			return connectors.Result{}, ErrToolNotFound(cc.Name)
		}
		return cc.Tool.Handler(ctx, cc.Call)
	}}
}

// AuditStage records one audit.Event per call after every later stage
// returned: tool, user, token, resolved account, resource identity from the
// tool's hook, decision, policy version, approval, operation, outcome,
// latency, request ID and a short error class. Arguments and results are
// never part of it (audit.Event has no field for them). A recorder failure
// is logged and does not change the call's outcome. Calls with no principal
// are not recorded: they are rejected before anything happened and an
// event without a user would be a system event.
func AuditStage(rec audit.Recorder, log *slog.Logger) Stage {
	if rec == nil {
		rec = audit.NopRecorder{}
	}
	if log == nil {
		log = slog.Default()
	}
	return stage{StageAudit, func(ctx context.Context, cc *CallContext, next Next) (connectors.Result, error) {
		res, err := next(ctx)
		if cc.Principal == nil {
			return res, err
		}
		ev := auditEvent(ctx, cc, res, err)
		if rerr := rec.Record(ctx, ev); rerr != nil {
			log.Error("audit event not recorded", "event", "mcp.audit_failed", "tool", cc.Name,
				"error", observability.RedactError(rerr), observability.RequestIDAttr(ctx))
		}
		log.Info("tool call", "event", "mcp.tool_call", "tool", ev.Tool, "user_id", ev.UserID,
			"public_id", cc.Principal.PublicID, "decision", ev.Decision, "outcome", ev.Outcome,
			"error_class", ev.ErrorClass, "latency_ms", ev.Latency.Milliseconds(), observability.RequestIDAttr(ctx))
		return res, err
	}}
}

// auditEvent derives the event from the call's final state.
func auditEvent(ctx context.Context, cc *CallContext, res connectors.Result, err error) audit.Event {
	requestID := cc.RequestID
	if requestID == "" {
		requestID = observability.RequestIDFromContext(ctx)
	}
	ev := audit.Event{
		Time:          time.Now(),
		UserID:        cc.Principal.UserID,
		TokenID:       cc.Principal.TokenID,
		Tool:          cc.Call.Tool,
		AccountID:     cc.AccountID,
		AccountLabel:  cc.AccountLabel,
		Decision:      cc.Decision,
		PolicyVersion: cc.PolicyVersion,
		ApprovalID:    cc.ApprovalID,
		OperationID:   cc.OperationID,
		Latency:       time.Since(cc.Started),
		RequestID:     requestID,
	}
	if cc.Tool != nil && cc.Tool.ResourceIdentity != nil {
		ev.ResourceIdentity = cc.Tool.ResourceIdentity(cc.Call.Args)
	}
	var te *ToolError
	switch {
	case errors.As(err, &te):
		ev.ErrorClass = te.Class()
		if te.Denial() {
			ev.Decision = "deny"
			ev.Outcome = "denied"
		} else {
			ev.Outcome = "failed"
		}
	case err != nil:
		ev.Outcome = "failed"
		ev.ErrorClass = "tool_error"
	default:
		ev.Outcome = "succeeded"
		switch {
		case res.Unavailable:
			ev.ErrorClass = "unavailable"
		case res.Partial:
			ev.ErrorClass = "partial"
		}
	}
	return ev
}
