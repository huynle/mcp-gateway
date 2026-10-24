package mcp_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/mcp"
)

// explainingSource is an account source with the optional MissingAccount
// hook (the federation's per-user servers, behind credential links).
type explainingSource struct {
	*connectors.StaticAccountSource
	answer error
	asked  []string
}

func (s *explainingSource) MissingAccount(_ context.Context, userID, app string) error {
	s.asked = append(s.asked, userID+"/"+app)
	return s.answer
}

func TestAccountStageMissingAccountHook(t *testing.T) {
	link := mcp.NewURLElicitationRequired("no_account", "notes: connect your account at https://gw/servers/1#connection, then retry",
		[]mcp.URLElicitation{{ElicitationID: "gwc_1", URL: "https://gw/servers/1#connection", Message: "Connect notes"}}, nil)
	src := &explainingSource{StaticAccountSource: connectors.NewStaticAccountSource(), answer: link}
	rec := &captureRecorder{}
	p := accountPipeline(t, newRegistry(t, echoTool("github", "list_issues", connectors.KindRead)), src, rec)
	_, err := p.Run(context.Background(), &mcp.CallContext{Principal: principal, Name: "github.list_issues"})
	var te *mcp.ToolError
	if !errors.As(err, &te) || te != link {
		t.Fatalf("err = %v, want the hook's answer", err)
	}
	if len(src.asked) != 1 || src.asked[0] != principal.UserID+"/github" {
		t.Errorf("hook asked %v", src.asked)
	}
	if ev := rec.events[0]; ev.ErrorClass != "no_account" || ev.Outcome != "failed" {
		t.Errorf("audit = %+v (the class stays no_account)", ev)
	}

	// Nothing to say (nil) or an error that is not a ToolError: today's
	// no_account, byte for byte.
	for _, answer := range []error{nil, errors.New("db down")} {
		src.answer = answer
		_, err := p.Run(context.Background(), &mcp.CallContext{Principal: principal, Name: "github.list_issues"})
		if !errors.As(err, &te) || te.Code != mcp.CodeNoAccount || te.Class() != "no_account" || te.Message != "no connected account for github" || te.Data != nil {
			t.Errorf("answer %v: err = %v, want today's no_account", answer, err)
		}
	}

	// The hook is not asked when there is an account.
	src.asked = nil
	src.Add(principal.UserID, connectors.Account{ID: "gh-1", App: "github"})
	if _, err := p.Run(context.Background(), &mcp.CallContext{Principal: principal, Name: "github.list_issues"}); err != nil {
		t.Fatal(err)
	}
	if len(src.asked) != 0 {
		t.Errorf("hook asked with an account: %v", src.asked)
	}
}

type toolErrorSource struct{ err error }

func (s toolErrorSource) ListAccounts(context.Context, string, string) ([]connectors.Account, error) {
	return nil, s.err
}

// A source that already knows the answer (a *ToolError) gets it through;
// any other failure stays account_lookup_failed.
func TestAccountStagePassesToolErrorsThrough(t *testing.T) {
	want := mcp.NewToolError(mcp.CodeNoAccount, "needs_reconnect", "reconnect")
	p := accountPipeline(t, newRegistry(t, echoTool("github", "list_issues", connectors.KindRead)), toolErrorSource{fmt.Errorf("wrapped: %w", want)}, nil)
	_, err := p.Run(context.Background(), &mcp.CallContext{Principal: principal, Name: "github.list_issues"})
	var te *mcp.ToolError
	if !errors.As(err, &te) || te != want {
		t.Fatalf("err = %v, want the source's ToolError", err)
	}
}
