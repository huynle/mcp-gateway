package github

import (
	"context"
	"errors"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Reconciliation checks (filled in by the following increments).

func (c *Connector) checkIssue(context.Context, connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	return connectors.ReconcileResult{}, errors.New("github: create_issue check not implemented")
}

func (c *Connector) checkComment(context.Context, connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	return connectors.ReconcileResult{}, errors.New("github: add_issue_comment check not implemented")
}

func (c *Connector) checkPullRequest(context.Context, connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	return connectors.ReconcileResult{}, errors.New("github: create_pull_request check not implemented")
}

func (c *Connector) checkBranch(context.Context, connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	return connectors.ReconcileResult{}, errors.New("github: create_branch check not implemented")
}
