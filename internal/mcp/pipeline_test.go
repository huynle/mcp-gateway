package mcp_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/mcp"
)

// traceStage appends "name>" on the way in and "<name" on the way out so a
// test can assert the onion order of a pipeline run.
type traceStage struct {
	name string
	log  *[]string
	// terminal stages answer without calling next.
	terminal bool
}

func (s traceStage) Name() string { return s.name }

func (s traceStage) Run(ctx context.Context, cc *mcp.CallContext, next mcp.Next) (connectors.Result, error) {
	*s.log = append(*s.log, s.name+">")
	if s.terminal {
		return connectors.Result{Content: "from " + s.name}, nil
	}
	res, err := next(ctx)
	*s.log = append(*s.log, "<"+s.name)
	return res, err
}

func TestPipelineRunsStagesInOrder(t *testing.T) {
	var log []string
	p, err := mcp.NewPipeline(
		traceStage{name: "a", log: &log},
		traceStage{name: "b", log: &log},
		traceStage{name: "c", log: &log, terminal: true},
	)
	if err != nil {
		t.Fatal(err)
	}
	res, err := p.Run(context.Background(), &mcp.CallContext{Name: "x.y"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Content != "from c" {
		t.Errorf("Content = %v", res.Content)
	}
	if got := strings.Join(log, " "); got != "a> b> c> <b <a" {
		t.Errorf("order = %q", got)
	}
	if got := strings.Join(p.Names(), ","); got != "a,b,c" {
		t.Errorf("Names = %q", got)
	}
}

func TestPipelineInsertBeforeAndAfter(t *testing.T) {
	var log []string
	p, err := mcp.NewPipeline(
		traceStage{name: "a", log: &log},
		traceStage{name: "c", log: &log, terminal: true},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Insert(mcp.Before, "c", traceStage{name: "b", log: &log}); err != nil {
		t.Fatalf("Insert before: %v", err)
	}
	if err := p.Insert(mcp.After, "a", traceStage{name: "a2", log: &log}); err != nil {
		t.Fatalf("Insert after: %v", err)
	}
	if got := strings.Join(p.Names(), ","); got != "a,a2,b,c" {
		t.Errorf("Names = %q", got)
	}
	if _, err := p.Run(context.Background(), &mcp.CallContext{}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(log, " "); got != "a> a2> b> c> <b <a2 <a" {
		t.Errorf("order = %q", got)
	}
}

func TestPipelineInsertErrors(t *testing.T) {
	var log []string
	p, err := mcp.NewPipeline(traceStage{name: "a", log: &log}, traceStage{name: "c", log: &log, terminal: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Insert(mcp.Before, "nope", traceStage{name: "b", log: &log}); !errors.Is(err, mcp.ErrStageNotFound) {
		t.Errorf("unknown anchor err = %v, want ErrStageNotFound", err)
	}
	if err := p.Insert(mcp.After, "a", traceStage{name: "c", log: &log}); !errors.Is(err, mcp.ErrDuplicateStage) {
		t.Errorf("duplicate name err = %v, want ErrDuplicateStage", err)
	}
	if err := p.Insert(mcp.After, "a", traceStage{name: "", log: &log}); !errors.Is(err, mcp.ErrInvalidStage) {
		t.Errorf("empty name err = %v, want ErrInvalidStage", err)
	}
	if err := p.Insert(mcp.After, "a", nil); !errors.Is(err, mcp.ErrInvalidStage) {
		t.Errorf("nil stage err = %v, want ErrInvalidStage", err)
	}
	if got := strings.Join(p.Names(), ","); got != "a,c" {
		t.Errorf("failed inserts changed the pipeline: %q", got)
	}
}

func TestNewPipelineRejectsDuplicateNames(t *testing.T) {
	var log []string
	_, err := mcp.NewPipeline(traceStage{name: "a", log: &log}, traceStage{name: "a", log: &log})
	if !errors.Is(err, mcp.ErrDuplicateStage) {
		t.Errorf("err = %v, want ErrDuplicateStage", err)
	}
}

func TestPipelineWithoutTerminalStageFails(t *testing.T) {
	var log []string
	p, err := mcp.NewPipeline(traceStage{name: "a", log: &log})
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.Run(context.Background(), &mcp.CallContext{})
	if !errors.Is(err, mcp.ErrNoDispatch) {
		t.Errorf("err = %v, want ErrNoDispatch", err)
	}
}

func TestPipelineRunSetsDefaults(t *testing.T) {
	var seen *mcp.CallContext
	capture := newStageFunc("cap", func(ctx context.Context, cc *mcp.CallContext, _ mcp.Next) (connectors.Result, error) {
		seen = cc
		return connectors.Result{}, nil
	})
	p, err := mcp.NewPipeline(capture)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Run(context.Background(), &mcp.CallContext{Name: "x.y"}); err != nil {
		t.Fatal(err)
	}
	if seen.Started.IsZero() {
		t.Error("Started not set")
	}
	if seen.Decision != "allow" {
		t.Errorf("Decision = %q, want allow by default (policy stage overrides)", seen.Decision)
	}
	if seen.Call.Tool != "x.y" {
		t.Errorf("Call.Tool = %q, want the requested name", seen.Call.Tool)
	}
}

// stageFunc adapts a function to the Stage interface.
type stageFunc struct {
	name string
	fn   func(context.Context, *mcp.CallContext, mcp.Next) (connectors.Result, error)
}

func (s stageFunc) Name() string { return s.name }
func (s stageFunc) Run(ctx context.Context, cc *mcp.CallContext, next mcp.Next) (connectors.Result, error) {
	return s.fn(ctx, cc, next)
}

func newStageFunc(name string, fn func(context.Context, *mcp.CallContext, mcp.Next) (connectors.Result, error)) stageFunc {
	return stageFunc{name: name, fn: fn}
}
