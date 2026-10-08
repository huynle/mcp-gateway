package connectors_test

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

func stubTool(app, name string, kind connectors.Kind) connectors.Tool {
	return connectors.Tool{
		App:         app,
		Name:        name,
		Description: app + " " + name,
		InputSchema: json.RawMessage(`{"type":"object","properties":{}}`),
		Kind:        kind,
		Handler: func(context.Context, connectors.Call) (connectors.Result, error) {
			return connectors.Result{Content: "ok"}, nil
		},
	}
}

func TestRegistryRegisterGetList(t *testing.T) {
	r := connectors.NewRegistry()
	if err := r.Register(stubTool("github", "list_issues", connectors.KindRead)); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := r.Register(stubTool("slack", "post_message", connectors.KindWrite)); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := r.Register(stubTool("github", "create_issue", connectors.KindWrite)); err != nil {
		t.Fatalf("Register: %v", err)
	}

	got, ok := r.Get("github.list_issues")
	if !ok {
		t.Fatal("Get(github.list_issues) = not found")
	}
	if got.FullName() != "github.list_issues" || got.Kind != connectors.KindRead {
		t.Errorf("Get returned %+v", got)
	}
	if _, ok := r.Get("github.nope"); ok {
		t.Error("Get(github.nope) found something")
	}
	if _, ok := r.Get("list_issues"); ok {
		t.Error("Get without app prefix found something")
	}

	var names []string
	for _, tool := range r.List() {
		names = append(names, tool.FullName())
	}
	want := []string{"github.create_issue", "github.list_issues", "slack.post_message"}
	if len(names) != len(want) {
		t.Fatalf("List = %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Errorf("List[%d] = %q, want %q (list must be sorted by full name)", i, names[i], want[i])
		}
	}
}

func TestRegistryRejectsDuplicateNames(t *testing.T) {
	r := connectors.NewRegistry()
	if err := r.Register(stubTool("github", "list_issues", connectors.KindRead)); err != nil {
		t.Fatal(err)
	}
	err := r.Register(stubTool("github", "list_issues", connectors.KindWrite))
	if !errors.Is(err, connectors.ErrDuplicateTool) {
		t.Fatalf("second Register err = %v, want ErrDuplicateTool", err)
	}
	if got, _ := r.Get("github.list_issues"); got.Kind != connectors.KindRead {
		t.Error("duplicate Register replaced the first tool")
	}
}

func TestRegistryRejectsInvalidTools(t *testing.T) {
	cases := map[string]func(t *connectors.Tool){
		"empty app":       func(t *connectors.Tool) { t.App = "" },
		"empty name":      func(t *connectors.Tool) { t.Name = "" },
		"dot in app":      func(t *connectors.Tool) { t.App = "git.hub" },
		"dot in name":     func(t *connectors.Tool) { t.Name = "list.issues" },
		"upper case":      func(t *connectors.Tool) { t.Name = "ListIssues" },
		"space":           func(t *connectors.Tool) { t.Name = "list issues" },
		"unknown kind":    func(t *connectors.Tool) { t.Kind = "maybe" },
		"empty kind":      func(t *connectors.Tool) { t.Kind = "" },
		"nil handler":     func(t *connectors.Tool) { t.Handler = nil },
		"no schema":       func(t *connectors.Tool) { t.InputSchema = nil },
		"schema not json": func(t *connectors.Tool) { t.InputSchema = json.RawMessage(`{`) },
		"schema not obj":  func(t *connectors.Tool) { t.InputSchema = json.RawMessage(`{"type":"string"}`) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			tool := stubTool("github", "list_issues", connectors.KindRead)
			mutate(&tool)
			err := connectors.NewRegistry().Register(tool)
			if !errors.Is(err, connectors.ErrInvalidTool) {
				t.Fatalf("Register err = %v, want ErrInvalidTool", err)
			}
		})
	}
}

func TestRegistryIsSafeForConcurrentUse(t *testing.T) {
	r := connectors.NewRegistry()
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = r.Register(stubTool("app", "tool_"+string(rune('a'+i%26))+string(rune('a'+i/26)), connectors.KindRead))
		}()
		go func() {
			defer wg.Done()
			_ = r.List()
			_, _ = r.Get("app.tool_aa")
		}()
	}
	wg.Wait()
	if n := len(r.List()); n != 50 {
		t.Errorf("List len = %d, want 50", n)
	}
}

func TestToolFullName(t *testing.T) {
	tool := connectors.Tool{App: "github", Name: "list_issues"}
	if got := tool.FullName(); got != "github.list_issues" {
		t.Errorf("FullName = %q", got)
	}
}
