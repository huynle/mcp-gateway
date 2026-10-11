package connectors_test

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

func names(tools []connectors.Tool) []string {
	out := make([]string, 0, len(tools))
	for _, t := range tools {
		out = append(out, t.FullName())
	}
	return out
}

func TestRegistryServerToolsReplaceAndRemove(t *testing.T) {
	r := connectors.NewRegistry()
	if err := r.Register(stubTool("github", "list_issues", connectors.KindRead)); err != nil {
		t.Fatal(err)
	}
	if err := r.AddServerTools("notes", []connectors.Tool{
		stubTool("notes", "search", connectors.KindRead),
		stubTool("notes", "create", connectors.KindWrite),
	}); err != nil {
		t.Fatalf("AddServerTools: %v", err)
	}
	if got := fmt.Sprint(names(r.List())); got != "[github.list_issues notes.create notes.search]" {
		t.Fatalf("List = %s", got)
	}
	if !r.IsServerApp("notes") || r.IsServerApp("github") {
		t.Errorf("IsServerApp: notes=%v github=%v, want true false", r.IsServerApp("notes"), r.IsServerApp("github"))
	}

	// A second add replaces the whole set atomically.
	if err := r.AddServerTools("notes", []connectors.Tool{stubTool("notes", "search", connectors.KindRead)}); err != nil {
		t.Fatalf("AddServerTools (replace): %v", err)
	}
	if _, ok := r.Get("notes.create"); ok {
		t.Error("notes.create survived a replacement without it")
	}
	if got := fmt.Sprint(r.ServerApps()); got != "[notes]" {
		t.Errorf("ServerApps = %s", got)
	}

	r.RemoveServerTools("notes")
	if _, ok := r.Get("notes.search"); ok {
		t.Error("notes.search survived RemoveServerTools")
	}
	if r.IsServerApp("notes") {
		t.Error("notes still a server app after removal")
	}
	// Removing a built-in app is a no-op.
	r.RemoveServerTools("github")
	if _, ok := r.Get("github.list_issues"); !ok {
		t.Error("RemoveServerTools removed a built-in tool")
	}
}

func TestRegistryServerToolsRefuseBuiltinApps(t *testing.T) {
	r := connectors.NewRegistry()
	if err := r.Register(stubTool("github", "list_issues", connectors.KindRead)); err != nil {
		t.Fatal(err)
	}
	err := r.AddServerTools("github", []connectors.Tool{stubTool("github", "evil", connectors.KindRead)})
	if !errors.Is(err, connectors.ErrAppTaken) {
		t.Fatalf("AddServerTools(github) = %v, want ErrAppTaken", err)
	}
	if _, ok := r.Get("github.evil"); ok {
		t.Error("a refused server add registered a tool")
	}
	// The other way round: a static registration cannot take a server app.
	if err := r.AddServerTools("notes", []connectors.Tool{stubTool("notes", "search", connectors.KindRead)}); err != nil {
		t.Fatal(err)
	}
	if err := r.Register(stubTool("notes", "other", connectors.KindRead)); !errors.Is(err, connectors.ErrAppTaken) {
		t.Errorf("Register(notes.other) = %v, want ErrAppTaken", err)
	}
}

func TestRegistryServerToolsValidate(t *testing.T) {
	r := connectors.NewRegistry()
	bad := stubTool("notes", "Bad.Name", connectors.KindRead)
	if err := r.AddServerTools("notes", []connectors.Tool{bad}); !errors.Is(err, connectors.ErrInvalidTool) {
		t.Errorf("invalid tool name: err = %v, want ErrInvalidTool", err)
	}
	other := stubTool("other", "search", connectors.KindRead)
	if err := r.AddServerTools("notes", []connectors.Tool{other}); !errors.Is(err, connectors.ErrInvalidTool) {
		t.Errorf("tool of another app: err = %v, want ErrInvalidTool", err)
	}
	dup := []connectors.Tool{stubTool("notes", "a", connectors.KindRead), stubTool("notes", "a", connectors.KindRead)}
	if err := r.AddServerTools("notes", dup); !errors.Is(err, connectors.ErrDuplicateTool) {
		t.Errorf("duplicate names: err = %v, want ErrDuplicateTool", err)
	}
	if len(r.List()) != 0 {
		t.Errorf("refused adds left tools behind: %v", names(r.List()))
	}
	if err := r.AddServerTools("Bad App", nil); !errors.Is(err, connectors.ErrInvalidTool) {
		t.Errorf("invalid app: err = %v, want ErrInvalidTool", err)
	}
}

// Concurrent readers see either the old or the new set of a server, never
// a mix, while writers replace it (run with -race).
func TestRegistryServerToolsConcurrent(t *testing.T) {
	r := connectors.NewRegistry()
	setA := []connectors.Tool{stubTool("notes", "a1", connectors.KindRead), stubTool("notes", "a2", connectors.KindRead)}
	setB := []connectors.Tool{stubTool("notes", "b1", connectors.KindRead), stubTool("notes", "b2", connectors.KindRead)}
	if err := r.AddServerTools("notes", setA); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			set := setA
			if i%2 == 0 {
				set = setB
			}
			if err := r.AddServerTools("notes", set); err != nil {
				t.Error(err)
				return
			}
		}
		close(stop)
	}()
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				got := fmt.Sprint(names(r.List()))
				if got != "[notes.a1 notes.a2]" && got != "[notes.b1 notes.b2]" {
					t.Errorf("torn read: %s", got)
					return
				}
			}
		}()
	}
	wg.Wait()
}
