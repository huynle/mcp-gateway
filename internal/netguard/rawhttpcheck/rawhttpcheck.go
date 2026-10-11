// Package rawhttpcheck is a small source scanner used by tests to enforce
// that packages calling user-supplied URLs (internal/federation) never build
// their own HTTP stack: every such call must go through netguard.Guard. It
// flags, in non-test Go files: http.Client / http.Transport composite
// literals and new(...), http.DefaultClient / http.DefaultTransport, the
// package-level helpers http.Get/Post/Head/PostForm (which use
// DefaultClient), and dot imports of net/http. Taking an injected
// *http.Client or building requests is fine.
//
// It is syntactic (go/parser, no type checking) on purpose: it stays fast
// and dependency-free, at the cost of not seeing through helper packages.
package rawhttpcheck

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
)

// Finding is one forbidden use of net/http.
type Finding struct {
	Pos  string // file:line:col
	What string
}

func (f Finding) String() string { return f.Pos + ": " + f.What }

var (
	bannedTypes = map[string]bool{"Client": true, "Transport": true}
	bannedVars  = map[string]bool{"DefaultClient": true, "DefaultTransport": true}
	bannedFuncs = map[string]bool{"Get": true, "Post": true, "Head": true, "PostForm": true}
)

// Source scans one file's source text.
func Source(filename, src string) ([]Finding, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filename, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, fmt.Errorf("rawhttpcheck: parse %s: %w", filename, err)
	}
	return file(fset, f), nil
}

// Dir scans every non-test .go file under root, skipping testdata and
// hidden or underscore-prefixed directories (as the go tool does).
func Dir(root string) ([]Finding, error) {
	var out []Finding
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if path != root && (name == "testdata" || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return fmt.Errorf("rawhttpcheck: parse %s: %w", path, err)
		}
		out = append(out, file(fset, f)...)
		return nil
	})
	return out, err
}

func file(fset *token.FileSet, f *ast.File) []Finding {
	var out []Finding
	add := func(n ast.Node, what string) {
		out = append(out, Finding{Pos: fset.Position(n.Pos()).String(), What: what})
	}

	names := map[string]bool{} // local names of net/http in this file
	for _, imp := range f.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil || path != "net/http" {
			continue
		}
		switch {
		case imp.Name == nil:
			names["http"] = true
		case imp.Name.Name == ".":
			add(imp, "dot import of net/http hides which identifiers come from it")
		case imp.Name.Name != "_":
			names[imp.Name.Name] = true
		}
	}
	if len(names) == 0 {
		return out
	}
	// httpSel returns the selected name when e is <net/http>.Name.
	httpSel := func(e ast.Expr) (string, bool) {
		sel, ok := e.(*ast.SelectorExpr)
		if !ok {
			return "", false
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok || !names[id.Name] {
			return "", false
		}
		return sel.Sel.Name, true
	}

	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CompositeLit:
			if name, ok := httpSel(n.Type); ok && bannedTypes[name] {
				add(n, "http."+name+" literal: use netguard.Guard.Client()/Transport()")
			}
		case *ast.CallExpr:
			if id, ok := n.Fun.(*ast.Ident); ok && id.Name == "new" && len(n.Args) == 1 {
				if name, ok := httpSel(n.Args[0]); ok && bannedTypes[name] {
					add(n, "new(http."+name+"): use netguard.Guard.Client()/Transport()")
				}
			}
			if name, ok := httpSel(n.Fun); ok && bannedFuncs[name] {
				add(n, "http."+name+" uses http.DefaultClient: use netguard.Guard.Client()")
			}
		case *ast.SelectorExpr:
			if name, ok := httpSel(n); ok && bannedVars[name] {
				add(n, "http."+name+": use netguard.Guard.Client()/Transport()")
			}
		}
		return true
	})
	return out
}
