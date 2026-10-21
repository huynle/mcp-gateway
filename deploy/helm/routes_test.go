package helm_test

// Route coverage (no helm needed): every public HTTP route the gateway
// registers must be routed by the chart's default ingress.paths, and the
// internal-only endpoints must never be. Routes are found by parsing the
// gateway's Go source: the first argument of every Handle / HandleFunc /
// mount* / Mount* call, with string constants resolved across the module.
// A new route the chart does not route fails this test, so the explicit
// path list cannot silently fall behind the code again.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const module = "github.com/huynle/mcp-gateway"

// internalOnly are paths served only to the cluster (probes, the private
// metrics listener, the replica-to-replica relay listener). The chart must
// never route them.
var internalOnly = map[string]string{
	"/healthz":      "liveness probe",
	"/readyz":       "readiness probe",
	"/metrics":      "private metrics listener",
	"/tunnel-relay": "replica-to-replica relay listener",
}

// skipDirs hold no gateway routes: connector code registers handlers on
// fake vendor servers, tests build their own muxes.
var skipDirs = []string{"internal/connectors", "test", "deploy", "internal/tunnelclient", "internal/machineclient", "cmd/mcp-gateway", "cmd/mcp-gateway-tunnel", "cmd/migrate"}

var (
	routeCallee = regexp.MustCompile(`^(Handle|HandleFunc|[mM]ount[A-Za-z]*)$`)
	patternRE   = regexp.MustCompile(`^(?:(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS) )?(/\S*)$`)
)

type pkgFiles struct {
	files  []*ast.File
	consts map[string]ast.Expr // package-level const name -> value expr
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// loadModule parses every non-test .go file outside skipDirs, by package
// import path.
func loadModule(t *testing.T, root string) map[string]*pkgFiles {
	t.Helper()
	fset := token.NewFileSet()
	pkgs := map[string]*pkgFiles{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if d.IsDir() {
			if strings.HasPrefix(d.Name(), ".") && rel != "." {
				return filepath.SkipDir
			}
			for _, s := range skipDirs {
				if rel == s || strings.HasPrefix(rel, s+string(filepath.Separator)) {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		ip := module
		if dir := filepath.ToSlash(filepath.Dir(rel)); dir != "." {
			ip += "/" + dir
		}
		p := pkgs[ip]
		if p == nil {
			p = &pkgFiles{consts: map[string]ast.Expr{}}
			pkgs[ip] = p
		}
		p.files = append(p.files, f)
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs := spec.(*ast.ValueSpec)
				for i, n := range vs.Names {
					if i < len(vs.Values) {
						p.consts[n.Name] = vs.Values[i]
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return pkgs
}

// eval resolves a string expression: literals, '+', and constants of this
// module (same package or imported by path).
func eval(pkgs map[string]*pkgFiles, pkg string, imports map[string]string, e ast.Expr) (string, bool) {
	switch x := e.(type) {
	case *ast.BasicLit:
		if x.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(x.Value)
		return s, err == nil
	case *ast.ParenExpr:
		return eval(pkgs, pkg, imports, x.X)
	case *ast.BinaryExpr:
		if x.Op != token.ADD {
			return "", false
		}
		a, ok1 := eval(pkgs, pkg, imports, x.X)
		b, ok2 := eval(pkgs, pkg, imports, x.Y)
		return a + b, ok1 && ok2
	case *ast.Ident:
		if v, ok := pkgs[pkg].consts[x.Name]; ok {
			return eval(pkgs, pkg, imports, v)
		}
	case *ast.SelectorExpr:
		id, ok := x.X.(*ast.Ident)
		if !ok {
			return "", false
		}
		target := imports[id.Name]
		if p, ok := pkgs[target]; ok {
			if v, ok := p.consts[x.Sel.Name]; ok {
				return eval(pkgs, target, importsOf(p.files[0]), v)
			}
		}
	}
	return "", false
}

func importsOf(f *ast.File) map[string]string {
	m := map[string]string{}
	for _, im := range f.Imports {
		p, _ := strconv.Unquote(im.Path.Value)
		name := p[strings.LastIndex(p, "/")+1:]
		if im.Name != nil {
			name = im.Name.Name
		}
		m[name] = p
	}
	return m
}

// gatewayRoutes returns route path -> "file: pattern" for every resolved
// pattern; unresolved route-looking calls are reported as errors.
func gatewayRoutes(t *testing.T) map[string]string {
	t.Helper()
	root := repoRoot(t)
	pkgs := loadModule(t, root)
	routes := map[string]string{}
	for ip, p := range pkgs {
		for _, f := range p.files {
			imports := importsOf(f)
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) == 0 {
					return true
				}
				var name string
				switch fn := call.Fun.(type) {
				case *ast.Ident:
					name = fn.Name
				case *ast.SelectorExpr:
					name = fn.Sel.Name
				}
				if !routeCallee.MatchString(name) {
					return true
				}
				s, ok := eval(pkgs, ip, imports, call.Args[0])
				if !ok {
					return true // not a constant pattern (a variable, a handler arg)
				}
				m := patternRE.FindStringSubmatch(s)
				if m == nil {
					return true
				}
				routes[m[2]] = strings.TrimPrefix(ip, module+"/") + ": " + s
				return true
			})
		}
	}
	if len(routes) < 20 {
		t.Fatalf("found only %d routes; the scanner is broken", len(routes))
	}
	return routes
}

type ingressPath struct {
	Path     string `yaml:"path"`
	PathType string `yaml:"pathType"`
}

func chartPaths(t *testing.T) []ingressPath {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("mcp-gateway", "values.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Ingress struct {
			Paths []ingressPath `yaml:"paths"`
		} `yaml:"ingress"`
	}
	if err := yaml.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Ingress.Paths) == 0 {
		t.Fatal("values.yaml has no ingress.paths")
	}
	return v.Ingress.Paths
}

// literal is the fixed part of a pattern path: up to the first wildcard;
// "/{$}" is the exact root.
func literal(p string) (string, bool) {
	if p == "/{$}" {
		return "/", true
	}
	if i := strings.Index(p, "{"); i >= 0 {
		return p[:i], false
	}
	return p, false
}

// routed reports whether an ingress path routes requests for route.
func routed(paths []ingressPath, route string) bool {
	lit, exactRoot := literal(route)
	for _, ip := range paths {
		switch ip.PathType {
		case "Exact":
			if exactRoot && ip.Path == "/" || !exactRoot && strings.TrimSuffix(lit, "/") == ip.Path && !strings.Contains(route, "{") {
				return true
			}
		case "Prefix":
			pre := strings.TrimSuffix(ip.Path, "/")
			if pre == "" {
				return true // "/" Prefix: everything
			}
			if l := strings.TrimSuffix(lit, "/"); l == pre || strings.HasPrefix(lit, pre+"/") {
				return true
			}
		}
	}
	return false
}

func TestChartRoutesEveryPublicGatewayRoute(t *testing.T) {
	routes := gatewayRoutes(t)
	paths := chartPaths(t)
	var missing []string
	for route, where := range routes {
		if route == "/" {
			continue // the portal's catch-all mount; its own routes are checked
		}
		lit, _ := literal(route)
		if internal(lit) != "" {
			continue
		}
		if !routed(paths, route) {
			missing = append(missing, route+"  ("+where+")")
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("deploy/helm/mcp-gateway/values.yaml ingress.paths does not route these gateway routes; add a path for each (pathType Prefix for a subtree):\n  %s", strings.Join(missing, "\n  "))
	}
}

func TestChartNeverRoutesInternalEndpoints(t *testing.T) {
	paths := chartPaths(t)
	for p, why := range internalOnly {
		for _, sub := range []string{p, p + "/x"} {
			if routed(paths, sub) {
				t.Errorf("ingress.paths routes %s (%s); it must stay cluster-internal", sub, why)
			}
		}
	}
	// The scanner sees the internal endpoints, so the list stays honest.
	routes := gatewayRoutes(t)
	for _, p := range []string{"/healthz", "/readyz"} {
		if _, ok := routes[p]; !ok {
			t.Errorf("scanner did not find %s; update the scanner or internalOnly", p)
		}
	}
}

func internal(lit string) string {
	for p, why := range internalOnly {
		if lit == p || strings.HasPrefix(lit, p+"/") {
			return why
		}
	}
	return ""
}

// TestRouteScannerListsKnownRoutes pins a few routes from different
// packages so a broken scanner cannot pass by finding nothing.
func TestRouteScannerListsKnownRoutes(t *testing.T) {
	routes := gatewayRoutes(t)
	for _, want := range []string{"/mcp", "/servers", "/activate", "/install", "/machine/token", "/tunnel/connect", "/privacy"} {
		found := false
		for r := range routes {
			if lit, _ := literal(r); lit == want || strings.HasPrefix(lit, want+"/") || strings.HasPrefix(want, lit) && lit != "/" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("scanner did not find a %s route", want)
		}
	}
}
