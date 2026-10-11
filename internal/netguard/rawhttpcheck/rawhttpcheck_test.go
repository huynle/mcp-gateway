package rawhttpcheck

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSource(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []string // substrings of the findings, in order
	}{
		{"clean: uses an injected client", `package p
import "net/http"
type C struct{ HC *http.Client }
func (c *C) Do(r *http.Request) (*http.Response, error) { return c.HC.Do(r) }
func NewReq() (*http.Request, error) { return http.NewRequest("GET", "https://x", nil) }
`, nil},
		{"client literal", `package p
import "net/http"
var c = &http.Client{}
`, []string{"http.Client literal"}},
		{"client value literal", `package p
import "net/http"
func f() { c := http.Client{Timeout: 1}; _ = c }
`, []string{"http.Client literal"}},
		{"transport literal", `package p
import "net/http"
var t = &http.Transport{}
`, []string{"http.Transport literal"}},
		{"new client and transport", `package p
import "net/http"
var c, t = new(http.Client), new(http.Transport)
`, []string{"new(http.Client)", "new(http.Transport)"}},
		{"default client and transport", `package p
import "net/http"
var c, t = http.DefaultClient, http.DefaultTransport
`, []string{"http.DefaultClient", "http.DefaultTransport"}},
		{"package helpers", `package p
import "net/http"
func f() { http.Get("x"); http.Post("x", "", nil); http.Head("x"); http.PostForm("x", nil) }
`, []string{"http.Get", "http.Post", "http.Head", "http.PostForm"}},
		{"aliased import", `package p
import nh "net/http"
var c = &nh.Client{}
`, []string{"http.Client literal"}},
		{"dot import", `package p
import . "net/http"
var _ = NewRequest
`, []string{"dot import of net/http"}},
		{"other package named http is ignored", `package p
import http "example.com/fake/http"
var c = &http.Client{}
`, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Source("p.go", tt.src)
			if err != nil {
				t.Fatalf("Source: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("findings = %v, want %d matching %v", got, len(tt.want), tt.want)
			}
			for i, w := range tt.want {
				if !strings.Contains(got[i].String(), w) {
					t.Fatalf("finding %d = %q, want it to mention %q", i, got[i], w)
				}
			}
		})
	}
}

func TestDirSkipsTestFilesAndWalksSubdirs(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, src string) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("ok.go", "package p\n")
	write("x_test.go", "package p\nimport \"net/http\"\nvar c = &http.Client{}\n")
	write("sub/bad.go", "package sub\nimport \"net/http\"\nvar t = http.DefaultTransport\n")
	write("testdata/fixture.go", "package f\nimport \"net/http\"\nvar c = &http.Client{}\n")

	got, err := Dir(dir)
	if err != nil {
		t.Fatalf("Dir: %v", err)
	}
	if len(got) != 1 || !strings.Contains(got[0].String(), filepath.Join("sub", "bad.go")) {
		t.Fatalf("findings = %v, want exactly sub/bad.go", got)
	}
}
