package machineclient

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// StdioSpec is a stdio MCP server ready to start: argv (never run through
// a shell), its complete environment and working directory ("" = the
// CLI's).
type StdioSpec struct {
	Command []string
	Env     []string
	Dir     string
}

// baseEnv are the variables every stdio server gets from the CLI's
// environment when set, plus every LC_* variable. Nothing else is passed
// unless the config names it (inherit_env, env): the CLI's own
// credentials and the rest of the user's environment stay out.
var baseEnv = []string{"PATH", "HOME", "USER", "LANG", "TMPDIR"}

// BuildStdioSpec builds the clean start specification of a stdio server
// from the CLI's environment (os.Environ form): the base variables, then
// inherit_env, then env (whose ${VAR} references are expanded from the
// CLI's environment; an unset reference is an error). The cwd's ~ is the
// CLI's $HOME. Errors name variables, never values.
func BuildStdioSpec(s *Server, environ []string) (*StdioSpec, error) {
	if s.Kind != KindStdio || len(s.Command) == 0 {
		return nil, fmt.Errorf("server %q is not a stdio server", s.Name)
	}
	cli := map[string]string{}
	for _, kv := range environ {
		if k, v, ok := strings.Cut(kv, "="); ok && k != "" {
			cli[k] = v
		}
	}
	env := map[string]string{}
	for _, k := range baseEnv {
		if v, ok := cli[k]; ok {
			env[k] = v
		}
	}
	for k, v := range cli {
		if strings.HasPrefix(k, "LC_") {
			env[k] = v
		}
	}
	for _, k := range s.InheritEnv {
		if v, ok := cli[k]; ok {
			env[k] = v
		}
	}
	for k, v := range s.Env {
		x, err := expandVars(v, cli)
		if err != nil {
			return nil, fmt.Errorf("server %q: env %s: %w", s.Name, k, err)
		}
		env[k] = x
	}
	out := make([]string, 0, len(env))
	for k, v := range env {
		out = append(out, k+"="+v)
	}
	sort.Strings(out)

	spec := &StdioSpec{Command: append([]string(nil), s.Command...), Env: out}
	switch {
	case s.Cwd == "":
	case s.Cwd == "~" || strings.HasPrefix(s.Cwd, "~/"):
		home := cli["HOME"]
		if home == "" {
			return nil, fmt.Errorf("server %q: cwd uses ~ but $HOME is not set", s.Name)
		}
		spec.Dir = filepath.Join(home, strings.TrimPrefix(s.Cwd, "~"))
	default:
		spec.Dir = filepath.Clean(s.Cwd)
	}
	return spec, nil
}

// expandVars replaces each ${NAME} with the CLI's value of NAME; any other
// "$" is literal.
func expandVars(v string, cli map[string]string) (string, error) {
	var b strings.Builder
	for {
		i := strings.Index(v, "${")
		if i < 0 {
			b.WriteString(v)
			return b.String(), nil
		}
		b.WriteString(v[:i])
		end := strings.IndexByte(v[i:], '}')
		if end < 0 {
			return "", errors.New("unterminated ${")
		}
		name := v[i+2 : i+end]
		if !envNameRE.MatchString(name) {
			return "", fmt.Errorf("invalid reference ${%s}", name)
		}
		val, ok := cli[name]
		if !ok {
			return "", fmt.Errorf("references $%s, which is not set in the environment of mcp-gateway", name)
		}
		b.WriteString(val)
		v = v[i+end+1:]
	}
}
