package machineclient

import (
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/huynle/mcp-gateway/internal/federation/connector"
	"github.com/huynle/mcp-gateway/internal/tunnelclient"
)

// SecretMode is how an action hands the secret to its command.
type SecretMode string

// Secret delivery modes (config `secret:`).
const (
	// SecretStdin writes the secret and "\n" to the command's stdin.
	SecretStdin SecretMode = "stdin"
	// SecretAskpass points SUDO_ASKPASS and SSH_ASKPASS at a one-shot
	// helper that prints the secret (see actions.go).
	SecretAskpass SecretMode = "askpass"
	// SecretFD writes the secret to file descriptor 3.
	SecretFD SecretMode = "fd"
	// SecretEnv sets one variable of the command's environment
	// (`env:NAME`); the weakest mode.
	SecretEnv SecretMode = "env"
)

// Action limits.
const (
	DefaultActionTimeout = 2 * time.Minute
	MinActionTimeout     = time.Second
	MaxActionTimeout     = 30 * time.Minute
	maxActionDescription = 500
	// SecretArg is the tool argument that carries the secret.
	SecretArg = "secret"
	// actionsServerSuffix makes the actions server name "<machine>-actions".
	actionsServerSuffix = "-actions"
)

// lookPath resolves a bare program name when the config is loaded
// (a variable for tests).
var lookPath = exec.LookPath

// Action is one machine action from config.yaml: a fixed command that
// receives an ephemeral secret, never through argv.
type Action struct {
	Name string
	// Secret is the delivery mode; SecretEnv is the variable for
	// SecretEnv.
	Secret    SecretMode
	SecretEnv string
	// Params are the declared parameters by name.
	Params      map[string]*ActionParam
	Description string
	Timeout     time.Duration

	// words is the argv template; words[0] is the resolved absolute
	// program and holds no placeholder.
	words [][]argPart
}

// ActionParam is a declared parameter: values must match Pattern, the
// configured regex anchored as ^(?:…)$.
type ActionParam struct {
	Name    string
	Pattern string
	re      *regexp.Regexp
}

// argPart is literal text or (param != "") a placeholder.
type argPart struct {
	lit   string
	param string
}

type rawAction struct {
	Run         string            `yaml:"run"`
	Secret      string            `yaml:"secret"`
	Params      map[string]string `yaml:"params"`
	Description string            `yaml:"description"`
	Timeout     string            `yaml:"timeout"`
}

var (
	actionNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
	paramNameRE  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	secretEnvRE  = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)
)

// splitRun splits a run: line into argv words: whitespace-separated,
// single and double quotes, backslash escapes; no expansion of any kind
// and never a shell.
func splitRun(s string) ([]string, error) { return tunnelclient.SplitCommand(s) }

func buildAction(name string, ra *rawAction) (*Action, error) {
	if !actionNameRE.MatchString(name) {
		return nil, errors.New("action name must be 1-63 characters of a-z, 0-9, _ and -, starting with a letter or digit")
	}
	if ra == nil || strings.TrimSpace(ra.Run) == "" {
		return nil, errors.New("run: the command is missing")
	}
	a := &Action{Name: name, Params: map[string]*ActionParam{}, Description: ra.Description, Timeout: DefaultActionTimeout}

	for pname, pat := range ra.Params {
		switch {
		case pname == SecretArg:
			return nil, fmt.Errorf("param %q: the name is reserved for the secret", pname)
		case !paramNameRE.MatchString(pname):
			return nil, fmt.Errorf("param name %q must be 1-32 characters of a-z, 0-9 and _, starting with a letter", pname)
		case pat == "":
			return nil, fmt.Errorf("param %q: the pattern is empty", pname)
		}
		anchored := "^(?:" + pat + ")$"
		re, err := regexp.Compile(anchored)
		if err != nil {
			return nil, fmt.Errorf("param %q: invalid pattern: %w", pname, err)
		}
		a.Params[pname] = &ActionParam{Name: pname, Pattern: anchored, re: re}
	}

	if err := a.parseSecret(ra.Secret); err != nil {
		return nil, err
	}
	if len(ra.Description) > maxActionDescription {
		return nil, fmt.Errorf("description is longer than %d characters", maxActionDescription)
	}
	if ra.Timeout != "" {
		d, err := time.ParseDuration(ra.Timeout)
		if err != nil {
			return nil, fmt.Errorf("timeout: %q is not a duration such as 2m", ra.Timeout)
		}
		if d < MinActionTimeout || d > MaxActionTimeout {
			return nil, fmt.Errorf("timeout must be between %s and %s", MinActionTimeout, MaxActionTimeout)
		}
		a.Timeout = d
	}

	argv, err := splitRun(ra.Run)
	if err != nil {
		return nil, fmt.Errorf("run: %w", err)
	}
	used := map[string]bool{}
	for i, w := range argv {
		parts := parseWord(w)
		for _, p := range parts {
			if p.param == "" {
				continue
			}
			if i == 0 {
				return nil, errors.New("run: the program must not contain a placeholder")
			}
			if a.Params[p.param] == nil {
				return nil, fmt.Errorf("run: placeholder {%s} is not a declared param", p.param)
			}
			used[p.param] = true
		}
		a.words = append(a.words, parts)
	}
	for pname := range a.Params {
		if !used[pname] {
			return nil, fmt.Errorf("param %q is not used in run", pname)
		}
	}
	prog, err := resolveProgram(literal(a.words[0]))
	if err != nil {
		return nil, fmt.Errorf("run: %w", err)
	}
	a.words[0] = []argPart{{lit: prog}}
	return a, nil
}

func (a *Action) parseSecret(s string) error {
	switch m := SecretMode(s); m {
	case SecretStdin, SecretAskpass, SecretFD:
		a.Secret = m
		return nil
	case "":
		return errors.New("secret: set one of stdin, askpass, fd or env:NAME")
	}
	if name, ok := strings.CutPrefix(s, "env:"); ok {
		if !secretEnvRE.MatchString(name) {
			return errors.New("secret: env:NAME needs a NAME of A-Z, 0-9 and _, not starting with a digit")
		}
		a.Secret, a.SecretEnv = SecretEnv, name
		return nil
	}
	return fmt.Errorf("secret: %q is not one of stdin, askpass, fd or env:NAME", s)
}

// resolveProgram returns the absolute path of the program: an absolute
// path that must be executable, or a bare name looked up on PATH now.
func resolveProgram(prog string) (string, error) {
	switch {
	case prog == "":
		return "", errors.New("the program name is empty")
	case filepath.IsAbs(prog):
	case strings.ContainsRune(prog, '/') || strings.ContainsRune(prog, filepath.Separator):
		return "", fmt.Errorf("the program %q must be an absolute path or a name on PATH", prog)
	}
	p, err := lookPath(prog)
	if err != nil {
		return "", fmt.Errorf("program %q not found (or not executable): %w", prog, err)
	}
	if !filepath.IsAbs(p) {
		return "", fmt.Errorf("program %q resolves to the relative path %q; use an absolute path", prog, p)
	}
	return filepath.Clean(p), nil
}

// parseWord splits an argv word into literal text and {param}
// placeholders. "{{" and "}}" are literal braces; any other brace that is
// not part of {name} (name as for params) is literal too.
func parseWord(w string) []argPart {
	var parts []argPart
	var lit strings.Builder
	flush := func() {
		if lit.Len() > 0 {
			parts = append(parts, argPart{lit: lit.String()})
			lit.Reset()
		}
	}
	for i := 0; i < len(w); {
		switch {
		case strings.HasPrefix(w[i:], "{{"):
			lit.WriteByte('{')
			i += 2
		case strings.HasPrefix(w[i:], "}}"):
			lit.WriteByte('}')
			i += 2
		case w[i] == '{':
			if end := strings.IndexByte(w[i:], '}'); end > 0 && paramNameRE.MatchString(w[i+1:i+end]) {
				flush()
				parts = append(parts, argPart{param: w[i+1 : i+end]})
				i += end + 1
				continue
			}
			lit.WriteByte('{')
			i++
		default:
			lit.WriteByte(w[i])
			i++
		}
	}
	flush()
	if len(parts) == 0 {
		parts = []argPart{{lit: ""}}
	}
	return parts
}

func literal(parts []argPart) string {
	var b strings.Builder
	for _, p := range parts {
		b.WriteString(p.lit)
	}
	return b.String()
}

// ParamNames returns the declared param names, sorted.
func (a *Action) ParamNames() []string {
	names := make([]string, 0, len(a.Params))
	for n := range a.Params {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Argv checks params (every declared param, nothing else, each matching
// its pattern) and returns the command's argv with them substituted.
// Errors name params, never values.
func (a *Action) Argv(params map[string]string) ([]string, error) {
	for k := range params {
		if a.Params[k] == nil {
			return nil, fmt.Errorf("%q is not a param of action %q", k, a.Name)
		}
	}
	for _, p := range a.Params {
		v, ok := params[p.Name]
		if !ok {
			return nil, fmt.Errorf("param %q is missing", p.Name)
		}
		if !p.re.MatchString(v) {
			return nil, fmt.Errorf("param %q does not match its pattern %s", p.Name, p.Pattern)
		}
	}
	argv := make([]string, len(a.words))
	for i, parts := range a.words {
		var b strings.Builder
		for _, p := range parts {
			if p.param != "" {
				b.WriteString(params[p.param])
			} else {
				b.WriteString(p.lit)
			}
		}
		argv[i] = b.String()
	}
	return argv, nil
}

// Command is the fixed command for display: argv with placeholders shown
// as {name}, literal braces doubled, and words quoted where needed.
func (a *Action) Command() string {
	out := make([]string, len(a.words))
	for i, parts := range a.words {
		var b strings.Builder
		for _, p := range parts {
			if p.param != "" {
				b.WriteString("{" + p.param + "}")
				continue
			}
			lit := p.lit
			if i > 0 {
				lit = strings.NewReplacer("{", "{{", "}", "}}").Replace(lit)
			}
			b.WriteString(lit)
		}
		out[i] = displayQuote(b.String())
	}
	return strings.Join(out, " ")
}

// displayQuote double-quotes a word that splitRun would not read back as
// one word.
func displayQuote(w string) string {
	if w != "" && !strings.ContainsAny(w, " \t\n\"'\\") {
		return w
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(w) + `"`
}

// ActionNames returns the action names, sorted.
func (c *Config) ActionNames() []string {
	names := make([]string, 0, len(c.Actions))
	for n := range c.Actions {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// ActionsServerName is the name of the in-process server that serves the
// actions of machine ("<machine>-actions"); "" when the config has no
// actions. It must be a valid server name and must not be a configured
// server's name.
func (c *Config) ActionsServerName(machine string) (string, error) {
	if len(c.Actions) == 0 {
		return "", nil
	}
	name := machine + actionsServerSuffix
	if len(name) > 63 {
		return "", fmt.Errorf("the actions server name %q is longer than 63 characters; actions need a machine name of at most %d", name, 63-len(actionsServerSuffix))
	}
	if err := connector.ValidateServerName(name); err != nil {
		return "", fmt.Errorf("the actions server name %q is not a valid server name", name)
	}
	if c.Servers[name] != nil {
		return "", fmt.Errorf("server %q has the name of this machine's actions server; rename the server", name)
	}
	return name, nil
}
