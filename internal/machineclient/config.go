package machineclient

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/huynle/mcp-gateway/internal/federation/connector"
	"github.com/huynle/mcp-gateway/internal/tunnelclient"
)

// EnvConfig overrides the config file path (after --config).
const EnvConfig = "MCP_GATEWAY_CONFIG"

// Server kinds.
const (
	KindHTTP  = "http"
	KindStdio = "stdio"
)

// Config is a validated config.yaml.
type Config struct {
	// Path is the file it was loaded from ("" when parsed from bytes).
	Path string
	// Gateway is the gateway base URL without a trailing slash; "" when
	// the file does not set it (the logged-in gateway is used).
	Gateway string
	// Machine is the machine name to request at login; "" for the default.
	Machine string
	// Servers by name.
	Servers map[string]*Server
	// Actions by name: fixed commands that receive an ephemeral secret,
	// served as one tool each by the in-process server
	// "<machine>-actions" (actions.go).
	Actions map[string]*Action
}

// Server is one local MCP server from the config.
type Server struct {
	Name string
	// Kind is KindHTTP or KindStdio.
	Kind string
	// URL is the HTTP MCP server (KindHTTP).
	URL string
	// Command is the stdio server's argv (KindStdio); never run through a
	// shell.
	Command []string
	// Env are extra variables for the stdio server; values may contain
	// ${VAR} references to the CLI's environment (see BuildEnv).
	Env map[string]string
	// Cwd is the stdio server's working directory: absolute or ~/...
	Cwd string
	// InheritEnv names variables copied from the CLI's environment.
	InheritEnv []string

	// actions is set on the in-process actions server only (up.go).
	actions map[string]*Action
}

// rawConfig and rawServer mirror the YAML; unknown keys are rejected.
type rawConfig struct {
	Gateway string                `yaml:"gateway"`
	Machine string                `yaml:"machine"`
	Servers map[string]*rawServer `yaml:"servers"`
	Actions map[string]*rawAction `yaml:"actions"`
}

type rawServer struct {
	HTTP       string            `yaml:"http"`
	Stdio      string            `yaml:"stdio"`
	Command    []string          `yaml:"command"`
	Env        map[string]string `yaml:"env"`
	Cwd        string            `yaml:"cwd"`
	InheritEnv []string          `yaml:"inherit_env"`
}

const configDirName = "mcp-gateway"

// ConfigPath resolves the config file: --config, then $MCP_GATEWAY_CONFIG,
// then $XDG_CONFIG_HOME/mcp-gateway/config.yaml, then
// ~/.config/mcp-gateway/config.yaml.
func ConfigPath(flagValue string, getenv func(string) string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	if p := getenv(EnvConfig); p != "" {
		return p, nil
	}
	dir, err := StateDir(getenv)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.yaml"), nil
}

// StateDir is the directory of machine.json and machine.key:
// $XDG_CONFIG_HOME/mcp-gateway (when absolute) or ~/.config/mcp-gateway.
func StateDir(getenv func(string) string) (string, error) {
	if x := getenv("XDG_CONFIG_HOME"); x != "" && filepath.IsAbs(x) {
		return filepath.Join(x, configDirName), nil
	}
	home := getenv("HOME")
	if home == "" || !filepath.IsAbs(home) {
		return "", errors.New("cannot find the config directory: $HOME is not set")
	}
	return filepath.Join(home, ".config", configDirName), nil
}

// LoadConfig reads and validates a config file. Errors name the file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path) //nolint:gosec // the user's own config path
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	c, err := ParseConfig(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	c.Path = path
	return c, nil
}

// ParseConfig parses and validates config.yaml content: one YAML
// document, no unknown or duplicate keys.
func ParseConfig(data []byte) (*Config, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var raw rawConfig
	if err := dec.Decode(&raw); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("the config must be one YAML document")
	}
	c := &Config{Machine: raw.Machine, Servers: map[string]*Server{}, Actions: map[string]*Action{}}
	if raw.Gateway != "" {
		gw, err := GatewayURL(raw.Gateway)
		if err != nil {
			return nil, err
		}
		c.Gateway = gw
	}
	if c.Machine != "" {
		if err := ValidateMachineName(c.Machine); err != nil {
			return nil, err
		}
	}
	for name, rs := range raw.Servers {
		s, err := buildServer(name, rs)
		if err != nil {
			return nil, fmt.Errorf("server %q: %w", name, err)
		}
		c.Servers[name] = s
	}
	for name, ra := range raw.Actions {
		a, err := buildAction(name, ra)
		if err != nil {
			return nil, fmt.Errorf("action %q: %w", name, err)
		}
		c.Actions[name] = a
	}
	if c.Machine != "" {
		if _, err := c.ActionsServerName(c.Machine); err != nil {
			return nil, err
		}
	}
	return c, nil
}

var envNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func buildServer(name string, rs *rawServer) (*Server, error) {
	switch err := connector.ValidateServerName(name); {
	case errors.Is(err, connector.ErrReservedServerName):
		return nil, errors.New("the server name is reserved for a built-in app")
	case err != nil:
		return nil, errors.New("server name must be 1-63 characters of a-z, 0-9, _ and -")
	}
	if rs == nil {
		rs = &rawServer{}
	}
	set := 0
	for _, ok := range []bool{rs.HTTP != "", rs.Stdio != "", len(rs.Command) > 0} {
		if ok {
			set++
		}
	}
	if set != 1 {
		return nil, errors.New("set exactly one of http, stdio or command")
	}
	s := &Server{Name: name}
	if rs.HTTP != "" {
		if len(rs.Env) > 0 || rs.Cwd != "" || len(rs.InheritEnv) > 0 {
			return nil, errors.New("env, cwd and inherit_env are only for stdio servers")
		}
		u, err := url.Parse(rs.HTTP)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, errors.New("http must be an http(s) URL such as http://127.0.0.1:8080/mcp")
		}
		if u.User != nil {
			return nil, errors.New("http must not contain credentials")
		}
		s.Kind, s.URL = KindHTTP, u.String()
		return s, nil
	}
	s.Kind = KindStdio
	if rs.Stdio != "" {
		argv, err := tunnelclient.SplitCommand(rs.Stdio)
		if err != nil {
			return nil, fmt.Errorf("stdio: %w", err)
		}
		s.Command = argv
	} else {
		if rs.Command[0] == "" {
			return nil, errors.New("command: the program name is empty")
		}
		s.Command = append([]string(nil), rs.Command...)
	}
	for k := range rs.Env {
		if !envNameRE.MatchString(k) {
			return nil, fmt.Errorf("env: %q is not a valid environment variable name", k)
		}
	}
	for _, k := range rs.InheritEnv {
		if !envNameRE.MatchString(k) {
			return nil, fmt.Errorf("inherit_env: %q is not a valid environment variable name", k)
		}
	}
	if rs.Cwd != "" && rs.Cwd != "~" && !strings.HasPrefix(rs.Cwd, "~/") && !filepath.IsAbs(rs.Cwd) {
		return nil, errors.New("cwd must be an absolute path or start with ~/")
	}
	s.Env, s.Cwd, s.InheritEnv = rs.Env, rs.Cwd, rs.InheritEnv
	return s, nil
}

// ServerNames returns the server names, sorted.
func (c *Config) ServerNames() []string {
	names := make([]string, 0, len(c.Servers))
	for n := range c.Servers {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// GatewayURL validates a gateway base URL: https (http only for a loopback
// host), no credentials, query or fragment; returned without a trailing
// slash.
func GatewayURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", errors.New("gateway must be a base URL such as https://gateway.example.com")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopback(u.Hostname()) {
			return "", errors.New("gateway must use https (http is allowed only for localhost)")
		}
	default:
		return "", errors.New("gateway must use https")
	}
	return strings.TrimSuffix(u.String(), "/"), nil
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

var machineNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// ValidateMachineName checks a machine name: 1-63 characters of
// [a-z0-9_-], starting with a letter or digit.
func ValidateMachineName(name string) error {
	if !machineNameRE.MatchString(name) {
		return errors.New("machine name must be 1-63 characters of a-z, 0-9, _ and -, starting with a letter or digit")
	}
	return nil
}

// DefaultMachineName derives a machine name from a hostname: the short
// name (before the first dot), lowercased, other characters replaced by
// "-", leading "-"/"_" dropped, at most 63 characters; "machine" when
// nothing is left.
func DefaultMachineName(hostname string) string {
	short, _, _ := strings.Cut(hostname, ".")
	var b strings.Builder
	for _, r := range strings.ToLower(short) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	name := strings.TrimLeft(b.String(), "-_")
	if len(name) > 63 {
		name = name[:63]
	}
	if name == "" {
		return "machine"
	}
	return name
}
