package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/huynle/mcp-gateway/internal/machineclient"
)

// EnvEnrollCode passes an enrollment code without putting it on the
// command line (flags are visible to other local users).
const EnvEnrollCode = "MCP_GATEWAY_ENROLL_CODE"

// Seams for tests.
var (
	// newConnector returns the machine connection used by `up`: one
	// tunnel.MachineAgent serving every server by tunnel id.
	newConnector = func() machineclient.Connector { return machineclient.NewTunnelConnector(nil) }
	// openBrowser opens the device-flow approval page.
	openBrowser = openURL
	// stdoutIsTerminal decides whether login may open a browser.
	stdoutIsTerminal = func() bool {
		fi, err := os.Stdout.Stat()
		return err == nil && fi.Mode()&os.ModeCharDevice != 0
	}
	// serviceExec runs launchctl / systemctl.
	serviceExec = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return exec.CommandContext(ctx, name, args...).CombinedOutput() //nolint:gosec // fixed launchctl/systemctl invocations
	}
	goos       = runtime.GOOS
	executable = os.Executable
	hostname   = os.Hostname
	environ    = os.Environ
)

const loginUsage = `usage: mcp-gateway login [--gateway URL] [--name NAME] [--enroll-code mge_...] [--key-store keychain|file] [--no-browser] [--config PATH]

Enrolls this machine with the gateway. Without --enroll-code it prints a
code to approve at <gateway>/activate (signed in to the portal) and waits.
With an enrollment code created on the portal's Machines page it enrolls
without a browser (headless machines); prefer $` + EnvEnrollCode + ` over
the flag, which other local users can see in the process list.

Flags:
  --gateway URL        gateway base URL (default: gateway in config.yaml)
  --name NAME          machine name (default: machine in config.yaml, else the hostname)
  --enroll-code CODE   one-time enrollment code (default $` + EnvEnrollCode + `)
  --key-store STORE    keychain (macOS default) or file (machine.key, 0600)
  --no-browser         do not open the approval page
  --config PATH        config file (default $MCP_GATEWAY_CONFIG, else ~/.config/mcp-gateway/config.yaml)
  --verbose            debug logging`

const statusUsage = `usage: mcp-gateway status [--config PATH] [--verbose]

Validates config.yaml, shows this machine and checks its credentials and
servers on the gateway (with review links). Exit status 1 on any problem.`

const upUsage = `usage: mcp-gateway up [--config PATH] [--register-only] [--verbose]

Registers every server of config.yaml on the gateway, connects them over
one connection and keeps it up (reconnecting with backoff). New servers are
snapshotted after the first connection and their review links printed:
approve their tools in the portal. SIGHUP reloads the config; SIGINT or
SIGTERM stops the stdio servers and exits.

Flags:
  --config PATH       config file (default $MCP_GATEWAY_CONFIG, else ~/.config/mcp-gateway/config.yaml)
  --register-only     register the servers and exit without connecting
  --verbose           debug logging`

const logoutUsage = `usage: mcp-gateway logout [--verbose]

Revokes this machine on the gateway and deletes its key and machine.json.`

const serviceUsage = `usage: mcp-gateway service install|uninstall|status [--config PATH]

Runs "mcp-gateway up" in the background: a LaunchAgent on macOS
(~/Library/LaunchAgents/com.huynle.mcp-gateway.plist, logs in
~/Library/Logs/mcp-gateway.log) or a systemd user unit on Linux
(~/.config/systemd/user/mcp-gateway.service). Prints every command it runs.`

// cmdFlags is a flag set that leaves usage to parse.
func cmdFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

// parse parses flags; stop reports that the command must return code (0
// after --help, 2 on a usage error).
func parse(fs *flag.FlagSet, args []string, usage string, stdout, stderr io.Writer) (code int, stop bool) {
	err := fs.Parse(args)
	switch {
	case errors.Is(err, flag.ErrHelp):
		say(stdout, "%s\n", usage)
		return 0, true
	case err != nil:
		say(stderr, "mcp-gateway %s: %v\n\n%s\n", fs.Name(), err, usage)
		return 2, true
	case fs.NArg() > 0:
		say(stderr, "mcp-gateway %s: unexpected arguments %q\n\n%s\n", fs.Name(), fs.Args(), usage)
		return 2, true
	}
	return 0, false
}

func newLogger(w io.Writer, verbose bool) *slog.Logger {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: level}))
}

// fail prints an error and returns exit status 1.
func fail(w io.Writer, cmd string, err error) int {
	say(w, "mcp-gateway %s: %v\n", cmd, err)
	return 1
}

func exitFor(stderr io.Writer, cmd string, err error) int {
	if err != nil {
		return fail(stderr, cmd, err)
	}
	return 0
}

func paths(configFlag string, getenv func(string) string) (cfgPath, stateDir string, err error) {
	if cfgPath, err = machineclient.ConfigPath(configFlag, getenv); err != nil {
		return "", "", err
	}
	stateDir, err = machineclient.StateDir(getenv)
	return cfgPath, stateDir, err
}

func login(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	fs := cmdFlags("login")
	gateway := fs.String("gateway", "", "")
	name := fs.String("name", "", "")
	code := fs.String("enroll-code", "", "")
	keyStore := fs.String("key-store", machineclient.DefaultKeyStore(), "")
	noBrowser := fs.Bool("no-browser", false, "")
	configFlag := fs.String("config", "", "")
	verbose := fs.Bool("verbose", false, "")
	if c, stop := parse(fs, args, loginUsage, stdout, stderr); stop {
		return c
	}
	cfgPath, stateDir, err := paths(*configFlag, getenv)
	if err != nil {
		return fail(stderr, "login", err)
	}
	// The config is optional at login; an invalid one is still an error.
	var cfg *machineclient.Config
	if _, err := os.Stat(cfgPath); err == nil {
		if cfg, err = machineclient.LoadConfig(cfgPath); err != nil {
			return fail(stderr, "login", err)
		}
	}
	if *gateway == "" && cfg != nil {
		*gateway = cfg.Gateway
	}
	if *name == "" && cfg != nil {
		*name = cfg.Machine
	}
	if *name == "" {
		h, _ := hostname()
		*name = machineclient.DefaultMachineName(h)
	}
	if *code == "" {
		*code = getenv(EnvEnrollCode)
	}
	o := machineclient.LoginOptions{
		Gateway: *gateway, Name: *name, EnrollCode: *code, KeyStore: *keyStore, StateDir: stateDir,
		Version: version, Out: stdout, Log: newLogger(stderr, *verbose),
	}
	if !*noBrowser && stdoutIsTerminal() {
		o.OpenBrowser = openBrowser
	}
	_, err = machineclient.Login(ctx, o)
	return exitFor(stderr, "login", err)
}

func status(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	fs := cmdFlags("status")
	configFlag := fs.String("config", "", "")
	verbose := fs.Bool("verbose", false, "")
	if c, stop := parse(fs, args, statusUsage, stdout, stderr); stop {
		return c
	}
	cfgPath, stateDir, err := paths(*configFlag, getenv)
	if err != nil {
		return fail(stderr, "status", err)
	}
	o := machineclient.StatusOptions{ConfigPath: cfgPath, StateDir: stateDir, Version: version, Out: stdout, Log: newLogger(stderr, *verbose)}
	if machineclient.Status(ctx, o) != nil {
		return 1 // Status printed the problem
	}
	return 0
}

func up(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	fs := cmdFlags("up")
	configFlag := fs.String("config", "", "")
	registerOnly := fs.Bool("register-only", false, "")
	verbose := fs.Bool("verbose", false, "")
	if c, stop := parse(fs, args, upUsage, stdout, stderr); stop {
		return c
	}
	cfgPath, stateDir, err := paths(*configFlag, getenv)
	if err != nil {
		return fail(stderr, "up", err)
	}
	conn := newConnector()
	if conn == nil && !*registerOnly {
		return fail(stderr, "up", errors.New("no machine connection available"))
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	reload := make(chan struct{}, 1)
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	go func() {
		for {
			select {
			case <-hup:
				select {
				case reload <- struct{}{}:
				default: // a reload is already pending
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	o := machineclient.UpOptions{
		ConfigPath: cfgPath, StateDir: stateDir, Version: version,
		Out: stderr, Stderr: stderr, Log: newLogger(stderr, *verbose),
		Connector: conn, Reload: reload, RegisterOnly: *registerOnly, Environ: environ,
	}
	if err := machineclient.Up(ctx, o); err != nil {
		return fail(stderr, "up", err)
	}
	return 0
}

func logout(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	fs := cmdFlags("logout")
	verbose := fs.Bool("verbose", false, "")
	if c, stop := parse(fs, args, logoutUsage, stdout, stderr); stop {
		return c
	}
	stateDir, err := machineclient.StateDir(getenv)
	if err != nil {
		return fail(stderr, "logout", err)
	}
	o := machineclient.LogoutOptions{StateDir: stateDir, Version: version, Out: stdout, Log: newLogger(stderr, *verbose)}
	return exitFor(stderr, "logout", machineclient.Logout(ctx, o))
}

func service(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		say(stderr, "%s\n", serviceUsage)
		return 2
	}
	action, rest := args[0], args[1:]
	switch action {
	case "-h", "--help", "-help", "help":
		say(stdout, "%s\n", serviceUsage)
		return 0
	case "install", "uninstall", "status":
	default:
		say(stderr, "mcp-gateway service: unknown action %q\n\n%s\n", action, serviceUsage)
		return 2
	}
	fs := cmdFlags("service " + action)
	configFlag := fs.String("config", "", "")
	if c, stop := parse(fs, rest, serviceUsage, stdout, stderr); stop {
		return c
	}
	cmd := "service " + action
	cfgPath, stateDir, err := paths(*configFlag, getenv)
	if err != nil {
		return fail(stderr, cmd, err)
	}
	if cfgPath, err = filepath.Abs(cfgPath); err != nil {
		return fail(stderr, cmd, err)
	}
	exe, err := executable()
	if err != nil {
		return fail(stderr, cmd, fmt.Errorf("cannot find the mcp-gateway executable: %w", err))
	}
	env := map[string]string{}
	for _, k := range []string{"PATH", "LANG", "XDG_CONFIG_HOME"} {
		env[k] = getenv(k)
	}
	o := machineclient.ServiceOptions{
		GOOS: goos, Home: getenv("HOME"), UID: os.Getuid(), Executable: exe, ConfigPath: cfgPath,
		Env: env, Exec: serviceExec, Out: stdout,
	}
	switch action {
	case "install":
		// Refuse to install a service that could only crash-loop.
		if _, err := machineclient.LoadState(stateDir); err != nil {
			return fail(stderr, cmd, err)
		}
		cfg, err := machineclient.LoadConfig(cfgPath)
		if err != nil {
			return fail(stderr, cmd, err)
		}
		if len(cfg.Servers) == 0 {
			return fail(stderr, cmd, fmt.Errorf("no servers in %s", cfgPath))
		}
		return exitFor(stderr, cmd, machineclient.ServiceInstall(ctx, o))
	case "uninstall":
		return exitFor(stderr, cmd, machineclient.ServiceUninstall(ctx, o))
	default:
		return exitFor(stderr, cmd, machineclient.ServiceStatus(ctx, o))
	}
}

// openURL opens a URL in the user's browser.
func openURL(u string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", u) //nolint:gosec,noctx // the gateway's own approval page
	case "linux":
		cmd = exec.Command("xdg-open", u) //nolint:gosec,noctx // the gateway's own approval page
	default:
		return errors.New("no browser opener on this system")
	}
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}
