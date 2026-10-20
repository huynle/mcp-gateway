package machineclient

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Service names.
const (
	launchdLabel   = "com.huynle.mcp-gateway"
	systemdUnit    = "mcp-gateway.service"
	serviceLogName = "mcp-gateway.log"
)

// serviceEnv are the variables of the installing shell the service gets:
// PATH so stdio servers (npx, uvx, ...) are found under launchd/systemd's
// minimal PATH, LANG, and XDG_CONFIG_HOME so the service finds the same
// machine.json. Nothing else (no credentials).
var serviceEnv = []string{"PATH", "LANG", "XDG_CONFIG_HOME"}

// ServiceOptions configure the background service commands. Everything
// system-specific is injected so the templates and commands are testable
// without touching the system.
type ServiceOptions struct {
	// GOOS selects launchd ("darwin") or systemd ("linux").
	GOOS string
	// Home is the user's home directory.
	Home string
	// UID is the user id (launchd's gui/<uid> domain).
	UID int
	// Executable is the absolute path of mcp-gateway (not resolved through
	// symlinks, so a Homebrew upgrade keeps working).
	Executable string
	// ConfigPath is passed to `up --config` (absolute).
	ConfigPath string
	// Env is the installing shell's environment (see serviceEnv).
	Env map[string]string
	// Exec runs a command and returns its combined output.
	Exec func(ctx context.Context, name string, args ...string) ([]byte, error)
	// Out shows each command run and its result.
	Out io.Writer
}

func (o *ServiceOptions) check() error {
	if o.GOOS != "darwin" && o.GOOS != "linux" {
		return fmt.Errorf("mcp-gateway service supports macOS (launchd) and Linux (systemd), not %s", o.GOOS)
	}
	if !filepath.IsAbs(o.Executable) || !filepath.IsAbs(o.ConfigPath) || !filepath.IsAbs(o.Home) {
		return errors.New("the executable, config and home paths must be absolute")
	}
	return nil
}

func (o *ServiceOptions) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	say(o.Out, "$ %s\n", strings.Join(append([]string{name}, args...), " "))
	return o.Exec(ctx, name, args...)
}

func (o *ServiceOptions) launchdPath() string {
	return filepath.Join(o.Home, "Library", "LaunchAgents", launchdLabel+".plist")
}

func (o *ServiceOptions) systemdPath() string {
	base := filepath.Join(o.Home, ".config")
	if x := o.Env["XDG_CONFIG_HOME"]; filepath.IsAbs(x) {
		base = x
	}
	return filepath.Join(base, "systemd", "user", systemdUnit)
}

func (o *ServiceOptions) launchdTarget() string { return fmt.Sprintf("gui/%d/%s", o.UID, launchdLabel) }

func (o *ServiceOptions) env() []string {
	var out []string
	for _, k := range serviceEnv {
		if v := o.Env[k]; v != "" {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// ServiceInstall writes the LaunchAgent / systemd user unit running
// `mcp-gateway up` and (re)starts it.
func ServiceInstall(ctx context.Context, o ServiceOptions) error {
	if err := o.check(); err != nil {
		return err
	}
	if o.GOOS == "darwin" {
		p := o.launchdPath()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil { //nolint:gosec // ~/Library/LaunchAgents is world-readable by convention
			return err
		}
		if err := os.MkdirAll(filepath.Join(o.Home, "Library", "Logs"), 0o755); err != nil { //nolint:gosec // standard log dir
			return err
		}
		if err := os.WriteFile(p, []byte(o.renderPlist()), 0o644); err != nil { //nolint:gosec // a LaunchAgent holds no secret
			return err
		}
		say(o.Out, "wrote %s\n", p)
		_, _ = o.run(ctx, "launchctl", "bootout", o.launchdTarget()) // not loaded yet is fine
		if out, err := o.run(ctx, "launchctl", "bootstrap", fmt.Sprintf("gui/%d", o.UID), p); err != nil {
			return fmt.Errorf("launchctl bootstrap failed (%w): %s", err, strings.TrimSpace(string(out)))
		}
		say(o.Out, "installed; logs: %s\n", filepath.Join(o.Home, "Library", "Logs", serviceLogName))
		return nil
	}
	p := o.systemdPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil { //nolint:gosec // systemd user unit dir
		return err
	}
	if err := os.WriteFile(p, []byte(o.renderUnit()), 0o644); err != nil { //nolint:gosec // a unit file holds no secret
		return err
	}
	say(o.Out, "wrote %s\n", p)
	for _, args := range [][]string{{"--user", "daemon-reload"}, {"--user", "enable", systemdUnit}, {"--user", "restart", systemdUnit}} {
		if out, err := o.run(ctx, "systemctl", args...); err != nil {
			return fmt.Errorf("systemctl %s failed (%w): %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
	}
	say(o.Out, "installed; logs: journalctl --user -u %s\n", systemdUnit)
	say(o.Out, "to keep it running while you are logged out (headless): loginctl enable-linger $USER\n")
	return nil
}

// ServiceUninstall stops the service and removes its file.
func ServiceUninstall(ctx context.Context, o ServiceOptions) error {
	if err := o.check(); err != nil {
		return err
	}
	if o.GOOS == "darwin" {
		_, _ = o.run(ctx, "launchctl", "bootout", o.launchdTarget())
		return removeServiceFile(o.Out, o.launchdPath())
	}
	_, _ = o.run(ctx, "systemctl", "--user", "disable", "--now", systemdUnit)
	if err := removeServiceFile(o.Out, o.systemdPath()); err != nil {
		return err
	}
	if out, err := o.run(ctx, "systemctl", "--user", "daemon-reload"); err != nil {
		return fmt.Errorf("systemctl --user daemon-reload failed (%w): %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func removeServiceFile(out io.Writer, p string) error {
	switch err := os.Remove(p); {
	case err == nil:
		say(out, "removed %s\n", p)
	case errors.Is(err, os.ErrNotExist):
		say(out, "%s was not installed\n", p)
	default:
		return err
	}
	return nil
}

// ServiceStatus shows whether the service is installed and running.
func ServiceStatus(ctx context.Context, o ServiceOptions) error {
	if err := o.check(); err != nil {
		return err
	}
	if o.GOOS == "darwin" {
		p := o.launchdPath()
		if _, err := os.Stat(p); err != nil {
			say(o.Out, "not installed (%s missing); run `mcp-gateway service install`\n", p)
		} else {
			say(o.Out, "installed: %s\n", p)
		}
		out, err := o.run(ctx, "launchctl", "print", o.launchdTarget())
		if err != nil {
			say(o.Out, "not loaded in launchd\n")
			return nil
		}
		for line := range strings.SplitSeq(string(out), "\n") {
			l := strings.TrimSpace(line)
			if strings.HasPrefix(l, "state =") || strings.HasPrefix(l, "pid =") || strings.HasPrefix(l, "last exit code =") {
				say(o.Out, "  %s\n", l)
			}
		}
		return nil
	}
	p := o.systemdPath()
	if _, err := os.Stat(p); err != nil {
		say(o.Out, "not installed (%s missing); run `mcp-gateway service install`\n", p)
	} else {
		say(o.Out, "installed: %s\n", p)
	}
	// systemctl status exits non-zero when the unit is inactive: report, not fail.
	out, _ := o.run(ctx, "systemctl", "--user", "status", systemdUnit, "--no-pager")
	say(o.Out, "%s\n", strings.TrimRight(string(out), "\n"))
	return nil
}

func xmlText(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

func (o *ServiceOptions) renderPlist() string {
	var b strings.Builder
	logPath := filepath.Join(o.Home, "Library", "Logs", serviceLogName)
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + launchdLabel + `</string>
	<key>ProgramArguments</key>
	<array>
`)
	for _, a := range []string{o.Executable, "up", "--config", o.ConfigPath} {
		b.WriteString("\t\t<string>" + xmlText(a) + "</string>\n")
	}
	b.WriteString(`	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ThrottleInterval</key>
	<integer>10</integer>
	<key>ProcessType</key>
	<string>Background</string>
	<key>StandardOutPath</key>
	<string>` + xmlText(logPath) + `</string>
	<key>StandardErrorPath</key>
	<string>` + xmlText(logPath) + `</string>
`)
	if env := o.env(); len(env) > 0 {
		b.WriteString("\t<key>EnvironmentVariables</key>\n\t<dict>\n")
		for _, k := range env {
			b.WriteString("\t\t<key>" + k + "</key>\n\t\t<string>" + xmlText(o.Env[k]) + "</string>\n")
		}
		b.WriteString("\t</dict>\n")
	}
	b.WriteString("</dict>\n</plist>\n")
	return b.String()
}

// systemdQuote quotes a word for ExecStart= (systemd.service(5) "Command
// lines"): backslash and double quote escaped, % and $ doubled.
func systemdQuote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, `%`, `%%`, `$`, `$$`)
	return `"` + r.Replace(s) + `"`
}

// systemdEnvQuote quotes an Environment= assignment: no $ expansion
// there, only % specifiers.
func systemdEnvQuote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, `%`, `%%`)
	return `"` + r.Replace(s) + `"`
}

func (o *ServiceOptions) renderUnit() string {
	var exec []string
	for _, a := range []string{o.Executable, "up", "--config", o.ConfigPath} {
		exec = append(exec, systemdQuote(a))
	}
	var b strings.Builder
	b.WriteString(`[Unit]
Description=MCP gateway machine connection (mcp-gateway up)
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
ExecStart=` + strings.Join(exec, " ") + `
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=10
KillSignal=SIGTERM
TimeoutStopSec=30
`)
	for _, k := range o.env() {
		b.WriteString("Environment=" + systemdEnvQuote(k+"="+o.Env[k]) + "\n")
	}
	b.WriteString(`
[Install]
WantedBy=default.target
`)
	return b.String()
}
