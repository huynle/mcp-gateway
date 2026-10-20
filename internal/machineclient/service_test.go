package machineclient

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeExec struct {
	calls []string
	fail  map[string]error // by the call's joined prefix
	out   map[string]string
}

func (f *fakeExec) run(_ context.Context, name string, args ...string) ([]byte, error) {
	call := strings.Join(append([]string{name}, args...), " ")
	f.calls = append(f.calls, call)
	for prefix, err := range f.fail {
		if strings.HasPrefix(call, prefix) {
			return []byte("boom output"), err
		}
	}
	for prefix, out := range f.out {
		if strings.HasPrefix(call, prefix) {
			return []byte(out), nil
		}
	}
	return nil, nil
}

func serviceOpts(t *testing.T, goos string) (ServiceOptions, *fakeExec, *bytes.Buffer) {
	t.Helper()
	home := t.TempDir()
	fe := &fakeExec{fail: map[string]error{}, out: map[string]string{}}
	out := &bytes.Buffer{}
	return ServiceOptions{
		GOOS: goos, Home: home, UID: 501,
		Executable: "/opt/homebrew/bin/mcp-gateway", ConfigPath: filepath.Join(home, ".config/mcp-gateway/config.yaml"),
		Env:  map[string]string{"PATH": "/opt/homebrew/bin:/usr/bin:/bin"},
		Exec: fe.run, Out: out,
	}, fe, out
}

func TestLaunchdInstall(t *testing.T) {
	o, fe, out := serviceOpts(t, "darwin")
	o.Env["XDG_CONFIG_HOME"] = "/x & <y>"
	if err := ServiceInstall(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(o.Home, "Library/LaunchAgents/com.huynle.mcp-gateway.plist")
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := xml.Unmarshal(data, new(any)); err != nil && !strings.Contains(err.Error(), "EOF") {
		// Well-formedness check: the decoder must get through the document.
		d := xml.NewDecoder(bytes.NewReader(data))
		for {
			if _, err := d.Token(); err != nil {
				if err.Error() != "EOF" {
					t.Fatalf("plist is not well-formed XML: %v\n%s", err, data)
				}
				break
			}
		}
	}
	s := string(data)
	for _, want := range []string{
		"<key>Label</key>", "<string>com.huynle.mcp-gateway</string>",
		"<string>/opt/homebrew/bin/mcp-gateway</string>", "<string>up</string>", "<string>--config</string>",
		"<string>" + o.ConfigPath + "</string>",
		"<key>RunAtLoad</key>\n\t<true/>", "<key>KeepAlive</key>\n\t<true/>",
		"<string>" + filepath.Join(o.Home, "Library/Logs/mcp-gateway.log") + "</string>",
		"<key>PATH</key>", "<string>/opt/homebrew/bin:/usr/bin:/bin</string>",
		"<string>/x &amp; &lt;y&gt;</string>",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("plist misses %q:\n%s", want, s)
		}
	}
	wantCalls := []string{
		"launchctl bootout gui/501/com.huynle.mcp-gateway",
		"launchctl bootstrap gui/501 " + p,
	}
	if strings.Join(fe.calls, "\n") != strings.Join(wantCalls, "\n") {
		t.Fatalf("calls:\n%s", strings.Join(fe.calls, "\n"))
	}
	for _, c := range wantCalls {
		if !strings.Contains(out.String(), "$ "+c) {
			t.Errorf("output does not show %q:\n%s", c, out.String())
		}
	}
}

func TestLaunchdInstallBootstrapFailure(t *testing.T) {
	o, fe, _ := serviceOpts(t, "darwin")
	fe.fail["launchctl bootout"] = errors.New("exit status 3") // not loaded: fine
	fe.fail["launchctl bootstrap"] = errors.New("exit status 5")
	err := ServiceInstall(context.Background(), o)
	if err == nil || !strings.Contains(err.Error(), "bootstrap") {
		t.Fatalf("err %v", err)
	}
}

func TestLaunchdUninstallAndStatus(t *testing.T) {
	o, fe, out := serviceOpts(t, "darwin")
	if err := ServiceInstall(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	fe.calls = nil
	fe.out["launchctl print"] = "gui/501/com.huynle.mcp-gateway = {\n\tstate = running\n\tpid = 4242\n\tlast exit code = 0\n\tother = x\n}\n"
	out.Reset()
	if err := ServiceStatus(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"installed", "state = running", "pid = 4242", "$ launchctl print gui/501/com.huynle.mcp-gateway"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("status misses %q:\n%s", want, out.String())
		}
	}
	fe.calls = nil
	if err := ServiceUninstall(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if strings.Join(fe.calls, "\n") != "launchctl bootout gui/501/com.huynle.mcp-gateway" {
		t.Fatalf("calls %v", fe.calls)
	}
	if _, err := os.Stat(filepath.Join(o.Home, "Library/LaunchAgents/com.huynle.mcp-gateway.plist")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("plist not removed")
	}
	out.Reset()
	fe.fail["launchctl print"] = errors.New("exit status 113")
	if err := ServiceStatus(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "not installed") {
		t.Fatalf("status:\n%s", out.String())
	}
}

func TestSystemdInstall(t *testing.T) {
	o, fe, out := serviceOpts(t, "linux")
	o.Executable = `/home/u/my bin/mcp-gateway`
	o.Env["PATH"] = `/usr/bin:/odd"dir$%`
	if err := ServiceInstall(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(o.Home, ".config/systemd/user/mcp-gateway.service")
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	for _, want := range []string{
		`ExecStart="/home/u/my bin/mcp-gateway" "up" "--config" "` + o.ConfigPath + `"`,
		"Restart=on-failure",
		`Environment="PATH=/usr/bin:/odd\"dir$%%"`, // systemd.exec(5): no $ expansion here, % specifiers are
		"ExecReload=/bin/kill -HUP $MAINPID",
		"WantedBy=default.target",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("unit misses %q:\n%s", want, s)
		}
	}
	wantCalls := []string{
		"systemctl --user daemon-reload",
		"systemctl --user enable mcp-gateway.service",
		"systemctl --user restart mcp-gateway.service",
	}
	if strings.Join(fe.calls, "\n") != strings.Join(wantCalls, "\n") {
		t.Fatalf("calls:\n%s", strings.Join(fe.calls, "\n"))
	}
	if !strings.Contains(out.String(), "loginctl enable-linger") {
		t.Errorf("output should mention lingering for headless machines:\n%s", out.String())
	}
}

func TestSystemdHonoursXDGConfigHome(t *testing.T) {
	o, _, _ := serviceOpts(t, "linux")
	xdg := filepath.Join(o.Home, "xdg")
	o.Env["XDG_CONFIG_HOME"] = xdg
	if err := ServiceInstall(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(xdg, "systemd/user/mcp-gateway.service")); err != nil {
		t.Fatal(err)
	}
}

func TestSystemdUninstallAndStatus(t *testing.T) {
	o, fe, out := serviceOpts(t, "linux")
	if err := ServiceInstall(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	fe.calls = nil
	fe.fail["systemctl --user status"] = errors.New("exit status 3") // inactive is not an error
	fe.out["systemctl --user status"] = "● mcp-gateway.service\n   Active: inactive (dead)\n"
	if err := ServiceStatus(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "$ systemctl --user status mcp-gateway.service --no-pager") {
		t.Fatalf("status:\n%s", out.String())
	}
	fe.calls = nil
	if err := ServiceUninstall(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	want := "systemctl --user disable --now mcp-gateway.service\nsystemctl --user daemon-reload"
	if strings.Join(fe.calls, "\n") != want {
		t.Fatalf("calls:\n%s", strings.Join(fe.calls, "\n"))
	}
	if _, err := os.Stat(filepath.Join(o.Home, ".config/systemd/user/mcp-gateway.service")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unit not removed")
	}
}

func TestServiceUnsupported(t *testing.T) {
	o, _, _ := serviceOpts(t, "windows")
	if err := ServiceInstall(context.Background(), o); err == nil {
		t.Fatal("windows accepted")
	}
	o, _, _ = serviceOpts(t, "linux")
	o.Executable = "relative/mcp-gateway"
	if err := ServiceInstall(context.Background(), o); err == nil {
		t.Fatal("relative executable accepted")
	}
}
