//go:build unix

package machineclient

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
)

// ownProcessGroup runs the command in a new session (its own process
// group, no controlling terminal) and makes cancellation kill the whole
// group.
func ownProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}

func platformSupports(SecretMode) error { return nil }

// askpass is the one-shot helper of SecretAskpass (see actions.go).
type askpass struct {
	dir, fifo, script string
	stopped           atomic.Bool
	done              chan struct{}
}

func startAskpass(payload []byte) (*askpass, error) {
	dir, err := os.MkdirTemp("", "mcp-gateway-askpass-")
	if err != nil {
		return nil, err
	}
	a := &askpass{dir: dir, fifo: filepath.Join(dir, "secret"), script: filepath.Join(dir, "askpass"), done: make(chan struct{})}
	fail := func(err error) (*askpass, error) {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	if strings.ContainsAny(dir, "'\n") {
		return fail(errors.New("askpass: unusable temporary directory name"))
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fail(err)
	}
	if err := syscall.Mkfifo(a.fifo, 0o600); err != nil {
		return fail(err)
	}
	script := "#!/bin/sh\nexec /bin/cat -- '" + a.fifo + "'\n"
	if err := os.WriteFile(a.script, []byte(script), 0o700); err != nil { //nolint:gosec // the helper must be executable
		return fail(err)
	}
	go a.serve(payload)
	return a, nil
}

// serve waits for the first reader, removes the FIFO (so the helper
// works once) and writes the payload.
func (a *askpass) serve(payload []byte) {
	defer close(a.done)
	f, err := os.OpenFile(a.fifo, os.O_WRONLY, 0)
	if err != nil {
		return
	}
	_ = os.Remove(a.fifo)
	if !a.stopped.Load() {
		_, _ = f.Write(payload)
	}
	_ = f.Close()
}

// close releases a writer still waiting for a reader (by opening the FIFO
// without reading it), waits for it and deletes the directory.
func (a *askpass) close() {
	a.stopped.Store(true)
	var r *os.File
	if f, err := os.OpenFile(a.fifo, os.O_RDONLY|syscall.O_NONBLOCK, 0); err == nil {
		r = f
	}
	<-a.done
	if r != nil {
		_ = r.Close()
	}
	_ = os.RemoveAll(a.dir)
}
