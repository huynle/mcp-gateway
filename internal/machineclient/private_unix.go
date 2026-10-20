//go:build unix

package machineclient

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// openPrivateFile opens path (not following a final symlink) and checks
// the open file: a regular file, owned by the current user, no group or
// other permissions.
func openPrivateFile(path string, uid func() int) (*os.File, error) {
	if uid == nil {
		uid = os.Getuid
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0) //nolint:gosec // the user's own state file
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	switch {
	case !fi.Mode().IsRegular():
		err = fmt.Errorf("%s is not a regular file", path)
	case !ok:
		err = fmt.Errorf("cannot check the owner of %s", path)
	case int(st.Uid) != uid():
		err = fmt.Errorf("%s is owned by another user (uid %d); refusing to use it", path, st.Uid)
	case fi.Mode().Perm()&0o077 != 0:
		err = fmt.Errorf("%s has mode %04o: other users can access it; refusing to use it (run chmod 600 %s)", path, fi.Mode().Perm(), path)
	}
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// runSecurity runs /usr/bin/security in a new session without a
// controlling terminal, so a password prompt reads stdin, not the tty.
func runSecurity(ctx context.Context, path string, args []string, stdin []byte) ([]byte, error) {
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Stdin = bytes.NewReader(stdin)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	err := cmd.Run()
	return out.Bytes(), err
}
