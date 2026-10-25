//go:build unix

package mcpproxy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

// lockPoll is how often a waiting proxy retries the lock.
const lockPoll = 100 * time.Millisecond

// lockFile takes an exclusive flock on path, waiting until ctx is done.
// The lock goes with the process: a crashed proxy never leaves it held.
func lockFile(ctx context.Context, path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600) //nolint:gosec // the user's own state directory
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) //nolint:gosec // a file descriptor fits an int
		if err == nil {
			return func() {
				_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) //nolint:gosec // a file descriptor fits an int
				_ = f.Close()
			}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EINTR) {
			_ = f.Close()
			return nil, fmt.Errorf("lock %s: %w", path, err)
		}
		t := time.NewTimer(lockPoll)
		select {
		case <-ctx.Done():
			t.Stop()
			_ = f.Close()
			return nil, ctx.Err()
		case <-t.C:
		}
	}
}
