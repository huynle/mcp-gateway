//go:build windows

package machineclient

import (
	"errors"
	"fmt"
	"os/exec"
)

// ownProcessGroup: Windows has no process groups to kill here; the
// default cancellation kills the process itself.
func ownProcessGroup(*exec.Cmd) {}

// platformSupports refuses the delivery modes Windows lacks.
func platformSupports(m SecretMode) error {
	if m == SecretAskpass || m == SecretFD {
		return fmt.Errorf("secret delivery %q is not supported on Windows", m)
	}
	return nil
}

type askpass struct{ script string }

func startAskpass([]byte) (*askpass, error) {
	return nil, errors.New("askpass is not supported on Windows")
}

func (*askpass) close() {}
