package machineclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

const stateFileName = "machine.json"

// ErrNotLoggedIn: there is no machine.json.
var ErrNotLoggedIn = errors.New("this machine is not logged in; run `mcp-gateway login`")

// State is machine.json: which gateway this machine is enrolled with and
// where its key is. It holds no secret.
type State struct {
	Gateway   string `json:"gateway"`
	MachineID string `json:"machine_id"`
	Name      string `json:"name"`
	KeyStore  string `json:"key_store"`
}

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func (s *State) validate() error {
	if _, err := GatewayURL(s.Gateway); err != nil {
		return err
	}
	if !uuidRE.MatchString(s.MachineID) {
		return errors.New("machine_id is not a uuid")
	}
	if err := ValidateMachineName(s.Name); err != nil {
		return err
	}
	if s.KeyStore != KeyStoreKeychain && s.KeyStore != KeyStoreFile {
		return fmt.Errorf("unknown key_store %q", s.KeyStore)
	}
	return nil
}

// SaveState writes dir/machine.json (0600).
func SaveState(dir string, s *State) error {
	if err := s.validate(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writePrivateFile(filepath.Join(dir, stateFileName), append(b, '\n'))
}

// LoadState reads dir/machine.json: ErrNotLoggedIn when it is missing; it
// is refused when other users can access it.
func LoadState(dir string) (*State, error) {
	p := filepath.Join(dir, stateFileName)
	data, err := readPrivateFile(p, nil)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotLoggedIn
	}
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var s State
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	if err := s.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	return &s, nil
}

// DeleteState removes machine.json; a missing file is fine.
func DeleteState(dir string) error {
	if err := os.Remove(filepath.Join(dir, stateFileName)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
