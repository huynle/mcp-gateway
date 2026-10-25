package machineclient

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// ErrNoSecret: the store holds no secret for the account.
var ErrNoSecret = errors.New("no stored secret")

// SecretStore keeps short single-line secrets (an OAuth refresh token) by
// account, next to but separate from the machine key: the keychain store
// uses its own service name, the file store its own directory. Secrets
// never appear in logs, errors or process arguments.
type SecretStore interface {
	// Name is KeyStoreKeychain or KeyStoreFile.
	Name() string
	Save(ctx context.Context, account, secret string) error
	// Load returns ErrNoSecret when there is none.
	Load(ctx context.Context, account string) (string, error)
	// Delete succeeds when the secret is already gone.
	Delete(ctx context.Context, account string) error
}

// NewSecretStore opens a secret store by name (KeyStoreKeychain or
// KeyStoreFile): keychain items of service (account = the account), or
// one 0600 file per account in dir (the account must then be a plain
// file name).
func NewSecretStore(name, dir, service string) (SecretStore, error) {
	switch name {
	case KeyStoreFile:
		return &FileSecretStore{Dir: dir}, nil
	case KeyStoreKeychain:
		if runtime.GOOS != "darwin" {
			return nil, errors.New("the keychain store is only available on macOS; use --key-store file")
		}
		return &KeychainSecretStore{Service: service, run: runSecurity}, nil
	default:
		return nil, fmt.Errorf("unknown key store %q (want keychain or file)", name)
	}
}

// checkSecret refuses what could not round-trip through a keychain
// password prompt or a one-line file.
func checkStoredSecret(s string) error {
	if s == "" {
		return errors.New("empty secret")
	}
	for _, r := range s {
		if r <= ' ' || r == 0x7f {
			return errors.New("the secret contains spaces or control characters")
		}
	}
	return nil
}

// FileSecretStore keeps each secret in Dir/<account> (mode 0600, Dir
// 0700); Load refuses a file other users can access.
type FileSecretStore struct {
	Dir string
}

// Name implements SecretStore.
func (*FileSecretStore) Name() string { return KeyStoreFile }

func (s *FileSecretStore) path(account string) (string, error) {
	if account == "" || strings.HasPrefix(account, ".") || strings.ContainsAny(account, `/\`) || filepath.Base(account) != account {
		return "", fmt.Errorf("invalid secret file name %q", account)
	}
	return filepath.Join(s.Dir, account), nil
}

// Save implements SecretStore.
func (s *FileSecretStore) Save(_ context.Context, account, secret string) error {
	p, err := s.path(account)
	if err != nil {
		return err
	}
	if err := checkStoredSecret(secret); err != nil {
		return err
	}
	return writePrivateFile(p, []byte(secret+"\n"))
}

// Load implements SecretStore.
func (s *FileSecretStore) Load(_ context.Context, account string) (string, error) {
	p, err := s.path(account)
	if err != nil {
		return "", err
	}
	data, err := readPrivateFile(p, nil)
	if errors.Is(err, os.ErrNotExist) {
		return "", ErrNoSecret
	}
	if err != nil {
		return "", err
	}
	v := strings.TrimSpace(string(data))
	if checkStoredSecret(v) != nil {
		return "", fmt.Errorf("%s is malformed", p)
	}
	return v, nil
}

// Delete implements SecretStore.
func (s *FileSecretStore) Delete(_ context.Context, account string) error {
	p, err := s.path(account)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("delete %s: %w", p, err)
	}
	return nil
}

// KeychainSecretStore keeps secrets as macOS keychain generic passwords
// of Service through /usr/bin/security, exactly like KeychainKeyStore
// (see there for why the secret goes through stdin).
type KeychainSecretStore struct {
	Service string
	run     runFunc
}

// Name implements SecretStore.
func (*KeychainSecretStore) Name() string { return KeyStoreKeychain }

// Save implements SecretStore.
func (s *KeychainSecretStore) Save(ctx context.Context, account, secret string) error {
	if err := checkStoredSecret(secret); err != nil {
		return err
	}
	args := []string{
		"add-generic-password", "-U", "-s", s.Service, "-a", account,
		"-l", s.Service, "-j", "OAuth refresh token of mcp-gateway proxy", "-w",
	}
	if _, err := s.run(ctx, securityPath, args, []byte(secret+"\n"+secret+"\n")); err != nil {
		return fmt.Errorf("store the token in the keychain: security add-generic-password failed%s", exitSuffix(err))
	}
	return nil
}

// Load implements SecretStore.
func (s *KeychainSecretStore) Load(ctx context.Context, account string) (string, error) {
	out, err := s.run(ctx, securityPath, []string{"find-generic-password", "-s", s.Service, "-a", account, "-w"}, nil)
	if exitCode(err) == errSecItemNotFound {
		return "", ErrNoSecret
	}
	if err != nil {
		return "", fmt.Errorf("read the token from the keychain: security find-generic-password failed%s", exitSuffix(err))
	}
	v := strings.TrimSpace(string(out))
	if checkStoredSecret(v) != nil {
		return "", fmt.Errorf("the keychain item %s/%s is malformed", s.Service, account)
	}
	return v, nil
}

// Delete implements SecretStore.
func (s *KeychainSecretStore) Delete(ctx context.Context, account string) error {
	_, err := s.run(ctx, securityPath, []string{"delete-generic-password", "-s", s.Service, "-a", account}, nil)
	if err != nil && exitCode(err) != errSecItemNotFound {
		return fmt.Errorf("delete the token from the keychain: security delete-generic-password failed%s", exitSuffix(err))
	}
	return nil
}

// WritePrivateFile atomically writes a 0600 file, creating its directory
// with 0700.
func WritePrivateFile(path string, data []byte) error { return writePrivateFile(path, data) }

// ReadPrivateFile reads a file only the current user may access (no group
// or other permissions, owned by the user, not a symlink); a missing file
// is os.ErrNotExist.
func ReadPrivateFile(path string) ([]byte, error) { return readPrivateFile(path, nil) }
