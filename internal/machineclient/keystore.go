package machineclient

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Key store names (machine.json key_store, --key-store).
const (
	KeyStoreKeychain = "keychain"
	KeyStoreFile     = "file"
	// KeychainService is the macOS keychain generic password service; the
	// account is the machine id.
	KeychainService = "mcp-gateway"

	keyFileName  = "machine.key"
	securityPath = "/usr/bin/security"
)

// ErrNoKey: the store has no key for the machine.
var ErrNoKey = errors.New("the machine key is missing; run `mcp-gateway login` again")

// KeyStore keeps the machine's private key. The key never leaves the
// machine and never appears in logs, errors or process arguments.
type KeyStore interface {
	// Name is KeyStoreKeychain or KeyStoreFile (recorded in machine.json).
	Name() string
	Save(ctx context.Context, machineID string, key ed25519.PrivateKey) error
	// Load returns ErrNoKey when the key is missing.
	Load(ctx context.Context, machineID string) (ed25519.PrivateKey, error)
	// Delete succeeds when the key is already gone.
	Delete(ctx context.Context, machineID string) error
}

// DefaultKeyStore is "keychain" on macOS (when /usr/bin/security exists),
// "file" elsewhere.
func DefaultKeyStore() string {
	if runtime.GOOS == "darwin" {
		if _, err := os.Stat(securityPath); err == nil {
			return KeyStoreKeychain
		}
	}
	return KeyStoreFile
}

// NewKeyStore opens a key store by name; the file store keeps machine.key
// in stateDir.
func NewKeyStore(name, stateDir string) (KeyStore, error) {
	switch name {
	case KeyStoreFile:
		return &FileKeyStore{Path: filepath.Join(stateDir, keyFileName)}, nil
	case KeyStoreKeychain:
		if runtime.GOOS != "darwin" {
			return nil, errors.New("the keychain key store is only available on macOS; use --key-store file")
		}
		return &KeychainKeyStore{run: runSecurity}, nil
	default:
		return nil, fmt.Errorf("unknown key store %q (want keychain or file)", name)
	}
}

// FileKeyStore keeps the key in a PKCS#8 PEM file (mode 0600). Load
// refuses a file other users can access or that another user owns.
type FileKeyStore struct {
	Path string
	uid  func() int // the current user (tests)
}

// Name implements KeyStore.
func (*FileKeyStore) Name() string { return KeyStoreFile }

// Save implements KeyStore: an atomic write of a 0600 file in a 0700
// directory.
func (s *FileKeyStore) Save(_ context.Context, _ string, key ed25519.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return errors.New("encode the machine key")
	}
	return writePrivateFile(s.Path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// Load implements KeyStore.
func (s *FileKeyStore) Load(_ context.Context, _ string) (ed25519.PrivateKey, error) {
	data, err := readPrivateFile(s.Path, s.uid)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoKey
	}
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("%s is not a PKCS#8 PEM private key", s.Path)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s is not a valid private key", s.Path)
	}
	ek, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s is not an Ed25519 key", s.Path)
	}
	return ek, nil
}

// Delete implements KeyStore.
func (s *FileKeyStore) Delete(context.Context, string) error {
	if err := os.Remove(s.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("delete the machine key: %w", err)
	}
	return nil
}

// runFunc runs a program with stdin and returns its stdout.
type runFunc func(ctx context.Context, path string, args []string, stdin []byte) ([]byte, error)

// KeychainKeyStore keeps the key as a macOS keychain generic password
// (service "mcp-gateway", account = machine id) through /usr/bin/security.
//
// Why /usr/bin/security and not a library: the binaries are built with
// CGO_ENABLED=0 and the Security framework needs cgo (keybase/go-keychain
// does). The secret is never an argument: `add-generic-password ... -w`
// with -w last makes security prompt for the password, and it reads the
// prompt answer from stdin when it has no controlling terminal, so the
// command runs in a new session (setsid) with the secret on stdin. `find
// -w` returns it on stdout. The item's access list trusts
// /usr/bin/security, so headless reads need no keychain prompt; like a
// 0600 file, same-user processes can read it, but it is encrypted at rest
// with the login keychain and stays out of plain-file backups.
type KeychainKeyStore struct{ run runFunc }

// Name implements KeyStore.
func (*KeychainKeyStore) Name() string { return KeyStoreKeychain }

// errSecItemNotFound is security's exit status for a missing item.
const errSecItemNotFound = 44

// Save implements KeyStore.
func (s *KeychainKeyStore) Save(ctx context.Context, machineID string, key ed25519.PrivateKey) error {
	secret := base64.RawURLEncoding.EncodeToString(key.Seed())
	args := []string{
		"add-generic-password", "-U", "-s", KeychainService, "-a", machineID,
		"-l", "mcp-gateway machine key", "-j", "Ed25519 key of this machine for the MCP gateway", "-w",
	}
	if _, err := s.run(ctx, securityPath, args, []byte(secret+"\n"+secret+"\n")); err != nil {
		return fmt.Errorf("store the machine key in the keychain: security add-generic-password failed%s", exitSuffix(err))
	}
	return nil
}

// Load implements KeyStore.
func (s *KeychainKeyStore) Load(ctx context.Context, machineID string) (ed25519.PrivateKey, error) {
	out, err := s.run(ctx, securityPath, []string{"find-generic-password", "-s", KeychainService, "-a", machineID, "-w"}, nil)
	if exitCode(err) == errSecItemNotFound {
		return nil, ErrNoKey
	}
	if err != nil {
		return nil, fmt.Errorf("read the machine key from the keychain: security find-generic-password failed%s", exitSuffix(err))
	}
	seed, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(out)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("the keychain item for the machine key is malformed; run `mcp-gateway login` again")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// Delete implements KeyStore.
func (s *KeychainKeyStore) Delete(ctx context.Context, machineID string) error {
	_, err := s.run(ctx, securityPath, []string{"delete-generic-password", "-s", KeychainService, "-a", machineID}, nil)
	if err != nil && exitCode(err) != errSecItemNotFound {
		return fmt.Errorf("delete the machine key from the keychain: security delete-generic-password failed%s", exitSuffix(err))
	}
	return nil
}

func exitCode(err error) int {
	var ec interface{ ExitCode() int }
	if errors.As(err, &ec) {
		return ec.ExitCode()
	}
	if err != nil {
		return -1
	}
	return 0
}

// exitSuffix describes a failure by exit status only: the command's output
// may contain the secret.
func exitSuffix(err error) string {
	if c := exitCode(err); c > 0 {
		return fmt.Sprintf(" (exit status %d)", c)
	}
	return ""
}

// writePrivateFile atomically writes a 0600 file, creating its directory
// with 0700.
func writePrivateFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*")
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// readPrivateFile reads a file only the current user may access: it is
// refused when group or others have any permission on it or when another
// user owns it. uid is the current user (nil: os.Getuid).
func readPrivateFile(path string, uid func() int) ([]byte, error) {
	f, err := openPrivateFile(path, uid)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(io.LimitReader(f, 64<<10))
}
