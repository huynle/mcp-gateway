package mcpproxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/huynle/mcp-gateway/internal/machineclient"
)

// SecretService is the macOS keychain service of the proxy's refresh
// tokens (account = the gateway base URL). It is not the machine key's
// service ("mcp-gateway"): the two credentials are independent.
const SecretService = "mcp-gateway-proxy"

// credentials is what a previous run left for one gateway.
type credentials struct {
	// ClientID is the proxy's registered OAuth client ("" = register).
	ClientID string
	// Scope is the scope of RefreshToken.
	Scope string
	// RefreshToken is the latest rotating refresh token ("" = sign in).
	RefreshToken string
}

// stateFile is <id>.json: who the proxy is on the gateway. No secret.
type stateFile struct {
	Gateway  string `json:"gateway"`
	ClientID string `json:"client_id"`
	Scope    string `json:"scope,omitempty"`
	KeyStore string `json:"key_store"`
}

// credStore persists the proxy's credentials for one gateway in dir
// (normally ~/.config/mcp-gateway/proxy), apart from machine enrollment:
//
//	<id>.json   client id, scope, key store (0600, no secret)
//	<id>.lock   serialises renewals between proxies of the same user
//	<id>.token  the refresh token (file store, 0600); with the keychain
//	            store it is the item service "mcp-gateway-proxy",
//	            account <gateway base URL>
//
// where <id> is the first 16 hex digits of SHA-256(gateway base URL).
type credStore struct {
	dir, gateway, id string
	secrets          machineclient.SecretStore
}

func newCredStore(dir, gateway string, secrets machineclient.SecretStore) *credStore {
	sum := sha256.Sum256([]byte(gateway))
	return &credStore{dir: dir, gateway: gateway, id: hex.EncodeToString(sum[:8]), secrets: secrets}
}

func (c *credStore) statePath() string { return filepath.Join(c.dir, c.id+".json") }
func (c *credStore) lockPath() string  { return filepath.Join(c.dir, c.id+".lock") }

// account names the refresh token in the secret store.
func (c *credStore) account() string {
	if c.secrets.Name() == machineclient.KeyStoreKeychain {
		return c.gateway
	}
	return c.id + ".token"
}

// load returns the stored credentials; missing ones are empty fields.
func (c *credStore) load(ctx context.Context) (*credentials, error) {
	cr := &credentials{}
	data, err := machineclient.ReadPrivateFile(c.statePath())
	switch {
	case errors.Is(err, os.ErrNotExist):
		return cr, nil
	case err != nil:
		return nil, err
	}
	var st stateFile
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&st); err != nil {
		return nil, fmt.Errorf("%s: %w", c.statePath(), err)
	}
	if st.Gateway != c.gateway {
		return cr, nil
	}
	cr.ClientID, cr.Scope = st.ClientID, st.Scope
	if cr.ClientID == "" {
		return cr, nil
	}
	rt, err := c.secrets.Load(ctx, c.account())
	switch {
	case errors.Is(err, machineclient.ErrNoSecret):
	case err != nil:
		return nil, err
	default:
		cr.RefreshToken = rt
	}
	return cr, nil
}

// saveClient records the client and the scope of the stored refresh token.
func (c *credStore) saveClient(_ context.Context, clientID, scope string) error {
	b, err := json.MarshalIndent(stateFile{Gateway: c.gateway, ClientID: clientID, Scope: scope, KeyStore: c.secrets.Name()}, "", "  ")
	if err != nil {
		return err
	}
	return machineclient.WritePrivateFile(c.statePath(), append(b, '\n'))
}

func (c *credStore) saveRefresh(ctx context.Context, rt string) error {
	return c.secrets.Save(ctx, c.account(), rt)
}

func (c *credStore) dropRefresh(ctx context.Context) error {
	return c.secrets.Delete(ctx, c.account())
}

// dropClient forgets the client and its refresh token.
func (c *credStore) dropClient(ctx context.Context) error {
	if err := c.dropRefresh(ctx); err != nil {
		return err
	}
	if err := os.Remove(c.statePath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// lock takes the cross-process lock of this gateway's credentials.
func (c *credStore) lock(ctx context.Context) (unlock func(), err error) {
	if err := os.MkdirAll(c.dir, 0o700); err != nil {
		return nil, fmt.Errorf("create %s: %w", c.dir, err)
	}
	return lockFile(ctx, c.lockPath())
}
