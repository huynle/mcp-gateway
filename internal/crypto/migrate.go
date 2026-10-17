package crypto

import (
	"context"
	"errors"
	"fmt"
	"regexp"
)

// MigratingProvider moves a deployment from the dev key file to Vault /
// OpenBao transit without re-encrypting anything up front: new data keys are
// wrapped by the target (Vault), and existing envelopes are unwrapped by the
// provider that owns their key ID. Vault transit IDs ("v1", "v2", ...) go to
// the target; every other ID goes to the legacy key file. There is no
// fallback between the two, so a Vault outage never silently routes a blob
// to the file and a file ID never reaches Vault.
//
// It is the provider for the cutover window only: run the re-wrap command
// (`migrate rewrap`) until every envelope carries a Vault key ID, then
// switch GATEWAY_KEY_PROVIDER to vault and retire the key file
// (docs/crypto.md "Moving from file to Vault/OpenBao").
type MigratingProvider struct {
	legacy *StaticProvider
	target *VaultProvider
}

// vaultShapedID matches IDs a file key must not use because they would be
// indistinguishable from transit versions (case-insensitive, leading zeros
// and v0 included, to rule out any ambiguity).
var vaultShapedID = regexp.MustCompile(`^[vV][0-9]+$`)

// NewMigratingProvider combines the legacy file keys with the Vault target.
// It refuses a key file whose IDs look like transit versions ("v<N>"):
// those envelopes could not be routed unambiguously.
func NewMigratingProvider(legacy *StaticProvider, target *VaultProvider) (*MigratingProvider, error) {
	if legacy == nil || target == nil {
		return nil, errors.New("crypto: migrating provider needs both the legacy key file and the vault target")
	}
	for _, id := range legacy.KeyIDs() {
		if vaultShapedID.MatchString(id) {
			return nil, fmt.Errorf("crypto: migrating provider: file key ID %q looks like a vault transit version; rename it before migrating (re-wrap under a new file key first)", id)
		}
	}
	return &MigratingProvider{legacy: legacy, target: target}, nil
}

// CurrentKeyID implements KeyProvider: the target's current version.
func (p *MigratingProvider) CurrentKeyID(ctx context.Context) (string, error) {
	return p.target.CurrentKeyID(ctx)
}

// WrapDataKey implements KeyProvider: new data keys always go to the target.
func (p *MigratingProvider) WrapDataKey(ctx context.Context, plaintextKey []byte) (string, []byte, error) {
	return p.target.WrapDataKey(ctx, plaintextKey)
}

// UnwrapDataKey implements KeyProvider by routing on the key ID's shape.
func (p *MigratingProvider) UnwrapDataKey(ctx context.Context, keyID string, wrapped []byte) ([]byte, error) {
	if isVaultKeyID(keyID) {
		return p.target.UnwrapDataKey(ctx, keyID, wrapped)
	}
	return p.legacy.UnwrapDataKey(ctx, keyID, wrapped)
}

// Ready reports the target's readiness: without it no new record can be
// written. The legacy keys were validated when the file was loaded.
func (p *MigratingProvider) Ready(ctx context.Context) error {
	return p.target.Ready(ctx)
}
