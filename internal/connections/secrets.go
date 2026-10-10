package connections

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/store"
)

// Secret keys of the vendor app secret bundle. Every vendor app has a
// client secret; Slack additionally needs the bot token the approval
// notifier posts DMs with and the signing secret /slack/interactions
// verifies requests with (docs/vendor-apps.md section 2).
const (
	SecretClientSecret       = "client_secret"
	SecretSlackBotToken      = "bot_token"
	SecretSlackSigningSecret = "signing_secret"
)

// ExtraSecretKeys lists the extra (non client-secret) keys a vendor's app
// may hold, in the order the admin editor shows them.
func ExtraSecretKeys(vendor string) []string {
	if vendor == VendorSlack {
		return []string{SecretSlackBotToken, SecretSlackSigningSecret}
	}
	return nil
}

// secretBundle is the plaintext sealed in the vendor_apps secret envelope:
// every secret the app holds, keyed by name (SecretClientSecret and the
// vendor's ExtraSecretKeys). Rows written before the bundle existed hold
// the raw client secret as the plaintext; decodeBundle recognises them.
type secretBundle map[string]string

// bundlePrefix starts every encoded bundle so a legacy plaintext (an
// opaque vendor-issued string, never a NUL byte) cannot be mistaken for
// one.
const bundlePrefix = "\x00mcp-gateway/vendor-app-secrets/v1\n"

func encodeSecrets(b secretBundle) ([]byte, error) {
	js, err := json.Marshal(b)
	if err != nil {
		return nil, fmt.Errorf("connections: encode secrets: %w", err)
	}
	return append([]byte(bundlePrefix), js...), nil
}

func decodeSecrets(plain []byte) (secretBundle, error) {
	if !bytes.HasPrefix(plain, []byte(bundlePrefix)) {
		return secretBundle{SecretClientSecret: string(plain)}, nil
	}
	var b secretBundle
	if err := json.Unmarshal(plain[len(bundlePrefix):], &b); err != nil {
		return nil, fmt.Errorf("connections: decode secrets: %w", err)
	}
	if b == nil {
		b = secretBundle{}
	}
	return b, nil
}

// keys returns the extra secret names present, sorted.
func (b secretBundle) keys() []string {
	var out []string
	for k, v := range b {
		if k != SecretClientSecret && v != "" {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// aadForApp is what a vendor app's secret bundle is sealed under.
func aadForApp(id string) crypto.AAD { return crypto.AAD{Kind: aadKindVendorApp, RecordID: id} }

// openBundle decrypts the app's secret bundle (empty when the row has no
// envelope yet).
func (s *Service) openBundle(ctx context.Context, row *store.VendorApp) (secretBundle, error) {
	if len(row.ClientSecret.Ciphertext) == 0 {
		return secretBundle{}, nil
	}
	plain, err := crypto.Decrypt(ctx, s.keys, aadForApp(row.ID), crypto.Envelope(row.ClientSecret))
	if err != nil {
		return nil, fmt.Errorf("connections: vendor app %s/%s secret: %w", row.Vendor, row.Name, err)
	}
	return decodeSecrets(plain)
}

// sealBundle encrypts the bundle into the row's envelope.
func (s *Service) sealBundle(ctx context.Context, row *store.VendorApp, b secretBundle) error {
	plain, err := encodeSecrets(b)
	if err != nil {
		return err
	}
	env, err := crypto.Encrypt(ctx, s.keys, aadForApp(row.ID), plain)
	if err != nil {
		return fmt.Errorf("connections: encrypt secrets: %w", err)
	}
	row.ClientSecret = store.Encrypted(env)
	return nil
}

// VendorSecrets returns the named secrets of the app registered for
// vendor/variant (variant "" is the default variant); keys the app does
// not hold are absent from the result. ErrNotConfigured when there is no
// such app. Callers are the OAuth flow (client secret), the Slack
// approval notifier (bot token) and /slack/interactions (signing secret);
// nothing renders the values.
func (s *Service) VendorSecrets(ctx context.Context, vendor, variant string, keys ...string) (map[string]string, error) {
	vendor, variant = normalizeKey(vendor, variant)
	var row *store.VendorApp
	err := s.store.Bypass(ctx, func(tx Tx) (err error) {
		row, err = tx.FindVendorApp(ctx, vendor, variant)
		return err
	})
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, fmt.Errorf("%w: %s/%s", ErrNotConfigured, vendor, variant)
	case err != nil:
		return nil, fmt.Errorf("connections: load vendor app: %w", err)
	}
	b, err := s.openBundle(ctx, row)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(keys))
	for _, k := range keys {
		if v, ok := b[strings.TrimSpace(k)]; ok && v != "" {
			out[k] = v
		}
	}
	return out, nil
}
