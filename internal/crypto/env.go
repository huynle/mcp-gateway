package crypto

import (
	"context"
	"fmt"
	"strings"
)

// Environment variables read by NewProviderFromEnv. They are documented for
// operators in docs/crypto.md.
const (
	// EnvKeyProvider selects the provider: "file" (default) or "vault".
	EnvKeyProvider = "GATEWAY_KEY_PROVIDER"
	// EnvKeyFile is the dev key file path (file provider).
	EnvKeyFile = "GATEWAY_KEY_FILE"
	// EnvVaultAddr is the Vault base URL (vault provider).
	EnvVaultAddr = "GATEWAY_VAULT_ADDR"
	// EnvVaultToken is the Vault token (vault provider).
	EnvVaultToken = "GATEWAY_VAULT_TOKEN"
	// EnvVaultTransitKey is the transit key name (vault provider).
	EnvVaultTransitKey = "GATEWAY_VAULT_TRANSIT_KEY"
	// EnvVaultMount is the transit mount path; default "transit".
	EnvVaultMount = "GATEWAY_VAULT_MOUNT"
)

// NewProviderFromEnv builds the provider selected by GATEWAY_KEY_PROVIDER
// using getenv (typically os.Getenv, or a map lookup in tests). An unset
// selector means "file" so local runs only need GATEWAY_KEY_FILE. Errors name
// the missing or invalid variable and never include its value when it is a
// secret.
func NewProviderFromEnv(getenv func(string) string) (KeyProvider, error) {
	kind := strings.ToLower(strings.TrimSpace(getenv(EnvKeyProvider)))
	switch kind {
	case "", "file":
		path := getenv(EnvKeyFile)
		if path == "" {
			return nil, fmt.Errorf("crypto: %s is required when %s is file", EnvKeyFile, EnvKeyProvider)
		}
		return LoadKeyFile(path)
	case "vault":
		cfg := VaultConfig{
			Addr:    getenv(EnvVaultAddr),
			Token:   getenv(EnvVaultToken),
			KeyName: getenv(EnvVaultTransitKey),
			Mount:   getenv(EnvVaultMount),
		}
		for name, value := range map[string]string{EnvVaultAddr: cfg.Addr, EnvVaultToken: cfg.Token, EnvVaultTransitKey: cfg.KeyName} {
			if value == "" {
				return nil, fmt.Errorf("crypto: %s is required when %s is vault", name, EnvKeyProvider)
			}
		}
		return NewVaultProvider(cfg)
	default:
		return nil, fmt.Errorf("crypto: %s=%q: must be file or vault", EnvKeyProvider, kind)
	}
}

// readyProvider is implemented by providers that can probe their backend
// more cheaply or precisely than CurrentKeyID.
type readyProvider interface {
	Ready(ctx context.Context) error
}

// ReadinessCheck returns a /readyz check for p: Ready when the provider
// implements it, otherwise a CurrentKeyID round trip. The result is
// assignable to observability.Check.
func ReadinessCheck(p KeyProvider) func(ctx context.Context) error {
	if rp, ok := p.(readyProvider); ok {
		return rp.Ready
	}
	return func(ctx context.Context) error {
		_, err := p.CurrentKeyID(ctx)
		return err
	}
}
