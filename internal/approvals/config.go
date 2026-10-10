package approvals

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Environment variables this package reads. They live here rather than in
// internal/config so the approvals module owns its own settings, the way
// the crypto package owns GATEWAY_KEY_*.
const (
	// EnvTTL is how long an approval may be acted on and, once approved,
	// consumed (GATEWAY_APPROVAL_TTL, default 15m).
	EnvTTL = "GATEWAY_APPROVAL_TTL"
	// EnvWait bounds how long a confirmed call waits for the user before
	// answering "approval required" (GATEWAY_APPROVAL_WAIT, default 30s).
	// It must stay below common harness timeouts (decision s0p05diu).
	EnvWait = "GATEWAY_APPROVAL_WAIT"
)

// Defaults from decision s0p05diu.
const (
	DefaultTTL  = 15 * time.Minute
	DefaultWait = 30 * time.Second
	// MaxWait caps the bounded wait: harnesses give up long before.
	MaxWait = 5 * time.Minute
)

// Config is the service configuration.
type Config struct {
	// TTL is the lifetime of an approval from creation (pending or
	// approved) until it expires and its payload is dropped.
	TTL time.Duration
	// Wait is the bounded wait before "approval required" is returned;
	// 0 disables waiting.
	Wait time.Duration
	// BaseURL is GATEWAY_BASE_URL; the "approval required" answer points
	// the user at BaseURL + "/approvals".
	BaseURL string
}

// ConfigFromEnv reads EnvTTL and EnvWait through getenv (typically
// os.Getenv), applying the defaults. BaseURL is left for the caller.
func ConfigFromEnv(getenv func(string) string) (Config, error) {
	cfg := Config{TTL: DefaultTTL, Wait: DefaultWait}
	if v := strings.TrimSpace(getenv(EnvTTL)); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return Config{}, fmt.Errorf("%s: %w", EnvTTL, err)
		}
		cfg.TTL = d
	}
	if v := strings.TrimSpace(getenv(EnvWait)); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return Config{}, fmt.Errorf("%s: %w", EnvWait, err)
		}
		cfg.Wait = d
	}
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) validate() error {
	switch {
	case c.TTL <= 0:
		return errors.New("approvals: ttl must be positive")
	case c.Wait < 0:
		return errors.New("approvals: wait must not be negative")
	case c.Wait > MaxWait:
		return fmt.Errorf("approvals: wait must be at most %v", MaxWait)
	case c.Wait >= c.TTL:
		return errors.New("approvals: wait must be shorter than ttl")
	}
	return nil
}
