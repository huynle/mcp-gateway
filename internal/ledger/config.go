package ledger

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Environment variables this package reads. They live here rather than in
// internal/config so the ledger module owns its settings, the way the
// approvals and crypto packages own theirs (decision hc1bh0i5).
const (
	// EnvIdempotencyWindow bounds how long an unconfirmed write's
	// user+account+tool+digest key refers to the same operation
	// (GATEWAY_LEDGER_IDEMPOTENCY_WINDOW, default 24h; decision dovthftx).
	EnvIdempotencyWindow = "GATEWAY_LEDGER_IDEMPOTENCY_WINDOW"
	// EnvStaleAfter is how long an in_progress operation may stay so
	// before the sweep treats it as unknown (GATEWAY_LEDGER_STALE_AFTER,
	// default 2m): the replica that owned it is presumed dead.
	EnvStaleAfter = "GATEWAY_LEDGER_STALE_AFTER"
	// EnvMaxReconcileAttempts caps the reconciler's checks per operation
	// before it gives up as unresolved
	// (GATEWAY_LEDGER_MAX_RECONCILE_ATTEMPTS, default 6).
	EnvMaxReconcileAttempts = "GATEWAY_LEDGER_MAX_RECONCILE_ATTEMPTS"
	// EnvMaxReconcileAge caps how old an unknown operation may be before
	// it is unresolved regardless of attempts
	// (GATEWAY_LEDGER_MAX_RECONCILE_AGE, default 24h).
	EnvMaxReconcileAge = "GATEWAY_LEDGER_MAX_RECONCILE_AGE"
)

// Defaults from decision dovthftx.
const (
	DefaultIdempotencyWindow    = 24 * time.Hour
	DefaultStaleAfter           = 2 * time.Minute
	DefaultMaxReconcileAttempts = 6
	DefaultMaxReconcileAge      = 24 * time.Hour
)

// Config is the service configuration.
type Config struct {
	IdempotencyWindow    time.Duration
	StaleAfter           time.Duration
	MaxReconcileAttempts int
	MaxReconcileAge      time.Duration
	// BaseURL is GATEWAY_BASE_URL; the "verify in the app" notification
	// points the user at BaseURL + "/operations".
	BaseURL string
}

// DefaultConfig returns the defaults.
func DefaultConfig() Config {
	return Config{
		IdempotencyWindow:    DefaultIdempotencyWindow,
		StaleAfter:           DefaultStaleAfter,
		MaxReconcileAttempts: DefaultMaxReconcileAttempts,
		MaxReconcileAge:      DefaultMaxReconcileAge,
	}
}

// ConfigFromEnv reads the four variables through getenv (typically
// os.Getenv), applying the defaults. BaseURL is left for the caller.
func ConfigFromEnv(getenv func(string) string) (Config, error) {
	cfg := DefaultConfig()
	durations := []struct {
		name string
		dst  *time.Duration
	}{
		{EnvIdempotencyWindow, &cfg.IdempotencyWindow},
		{EnvStaleAfter, &cfg.StaleAfter},
		{EnvMaxReconcileAge, &cfg.MaxReconcileAge},
	}
	for _, d := range durations {
		if v := strings.TrimSpace(getenv(d.name)); v != "" {
			parsed, err := time.ParseDuration(v)
			if err != nil {
				return Config{}, fmt.Errorf("%s: %w", d.name, err)
			}
			*d.dst = parsed
		}
	}
	if v := strings.TrimSpace(getenv(EnvMaxReconcileAttempts)); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return Config{}, fmt.Errorf("%s: %w", EnvMaxReconcileAttempts, err)
		}
		cfg.MaxReconcileAttempts = n
	}
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) validate() error {
	switch {
	case c.IdempotencyWindow <= 0:
		return errors.New("ledger: idempotency window must be positive")
	case c.StaleAfter <= 0:
		return errors.New("ledger: stale-after must be positive")
	case c.MaxReconcileAttempts <= 0:
		return errors.New("ledger: max reconcile attempts must be positive")
	case c.MaxReconcileAge <= c.StaleAfter:
		return errors.New("ledger: max reconcile age must be longer than stale-after")
	}
	return nil
}
