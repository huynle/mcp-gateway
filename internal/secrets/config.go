package secrets

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// EnvEnabled turns the feature on (GATEWAY_SECRETS_ENABLED, default off).
// The feature also stays off without a key provider: New refuses a nil one.
const EnvEnabled = "GATEWAY_SECRETS_ENABLED"

// Limits and defaults (design section 3; constants by decision, correction 7).
const (
	// DefaultTTL is how long a provided secret stays usable when the
	// request names no TTL; MinTTL and MaxTTL bound a requested one.
	DefaultTTL = 15 * time.Minute
	MinTTL     = time.Minute
	MaxTTL     = time.Hour
	// DefaultUses and MaxUses bound how often a secret may be used.
	DefaultUses = 1
	MaxUses     = 10
	// LinkTTL is how long the /s/<id> entry link stays valid.
	LinkTTL = 10 * time.Minute
	// MaxPendingPerOwner is the number of pending requests with a live
	// link one user may have; MaxRequestsPerHour caps requests per user
	// in any rolling hour. Beyond either, Request returns ErrLimited.
	MaxPendingPerOwner = 5
	MaxRequestsPerHour = 20
	// MinValueLen and MaxValueLen bound a value in bytes. Short values
	// are refused because scrubbing them from results is unreliable.
	MinValueLen = 8
	MaxValueLen = 4096
	// MaxLabelLen bounds the label in characters.
	MaxLabelLen = 100
	// Retention is how long ended rows (denied, revoked, expired) are kept
	// for the /secrets history before the expiry job deletes them.
	Retention = 7 * 24 * time.Hour
)

// Config is the feature configuration.
type Config struct {
	// Enabled is EnvEnabled.
	Enabled bool
}

// ConfigFromEnv reads EnvEnabled through getenv (typically os.Getenv).
func ConfigFromEnv(getenv func(string) string) (Config, error) {
	var cfg Config
	if v := strings.TrimSpace(getenv(EnvEnabled)); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return Config{}, fmt.Errorf("%s: %w", EnvEnabled, err)
		}
		cfg.Enabled = b
	}
	return cfg, nil
}
