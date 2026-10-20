package tunnel

import "time"

// Limits bound one tunnel connection. Zero fields take the defaults.
type Limits struct {
	// MaxRequestBytes bounds a request body sent through the tunnel.
	MaxRequestBytes int64
	// MaxResponseBytes bounds a non-streaming (non text/event-stream)
	// response body.
	MaxResponseBytes int64
	// MaxBufferedBytes bounds the response bytes received but not yet read
	// by the caller, per stream (event streams included).
	MaxBufferedBytes int64
	// MaxStreams bounds concurrent requests per tunnel.
	MaxStreams int
	// ResponseHeaderTimeout bounds the wait for the response status and
	// headers of each request.
	ResponseHeaderTimeout time.Duration
	// HeartbeatInterval is how often the gateway pings the client,
	// re-checks the tunnel (revocation) and touches last_seen_at.
	HeartbeatInterval time.Duration
	// MachineSyncInterval is how often a machine connection re-reads the
	// machine (revocation through another replica) and its tunnel set
	// (servers added through another replica). Default 5s, at most
	// HeartbeatInterval.
	MachineSyncInterval time.Duration
}

// Defaults.
const (
	DefaultMaxRequestBytes       = 4 << 20
	DefaultMaxResponseBytes      = 10 << 20
	DefaultMaxBufferedBytes      = 8 << 20
	DefaultMaxStreams            = 32
	DefaultResponseHeaderTimeout = 30 * time.Second
	DefaultHeartbeatInterval     = 30 * time.Second
	DefaultMachineSyncInterval   = 5 * time.Second
)

func (l Limits) withDefaults() Limits {
	if l.MaxRequestBytes <= 0 {
		l.MaxRequestBytes = DefaultMaxRequestBytes
	}
	if l.MaxResponseBytes <= 0 {
		l.MaxResponseBytes = DefaultMaxResponseBytes
	}
	if l.MaxBufferedBytes <= 0 {
		l.MaxBufferedBytes = DefaultMaxBufferedBytes
	}
	if l.MaxStreams <= 0 {
		l.MaxStreams = DefaultMaxStreams
	}
	if l.ResponseHeaderTimeout <= 0 {
		l.ResponseHeaderTimeout = DefaultResponseHeaderTimeout
	}
	if l.HeartbeatInterval <= 0 {
		l.HeartbeatInterval = DefaultHeartbeatInterval
	}
	if l.MachineSyncInterval <= 0 {
		l.MachineSyncInterval = DefaultMachineSyncInterval
	}
	l.MachineSyncInterval = min(l.MachineSyncInterval, l.HeartbeatInterval)
	return l
}
