package netguard

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
)

// AllowList lets an admin open specific destinations that the guard would
// otherwise refuse (an internal MCP server, a private OAuth issuer).
//
// Allowed is asked:
//   - at URL time with the URL host and, for an IP literal, its address
//     (otherwise the zero netip.Addr): a match there also permits plain
//     http for that host;
//   - at dial time once per blocked resolved address, with the host being
//     dialled and that address.
//
// Implementations must be safe for concurrent use and fail closed (return
// false) on any error. The store-backed implementation comes with the
// federation schema; StaticAllowList is the in-memory one.
type AllowList interface {
	Allowed(ctx context.Context, host string, ip netip.Addr) bool
}

// StaticAllowList is an immutable in-memory AllowList of exact host names
// (case-insensitive, trailing dot ignored, no wildcards) and IP prefixes. A
// nil *StaticAllowList allows nothing.
type StaticAllowList struct {
	hosts    map[string]bool
	prefixes []netip.Prefix
}

// NewStaticAllowList parses entries: each is an exact host name, an IP
// address (treated as a single-address prefix) or a CIDR prefix.
func NewStaticAllowList(entries ...string) (*StaticAllowList, error) {
	a := &StaticAllowList{hosts: make(map[string]bool)}
	for _, e := range entries {
		if p, err := netip.ParsePrefix(e); err == nil {
			a.prefixes = append(a.prefixes, p.Masked())
			continue
		}
		if ip, err := netip.ParseAddr(e); err == nil {
			ip = ip.Unmap()
			a.prefixes = append(a.prefixes, netip.PrefixFrom(ip, ip.BitLen()))
			continue
		}
		if strings.Contains(e, "/") {
			return nil, fmt.Errorf("netguard: allow-list entry %q: invalid CIDR prefix", e)
		}
		name := normalizeHost(e)
		if name == "" || !isHostName(name) {
			return nil, fmt.Errorf("netguard: allow-list entry %q: not a host name, IP or CIDR", e)
		}
		a.hosts[name] = true
	}
	return a, nil
}

// Allowed reports whether host is listed exactly or ip (when valid) falls
// inside a listed prefix. IPv4-mapped IPv6 addresses match IPv4 prefixes.
func (a *StaticAllowList) Allowed(_ context.Context, host string, ip netip.Addr) bool {
	if a == nil {
		return false
	}
	if host != "" && a.hosts[normalizeHost(host)] {
		return true
	}
	if !ip.IsValid() || ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	for _, p := range a.prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// normalizeHost lower-cases a host name and drops one trailing dot.
func normalizeHost(h string) string {
	return strings.ToLower(strings.TrimSuffix(h, "."))
}

func isHostName(name string) bool {
	for i := 0; i < len(name); i++ {
		if !isHostByte(name[i]) {
			return false
		}
	}
	return true
}
