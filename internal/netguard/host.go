package netguard

import (
	"net/netip"
	"strconv"
	"strings"
)

// Literal-stage reasons.
const (
	// ReasonAmbiguousIP is a host made of numbers that is not a canonical
	// dotted-quad or IPv6 literal (2130706433, 0x7f.1, 017700000001,
	// 127.1, ...). Go resolves such hosts as names while browsers and
	// libc decode them as addresses; the disagreement is the attack, so
	// they are refused outright.
	ReasonAmbiguousIP Reason = "ambiguous_ip_literal"
	// ReasonInvalidHost is an empty host or one with characters outside
	// [A-Za-z0-9._-] (IDNs must be given in punycode).
	ReasonInvalidHost Reason = "invalid_host"
)

// parseHost inspects a URL or dial host (no brackets, no port) before any
// DNS lookup. It returns the address when the host is a canonical IP
// literal and a non-empty reason when the host must be refused. A name with
// an empty reason still has to pass the dial-time check of its resolved
// addresses.
func parseHost(host string) (netip.Addr, Reason) {
	if host == "" {
		return netip.Addr{}, ReasonInvalidHost
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		r, _ := classifyAddr(ip)
		return ip, r
	}
	for i := 0; i < len(host); i++ {
		if !isHostByte(host[i]) {
			return netip.Addr{}, ReasonInvalidHost
		}
	}
	name := strings.ToLower(strings.TrimSuffix(host, "."))
	if name == "" {
		return netip.Addr{}, ReasonInvalidHost
	}
	if endsInNumber(name) {
		// Decode as a browser would (WHATWG IPv4 parser) only to report a
		// precise reason; the host is refused either way.
		if ip, ok := parseLegacyIPv4(name); ok {
			if r, blocked := classifyAddr(ip); blocked {
				return netip.Addr{}, r
			}
		}
		return netip.Addr{}, ReasonAmbiguousIP
	}
	if name == "localhost" || strings.HasSuffix(name, ".localhost") {
		return netip.Addr{}, ReasonLoopback
	}
	return netip.Addr{}, ""
}

func isHostByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '.' || c == '-' || c == '_'
}

// endsInNumber is the WHATWG URL "ends in a number" check: a host whose
// last label is all digits or a valid IPv4 number (0x...) is parsed as
// IPv4 by browsers.
func endsInNumber(name string) bool {
	parts := strings.Split(name, ".")
	last := parts[len(parts)-1]
	if last == "" {
		return false
	}
	if strings.Trim(last, "0123456789") == "" {
		return true
	}
	_, ok := parseIPv4Number(last)
	return ok
}

// parseIPv4Number parses one WHATWG IPv4 part: 0x/0X prefix is hex, a
// leading 0 is octal, anything else decimal.
func parseIPv4Number(s string) (uint64, bool) {
	if s == "" {
		return 0, false
	}
	base := 10
	switch {
	case len(s) >= 2 && (s[:2] == "0x" || s[:2] == "0X"):
		base, s = 16, s[2:]
	case len(s) >= 2 && s[0] == '0':
		base, s = 8, s[1:]
	}
	if s == "" {
		return 0, true
	}
	n, err := strconv.ParseUint(s, base, 64)
	return n, err == nil
}

// parseLegacyIPv4 is the WHATWG IPv4 parser (inet_aton semantics): 1 to 4
// parts, each decimal/octal/hex; the last part fills the remaining bytes.
func parseLegacyIPv4(name string) (netip.Addr, bool) {
	parts := strings.Split(name, ".")
	if len(parts) > 4 {
		return netip.Addr{}, false
	}
	nums := make([]uint64, len(parts))
	for i, p := range parts {
		n, ok := parseIPv4Number(p)
		if !ok {
			return netip.Addr{}, false
		}
		nums[i] = n
	}
	for _, n := range nums[:len(nums)-1] {
		if n > 255 {
			return netip.Addr{}, false
		}
	}
	last := nums[len(nums)-1]
	if last >= 1<<(8*(5-len(nums))) {
		return netip.Addr{}, false
	}
	v := last
	for i, n := range nums[:len(nums)-1] {
		v += n << (8 * (3 - i))
	}
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}), true
}
