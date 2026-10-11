package netguard

import (
	"encoding/binary"
	"net/netip"
)

// Reason is a short, fixed classification of why a destination was blocked.
// It is safe to log and to use as a metric label: it never carries a host,
// URL or address.
type Reason string

// Reasons a destination or request is blocked.
const (
	ReasonLoopback    Reason = "loopback"
	ReasonUnspecified Reason = "unspecified"
	ReasonThisNetwork Reason = "this_network" // 0.0.0.0/8
	ReasonPrivate     Reason = "private"      // RFC 1918, ULA, site-local, local-use NAT64
	ReasonMetadata    Reason = "metadata"     // cloud instance metadata endpoints
	ReasonLinkLocal   Reason = "link_local"
	ReasonCGNAT       Reason = "cgnat" // 100.64.0.0/10
	ReasonMulticast   Reason = "multicast"
	ReasonBroadcast   Reason = "broadcast"
	ReasonReserved    Reason = "reserved" // documentation, benchmarking, future use, IPv4-compatible IPv6, ...
	ReasonInvalid     Reason = "invalid_address"
	ReasonZone        Reason = "ipv6_zone"
)

// metadataAddrs are cloud instance-metadata endpoints. They sit inside
// ranges that are blocked anyway; they get their own reason so an attempt
// to reach them stands out in metrics.
var metadataAddrs = []netip.Addr{
	netip.MustParseAddr("169.254.169.254"), // AWS, GCP, Azure, OpenStack, ...
	netip.MustParseAddr("fd00:ec2::254"),   // AWS IMDS over IPv6
}

type blockedPrefix struct {
	p      netip.Prefix
	reason Reason
}

// v4Blocked is checked in order; the first match wins.
var v4Blocked = []blockedPrefix{
	{netip.MustParsePrefix("0.0.0.0/32"), ReasonUnspecified},
	{netip.MustParsePrefix("0.0.0.0/8"), ReasonThisNetwork},
	{netip.MustParsePrefix("127.0.0.0/8"), ReasonLoopback},
	{netip.MustParsePrefix("10.0.0.0/8"), ReasonPrivate},
	{netip.MustParsePrefix("172.16.0.0/12"), ReasonPrivate},
	{netip.MustParsePrefix("192.168.0.0/16"), ReasonPrivate},
	{netip.MustParsePrefix("169.254.0.0/16"), ReasonLinkLocal},
	{netip.MustParsePrefix("100.64.0.0/10"), ReasonCGNAT},
	{netip.MustParsePrefix("224.0.0.0/4"), ReasonMulticast},
	{netip.MustParsePrefix("255.255.255.255/32"), ReasonBroadcast},
	{netip.MustParsePrefix("240.0.0.0/4"), ReasonReserved},
	{netip.MustParsePrefix("192.0.0.0/24"), ReasonReserved},    // IETF protocol assignments
	{netip.MustParsePrefix("192.0.2.0/24"), ReasonReserved},    // TEST-NET-1
	{netip.MustParsePrefix("198.18.0.0/15"), ReasonReserved},   // benchmarking
	{netip.MustParsePrefix("198.51.100.0/24"), ReasonReserved}, // TEST-NET-2
	{netip.MustParsePrefix("203.0.113.0/24"), ReasonReserved},  // TEST-NET-3
	{netip.MustParsePrefix("192.88.99.0/24"), ReasonReserved},  // 6to4 relay anycast (deprecated)
}

var (
	nat64WellKnown = netip.MustParsePrefix("64:ff9b::/96")
	sixToFour      = netip.MustParsePrefix("2002::/16")
	teredo         = netip.MustParsePrefix("2001::/32")
	v4Compatible   = netip.MustParsePrefix("::/96")
)

// v6Blocked is checked in order after the embedded-IPv4 forms.
var v6Blocked = []blockedPrefix{
	{netip.MustParsePrefix("::/128"), ReasonUnspecified},
	{netip.MustParsePrefix("::1/128"), ReasonLoopback},
	{netip.MustParsePrefix("fc00::/7"), ReasonPrivate},
	{netip.MustParsePrefix("fec0::/10"), ReasonPrivate}, // deprecated site-local
	{netip.MustParsePrefix("fe80::/10"), ReasonLinkLocal},
	{netip.MustParsePrefix("ff00::/8"), ReasonMulticast},
	{netip.MustParsePrefix("64:ff9b:1::/48"), ReasonPrivate}, // local-use NAT64
	{netip.MustParsePrefix("100::/64"), ReasonReserved},      // discard-only
	{netip.MustParsePrefix("2001:db8::/32"), ReasonReserved}, // documentation
	{netip.MustParsePrefix("2001:2::/48"), ReasonReserved},   // benchmarking
	{netip.MustParsePrefix("2001:10::/28"), ReasonReserved},  // ORCHID (deprecated)
	{netip.MustParsePrefix("3fff::/20"), ReasonReserved},     // documentation (RFC 9637)
}

// classifyAddr reports whether ip must not be dialled and why. It is the
// single source of truth for "internal" destinations. IPv6 forms that embed
// an IPv4 address (mapped, compatible, NAT64, 6to4, Teredo) are judged by
// the embedded address as well.
func classifyAddr(ip netip.Addr) (Reason, bool) {
	if !ip.IsValid() {
		return ReasonInvalid, true
	}
	if ip.Zone() != "" {
		return ReasonZone, true
	}
	for _, m := range metadataAddrs {
		if ip == m {
			return ReasonMetadata, true
		}
	}
	if ip.Is4In6() {
		return classifyAddr(ip.Unmap())
	}
	if ip.Is4() {
		return classifyV4(ip)
	}
	return classifyV6(ip)
}

func classifyV4(ip netip.Addr) (Reason, bool) {
	for _, b := range v4Blocked {
		if b.p.Contains(ip) {
			return b.reason, true
		}
	}
	return "", false
}

func classifyV6(ip netip.Addr) (Reason, bool) {
	for _, b := range v6Blocked {
		if b.p.Contains(ip) {
			return b.reason, true
		}
	}
	a := ip.As16()
	switch {
	case v4Compatible.Contains(ip):
		// ::a.b.c.d (deprecated IPv4-compatible). Report the embedded
		// address's reason when it is blocked; the form itself is never
		// legitimate, so a public embedded address is still refused.
		if r, blocked := classifyAddr(v4At(a, 12)); blocked {
			return r, true
		}
		return ReasonReserved, true
	case nat64WellKnown.Contains(ip):
		return classifyAddr(v4At(a, 12))
	case sixToFour.Contains(ip):
		return classifyAddr(v4At(a, 2))
	case teredo.Contains(ip):
		if r, blocked := classifyAddr(v4At(a, 4)); blocked { // Teredo server
			return r, true
		}
		var client [4]byte
		binary.BigEndian.PutUint32(client[:], ^binary.BigEndian.Uint32(a[12:16]))
		return classifyAddr(netip.AddrFrom4(client)) // obfuscated Teredo client
	}
	return "", false
}

func v4At(a [16]byte, off int) netip.Addr {
	return netip.AddrFrom4([4]byte{a[off], a[off+1], a[off+2], a[off+3]})
}
