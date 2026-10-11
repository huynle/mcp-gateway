package netguard

import (
	"net/netip"
	"testing"
)

func TestParseHost(t *testing.T) {
	tests := []struct {
		host   string
		wantIP string // "" when the host is a name (or refused before parsing)
		reason Reason // "" when not blocked at the literal stage
	}{
		// Names pass the literal stage (they are checked at dial time).
		{"example.com", "", ""},
		{"EXAMPLE.com.", "", ""},
		{"mcp.example-1.co_uk", "", ""},
		{"deadbeef", "", ""},      // hex-looking label is a name for Go and browsers
		{"1.2.3.example", "", ""}, // last label not numeric
		{"0x7f.example.com", "", ""},

		// Canonical public literals are IPs and allowed here.
		{"8.8.8.8", "8.8.8.8", ""},
		{"2606:4700:4700::1111", "2606:4700:4700::1111", ""},

		// Canonical internal literals.
		{"127.0.0.1", "127.0.0.1", ReasonLoopback},
		{"::1", "::1", ReasonLoopback},
		{"::ffff:127.0.0.1", "::ffff:127.0.0.1", ReasonLoopback},
		{"169.254.169.254", "169.254.169.254", ReasonMetadata},
		{"fe80::1%en0", "", ReasonZone},

		// localhost names never reach the resolver.
		{"localhost", "", ReasonLoopback},
		{"LOCALHOST.", "", ReasonLoopback},
		{"api.localhost", "", ReasonLoopback},

		// Non-canonical numeric forms: decoded like a browser would and
		// refused whatever they decode to (Go would treat them as names).
		{"2130706433", "", ReasonLoopback},          // decimal 127.0.0.1
		{"0x7f.1", "", ReasonLoopback},              // hex + short form
		{"0x7f000001", "", ReasonLoopback},          // hex
		{"017700000001", "", ReasonLoopback},        // octal
		{"0177.0.0.1", "", ReasonLoopback},          // octal octet
		{"127.1", "", ReasonLoopback},               // short form
		{"127.0.1", "", ReasonLoopback},             // short form
		{"127.0.0.1.", "", ReasonLoopback},          // trailing dot
		{"0", "", ReasonUnspecified},                // 0.0.0.0
		{"0x0", "", ReasonUnspecified},              //
		{"2852039166", "", ReasonMetadata},          // decimal 169.254.169.254
		{"0xa9.0xfe.0xa9.0xfe", "", ReasonMetadata}, //
		{"0251.0376.0251.0376", "", ReasonMetadata}, //
		{"167772161", "", ReasonPrivate},            // 10.0.0.1
		{"134744072", "", ReasonAmbiguousIP},        // decimal 8.8.8.8: public but ambiguous
		{"0x08.0x08.0x08.0x08", "", ReasonAmbiguousIP},
		{"010.8.8.8", "", ReasonAmbiguousIP},    // leading zero (octal 8.8.8.8)
		{"1.2.3.4.5", "", ReasonAmbiguousIP},    // too many parts
		{"1.2.3.256", "", ReasonAmbiguousIP},    // out of range
		{"256.1.1.1", "", ReasonAmbiguousIP},    //
		{"1..1", "", ReasonAmbiguousIP},         // empty part
		{"08.1.1.1", "", ReasonAmbiguousIP},     // invalid octal
		{"0xg.1.1.1", "", ReasonAmbiguousIP},    // ends in a number, earlier label not a number
		{"4294967296", "", ReasonAmbiguousIP},   // > 32 bits
		{"example.0x10", "", ReasonAmbiguousIP}, // ends in a number

		// Malformed hosts.
		{"", "", ReasonInvalidHost},
		{"exa mple.com", "", ReasonInvalidHost},
		{"exa%2fmple.com", "", ReasonInvalidHost},
		{"bücher.example", "", ReasonInvalidHost}, // IDN must be punycode
	}
	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			ip, reason := parseHost(tt.host)
			if reason != tt.reason {
				t.Fatalf("parseHost(%q) reason = %q, want %q", tt.host, reason, tt.reason)
			}
			if tt.wantIP == "" {
				if ip.IsValid() && reason == "" {
					t.Fatalf("parseHost(%q) ip = %s, want a name", tt.host, ip)
				}
				return
			}
			if ip != netip.MustParseAddr(tt.wantIP) {
				t.Fatalf("parseHost(%q) ip = %s, want %s", tt.host, ip, tt.wantIP)
			}
		})
	}
}
