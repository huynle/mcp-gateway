package netguard

import (
	"net/netip"
	"testing"
)

func TestClassifyAddr(t *testing.T) {
	tests := []struct {
		addr string
		want Reason // "" means allowed
	}{
		// Public addresses pass.
		{"8.8.8.8", ""},
		{"93.184.216.34", ""},
		{"1.1.1.1", ""},
		{"2606:4700:4700::1111", ""},
		{"::ffff:8.8.8.8", ""},
		{"64:ff9b::808:808", ""},         // NAT64 of a public v4
		{"2002:808:808::1", ""},          // 6to4 of a public v4
		{"100.63.255.255", ""},           // just below CGNAT
		{"100.128.0.0", ""},              // just above CGNAT
		{"172.15.255.255", ""},           // just below 172.16/12
		{"172.32.0.0", ""},               // just above 172.16/12
		{"2001:4860:4860::8888", ""},     // Google DNS (not Teredo)
		{"169.253.255.255", ""},          // just below link-local
		{"223.255.255.255", ""},          // just below multicast
		{"11.0.0.0", ""},                 // just above 10/8
		{"192.167.255.255", ""},          // just below 192.168/16
		{"2a00:1450:4001:80b::200e", ""}, // public v6

		// IPv4 blocked ranges.
		{"127.0.0.1", ReasonLoopback},
		{"127.255.255.254", ReasonLoopback},
		{"0.0.0.0", ReasonUnspecified},
		{"0.1.2.3", ReasonThisNetwork},
		{"10.0.0.1", ReasonPrivate},
		{"172.16.0.1", ReasonPrivate},
		{"172.31.255.255", ReasonPrivate},
		{"192.168.1.1", ReasonPrivate},
		{"169.254.169.254", ReasonMetadata},
		{"169.254.1.1", ReasonLinkLocal},
		{"100.64.0.1", ReasonCGNAT},
		{"100.127.255.255", ReasonCGNAT},
		{"224.0.0.1", ReasonMulticast},
		{"239.255.255.250", ReasonMulticast},
		{"255.255.255.255", ReasonBroadcast},
		{"240.0.0.1", ReasonReserved},
		{"192.0.0.1", ReasonReserved},
		{"192.0.2.1", ReasonReserved},
		{"198.18.0.1", ReasonReserved},
		{"198.51.100.1", ReasonReserved},
		{"203.0.113.1", ReasonReserved},

		// IPv6 blocked ranges.
		{"::1", ReasonLoopback},
		{"::", ReasonUnspecified},
		{"fc00::1", ReasonPrivate},
		{"fd12:3456::1", ReasonPrivate},
		{"fd00:ec2::254", ReasonMetadata},
		{"fe80::1", ReasonLinkLocal},
		{"febf::1", ReasonLinkLocal},
		{"fec0::1", ReasonPrivate}, // deprecated site-local
		{"ff02::1", ReasonMulticast},
		{"2001:db8::1", ReasonReserved},
		{"100::1", ReasonReserved},
		{"64:ff9b:1::1", ReasonPrivate}, // local-use NAT64

		// IPv4-mapped / compatible forms of blocked v4.
		{"::ffff:127.0.0.1", ReasonLoopback},
		{"::ffff:10.0.0.1", ReasonPrivate},
		{"::ffff:169.254.169.254", ReasonMetadata},
		{"::ffff:0.0.0.0", ReasonUnspecified},
		{"::127.0.0.1", ReasonLoopback}, // IPv4-compatible (deprecated)
		{"::10.0.0.1", ReasonPrivate},
		{"::8.8.8.8", ReasonReserved}, // compat form is never legitimate

		// NAT64 embedding a blocked v4.
		{"64:ff9b::7f00:1", ReasonLoopback},
		{"64:ff9b::a9fe:a9fe", ReasonMetadata},
		{"64:ff9b::a00:1", ReasonPrivate},

		// 6to4 embedding a blocked v4.
		{"2002:7f00:1::", ReasonLoopback},
		{"2002:a9fe:a9fe::1", ReasonMetadata},
		{"2002:c0a8:101::1", ReasonPrivate},

		// Teredo: server in bits 32-63, client = ^bits 96-127.
		{"2001:0:7f00:1::", ReasonLoopback},           // server 127.0.0.1
		{"2001:0:808:808::80ff:fffe", ReasonLoopback}, // client ^7f000001 = 80fffffe
		{"2001:0:808:808::f5ff:fffe", ReasonPrivate},  // client 10.0.0.1
		{"2001:0:808:808::f7f7:f7f7", ""},             // client 8.8.8.8, server 8.8.8.8
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			ip := netip.MustParseAddr(tt.addr)
			got, blocked := classifyAddr(ip)
			if blocked != (tt.want != "") || got != tt.want {
				t.Fatalf("classifyAddr(%s) = (%q, %v), want (%q, %v)", tt.addr, got, blocked, tt.want, tt.want != "")
			}
		})
	}
}

func TestClassifyAddrRejectsZonesAndInvalid(t *testing.T) {
	if r, b := classifyAddr(netip.Addr{}); !b || r != ReasonInvalid {
		t.Fatalf("invalid addr: got (%q, %v)", r, b)
	}
	if r, b := classifyAddr(netip.MustParseAddr("2606:4700::1%eth0")); !b || r != ReasonZone {
		t.Fatalf("zoned addr: got (%q, %v)", r, b)
	}
}
