package netguard

import (
	"context"
	"net/netip"
	"testing"
)

func TestStaticAllowList(t *testing.T) {
	al, err := NewStaticAllowList("Internal.Example.com.", "10.1.0.0/16", "192.168.5.7", "fd00:abcd::/32")
	if err != nil {
		t.Fatalf("NewStaticAllowList: %v", err)
	}
	ctx := context.Background()
	tests := []struct {
		name string
		host string
		ip   string // "" means no address (URL-time check of a name)
		want bool
	}{
		{"exact host", "internal.example.com", "", true},
		{"host case and trailing dot", "INTERNAL.example.COM.", "10.9.9.9", true},
		{"subdomain is not exact", "a.internal.example.com", "", false},
		{"other host", "example.com", "", false},
		{"cidr match", "svc.example.net", "10.1.200.3", true},
		{"cidr miss", "svc.example.net", "10.2.0.1", false},
		{"single ip", "192.168.5.7", "192.168.5.7", true},
		{"single ip neighbour", "192.168.5.8", "192.168.5.8", false},
		{"mapped form matches v4 cidr", "x.example", "::ffff:10.1.2.3", true},
		{"v6 cidr", "x.example", "fd00:abcd::1", true},
		{"no ip, name not listed", "svc.example.net", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ip netip.Addr
			if tt.ip != "" {
				ip = netip.MustParseAddr(tt.ip)
			}
			if got := al.Allowed(ctx, tt.host, ip); got != tt.want {
				t.Fatalf("Allowed(%q, %q) = %v, want %v", tt.host, tt.ip, got, tt.want)
			}
		})
	}
}

func TestStaticAllowListRejectsBadEntries(t *testing.T) {
	for _, e := range []string{"", "10.0.0.0/33", "not a host", "http://x.example", "*.example.com"} {
		if _, err := NewStaticAllowList(e); err == nil {
			t.Errorf("NewStaticAllowList(%q): want error", e)
		}
	}
}

func TestNilStaticAllowListAllowsNothing(t *testing.T) {
	var al *StaticAllowList
	if al.Allowed(context.Background(), "x", netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("nil allow list allowed something")
	}
}

// The interface must be satisfiable by the in-memory implementation.
var _ AllowList = (*StaticAllowList)(nil)
