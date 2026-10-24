package webpush

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateEndpoint(t *testing.T) {
	long := "https://fcm.googleapis.com/fcm/send/" + strings.Repeat("a", 1024)
	tests := []struct {
		name string
		url  string
		ok   bool
	}{
		{"fcm", "https://fcm.googleapis.com/fcm/send/abc:def", true},
		{"mozilla", "https://updates.push.services.mozilla.com/wpush/v2/gAAAA", true},
		{"apple web", "https://web.push.apple.com/QGu4", true},
		{"apple subdomain", "https://api.push.apple.com/3/device/x", true},
		{"windows", "https://wns2-par02p.notify.windows.com/w/?token=BQYAAA", true},
		{"windows nested", "https://a.b.notify.windows.com/w/", true},
		{"uppercase host", "https://FCM.GoogleAPIs.com/fcm/send/abc", true},
		{"explicit 443", "https://fcm.googleapis.com:443/fcm/send/abc", true},

		{"http", "http://fcm.googleapis.com/fcm/send/abc", false},
		{"uppercase scheme ok? no: other scheme", "wss://fcm.googleapis.com/fcm/send/abc", false},
		{"no scheme", "fcm.googleapis.com/fcm/send/abc", false},
		{"userinfo", "https://user@fcm.googleapis.com/fcm/send/abc", false},
		{"userinfo pass", "https://u:p@fcm.googleapis.com/fcm/send/abc", false},
		{"port 8443", "https://fcm.googleapis.com:8443/fcm/send/abc", false},
		{"port 80", "https://fcm.googleapis.com:80/fcm/send/abc", false},
		{"empty port", "https://fcm.googleapis.com:/fcm/send/abc", false},
		{"no path", "https://fcm.googleapis.com", false},
		{"root path", "https://fcm.googleapis.com/", false},
		{"fragment", "https://fcm.googleapis.com/fcm/send/abc#x", false},
		{"too long", long, false},
		{"empty", "", false},
		{"garbage", "::::", false},
		{"opaque", "https:fcm.googleapis.com/x", false},
		{"other host", "https://example.com/push", false},
		{"suffix not on dot", "https://xpush.apple.com/x", false},
		{"bare push.apple.com", "https://push.apple.com/x", false},
		{"bare notify.windows.com", "https://notify.windows.com/x", false},
		{"allowed as prefix", "https://evilpush.apple.com.attacker.net/x", false},
		{"allowed label prefix", "https://web.push.apple.com.attacker.net/x", false},
		{"fcm subdomain", "https://x.fcm.googleapis.com/fcm/send/abc", false},
		{"fcm lookalike", "https://fcm.googleapis.com.evil.net/x", false},
		{"trailing dot", "https://fcm.googleapis.com./fcm/send/abc", false},
		{"trailing dot suffix", "https://api.push.apple.com./x", false},
		{"empty label", "https://a..notify.windows.com/x", false},
		{"leading dot", "https://.push.apple.com/x", false},
		{"underscore label", "https://a_b.notify.windows.com/x", false},
		{"ipv4", "https://142.250.0.1/fcm/send/abc", false},
		{"loopback", "https://127.0.0.1/x", false},
		{"ipv6", "https://[::1]/x", false},
		{"decimal ip", "https://2130706433/x", false},
		{"unicode lookalike", "https://fcm.googleapis.c\u03bfm/fcm/send/abc", false},
		{"unicode subdomain", "https://\u00e9.push.apple.com/x", false},
		{"punycode subdomain", "https://xn--9ca.push.apple.com/x", true},
		{"backslash", "https://fcm.googleapis.com\\@evil.net/x", false},
		{"space", "https://fcm.googleapis.com /x", false},
		{"percent host", "https://fcm%2egoogleapis.com/x", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateEndpoint(tc.url)
			if tc.ok && err != nil {
				t.Fatalf("ValidateEndpoint(%q) = %v, want nil", tc.url, err)
			}
			if !tc.ok {
				if err == nil {
					t.Fatalf("ValidateEndpoint(%q) = nil, want error", tc.url)
				}
				if !errors.Is(err, ErrEndpointNotAllowed) {
					t.Fatalf("err = %v, want ErrEndpointNotAllowed", err)
				}
			}
		})
	}
}

func TestValidateEndpointErrorOmitsPath(t *testing.T) {
	err := ValidateEndpoint("https://example.com/secret-capability-token")
	if err == nil || strings.Contains(err.Error(), "secret-capability-token") {
		t.Fatalf("err = %v", err)
	}
}

func TestDefaultAllowListContents(t *testing.T) {
	want := map[string]bool{
		"fcm.googleapis.com":                true,
		"updates.push.services.mozilla.com": true,
		"web.push.apple.com":                true,
	}
	hosts := DefaultAllowedHosts()
	if len(hosts) != len(want) {
		t.Fatalf("DefaultAllowedHosts() = %v", hosts)
	}
	for _, h := range hosts {
		if !want[h] {
			t.Errorf("unexpected host %q", h)
		}
	}
	suffixes := DefaultAllowedSuffixes()
	if len(suffixes) != 2 || suffixes[0] != "push.apple.com" || suffixes[1] != "notify.windows.com" {
		t.Fatalf("DefaultAllowedSuffixes() = %v", suffixes)
	}
	// The returned slices are copies: mutating them must not widen the list.
	hosts[0] = "example.com"
	suffixes[0] = "com"
	if ValidateEndpoint("https://example.com/x") == nil || ValidateEndpoint("https://a.example.com/x") == nil {
		t.Fatal("mutating the returned slices changed the allow-list")
	}
}
