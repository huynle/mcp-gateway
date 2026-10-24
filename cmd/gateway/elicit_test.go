package main

import "testing"

// elicitDomain shows the interstitial the relay's view of the URL: the
// ASCII host, its registrable domain and the punycode warning.
func TestElicitDomain(t *testing.T) {
	for _, tc := range []struct {
		url, host, reg string
		puny           bool
	}{
		{"https://auth.mcp.example.com/connect?x=1", "auth.mcp.example.com", "example.com", false},
		{"https://user.github.io/x", "user.github.io", "user.github.io", false},
		{"https://xn--pple-43d.com/login", "xn--pple-43d.com", "xn--pple-43d.com", true},
		{"https://Example.COM:8443/", "example.com", "example.com", false},
		{"https://127.0.0.1/", "127.0.0.1", "127.0.0.1", true},
	} {
		host, reg, puny := elicitDomain(tc.url)
		if host != tc.host || reg != tc.reg || puny != tc.puny {
			t.Errorf("elicitDomain(%s) = %s %s %v, want %s %s %v", tc.url, host, reg, puny, tc.host, tc.reg, tc.puny)
		}
	}
}
