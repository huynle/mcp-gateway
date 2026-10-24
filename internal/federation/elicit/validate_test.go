package elicit

import (
	"errors"
	"strings"
	"testing"
)

func TestRulesCheck(t *testing.T) {
	example := Rules{ServerURL: "https://mcp.example.com/mcp"}
	ghio := Rules{ServerURL: "https://a.github.io/mcp"}
	couk := Rules{ServerURL: "https://mcp.shop.co.uk/mcp"}
	tunnel := Rules{ServerURL: "tunnel://abc123"}
	tunnelList := Rules{ServerURL: "tunnel://abc123", AllowedOrigins: []string{"https://auth.vendor.com", "https://login.other.org:8443"}}
	listed := Rules{ServerURL: "https://mcp.example.com/mcp", AllowedOrigins: []string{"https://login.partner.net", "not an origin", "https://Bücher.example"}}
	httpServer := Rules{ServerURL: "http://mcp.example.com/mcp"}
	ipServer := Rules{ServerURL: "https://203.0.113.7/mcp"}

	long := "https://auth.example.com/" + strings.Repeat("a", MaxURLBytes-len("https://auth.example.com/"))

	tests := []struct {
		name  string
		rules Rules
		raw   string
		err   error
		reg   string // want RegistrableDomain on success
	}{
		{"same host", example, "https://mcp.example.com/connect?x=1", nil, "example.com"},
		{"subdomain", example, "https://auth.eu.example.com/connect", nil, "example.com"},
		{"registrable domain itself", example, "https://example.com/", nil, "example.com"},
		{"upper case host", example, "https://AUTH.Example.COM/x", nil, "example.com"},
		{"port", example, "https://auth.example.com:8443/x", nil, "example.com"},
		{"fragment kept", example, "https://auth.example.com/x#step2", nil, "example.com"},
		{"sibling registrable domain", example, "https://example.org/", ErrNotAllowed, ""},
		{"lookalike suffix", example, "https://example.com.evil.net/", ErrNotAllowed, ""},
		{"lookalike prefix", example, "https://myexample.com/", ErrNotAllowed, ""},
		{"github.io same", ghio, "https://a.github.io/connect", nil, "a.github.io"},
		{"github.io sibling", ghio, "https://b.github.io/connect", ErrNotAllowed, ""},
		{"github.io suffix itself", ghio, "https://github.io/", ErrNotAllowed, ""},
		{"co.uk same", couk, "https://auth.shop.co.uk/", nil, "shop.co.uk"},
		{"co.uk sibling", couk, "https://other.co.uk/", ErrNotAllowed, ""},
		{"http refused", example, "http://auth.example.com/", ErrNotHTTPS, ""},
		{"javascript", example, "javascript:alert(1)", ErrNotHTTPS, ""},
		{"data", example, "data:text/html,hi", ErrNotHTTPS, ""},
		{"relative", example, "/connect", ErrNotHTTPS, ""},
		{"scheme-relative", example, "//auth.example.com/x", ErrNotHTTPS, ""},
		{"opaque https", example, "https:auth.example.com", ErrInvalid, ""},
		{"empty host", example, "https:///path", ErrInvalid, ""},
		{"userinfo", example, "https://user@auth.example.com/", ErrUserinfo, ""},
		{"userinfo with password", example, "https://u:p@auth.example.com/", ErrUserinfo, ""},
		{"userinfo phishing", example, "https://auth.example.com@evil.net/", ErrUserinfo, ""},
		{"backslash", example, "https://evil.net\\@auth.example.com/", ErrInvalid, ""},
		{"at limit", example, long, nil, "example.com"},
		{"over limit", example, long + "a", ErrTooLong, ""},
		{"space", example, "https://auth.example.com/a b", ErrInvalid, ""},
		{"tab", example, "https://auth.example.com/a\tb", ErrInvalid, ""},
		{"newline", example, "https://auth.example.com/\nx", ErrInvalid, ""},
		{"nul", example, "https://auth.example.com/\x00", ErrInvalid, ""},
		{"del", example, "https://auth.example.com/\x7f", ErrInvalid, ""},
		{"bidi override", example, "https://auth.example.com/\u202egnp.exe", ErrInvalid, ""},
		{"nbsp", example, "https://auth.example.com/\u00a0", ErrInvalid, ""},
		{"invalid utf8", example, "https://auth.example.com/\xff", ErrInvalid, ""},
		{"ipv4", example, "https://203.0.113.7/", ErrIPHost, ""},
		{"ipv6", example, "https://[2001:db8::1]/", ErrIPHost, ""},
		{"ipv4 decimal", example, "https://3405803783/", ErrIPHost, ""},
		{"ipv4 hex", example, "https://0xcb.0.113.7/", ErrIPHost, ""},
		{"ipv4 short", example, "https://127.1/", ErrIPHost, ""},
		{"ipv4 octal", example, "https://0313.0.0161.7/", ErrIPHost, ""},
		{"ends in number", example, "https://auth.example.123/", ErrIPHost, ""},
		{"localhost", example, "https://localhost/", ErrInvalid, ""},
		{"sub localhost", example, "https://auth.localhost/", ErrInvalid, ""},
		{"single label", example, "https://intranet/", ErrInvalid, ""},
		{"trailing dot", example, "https://auth.example.com./", ErrInvalid, ""},
		{"bad port", example, "https://auth.example.com:99999/", ErrInvalid, ""},
		{"empty port", example, "https://auth.example.com:/", ErrInvalid, ""},
		{"tunnel no list", tunnel, "https://auth.vendor.com/", ErrNotAllowed, ""},
		{"tunnel listed", tunnelList, "https://auth.vendor.com/connect?a=b", nil, "vendor.com"},
		{"tunnel listed subdomain is not listed", tunnelList, "https://x.auth.vendor.com/", ErrNotAllowed, ""},
		{"tunnel listed port exact", tunnelList, "https://login.other.org:8443/", nil, "other.org"},
		{"tunnel listed port mismatch", tunnelList, "https://login.other.org/", ErrNotAllowed, ""},
		{"tunnel listed port missing on list", tunnelList, "https://auth.vendor.com:8443/", ErrNotAllowed, ""},
		{"tunnel listed default port", tunnelList, "https://auth.vendor.com:443/", nil, "vendor.com"},
		{"allow list on https server", listed, "https://login.partner.net/x", nil, "partner.net"},
		{"allow list idn", listed, "https://xn--bcher-kva.example/", nil, "xn--bcher-kva.example"},
		{"allow list not prefix", listed, "https://partner.net/", ErrNotAllowed, ""},
		{"http server has no domain", httpServer, "https://mcp.example.com/", ErrNotAllowed, ""},
		{"ip server has no domain", ipServer, "https://mcp.example.com/", ErrNotAllowed, ""},
		{"empty server", Rules{}, "https://mcp.example.com/", ErrNotAllowed, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, err := tc.rules.Check(tc.raw)
			if tc.err != nil {
				if !errors.Is(err, tc.err) {
					t.Fatalf("Check(%q) = %+v, %v; want %v", tc.raw, c, err, tc.err)
				}
				if c.URL != nil {
					t.Errorf("Checked.URL set on error")
				}
				return
			}
			if err != nil {
				t.Fatalf("Check(%q) = %v", tc.raw, err)
			}
			if c.RegistrableDomain != tc.reg {
				t.Errorf("RegistrableDomain = %q, want %q", c.RegistrableDomain, tc.reg)
			}
			if c.URL == nil || c.Display != c.URL.String() {
				t.Errorf("Display %q does not match URL %v", c.Display, c.URL)
			}
		})
	}
}

func TestRulesCheckFields(t *testing.T) {
	r := Rules{ServerURL: "https://mcp.example.com/mcp"}
	c, err := r.Check("https://Auth.Example.com:443/connect?state=abc#frag")
	if err != nil {
		t.Fatal(err)
	}
	if c.Host != "auth.example.com" || c.Origin != "https://auth.example.com" || c.RegistrableDomain != "example.com" || c.Punycode {
		t.Errorf("fields = %+v", c)
	}
	if c.Display != "https://auth.example.com:443/connect?state=abc#frag" {
		t.Errorf("Display = %q", c.Display)
	}
	c, err = r.Check("https://auth.example.com:8443/x")
	if err != nil || c.Origin != "https://auth.example.com:8443" {
		t.Errorf("origin with port = %q, %v", c.Origin, err)
	}

	// Punycode, given as A-label or U-label, is flagged and shown as
	// A-label (the redirect goes to exactly the checked host).
	for _, raw := range []string{"https://xn--exmple-cua.example.com/", "https://exämple.example.com/"} {
		c, err := r.Check(raw)
		if err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		if !c.Punycode || c.Host != "xn--exmple-cua.example.com" || c.Display != "https://xn--exmple-cua.example.com/" {
			t.Errorf("%s: %+v", raw, c)
		}
	}
	// An IDN registrable domain differs from its ASCII lookalike.
	if _, err := r.Check("https://exämple.com/"); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("IDN lookalike = %v, want ErrNotAllowed", err)
	}
	// A server given as an IDN matches its punycode form.
	idn := Rules{ServerURL: "https://mcp.bücher.example/mcp"}
	if c, err := idn.Check("https://auth.xn--bcher-kva.example/"); err != nil || c.RegistrableDomain != "xn--bcher-kva.example" || !c.Punycode {
		t.Errorf("IDN server = %+v, %v", c, err)
	}
}

func TestErrorsSafe(t *testing.T) {
	r := Rules{ServerURL: "https://mcp.example.com/"}
	secret := "token-should-not-appear"
	for _, raw := range []string{
		"http://x.example.com/" + secret, "https://u@x.example.com/" + secret, "https://evil.net/" + secret,
		"https://203.0.113.1/" + secret, "https://x.example.com/ " + secret,
	} {
		_, err := r.Check(raw)
		if err == nil || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "evil") {
			t.Errorf("Check(%q) error %v leaks input", raw, err)
		}
	}
}

func TestValidateOrigin(t *testing.T) {
	tests := []struct {
		in, want string
		err      error
	}{
		{"https://auth.vendor.com", "https://auth.vendor.com", nil},
		{"https://auth.vendor.com/", "https://auth.vendor.com", nil},
		{"  https://Auth.Vendor.COM  ", "https://auth.vendor.com", nil},
		{"https://auth.vendor.com:8443", "https://auth.vendor.com:8443", nil},
		{"https://auth.vendor.com:443", "https://auth.vendor.com", nil},
		{"https://bücher.example", "https://xn--bcher-kva.example", nil},
		{"http://auth.vendor.com", "", ErrNotHTTPS},
		{"auth.vendor.com", "", ErrNotHTTPS},
		{"https://auth.vendor.com/path", "", ErrInvalid},
		{"https://auth.vendor.com?x", "", ErrInvalid},
		{"https://auth.vendor.com/?", "", ErrInvalid},
		{"https://auth.vendor.com#f", "", ErrInvalid},
		{"https://u@auth.vendor.com", "", ErrUserinfo},
		{"https://10.0.0.1", "", ErrIPHost},
		{"https://[::1]", "", ErrIPHost},
		{"https://localhost", "", ErrInvalid},
		{"https://intranet", "", ErrInvalid},
		{"https://auth.vendor.com:0", "", ErrInvalid},
		{"", "", ErrNotHTTPS},
		{"https://" + strings.Repeat("a", MaxURLBytes), "", ErrTooLong},
	}
	for _, tc := range tests {
		got, err := ValidateOrigin(tc.in)
		if tc.err != nil {
			if !errors.Is(err, tc.err) || got != "" {
				t.Errorf("ValidateOrigin(%q) = %q, %v; want %v", tc.in, got, err, tc.err)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("ValidateOrigin(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
}
