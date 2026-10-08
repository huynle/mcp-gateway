package tokens_test

import (
	"crypto/sha256"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/tokens"
)

// The documented secret-scanning pattern; the README quotes it.
var scanRE = regexp.MustCompile(tokens.ScanPattern)

func TestGenerateProducesDocumentedShape(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		g, err := tokens.Generate()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(g.Raw, tokens.Prefix) {
			t.Fatalf("raw %q lacks prefix %q", g.Raw, tokens.Prefix)
		}
		if len(g.PublicID) != tokens.PublicIDLen {
			t.Fatalf("public id %q is %d chars, want %d", g.PublicID, len(g.PublicID), tokens.PublicIDLen)
		}
		if len(g.Secret) != tokens.SecretLen {
			t.Fatalf("secret is %d chars, want %d", len(g.Secret), tokens.SecretLen)
		}
		if want := tokens.Prefix + g.PublicID + "_" + g.Secret; g.Raw != want {
			t.Fatalf("raw = %q, want %q", g.Raw, want)
		}
		if !scanRE.MatchString(g.Raw) || scanRE.FindString(g.Raw) != g.Raw {
			t.Fatalf("raw %q does not match the scan pattern %q", g.Raw, tokens.ScanPattern)
		}
		sum := sha256.Sum256([]byte(g.Secret))
		if string(g.Hash) != string(sum[:]) {
			t.Fatal("hash is not sha256(secret)")
		}
		if seen[g.PublicID] || seen[g.Secret] {
			t.Fatal("generator repeated a value")
		}
		seen[g.PublicID], seen[g.Secret] = true, true
	}
}

func TestParseRoundTripsGeneratedTokens(t *testing.T) {
	g, err := tokens.Generate()
	if err != nil {
		t.Fatal(err)
	}
	publicID, secret, err := tokens.Parse(g.Raw)
	if err != nil {
		t.Fatalf("Parse(%q): %v", g.Raw, err)
	}
	if publicID != g.PublicID || secret != g.Secret {
		t.Errorf("Parse = (%q, %q), want (%q, %q)", publicID, secret, g.PublicID, g.Secret)
	}
	if string(tokens.HashSecret(secret)) != string(g.Hash) {
		t.Error("HashSecret(parsed secret) != generated hash")
	}
}

func TestParseRejectsMalformedTokens(t *testing.T) {
	g, err := tokens.Generate()
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"empty":             "",
		"no prefix":         strings.TrimPrefix(g.Raw, "mgw_"),
		"wrong prefix":      "mgx_" + g.Raw[4:],
		"missing secret":    tokens.Prefix + g.PublicID,
		"missing separator": tokens.Prefix + g.PublicID + g.Secret,
		"short id":          tokens.Prefix + g.PublicID[:7] + "_" + g.Secret,
		"long id":           tokens.Prefix + g.PublicID + "x_" + g.Secret,
		"short secret":      tokens.Prefix + g.PublicID + "_" + g.Secret[:len(g.Secret)-1],
		"long secret":       g.Raw + "x",
		"bad id charset":    tokens.Prefix + "abc-1234_" + g.Secret,
		"bad secret chars":  tokens.Prefix + g.PublicID + "_" + strings.Repeat("-", tokens.SecretLen),
		"surrounding space": " " + g.Raw + " ",
		"jwt":               "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.sig",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, err := tokens.Parse(raw)
			if !errors.Is(err, tokens.ErrMalformed) {
				t.Errorf("Parse(%q) = %v, want ErrMalformed", raw, err)
			}
		})
	}
}

func TestScanPatternMatchesOnlyWholeTokensInText(t *testing.T) {
	g, err := tokens.Generate()
	if err != nil {
		t.Fatal(err)
	}
	text := "Authorization: Bearer " + g.Raw + "\n"
	if got := scanRE.FindString(text); got != g.Raw {
		t.Errorf("scan found %q in text, want %q", got, g.Raw)
	}
	if scanRE.MatchString("mgw_short_token") {
		t.Error("scan pattern matched a value that is not a token")
	}
}
