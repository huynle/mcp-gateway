package snapshot

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Display caps for upstream text shown in the portal (runes).
const (
	MaxDisplayName        = 128
	MaxDisplayTitle       = 256
	MaxDisplayDescription = 4096
)

// Display returns upstream text (a name, title, URI) as one safe line of at
// most limit runes: invalid UTF-8 becomes U+FFFD, whitespace controls become
// spaces, other control characters (C0, C1, DEL) and format characters
// (bidi overrides, zero-width, BOM) are dropped, runs of whitespace collapse
// to one space, and an overlong result ends in "…". It does not
// HTML-escape: the template layer still must.
func Display(s string, limit int) string {
	var b strings.Builder
	space := false
	for _, r := range strings.ToValidUTF8(s, "\uFFFD") {
		switch {
		case unicode.IsSpace(r):
			space = true
			continue
		case dropRune(r):
			continue
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		b.WriteRune(r)
	}
	return capRunes(b.String(), limit)
}

// DisplayMultiline is Display for descriptions: line breaks are kept (at
// most one blank line in a row), every line is cleaned like Display.
func DisplayMultiline(s string, limit int) string {
	s = strings.ToValidUTF8(s, "\uFFFD")
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	lines := strings.Split(s, "\n")
	var out []string
	blank := 0
	for _, l := range lines {
		l = Display(l, utf8.RuneCountInString(l)+1)
		if l == "" {
			blank++
			if blank > 1 || len(out) == 0 {
				continue
			}
		} else {
			blank = 0
		}
		out = append(out, l)
	}
	for len(out) > 0 && out[len(out)-1] == "" {
		out = out[:len(out)-1]
	}
	return capRunes(strings.Join(out, "\n"), limit)
}

// DisplayName is Display capped at MaxDisplayName.
func DisplayName(s string) string { return Display(s, MaxDisplayName) }

// DisplayTitle is Display capped at MaxDisplayTitle.
func DisplayTitle(s string) string { return Display(s, MaxDisplayTitle) }

// DisplayDescription is DisplayMultiline capped at MaxDisplayDescription.
func DisplayDescription(s string) string { return DisplayMultiline(s, MaxDisplayDescription) }

func dropRune(r rune) bool {
	return unicode.IsControl(r) || unicode.Is(unicode.Cf, r)
}

func capRunes(s string, limit int) string {
	if limit <= 0 {
		return ""
	}
	if utf8.RuneCountInString(s) <= limit {
		return s
	}
	rs := []rune(s)
	return strings.TrimRightFunc(string(rs[:limit-1]), unicode.IsSpace) + "…"
}
