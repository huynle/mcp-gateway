package snapshot

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestDisplayStripsControlAndFormatChars(t *testing.T) {
	cases := map[string]struct{ in, want string }{
		"plain":              {"search_docs", "search_docs"},
		"ansi escape":        {"\x1b[31mred\x1b[0m", "[31mred[0m"},
		"newlines and tabs":  {"line1\nline2\tx\r\n", "line1 line2 x"},
		"nul and del":        {"a\x00b\x7fc", "abc"},
		"c1 control":         {"a\u0085b\u009bc", "a bc"},
		"bidi override":      {"safe\u202Etxt.exe", "safetxt.exe"},
		"zero width":         {"ad\u200bmin\ufeff", "admin"},
		"invalid utf8":       {"ok\xffok", "ok\uFFFDok"},
		"spaces collapsed":   {"  a   b  ", "a b"},
		"unicode kept":       {"Café 東京 ✓", "Café 東京 ✓"},
		"html kept verbatim": {"<script>x</script>", "<script>x</script>"},
	}
	for name, c := range cases {
		if got := Display(c.in, 100); got != c.want {
			t.Errorf("%s: Display(%q) = %q, want %q", name, c.in, got, c.want)
		}
	}
}

func TestDisplayCapsLength(t *testing.T) {
	got := Display(strings.Repeat("é", 50), 10)
	if utf8.RuneCountInString(got) != 10 || !strings.HasSuffix(got, "…") {
		t.Errorf("Display capped = %q (%d runes)", got, utf8.RuneCountInString(got))
	}
	if got := Display("short", 10); got != "short" {
		t.Errorf("short = %q", got)
	}
	if got := Display("abc", 0); got != "" {
		t.Errorf("max 0 = %q", got)
	}
}

func TestDisplayMultilineKeepsNewlines(t *testing.T) {
	got := DisplayMultiline("para 1\r\n\n\n\n\npara\t2\x1b[0m\u202E\n", 100)
	want := "para 1\n\npara 2[0m"
	if got != want {
		t.Errorf("DisplayMultiline = %q, want %q", got, want)
	}
}

func TestDisplayHelpersForFields(t *testing.T) {
	long := strings.Repeat("x", MaxDisplayDescription+50)
	if n := utf8.RuneCountInString(DisplayDescription(long)); n != MaxDisplayDescription {
		t.Errorf("DisplayDescription runes = %d", n)
	}
	if n := utf8.RuneCountInString(DisplayName(long)); n != MaxDisplayName {
		t.Errorf("DisplayName runes = %d", n)
	}
}
