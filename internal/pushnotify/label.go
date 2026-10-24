package pushnotify

import (
	"strings"
	"unicode"
)

// defaultLabel names a device whose label is empty and whose User-Agent
// says nothing recognisable.
const defaultLabel = "Browser"

// uaPlatforms and uaBrowsers are checked in order: the first marker found
// wins. Order matters because User-Agents claim each other (every iPhone
// says "like Mac OS X", Edge and Samsung Internet say "Chrome", Chrome
// says "Safari").
var (
	uaPlatforms = []struct{ marker, name string }{
		{"iPhone", "iPhone"}, {"iPad", "iPad"}, {"Android", "Android"}, {"CrOS", "ChromeOS"},
		{"Windows", "Windows"}, {"Macintosh", "Mac"}, {"Mac OS X", "Mac"}, {"Linux", "Linux"},
	}
	uaBrowsers = []struct{ marker, name string }{
		{"Edg/", "Edge"}, {"EdgA/", "Edge"}, {"EdgiOS/", "Edge"},
		{"SamsungBrowser/", "Samsung Internet"}, {"OPR/", "Opera"},
		{"Firefox/", "Firefox"}, {"FxiOS/", "Firefox"},
		{"CriOS/", "Chrome"}, {"Chrome/", "Chrome"},
		{"Safari/", "Safari"},
	}
)

// DeviceLabel derives a short, generic device name ("Android Chrome",
// "iPhone Safari") from a User-Agent: platform and browser family only,
// never versions or models, so the label identifies the device to its
// owner without fingerprinting it. "Browser" when nothing is recognised.
func DeviceLabel(userAgent string) string {
	var parts []string
	for _, p := range uaPlatforms {
		if strings.Contains(userAgent, p.marker) {
			parts = append(parts, p.name)
			break
		}
	}
	for _, b := range uaBrowsers {
		if strings.Contains(userAgent, b.marker) {
			parts = append(parts, b.name)
			break
		}
	}
	if len(parts) == 0 {
		return defaultLabel
	}
	return strings.Join(parts, " ")
}

// cleanLabel makes a user-supplied label displayable: control characters
// become spaces, runs of whitespace collapse, the ends are trimmed and the
// result is cut to MaxLabelLen characters. Empty becomes "Browser".
func cleanLabel(label string) string {
	label = strings.Join(strings.FieldsFunc(label, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	}), " ")
	if r := []rune(label); len(r) > MaxLabelLen {
		label = strings.TrimSpace(string(r[:MaxLabelLen]))
	}
	if label == "" {
		return defaultLabel
	}
	return label
}
