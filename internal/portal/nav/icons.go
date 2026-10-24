package nav

import (
	"fmt"
	"html/template"
)

// icons are the shell's inline SVG icons: the inside of a 24×24 viewBox,
// drawn with strokes in currentColor (portal.css sizes and strokes .icon).
// They are drawn for this project; none is copied from an icon set.
var icons = map[string]string{
	"brand":       `<rect class="brand-tile" x="1" y="1" width="22" height="22" rx="6"/><path class="brand-gate" d="M7 18v-7a5 5 0 0 1 10 0v7M12 12.5V18"/>`,
	"account":     `<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4.4 3.6-7 8-7s8 2.6 8 7"/>`,
	"tokens":      `<circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M17 6l3 3M14 9l2 2"/>`,
	"harnesses":   `<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M7 9l3 3-3 3M13 15h4"/>`,
	"machines":    `<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>`,
	"connections": `<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1"/><path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/>`,
	"servers":     `<rect x="3" y="4" width="18" height="7" rx="1.5"/><rect x="3" y="13" width="18" height="7" rx="1.5"/><path d="M7 7.5h.01M7 16.5h.01"/>`,
	"secrets":     `<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4M12 15v2"/>`,
	"approvals":   `<circle cx="12" cy="12" r="9"/><path d="M8 12.5l2.5 2.5L16 9.5"/>`,
	"operations":  `<path d="M9 6h11M9 12h11M9 18h11M4 6h.01M4 12h.01M4 18h.01"/>`,
	"activity":    `<path d="M3 12h4l3-8 4 16 3-8h4"/>`,
	"settings":    `<path d="M4 6h9M19 6h1M4 12h3M13 12h7M4 18h11M21 18h-1"/><circle cx="16" cy="6" r="2.5"/><circle cx="10" cy="12" r="2.5"/><circle cx="17.5" cy="18" r="2.5"/>`,
	"users":       `<circle cx="9" cy="8" r="3.5"/><path d="M2.5 20c0-3.6 2.9-6 6.5-6s6.5 2.4 6.5 6M16 4.5a3.5 3.5 0 0 1 0 7M18 14c2.2.6 3.5 2.6 3.5 6"/>`,
	"roles":       `<path d="M12 3l8 3v6c0 4.5-3.4 8-8 9-4.6-1-8-4.5-8-9V6z"/><path d="M9 12l2 2 4-4"/>`,
	"allservers":  `<path d="M12 3l9 5-9 5-9-5z"/><path d="M3 12.5l9 5 9-5M3 16.5l9 5 9-5"/>`,
	"allmachines": `<rect x="2" y="7" width="14" height="10" rx="1.5"/><path d="M6 21h6M9 17v4M6 4h14.5A1.5 1.5 0 0 1 22 5.5V14"/>`,
	"audit":       `<path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h5M14 3l5 5h-5z"/><circle cx="16.5" cy="16.5" r="3"/><path d="M19 19l2.5 2.5"/>`,
	"vendorapps":  `<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>`,
	"sun":         `<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>`,
	"moon":        `<path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z"/>`,
	"system":      `<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>`,
	"menu":        `<path d="M4 7h16M4 12h16M4 17h16"/>`,
	"signout":     `<path d="M15 4h3a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-3M10 8l-4 4 4 4M6 12h10"/>`,
	"plus":        `<path d="M12 5v14M5 12h14"/>`,
	"copy":        `<rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2"/>`,
	"external":    `<path d="M14 4h6v6M20 4l-9 9M18 14v4a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4"/>`,
	"arrow-left":  `<path d="M19 12H5M11 6l-6 6 6 6"/>`,
	"warning":     `<path d="M12 3l10 18H2z"/><path d="M12 10v4M12 17.5h.01"/>`,
	"info":        `<circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7.5h.01"/>`,
	"check":       `<path d="M5 12.5l4.5 4.5L19 7.5"/>`,
	"x":           `<path d="M6 6l12 12M18 6L6 18"/>`,
	"search":      `<circle cx="11" cy="11" r="7"/><path d="M16 16l5 5"/>`,
	"inbox":       `<path d="M3 13l3-8h12l3 8v6a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1z"/><path d="M3 13h5l1.5 3h5l1.5-3h5"/>`,
}

// Icon renders the named icon as an inline <svg> (aria-hidden: the label
// next to it carries the meaning). An unknown name is an error, so a typo
// fails the template instead of rendering nothing.
func Icon(name string) (template.HTML, error) {
	body, ok := icons[name]
	if !ok {
		return "", fmt.Errorf("nav: no icon %q", name)
	}
	return template.HTML(`<svg class="icon icon-` + name + `" viewBox="0 0 24 24" aria-hidden="true" focusable="false">` + body + `</svg>`), nil
}
