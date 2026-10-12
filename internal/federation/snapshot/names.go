package snapshot

import (
	"slices"
	"strings"
)

// maxToolNameLen bounds a registry tool name.
const maxToolNameLen = 64

// RegistryToolName maps an upstream tool name onto the gateway registry's
// tool rule ([a-z0-9_-]): camelCase boundaries become "_", upper case is
// lowered, every other character becomes "_", runs of "_" collapse,
// leading and trailing "_" go, and the result is capped at 64 characters.
// It reports false when nothing usable is left. The federation connector
// registers tools as "<server>.<RegistryToolName>"; the policy store
// names auto-run tools the same way (Review.AutoRunToolNames).
func RegistryToolName(upstream string) (string, bool) {
	var b strings.Builder
	prevLower := false
	for _, r := range upstream {
		switch {
		case r >= 'A' && r <= 'Z':
			if prevLower {
				b.WriteByte('_')
			}
			b.WriteRune(r + ('a' - 'A'))
			prevLower = false
		case r >= 'a' && r <= 'z' || r >= '0' && r <= '9':
			b.WriteRune(r)
			prevLower = true
		case r == '-' || r == '_':
			b.WriteRune(r)
			prevLower = false
		default:
			b.WriteByte('_')
			prevLower = false
		}
	}
	name := b.String()
	for strings.Contains(name, "__") {
		name = strings.ReplaceAll(name, "__", "_")
	}
	name = strings.Trim(name, "_")
	if len(name) > maxToolNameLen {
		name = strings.TrimRight(name[:maxToolNameLen], "_")
	}
	return name, name != ""
}

// AutoRunToolNames lists, sorted, the registry names (RegistryToolName)
// of the enabled write tools set to auto. A tool whose name sanitizes to
// nothing, or to the same name as another enabled tool (the connector
// registers neither), is left out: it then asks, the safe default.
func (r Review) AutoRunToolNames() []string {
	count := map[string]int{}
	for up, tr := range r {
		if !tr.Enabled {
			continue
		}
		if name, ok := RegistryToolName(up); ok {
			count[name]++
		}
	}
	var out []string
	for _, up := range r.AutoRunWrites() {
		if name, ok := RegistryToolName(up); ok && count[name] == 1 {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}
