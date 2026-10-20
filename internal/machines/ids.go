package machines

import "regexp"

// uuidRE matches a lower-case uuid (machine, tunnel and request ids).
var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// nameRE is a machine name: 1-63 of [a-z0-9_-], starting with a letter or
// digit (the CLI defaults to the sanitized short host name).
var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// ValidName reports whether name is a valid machine name.
func ValidName(name string) bool { return nameRE.MatchString(name) }
