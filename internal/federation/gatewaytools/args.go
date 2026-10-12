package gatewaytools

import (
	"fmt"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/huynle/mcp-gateway/internal/observability"
)

// toolError is a tool failure the model sees (an IsError result) with a
// fixed audit class. Messages are short (the pipeline keeps 200
// characters), never echo argument values that could be secrets, and
// never carry upstream text.
type toolError struct {
	class string
	msg   string
}

func (e *toolError) Error() string { return e.msg }

// ErrorClass implements mcp.ClassedError.
func (e *toolError) ErrorClass() string { return e.class }

func fail(class, format string, a ...any) error {
	return &toolError{class: class, msg: fmt.Sprintf(format, a...)}
}

var (
	serverNameRE = regexp.MustCompile(`^[a-z0-9_-]{1,63}$`)
	uuidRE       = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	hostRE       = regexp.MustCompile(`^[A-Za-z0-9.:_-]{1,253}$`)
	// secretKeyRE matches argument (and nested object) names that suggest
	// a credential.
	secretKeyRE = regexp.MustCompile(`(?i)(key|token|secret|passw|pwd|credential|authori[sz]ation|bearer|cookie|private|session|signature)`)
)

// secretMessage is what a refused secret gets: where secrets go instead.
const secretMessage = "refused: arguments must never contain a secret. Enter API keys, tokens and header values in the browser at the server's portal page."

// checkArgs refuses arguments that are not in allowed (args_invalid), and
// any argument that looks like a secret (secret_refused): an unknown name
// suggesting a credential (also inside objects), an Authorization or
// Cookie header, or a value the log redactor would hide (bearer tokens,
// provider token formats, key=value pairs, credentials in URL queries).
func checkArgs(args map[string]any, allowed ...string) error {
	for _, k := range slices.Sorted(maps.Keys(args)) {
		if !slices.Contains(allowed, k) && secretKeyRE.MatchString(k) {
			return fail("secret_refused", "%s", secretMessage)
		}
		if secretValue(args[k]) {
			return fail("secret_refused", "%s", secretMessage)
		}
	}
	for _, k := range slices.Sorted(maps.Keys(args)) {
		if !slices.Contains(allowed, k) {
			if !serverNameRE.MatchString(k) {
				k = "?"
			}
			return fail("args_invalid", "unknown argument %q; allowed: %s", k, strings.Join(allowed, ", "))
		}
	}
	return nil
}

// secretValue walks v: object keys suggesting a credential, and strings
// the redactor would change, are secrets.
func secretValue(v any) bool {
	switch x := v.(type) {
	case string:
		return observability.Redact(x) != x
	case []any:
		return slices.ContainsFunc(x, secretValue)
	case map[string]any:
		for k, inner := range x {
			if secretKeyRE.MatchString(k) || secretValue(inner) {
				return true
			}
		}
	}
	return false
}

// stringArg returns args[key] as a trimmed string; a missing key is "",
// another type is args_invalid.
func stringArg(args map[string]any, key string) (string, error) {
	v, ok := args[key]
	if !ok || v == nil {
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", fail("args_invalid", "%s must be a string", key)
	}
	return strings.TrimSpace(s), nil
}

func requiredString(args map[string]any, key string) (string, error) {
	s, err := stringArg(args, key)
	if err == nil && s == "" {
		err = fail("args_invalid", "%s is required", key)
	}
	return s, err
}

// stringList returns args[key] as a list of trimmed, non-empty strings.
func stringList(args map[string]any, key string) ([]string, error) {
	v, ok := args[key]
	if !ok || v == nil {
		return nil, nil
	}
	list, ok := v.([]any)
	if !ok {
		return nil, fail("args_invalid", "%s must be a list of strings", key)
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		s, ok := item.(string)
		if !ok {
			return nil, fail("args_invalid", "%s must be a list of strings", key)
		}
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out, nil
}

// secretQuery reports whether a URL's query names a credential (key,
// token, secret, ...): such URLs embed a secret and are refused.
func secretQuery(u *url.URL) bool {
	for k := range u.Query() {
		if secretKeyRE.MatchString(k) {
			return true
		}
	}
	return false
}
