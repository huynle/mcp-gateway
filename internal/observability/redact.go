package observability

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Redacted replaces every value the redactor refuses to log.
const Redacted = "[REDACTED]"

// MaxErrorLen bounds error values after redaction: vendor errors echo request
// bodies and we only need the head to classify them (decision v6piaxdb).
const MaxErrorLen = 200

// EnvLogSalt names the per-deployment salt for pseudonymous user IDs in logs.
const EnvLogSalt = "GATEWAY_LOG_SALT"

// maxDepth bounds recursion into nested values; deeper structures are cut
// off rather than walked (cycles, pathological payloads).
const maxDepth = 8

// deniedKeys are attribute keys whose entire value is replaced, whatever the
// type. Keys are compared after normalizeKey (case, '-', '_', '.' and ' '
// are ignored), so Authorization, refresh-token and ClientSecret all match.
var deniedKeys = map[string]bool{
	"token": true, "secret": true, "password": true, "passwd": true, "code": true,
	"authorization": true, "cookie": true, "setcookie": true, "arguments": true, "args": true,
	"body": true, "content": true, "payload": true, "refreshtoken": true,
	"accesstoken": true, "idtoken": true, "clientsecret": true, "privatekey": true,
	"signingsecret": true, "apikey": true,
}

// deniedSuffixes catch prefixed variants (github_token, x-api-key,
// proxy-authorization, request_body, tool_args). "code" is deliberately not
// a suffix: error_code and status_code are classification, not secrets.
var deniedSuffixes = []string{
	"token", "secret", "password", "passwd", "authorization", "cookie", "arguments", "args",
	"body", "content", "payload", "privatekey", "apikey",
}

// hashedKeys carry a user ID that is logged pseudonymously (HMAC with the
// deployment salt) rather than dropped, so one user's lines can be
// correlated without naming them.
var hashedKeys = map[string]bool{"user": true, "userid": true}

const hashedSuffix = "userid"

// valuePatterns are applied to every string that reaches the log: message,
// attribute values, error text, struct fields and map entries. Order matters
// only for overlapping matches (PEM first so its body is not partially
// matched by narrower patterns).
var valuePatterns = []struct {
	re   *regexp.Regexp
	repl string
}{
	{regexp.MustCompile(`-----BEGIN [A-Z0-9 ]+-----[\s\S]*?-----END [A-Z0-9 ]+-----`), Redacted},
	{regexp.MustCompile(`-----BEGIN [A-Z0-9 ]+-----[\s\S]*$`), Redacted},
	{regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+`), "$1 " + Redacted},
	{regexp.MustCompile(`\bmgw_[A-Za-z0-9_-]+`), Redacted},
	{regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}(?:\.[A-Za-z0-9_-]*)?`), Redacted},
	{regexp.MustCompile(`\bxox[abopsre]-[A-Za-z0-9-]+`), Redacted},
	{regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{10,}`), Redacted},
	{regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{10,}`), Redacted},
	{regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{20,}`), Redacted},
	// Ephemeral secrets (internal/secrets): the id of an entry link opens
	// that page, plain or URL-encoded (a sign-in return_to), and a handle
	// is what a harness uses the secret with.
	{regexp.MustCompile(`(/s/|%2[Ff]s%2[Ff])[A-Za-z0-9]{20,100}`), "$1" + Redacted},
	{regexp.MustCompile(`\bsec_[A-Za-z0-9]{20,100}`), Redacted},
	// Upstream URL elicitations (internal/federation/elicit): the id of an
	// interstitial link (/elicit/<id>) opens that page, plain or encoded.
	{regexp.MustCompile(`(/elicit/|%2[Ff]elicit%2[Ff])[A-Za-z0-9]{20,100}`), "$1" + Redacted},
	// URL query parameters.
	{regexp.MustCompile(`(?i)([?&](?:code|state|token|access_token|refresh_token|id_token|client_secret|secret|api_key|apikey|key|password|signature|sig)=)[^&\s"']+`), "$1" + Redacted},
	// key=value and key: value in free text (vendor error strings).
	{regexp.MustCompile(`(?i)\b((?:[a-z]+[_-])?(?:token|secret|password|passwd|api_key|apikey|authorization))\s*[:=]\s*["']?[^\s"',;&]+`), "$1=" + Redacted},
	// "key": "value" in JSON-shaped text.
	{regexp.MustCompile(`(?i)"((?:[a-z_-]*)(?:token|secret|password|passwd|api_key|apikey|authorization|code))"\s*:\s*"[^"]*"`), `"$1":"` + Redacted + `"`},
}

var hashedRE = regexp.MustCompile(`^[0-9a-f]{16}$`)

// Redact applies the value patterns to s. Use it for any string that is
// about to leave the process by a path other than the logger (for example
// an error class derived from vendor text).
func Redact(s string) string {
	for _, p := range valuePatterns {
		s = p.re.ReplaceAllString(s, p.repl)
	}
	return s
}

// RedactError renders err for a log or audit field: redacted and truncated
// to MaxErrorLen. A nil error renders as "".
func RedactError(err error) string {
	if err == nil {
		return ""
	}
	return truncate(Redact(err.Error()), MaxErrorLen)
}

// UserAttr returns the attribute to log for a user: key "user", value
// HMAC-SHA256(GATEWAY_LOG_SALT, userID) truncated to 16 hex characters. The
// redactor applies the same transform to any user_id / user key it sees, so
// both spellings correlate.
func UserAttr(userID string) slog.Attr {
	return slog.String("user", HashUserID(userID))
}

// HashUserID is UserAttr's transform. An empty ID stays empty; a value that
// already looks hashed is returned unchanged so re-logging is idempotent.
func HashUserID(userID string) string {
	if userID == "" || hashedRE.MatchString(userID) {
		return userID
	}
	mac := hmac.New(sha256.New, logSalt())
	mac.Write([]byte(userID))
	return hex.EncodeToString(mac.Sum(nil))[:16]
}

var (
	fallbackSaltOnce sync.Once
	fallbackSalt     []byte
)

// logSalt reads GATEWAY_LOG_SALT on every call (cheap; lets tests and
// reloads change it). Without a configured salt a random per-process salt is
// used so hashes stay consistent within one process but cannot be matched
// against a dictionary of user IDs; the docs tell operators to set one.
func logSalt() []byte {
	if s := os.Getenv(EnvLogSalt); s != "" {
		return []byte(s)
	}
	fallbackSaltOnce.Do(func() {
		fallbackSalt = make([]byte, 32)
		if _, err := rand.Read(fallbackSalt); err != nil {
			panic("observability: cannot generate fallback log salt: " + err.Error())
		}
	})
	return fallbackSalt
}

// RedactingHandler wraps any slog.Handler and rewrites every record before
// it reaches the sink: denied keys are replaced wholesale, user IDs are
// hashed, value patterns are scrubbed from the message and from every string
// reachable through groups, maps, slices, structs, errors (including
// wrapped ones), Stringers and LogValuers, and errors are truncated.
type RedactingHandler struct {
	inner slog.Handler
}

// NewRedactingHandler wraps inner. NewLogger already does this; use it
// directly only when composing handlers by hand.
func NewRedactingHandler(inner slog.Handler) *RedactingHandler {
	return &RedactingHandler{inner: inner}
}

// Enabled reports whether inner would log at level.
func (h *RedactingHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

// Handle redacts the record and forwards it.
func (h *RedactingHandler) Handle(ctx context.Context, r slog.Record) error {
	nr := slog.NewRecord(r.Time, r.Level, Redact(r.Message), r.PC)
	r.Attrs(func(a slog.Attr) bool {
		nr.AddAttrs(redactAttr(a, 0))
		return true
	})
	return h.inner.Handle(ctx, nr)
}

// WithAttrs redacts attrs before binding them to the inner handler.
func (h *RedactingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	out := make([]slog.Attr, 0, len(attrs))
	for _, a := range attrs {
		out = append(out, redactAttr(a, 0))
	}
	return &RedactingHandler{inner: h.inner.WithAttrs(out)}
}

// WithGroup opens a group on the inner handler.
func (h *RedactingHandler) WithGroup(name string) slog.Handler {
	return &RedactingHandler{inner: h.inner.WithGroup(name)}
}

// normalizeKey lower-cases k and strips separators so Authorization,
// refresh-token, Refresh_Token and ClientSecret compare equal to their
// denylist entries.
func normalizeKey(k string) string {
	var b strings.Builder
	b.Grow(len(k))
	for _, r := range strings.ToLower(k) {
		switch r {
		case '-', '_', '.', ' ':
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func isDeniedKey(k string) bool {
	n := normalizeKey(k)
	if deniedKeys[n] {
		return true
	}
	for _, s := range deniedSuffixes {
		if len(n) > len(s) && strings.HasSuffix(n, s) {
			return true
		}
	}
	return false
}

func isHashedKey(k string) bool {
	n := normalizeKey(k)
	return hashedKeys[n] || (len(n) > len(hashedSuffix) && strings.HasSuffix(n, hashedSuffix))
}

func redactAttr(a slog.Attr, depth int) slog.Attr {
	return slog.Attr{Key: a.Key, Value: redactValue(a.Key, a.Value, depth)}
}

// redactValue is the slog.Value walker. key is the attribute the value sits
// under (empty for slice elements).
func redactValue(key string, v slog.Value, depth int) slog.Value {
	v = v.Resolve()
	if isDeniedKey(key) {
		return slog.StringValue(Redacted)
	}
	if depth > maxDepth {
		return slog.StringValue("[omitted: nesting too deep]")
	}
	switch v.Kind() {
	case slog.KindString:
		if isHashedKey(key) {
			return slog.StringValue(HashUserID(v.String()))
		}
		return slog.StringValue(Redact(v.String()))
	case slog.KindGroup:
		attrs := v.Group()
		out := make([]slog.Attr, 0, len(attrs))
		for _, a := range attrs {
			out = append(out, redactAttr(a, depth+1))
		}
		return slog.GroupValue(out...)
	case slog.KindAny:
		return slog.AnyValue(sanitizeAny(key, v.Any(), depth+1))
	default:
		// Bool, Duration, Float64, Int64, Time, Uint64: nothing to scrub.
		return v
	}
}

// sanitizeAny converts an arbitrary Go value into a plain tree (string,
// number, bool, time, map[string]any, []any) with every string redacted and
// every denied key dropped. Plain trees render the same through the JSON and
// text handlers, so no String(), Error() or MarshalJSON method of the
// original value can reintroduce a secret downstream.
func sanitizeAny(key string, v any, depth int) any {
	if v == nil {
		return nil
	}
	if depth > maxDepth {
		return "[omitted: nesting too deep]"
	}
	switch x := v.(type) {
	case error:
		return RedactError(x)
	case slog.LogValuer:
		return valueToAny(redactValue(key, x.LogValue(), depth))
	case time.Time, time.Duration:
		return x
	case []byte:
		return Redact(string(x))
	case string:
		if isHashedKey(key) {
			return HashUserID(x)
		}
		return Redact(x)
	}

	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Interface:
		if rv.IsNil() {
			return nil
		}
		return sanitizeAny(key, rv.Elem().Interface(), depth+1)
	case reflect.Struct:
		return sanitizeStruct(rv, depth)
	case reflect.Map:
		return sanitizeMap(rv, depth)
	case reflect.Slice, reflect.Array:
		if rv.Kind() == reflect.Slice && rv.IsNil() {
			return nil
		}
		if rv.Type().Elem().Kind() == reflect.Uint8 {
			return Redact(string(rv.Bytes()))
		}
		out := make([]any, rv.Len())
		for i := range out {
			out[i] = sanitizeAny("", rv.Index(i).Interface(), depth+1)
		}
		return out
	case reflect.String:
		if s, ok := v.(fmt.Stringer); ok {
			return Redact(s.String())
		}
		if isHashedKey(key) {
			return HashUserID(rv.String())
		}
		return Redact(rv.String())
	case reflect.Bool:
		return rv.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if s, ok := v.(fmt.Stringer); ok {
			return Redact(s.String())
		}
		return rv.Int()
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		if s, ok := v.(fmt.Stringer); ok {
			return Redact(s.String())
		}
		return rv.Uint()
	case reflect.Float32, reflect.Float64:
		return rv.Float()
	default:
		// Chan, Func, Complex, UnsafePointer: never meaningful in a log.
		return "[unloggable " + rv.Kind().String() + "]"
	}
}

func sanitizeStruct(rv reflect.Value, depth int) map[string]any {
	t := rv.Type()
	out := make(map[string]any, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name := f.Name
		if tag, ok := f.Tag.Lookup("json"); ok {
			if n, _, _ := strings.Cut(tag, ","); n == "-" {
				continue
			} else if n != "" {
				name = n
			}
		}
		if isDeniedKey(name) {
			out[name] = Redacted
			continue
		}
		out[name] = sanitizeAny(name, rv.Field(i).Interface(), depth+1)
	}
	return out
}

func sanitizeMap(rv reflect.Value, depth int) any {
	if rv.IsNil() {
		return nil
	}
	out := make(map[string]any, rv.Len())
	iter := rv.MapRange()
	for iter.Next() {
		k := iter.Key()
		name := fmt.Sprint(k.Interface())
		if k.Kind() == reflect.String {
			name = k.String()
		}
		if isDeniedKey(name) {
			out[name] = Redacted
			continue
		}
		out[name] = sanitizeAny(name, iter.Value().Interface(), depth+1)
	}
	return out
}

// valueToAny flattens an already-redacted slog.Value into the plain tree
// shape used for nested LogValuers.
func valueToAny(v slog.Value) any {
	switch v.Kind() {
	case slog.KindGroup:
		attrs := v.Group()
		out := make(map[string]any, len(attrs))
		for _, a := range attrs {
			out[a.Key] = valueToAny(a.Value)
		}
		return out
	default:
		return v.Any()
	}
}

// truncate cuts s to at most n bytes on a rune boundary.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
