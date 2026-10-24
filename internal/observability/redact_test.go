package observability_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/observability"
)

// Secrets the corpus tries to smuggle into the log. Each is distinctive so a
// substring search is unambiguous; none contains characters a JSON encoder
// would escape.
const (
	secMGW       = "mgw_01HX7ZQ_sEcReTvAlUe1234567890"
	secJWT       = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c"
	secBearer    = "ya29A0AfH6SMBxyzBEARERSECRET"
	secSlackBot  = "xoxb-1234567890-abcdefghijSLACK"
	secSlackUser = "xoxp-9876543210-zyxwvutSLACK"
	secGHP       = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	secGHO       = "gho_abcdefghijklmnopqrstuvwxyz0123456789"
	secGHPAT     = "github_pat_11ABCDEFG_abcdefghijklmnopqrstuv"
	secGoogle    = "AIzaSyAabcdefghijklmnopqrstuvwxyz012345"
	secPEMBody   = "MIIEvQIBADANBgSECRETPEMBODYLINE"
	secPEM       = "-----BEGIN PRIVATE KEY-----\n" + secPEMBody + "\n-----END PRIVATE KEY-----"
	secPassword  = "hunter2PASSWORDVALUE"
	secCode      = "oauthcodeZXC123CODEVALUE"
	secArgs      = "argumentsWithSSN123456789"
	secBody      = "bodySuperPrivateContentValue"
	secCookie    = "sessionCOOKIEVALUEabc123"
	secClient    = "clientSECRETvalue987"
	secRefresh   = "refreshTOKENvalue456"
	secIDToken   = "idTOKENvalue789"
	secAPIKey    = "apiKEYvalue321"
	secPayload   = "payloadPRIVATEvalue654"
	secContent   = "contentOfTheEmailBody"
	secSigning   = "signingSECRETvalue111"
	secPrivKey   = "privateKEYvalue222"
	secUserUUID  = "0b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d"
	// An ephemeral-secret entry link id (/s/<id>) and handle (sec_…):
	// base62 of 256 bits (internal/secrets).
	secEntryID = "oAUeiozOG65nkEiRZJiPYF78P5LeWHu35LynQjMUD76"
	secHandle  = "sec_7Gq2LmXv9TzR4bWk1NcPa8YdE3sHfJ6uQiK0oVxZl5r"
)

type leakyError struct{ token string }

func (e *leakyError) Error() string { return "vendor refused token " + e.token }

type leakyStringer struct{ Token string }

func (s leakyStringer) String() string { return "stringer says " + s.Token }

type scalarStringer string

func (s scalarStringer) String() string { return "scalar " + string(s) }

type leakyValuer struct{}

func (leakyValuer) LogValue() slog.Value {
	return slog.GroupValue(slog.String("access_token", secRefresh), slog.String("note", "fine"))
}

type nested struct {
	Name  string
	Inner struct{ Secret string }
	Meta  map[string]string
}

type leakCase struct {
	name    string
	log     func(l *slog.Logger)
	secrets []string
}

func corpus() []leakCase {
	return []leakCase{
		{"denied key: token", func(l *slog.Logger) { l.Info("x", "token", secPassword) }, []string{secPassword}},
		{"denied key: Authorization mixed case", func(l *slog.Logger) { l.Info("x", "Authorization", "Basic "+secPassword) }, []string{secPassword}},
		{"denied key: refresh_token", func(l *slog.Logger) { l.Info("x", "refresh_token", secRefresh) }, []string{secRefresh}},
		{"denied key: id_token", func(l *slog.Logger) { l.Info("x", "id_token", secIDToken) }, []string{secIDToken}},
		{"denied key: client_secret", func(l *slog.Logger) { l.Info("x", "client_secret", secClient) }, []string{secClient}},
		{"denied key: private_key", func(l *slog.Logger) { l.Info("x", "private_key", secPrivKey) }, []string{secPrivKey}},
		{"denied key: signing_secret", func(l *slog.Logger) { l.Info("x", "signing_secret", secSigning) }, []string{secSigning}},
		{"denied key: api_key", func(l *slog.Logger) { l.Info("x", "api_key", secAPIKey) }, []string{secAPIKey}},
		{"denied key: dashed header name x-api-key", func(l *slog.Logger) { l.Info("x", "x-api-key", secAPIKey) }, []string{secAPIKey}},
		{"denied key: camel ClientSecret", func(l *slog.Logger) { l.Info("x", "ClientSecret", secClient) }, []string{secClient}},
		{"denied key: suffix github_token", func(l *slog.Logger) { l.Info("x", "github_token", secPassword) }, []string{secPassword}},
		{"denied key: code", func(l *slog.Logger) { l.Info("x", "code", secCode) }, []string{secCode}},
		{"denied key: cookie", func(l *slog.Logger) { l.Info("x", "cookie", secCookie) }, []string{secCookie}},
		{"denied key: arguments", func(l *slog.Logger) { l.Info("x", "arguments", secArgs) }, []string{secArgs}},
		{"denied key: args map subtree", func(l *slog.Logger) {
			l.Info("x", slog.Any("args", map[string]any{"title": secArgs, "n": 1}))
		}, []string{secArgs}},
		{"denied key: body", func(l *slog.Logger) { l.Info("x", "body", secBody) }, []string{secBody}},
		{"denied key: content", func(l *slog.Logger) { l.Info("x", "content", secContent) }, []string{secContent}},
		{"denied key: payload", func(l *slog.Logger) { l.Info("x", "payload", secPayload) }, []string{secPayload}},
		{"denied key: password", func(l *slog.Logger) { l.Info("x", "password", secPassword) }, []string{secPassword}},
		{"nested groups", func(l *slog.Logger) {
			l.Info("x", slog.Group("req", slog.Group("headers", slog.String("Cookie", secCookie))))
		}, []string{secCookie}},
		{"WithGroup + With", func(l *slog.Logger) {
			l.WithGroup("http").With("password", secPassword).Info("x", "route", "/a")
		}, []string{secPassword}},
		{"With group attr", func(l *slog.Logger) {
			l.With(slog.Group("auth", "client_secret", secClient)).Info("x")
		}, []string{secClient}},
		{"Any map[string]any denied key", func(l *slog.Logger) {
			l.Info("x", slog.Any("ctx", map[string]any{"token": secPassword, "n": 2}))
		}, []string{secPassword}},
		{"Any map[string]string denied key", func(l *slog.Logger) {
			l.Info("x", slog.Any("ctx", map[string]string{"Authorization": secPassword}))
		}, []string{secPassword}},
		{"map nested in slice", func(l *slog.Logger) {
			l.Info("x", slog.Any("items", []any{"a", map[string]any{"access_token": secRefresh}}))
		}, []string{secRefresh}},
		{"slice of strings with mgw token", func(l *slog.Logger) {
			l.Info("x", slog.Any("list", []string{"ok", secMGW}))
		}, []string{secMGW}},
		{"struct exported Password field", func(l *slog.Logger) {
			l.Info("x", slog.Any("cfg", struct{ Password, Host string }{secPassword, "db"}))
		}, []string{secPassword}},
		{"pointer to nested struct with Secret and map", func(l *slog.Logger) {
			n := &nested{Name: "n", Meta: map[string]string{"api_key": secAPIKey}}
			n.Inner.Secret = secClient
			l.Info("x", slog.Any("n", n))
		}, []string{secClient, secAPIKey}},
		{"plain error with mgw token", func(l *slog.Logger) {
			l.Error("x", "error", errors.New("vendor said: bad token "+secMGW))
		}, []string{secMGW}},
		{"fmt-wrapped error with JWT", func(l *slog.Logger) {
			inner := errors.New("jwt " + secJWT + " rejected")
			l.Error("x", "err", fmt.Errorf("refresh: %w", inner))
		}, []string{secJWT}},
		{"custom error type", func(l *slog.Logger) {
			l.Error("x", "err", fmt.Errorf("outer: %w", &leakyError{token: secGHP}))
		}, []string{secGHP}},
		{"errors.Join", func(l *slog.Logger) {
			l.Error("x", "err", errors.Join(errors.New("a"), errors.New("b "+secSlackBot)))
		}, []string{secSlackBot}},
		{"error inside a slice", func(l *slog.Logger) {
			l.Error("x", slog.Any("errs", []error{errors.New("c " + secGHO)}))
		}, []string{secGHO}},
		{"Stringer struct with exported Token field", func(l *slog.Logger) {
			l.Info("x", slog.Any("s", leakyStringer{Token: secPassword}))
		}, []string{secPassword}},
		{"scalar Stringer leaking a pattern", func(l *slog.Logger) {
			l.Info("x", slog.Any("s", scalarStringer(secGHPAT)))
		}, []string{secGHPAT}},
		{"LogValuer resolving to a group", func(l *slog.Logger) {
			l.Info("x", slog.Any("v", leakyValuer{}))
		}, []string{secRefresh}},
		{"message contains JWT", func(l *slog.Logger) { l.Info("got " + secJWT) }, []string{secJWT}},
		{"message contains Bearer", func(l *slog.Logger) { l.Info("auth header Bearer " + secBearer) }, []string{secBearer}},
		{"value: header line under innocent key", func(l *slog.Logger) {
			l.Info("x", "detail", "Authorization: Bearer "+secBearer)
		}, []string{secBearer}},
		{"URL query code and state", func(l *slog.Logger) {
			l.Info("x", "url", "https://gw.example/cb?code="+secCode+"&state=abc")
		}, []string{secCode}},
		{"URL query access_token", func(l *slog.Logger) {
			l.Info("x", "url", "https://api.example/v1?access_token="+secRefresh+"&x=1")
		}, []string{secRefresh}},
		{"key=value in free text", func(l *slog.Logger) {
			l.Info("x", "detail", "oauth2: invalid_client client_secret="+secClient+" for app")
		}, []string{secClient}},
		{"PEM block in value", func(l *slog.Logger) { l.Info("x", "pem", secPEM) }, []string{secPEMBody}},
		{"PEM block in error", func(l *slog.Logger) {
			l.Error("x", "error", errors.New("parse key: "+secPEM))
		}, []string{secPEMBody}},
		{"Slack user token in free text", func(l *slog.Logger) { l.Info("x", "note", "got "+secSlackUser) }, []string{secSlackUser}},
		{"GitHub PAT in free text", func(l *slog.Logger) { l.Info("x", "note", "using "+secGHPAT) }, []string{secGHPAT}},
		{"Google API key in free text", func(l *slog.Logger) { l.Info("x", "note", "key "+secGoogle) }, []string{secGoogle}},
		{"[]byte containing a token", func(l *slog.Logger) { l.Info("x", slog.Any("raw", []byte("t="+secMGW))) }, []string{secMGW}},
		{"user_id is hashed not raw", func(l *slog.Logger) { l.Info("x", "user_id", secUserUUID) }, []string{secUserUUID}},
		{"actor_user_id is hashed not raw", func(l *slog.Logger) { l.Info("x", "actor_user_id", secUserUUID) }, []string{secUserUUID}},
		{"secret entry link path under an innocent key", func(l *slog.Logger) {
			l.Info("x", "path", "/s/"+secEntryID)
		}, []string{secEntryID}},
		{"secret entry link as an encoded return_to", func(l *slog.Logger) {
			l.Info("x", "location", "/signin?return_to=%2Fs%2F"+secEntryID)
		}, []string{secEntryID}},
		{"secret entry link and handle in an error message", func(l *slog.Logger) {
			l.Error("x", "error", errors.New("Ask the user to open https://gw.example/s/"+secEntryID+" then retry with "+secHandle))
		}, []string{secEntryID, secHandle}},
		{"elicitation link path under an innocent key", func(l *slog.Logger) {
			l.Info("x", "path", "/elicit/"+secEntryID)
		}, []string{secEntryID}},
		{"elicitation link as an encoded return_to", func(l *slog.Logger) {
			l.Info("x", "location", "/signin?return_to=%2Felicit%2F"+secEntryID)
		}, []string{secEntryID}},
		{"elicitation link in an error message", func(l *slog.Logger) {
			l.Error("x", "error", errors.New("open https://gw.example/elicit/"+secEntryID+" to continue"))
		}, []string{secEntryID}},
		{"user key under group", func(l *slog.Logger) {
			l.Info("x", slog.Group("session", "user", secUserUUID))
		}, []string{secUserUUID}},
	}
}

func TestRedactionCorpusHasAtLeast30Cases(t *testing.T) {
	if n := len(corpus()); n < 30 {
		t.Fatalf("corpus has %d cases, want >= 30", n)
	}
}

func TestRedactingHandlerLeaksNothing(t *testing.T) {
	t.Setenv("GATEWAY_LOG_SALT", "test-salt")
	for _, sink := range []string{"json", "text"} {
		for _, c := range corpus() {
			t.Run(sink+"/"+c.name, func(t *testing.T) {
				var buf bytes.Buffer
				var inner slog.Handler
				if sink == "json" {
					inner = slog.NewJSONHandler(&buf, nil)
				} else {
					inner = slog.NewTextHandler(&buf, nil)
				}
				l := slog.New(observability.NewRedactingHandler(inner))
				c.log(l)
				out := buf.String()
				if out == "" {
					t.Fatal("nothing was logged")
				}
				for _, s := range c.secrets {
					if strings.Contains(out, s) {
						t.Errorf("secret %q leaked into %s output:\n%s", s, sink, out)
					}
				}
			})
		}
	}
}

// TestRedactionControlLeaksWithoutHandler proves the corpus is real: the same
// cases through a plain JSON handler expose secrets.
func TestRedactionControlLeaksWithoutHandler(t *testing.T) {
	leaked := 0
	for _, c := range corpus() {
		var buf bytes.Buffer
		l := slog.New(slog.NewJSONHandler(&buf, nil))
		c.log(l)
		for _, s := range c.secrets {
			if strings.Contains(buf.String(), s) {
				leaked++
				break
			}
		}
	}
	if leaked == 0 {
		t.Fatal("control: expected the unredacted handler to leak at least one case")
	}
	t.Logf("control: %d/%d cases leak without the redacting handler", leaked, len(corpus()))
}

func TestRedactingHandlerKeepsHarmlessAttributes(t *testing.T) {
	var buf bytes.Buffer
	l := slog.New(observability.NewRedactingHandler(slog.NewJSONHandler(&buf, nil)))
	l.WithGroup("http").Info("request done", "route", "/mcp", "method", "POST", "status", 200, "token_id", "01HX7ZQ",
		slog.Group("timing", "ms", 12.5), slog.Any("tags", []string{"a", "b"}))
	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, buf.String())
	}
	if rec["msg"] != "request done" {
		t.Errorf("msg = %v", rec["msg"])
	}
	h, _ := rec["http"].(map[string]any)
	if h["route"] != "/mcp" || h["method"] != "POST" || h["status"] != float64(200) || h["token_id"] != "01HX7ZQ" {
		t.Errorf("harmless attrs altered: %v", h)
	}
	timing, _ := h["timing"].(map[string]any)
	if timing["ms"] != 12.5 {
		t.Errorf("group attr altered: %v", h["timing"])
	}
	tags, _ := h["tags"].([]any)
	if len(tags) != 2 || tags[0] != "a" {
		t.Errorf("slice altered: %v", h["tags"])
	}
}

func TestRedactingHandlerMarksRedactedValues(t *testing.T) {
	var buf bytes.Buffer
	l := slog.New(observability.NewRedactingHandler(slog.NewJSONHandler(&buf, nil)))
	l.Info("x", "token", secPassword, "note", "see "+secMGW)
	if !strings.Contains(buf.String(), observability.Redacted) {
		t.Errorf("expected %q marker in output: %s", observability.Redacted, buf.String())
	}
}

func TestRedactingHandlerTruncatesErrors(t *testing.T) {
	long := strings.Repeat("v", 300) + "TAIL"
	var buf bytes.Buffer
	l := slog.New(observability.NewRedactingHandler(slog.NewJSONHandler(&buf, nil)))
	l.Error("x", "error", errors.New(long))
	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	got, _ := rec["error"].(string)
	if strings.Contains(got, "TAIL") {
		t.Errorf("error value not truncated: %d chars", len(got))
	}
	if len(got) > observability.MaxErrorLen {
		t.Errorf("error value length %d > %d", len(got), observability.MaxErrorLen)
	}
}

var hexRE = regexp.MustCompile(`^[0-9a-f]{16}$`)

func TestUserAttrHashesWithSalt(t *testing.T) {
	t.Setenv("GATEWAY_LOG_SALT", "salt-one")
	a := observability.UserAttr(secUserUUID)
	if a.Key != "user" {
		t.Errorf("key = %q, want user", a.Key)
	}
	h1 := a.Value.String()
	if !hexRE.MatchString(h1) {
		t.Fatalf("hash %q is not 16 hex chars", h1)
	}
	if observability.UserAttr(secUserUUID).Value.String() != h1 {
		t.Error("hash not deterministic")
	}
	t.Setenv("GATEWAY_LOG_SALT", "salt-two")
	if observability.UserAttr(secUserUUID).Value.String() == h1 {
		t.Error("hash did not change with the salt")
	}
}

func TestRedactorHashesUserIDConsistentlyWithUserAttr(t *testing.T) {
	t.Setenv("GATEWAY_LOG_SALT", "salt-one")
	want := observability.UserAttr(secUserUUID).Value.String()
	var buf bytes.Buffer
	l := slog.New(observability.NewRedactingHandler(slog.NewJSONHandler(&buf, nil)))
	l.Info("x", "user_id", secUserUUID, observability.UserAttr(secUserUUID))
	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	if rec["user_id"] != want {
		t.Errorf("user_id = %v, want hashed %q", rec["user_id"], want)
	}
	if rec["user"] != want {
		t.Errorf("UserAttr re-hashed by the redactor: %v, want %q", rec["user"], want)
	}
}

func TestRedactingHandlerPropagatesEnabled(t *testing.T) {
	var buf bytes.Buffer
	h := observability.NewRedactingHandler(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	if h.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("info should be disabled")
	}
	if !h.Enabled(context.Background(), slog.LevelWarn) {
		t.Error("warn should be enabled")
	}
}

func TestNewLoggerRedactsByDefault(t *testing.T) {
	var buf bytes.Buffer
	l, err := observability.NewLogger(&buf, "info", "json")
	if err != nil {
		t.Fatal(err)
	}
	l.Info("x", "token", secPassword)
	if strings.Contains(buf.String(), secPassword) {
		t.Errorf("NewLogger did not redact: %s", buf.String())
	}
}

func TestRedactStringHelper(t *testing.T) {
	got := observability.Redact("Bearer " + secBearer + " and " + secMGW)
	if strings.Contains(got, secBearer) || strings.Contains(got, secMGW) {
		t.Errorf("Redact left secrets: %q", got)
	}
	for _, harmless := range []string{"/secrets", "/secrets/0b1c2d3e/revoke", "/servers/abc", "/s/…", "/s/short", "sec_short", "/elicit/…", "/elicit/short"} {
		if got := observability.Redact(harmless); got != harmless {
			t.Errorf("Redact(%q) = %q", harmless, got)
		}
	}
	if observability.Redact("plain text") != "plain text" {
		t.Error("Redact altered harmless text")
	}
}
