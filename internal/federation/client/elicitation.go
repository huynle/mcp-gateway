package client

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Bounds on what an upstream can make the gateway keep from URL-mode
// elicitations (MCP 2025-11-25). The URL is only capped here: the relay
// validates it (internal/federation/elicit Rules.Check refuses anything
// over 2048 bytes, so a capped URL is always refused there).
const (
	// MaxElicitations is the number of distinct elicitations kept per
	// session (mid-call requests) or per -32042 error.
	MaxElicitations = 5
	// MaxElicitationMessageRunes caps Elicitation.Message.
	MaxElicitationMessageRunes = 500
	// MaxElicitationURLBytes caps Elicitation.URL.
	MaxElicitationURLBytes = 4096
	// MaxElicitationIDBytes is the longest elicitationId kept; entries
	// with a longer id are dropped (an id is never truncated: it is the
	// de-duplication key).
	MaxElicitationIDBytes = 256
)

// errFormElicitation answers a form-mode (or mode-less) elicitation: the
// gateway declares only URL mode and never shows upstream forms.
var errFormElicitation = &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "form elicitation not supported"}

// Elicitation is one URL-mode elicitation an upstream asked for, either
// mid-call (elicitation/create, also as a multi round-trip input request)
// or in a -32042 error. All three fields are upstream-controlled: never
// pass them to a harness, and show URL and Message to the user only after
// validation (elicit.Rules.Check), as plain text.
type Elicitation struct {
	ElicitationID string
	URL           string
	Message       string
}

// Recorder keeps URL-mode elicitations de-duplicated by ElicitationID, at
// most MaxElicitations, with Message and URL capped and made valid UTF-8.
// The zero value is ready to use; it is safe for concurrent use (the SDK
// fulfils multi round-trip input requests in parallel).
type Recorder struct {
	mu   sync.Mutex
	list []Elicitation
}

// Add records e. It reports whether e was kept: an entry with an empty or
// over-long id or an empty URL, a duplicate id, or one past
// MaxElicitations is dropped.
func (r *Recorder) Add(e Elicitation) bool {
	e, ok := normalize(e)
	if !ok {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.list) >= MaxElicitations {
		return false
	}
	for _, x := range r.list {
		if x.ElicitationID == e.ElicitationID {
			return false
		}
	}
	r.list = append(r.list, e)
	return true
}

// List returns a copy of the recorded elicitations in arrival order, nil
// when there are none.
func (r *Recorder) List() []Elicitation {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.list) == 0 {
		return nil
	}
	return append([]Elicitation(nil), r.list...)
}

// Clear forgets everything recorded (before a retry after reauth).
func (r *Recorder) Clear() {
	r.mu.Lock()
	r.list = nil
	r.mu.Unlock()
}

// handle is the ClientOptions.ElicitationHandler of a URLElicitation
// connection. It records URL-mode requests and declines them with
// "cancel": the gateway cannot ask the user mid-call, so the connector
// relays the recorded link if the call then fails. Form mode (or no
// mode), which the connection never declared, gets -32602: the go-sdk
// hands it to the handler regardless.
func (r *Recorder) handle(_ context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
	if req == nil || req.Params == nil || req.Params.Mode != "url" {
		return nil, errFormElicitation
	}
	p := req.Params
	r.Add(Elicitation{ElicitationID: p.ElicitationID, URL: p.URL, Message: p.Message})
	return &mcp.ElicitResult{Action: "cancel"}, nil
}

func normalize(e Elicitation) (Elicitation, bool) {
	if e.ElicitationID == "" || len(e.ElicitationID) > MaxElicitationIDBytes || e.URL == "" {
		return Elicitation{}, false
	}
	e.ElicitationID = strings.ToValidUTF8(e.ElicitationID, "\uFFFD")
	e.URL = truncateBytes(strings.ToValidUTF8(e.URL, "\uFFFD"), MaxElicitationURLBytes)
	e.Message = truncateRunes(strings.ToValidUTF8(e.Message, "\uFFFD"), MaxElicitationMessageRunes)
	return e, true
}

// truncateBytes cuts s to at most n bytes on a rune boundary.
func truncateBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for s != "" && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

// truncateRunes cuts s to at most n runes.
func truncateRunes(s string, n int) string {
	i := 0
	for j := range s {
		if i == n {
			return s[:j]
		}
		i++
	}
	return s
}

// URLElicitations extracts the URL-mode elicitations of a JSON-RPC -32042
// (URL elicitation required) anywhere in err's chain. It arrives as an
// *Error with RPCCode -32042 of class ClassToolError (HTTP 200, what
// go-sdk servers send) or ClassProtocol with Status 400 (servers that
// answer JSON-RPC errors with 400); both keep the *jsonrpc.Error as their
// cause. Entries that are not mode "url", lack an elicitationId or URL,
// or repeat an id are ignored, and at most MaxElicitations are returned,
// capped like Recorder.Add. ok is true only for code -32042 with at least
// one usable entry. Callers check it before treating a failure as an
// unknown outcome.
func URLElicitations(err error) ([]Elicitation, bool) {
	var we *jsonrpc.Error
	if !errors.As(err, &we) || we.Code != mcp.CodeURLElicitationRequired || len(we.Data) == 0 {
		return nil, false
	}
	var data struct {
		Elicitations []*mcp.ElicitParams `json:"elicitations"`
	}
	if json.Unmarshal(we.Data, &data) != nil {
		return nil, false
	}
	var r Recorder
	for _, p := range data.Elicitations {
		if p != nil && p.Mode == "url" {
			r.Add(Elicitation{ElicitationID: p.ElicitationID, URL: p.URL, Message: p.Message})
		}
	}
	list := r.List()
	return list, len(list) > 0
}

// IsURLElicitationRequired reports whether e is an upstream's JSON-RPC
// -32042 answer (on HTTP 200 or 400), whatever its Class. Use
// URLElicitations to read the entries.
func (e *Error) IsURLElicitationRequired() bool {
	return e != nil && e.RPCCode == mcp.CodeURLElicitationRequired
}

// Elicitations returns the URL-mode elicitations the upstream sent during
// this session's calls (nil without Options.URLElicitation). Sessions are
// per call in the connector, so this is per call.
func (s *Session) Elicitations() []Elicitation {
	if s.rec == nil {
		return nil
	}
	return s.rec.List()
}

// ClearElicitations forgets the recorded elicitations (before a retry on
// the same session, e.g. after reauth).
func (s *Session) ClearElicitations() {
	if s.rec != nil {
		s.rec.Clear()
	}
}
