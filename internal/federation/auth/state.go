package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/huynle/mcp-gateway/internal/store"
)

// flowState is what a connect flow needs at the callback. It travels in
// the OAuth state parameter, sealed with the envelope crypto under AAD
// bound to the user and the server, so it is confidential (the PKCE
// verifier), authenticated, and useless to anyone else. One use is
// enforced by the ReplayGuard on its ID; expiry by Exp.
type flowState struct {
	ID            string `json:"id"`
	UserID        string `json:"u"`
	ServerID      string `json:"s"`
	Verifier      string `json:"v"`
	Issuer        string `json:"iss"`
	IssRequired   bool   `json:"iss_req,omitempty"`
	TokenEndpoint string `json:"te"`
	ClientID      string `json:"cid"`
	ClientMethod  string `json:"cm"`
	AuthMethod    string `json:"am"`
	Resource      string `json:"res"`
	// ServerURL is the server's URL when the flow started: the callback
	// refuses to store a token for a server whose URL changed meanwhile
	// (the token was minted for the old resource and would be sent to
	// the new address).
	ServerURL string   `json:"url"`
	Scopes    []string `json:"sc,omitempty"`
	Exp       int64    `json:"exp"`
}

// sealedState is the wire form of the envelope.
type sealedState struct {
	K string `json:"k"`
	W []byte `json:"w"`
	N []byte `json:"n"`
	C []byte `json:"c"`
}

// encodeState returns "<server id>.<base64url(envelope JSON)>". The server
// ID is in clear so the callback can rebuild the AAD; tampering with it
// fails decryption.
func (s *Service) encodeState(ctx context.Context, st *flowState) (string, error) {
	enc, err := s.seal(ctx, aadState(st.UserID, st.ServerID), st)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(sealedState{K: enc.KeyID, W: enc.WrappedDataKey, N: enc.Nonce, C: enc.Ciphertext})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString([]byte(st.ServerID)) + "." + base64.RawURLEncoding.EncodeToString(raw), nil
}

// decodeState opens a state for userID; any failure is ErrFlowInvalid.
func (s *Service) decodeState(ctx context.Context, userID, value string) (*flowState, error) {
	sid64, body64, ok := strings.Cut(value, ".")
	if !ok || userID == "" {
		return nil, fmt.Errorf("%w: malformed state", ErrFlowInvalid)
	}
	sid, err1 := base64.RawURLEncoding.DecodeString(sid64)
	raw, err2 := base64.RawURLEncoding.DecodeString(body64)
	var ss sealedState
	if err1 != nil || err2 != nil || json.Unmarshal(raw, &ss) != nil || len(sid) == 0 {
		return nil, fmt.Errorf("%w: malformed state", ErrFlowInvalid)
	}
	var st flowState
	enc := store.Encrypted{KeyID: ss.K, WrappedDataKey: ss.W, Nonce: ss.N, Ciphertext: ss.C}
	if err := s.open(ctx, aadState(userID, string(sid)), enc, &st); err != nil {
		return nil, fmt.Errorf("%w: state does not belong to this user", ErrFlowInvalid)
	}
	if st.UserID != userID || st.ServerID != string(sid) {
		return nil, fmt.Errorf("%w: state does not belong to this user", ErrFlowInvalid)
	}
	if !s.clock().Before(time.Unix(st.Exp, 0)) {
		return nil, fmt.Errorf("%w: state expired", ErrFlowInvalid)
	}
	return &st, nil
}

func randomID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("auth: random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// ReplayGuard makes connect-flow states one-use. Use reports whether id
// was unused (and marks it used until until). A multi-replica deployment
// can plug in a shared implementation; the default is per process, which
// together with the authorization server's one-use codes and the PKCE
// verifier bound into the state leaves no replay that yields a token.
type ReplayGuard interface {
	Use(ctx context.Context, id string, until time.Time) (bool, error)
}

// MemoryReplayGuard is the in-process ReplayGuard.
type MemoryReplayGuard struct {
	mu   sync.Mutex
	used map[string]time.Time
	now  func() time.Time
}

// NewMemoryReplayGuard returns an empty in-process ReplayGuard; now
// (default time.Now) must be the clock states are checked against.
func NewMemoryReplayGuard(now func() time.Time) *MemoryReplayGuard {
	if now == nil {
		now = time.Now
	}
	return &MemoryReplayGuard{used: map[string]time.Time{}, now: now}
}

// Use implements ReplayGuard. Entries past their expiry are purged on the
// way (an expired state is refused before Use anyway).
func (g *MemoryReplayGuard) Use(_ context.Context, id string, until time.Time) (bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	for k, exp := range g.used {
		if exp.Before(now) {
			delete(g.used, k)
		}
	}
	if _, seen := g.used[id]; seen {
		return false, nil
	}
	g.used[id] = until
	return true, nil
}
