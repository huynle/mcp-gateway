package tokens_test

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

// memStore is an in-memory tokens.Store that imitates row-level security:
// under AsUser only the scoped user's tokens are visible; under Bypass every
// row is. touchErr lets a test make TouchToken fail.
type memStore struct {
	mu       sync.Mutex
	seq      int
	users    map[string]*memUser
	tokens   map[string]*store.Token // by id
	touchErr error
}

type memUser struct {
	status     string
	lastSignIn *time.Time
}

func newMemStore() *memStore {
	return &memStore{users: map[string]*memUser{}, tokens: map[string]*store.Token{}}
}

func (m *memStore) addUser(id string, lastSignIn *time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users[id] = &memUser{status: store.UserActive, lastSignIn: lastSignIn}
}

func (m *memStore) setUser(id, status string, lastSignIn *time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users[id] = &memUser{status: status, lastSignIn: lastSignIn}
}

func (m *memStore) token(id string) store.Token {
	m.mu.Lock()
	defer m.mu.Unlock()
	return *m.tokens[id]
}

func (m *memStore) Bypass(_ context.Context, fn func(tokens.Tx) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return fn(&memTx{m: m})
}

func (m *memStore) AsUser(_ context.Context, userID string, fn func(tokens.Tx) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.users[userID]; !ok {
		return store.ErrNotFound
	}
	return fn(&memTx{m: m, scope: userID})
}

type memTx struct {
	m     *memStore
	scope string // "" = bypass
}

func (t *memTx) visible(tok *store.Token) bool { return t.scope == "" || tok.UserID == t.scope }

func (t *memTx) CreateToken(_ context.Context, tok *store.Token) error {
	if !t.visible(tok) {
		return fmt.Errorf("rls: insert for another user")
	}
	for _, other := range t.m.tokens {
		if other.PublicID == tok.PublicID || bytes.Equal(other.TokenHash, tok.TokenHash) {
			return fmt.Errorf("unique violation")
		}
	}
	t.m.seq++
	tok.ID = fmt.Sprintf("00000000-0000-4000-8000-%012x", t.m.seq)
	if tok.CreatedAt.IsZero() {
		tok.CreatedAt = time.Now()
	}
	cp := *tok
	t.m.tokens[tok.ID] = &cp
	return nil
}

func (t *memTx) FindTokenByPublicID(_ context.Context, publicID string) (*store.TokenLookup, error) {
	for _, tok := range t.m.tokens {
		if tok.PublicID == publicID && t.visible(tok) {
			u := t.m.users[tok.UserID]
			return &store.TokenLookup{Token: *tok, UserStatus: u.status, LastCompanySignInAt: u.lastSignIn}, nil
		}
	}
	return nil, store.ErrNotFound
}

func (t *memTx) TouchToken(_ context.Context, id string, at time.Time) error {
	if t.m.touchErr != nil {
		return t.m.touchErr
	}
	if tok, ok := t.m.tokens[id]; ok && t.visible(tok) {
		tok.LastUsedAt = &at
	}
	return nil
}

func (t *memTx) ListTokensForUser(_ context.Context, userID string) ([]store.Token, error) {
	var out []store.Token
	for _, tok := range t.m.tokens {
		if tok.UserID == userID && t.visible(tok) {
			out = append(out, *tok)
		}
	}
	slices.SortFunc(out, func(a, b store.Token) int {
		if c := b.CreatedAt.Compare(a.CreatedAt); c != 0 {
			return c
		}
		return bytes.Compare([]byte(a.ID), []byte(b.ID))
	})
	return out, nil
}

func (t *memTx) RevokeToken(_ context.Context, id string, at time.Time) (time.Time, error) {
	tok, ok := t.m.tokens[id]
	if !ok || !t.visible(tok) {
		return time.Time{}, store.ErrNotFound
	}
	if tok.RevokedAt == nil {
		tok.RevokedAt = &at
	}
	return *tok.RevokedAt, nil
}

func (t *memTx) RevokeUserTokens(_ context.Context, userID string, at time.Time) (int64, error) {
	var n int64
	for _, tok := range t.m.tokens {
		if tok.UserID == userID && t.visible(tok) && tok.RevokedAt == nil {
			tok.RevokedAt = &at
			n++
		}
	}
	return n, nil
}
