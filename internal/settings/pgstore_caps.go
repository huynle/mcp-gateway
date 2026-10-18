package settings

import (
	"context"
	"errors"

	"github.com/huynle/mcp-gateway/internal/caps"
	"github.com/huynle/mcp-gateway/internal/store"
)

// pgCapsStore persists resource caps (migration 00028): settings through
// WithJobs (administrators only change them; gateway_app may only read),
// usage counts as the user (row-level security).
type pgCapsStore struct{ st *store.Store }

// NewPostgresCapsStore returns the PostgreSQL CapsStore; st needs the jobs
// pool.
func NewPostgresCapsStore(st *store.Store) CapsStore { return pgCapsStore{st} }

func toValues(m map[string]int) caps.Values {
	out := caps.Values{}
	for k, v := range m {
		out[caps.Resource(k)] = v
	}
	return out
}

func toColumns(p caps.Patch) map[string]*int {
	out := make(map[string]*int, len(p))
	for k, v := range p {
		out[string(k)] = v
	}
	return out
}

func (p pgCapsStore) LoadCaps(ctx context.Context) (CapsSnapshot, error) {
	out := CapsSnapshot{Users: map[string]caps.Values{}, Admins: map[string]bool{}}
	err := p.st.WithJobs(ctx, func(tx store.Tx) error {
		org, version, err := store.GetGatewayResourceCaps(ctx, tx)
		if err != nil {
			return err
		}
		out.Org, out.Version = toValues(org), version
		users, err := store.ListGatewayUserResourceCaps(ctx, tx)
		if err != nil {
			return err
		}
		for u, v := range users {
			out.Users[u] = toValues(v)
		}
		assign, err := store.ListRoleAssignments(ctx, tx)
		if err != nil {
			return err
		}
		for _, a := range assign {
			if a.RoleName == "admin" {
				out.Admins[a.UserID] = true
			}
		}
		return nil
	})
	return out, err
}

func (p pgCapsStore) PatchOrgCaps(ctx context.Context, patch caps.Patch, actor string) error {
	return p.st.WithJobs(ctx, func(tx store.Tx) error { return store.PatchGatewayResourceCaps(ctx, tx, toColumns(patch), actor) })
}

func (p pgCapsStore) PatchUserCaps(ctx context.Context, user string, patch caps.Patch, actor string) error {
	return p.st.WithJobs(ctx, func(tx store.Tx) error {
		return store.PatchGatewayUserResourceCaps(ctx, tx, user, toColumns(patch), actor)
	})
}

func (p pgCapsStore) UsageCaps(ctx context.Context, user string) (caps.Values, error) {
	var out caps.Values
	err := p.st.WithUser(ctx, user, func(tx store.Tx) (err error) {
		out, err = caps.Usage(ctx, tx, user)
		return err
	})
	return out, err
}

// ErrNoUsage is returned by Usage when the store cannot count.
var ErrNoUsage = errors.New("settings: resource usage unavailable")

// Usage returns what user currently holds of every capped resource.
func (s *CapsService) Usage(ctx context.Context, user string) (caps.Values, error) {
	u, ok := s.st.(interface {
		UsageCaps(ctx context.Context, user string) (caps.Values, error)
	})
	if !ok {
		return nil, ErrNoUsage
	}
	return u.UsageCaps(ctx, user)
}
