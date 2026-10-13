package settings

import (
	"context"
	"errors"

	"github.com/huynle/mcp-gateway/internal/store"
)

type pgStore struct{ st *store.Store }

func NewPostgresStore(st *store.Store) Store { return pgStore{st} }

func (p pgStore) Load(ctx context.Context) (Snapshot, error) {
	var out Snapshot
	out.Apps = map[string]int{}
	out.Users = map[string]UserLimit{}
	out.Admins = map[string]bool{}
	err := p.st.WithJobs(ctx, func(tx store.Tx) error {
		g, err := store.GetGatewayRateSettings(ctx, tx)
		if err != nil {
			return err
		}
		if g.UserPerMin != nil {
			out.UserDefault = *g.UserPerMin
		}
		if g.AppPerMin != nil {
			out.AppDefault = *g.AppPerMin
		}
		out.Version = g.Version
		apps, err := store.ListGatewayAppRateLimits(ctx, tx)
		if err != nil {
			return err
		}
		for _, x := range apps {
			out.Apps[x.App] = x.PerMin
		}
		users, err := store.ListGatewayUserRateLimits(ctx, tx)
		if err != nil {
			return err
		}
		for _, x := range users {
			out.Users[x.UserID] = UserLimit{Admin: x.AdminPerMin, Self: x.SelfPerMin}
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
func (p pgStore) SetOrg(ctx context.Context, u, a int, actor string) error {
	return p.st.WithJobs(ctx, func(tx store.Tx) error { return store.SetGatewayRateSettings(ctx, tx, &u, &a, actor) })
}
func (p pgStore) SetApp(ctx context.Context, app string, n *int, actor string) error {
	return p.st.WithJobs(ctx, func(tx store.Tx) error { return store.SetGatewayAppRateLimit(ctx, tx, app, n, actor) })
}
func (p pgStore) SetUserAdmin(ctx context.Context, user string, n *int, actor string) error {
	return p.st.WithJobs(ctx, func(tx store.Tx) error {
		var self *int
		x, err := store.GetGatewayUserRateLimit(ctx, tx, user)
		if err == nil {
			self = x.SelfPerMin
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		return store.SetGatewayUserRateLimit(ctx, tx, user, n, self, actor)
	})
}
func (p pgStore) SetUserSelf(ctx context.Context, user string, n *int) error {
	return p.st.WithUser(ctx, user, func(tx store.Tx) error {
		return store.SetGatewayUserSelfRateLimit(ctx, tx, user, n)
	})
}
