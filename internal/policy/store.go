package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/store"
)

// postgresStore implements Store over the PostgreSQL store. Everything
// runs through WithJobs: roles and policy versions are global tables, and
// assignments and restrictions are read across every user (admin
// metadata, decision 9z5sdzsm point 3). Admin writes too: they act on
// other users' rows.
type postgresStore struct{ st *store.Store }

// NewPostgresStore returns the production Store.
func NewPostgresStore(st *store.Store) Store { return postgresStore{st: st} }

func (p postgresStore) Load(ctx context.Context) (Snapshot, error) {
	var snap Snapshot
	err := p.st.WithJobs(ctx, func(tx store.Tx) error {
		roles, err := store.ListRoles(ctx, tx)
		if err != nil {
			return err
		}
		for _, r := range roles {
			role, err := RoleFromDefinition(r.Name, r.Description, r.Definition)
			if err != nil {
				return err
			}
			role.MayAddServers = r.MayAddServers
			snap.Roles = append(snap.Roles, StoredRole{Role: role, IsDefault: r.IsDefault})
		}
		assignments, err := store.ListRoleAssignments(ctx, tx)
		if err != nil {
			return err
		}
		for _, a := range assignments {
			snap.Assignments = append(snap.Assignments, Assignment{UserID: a.UserID, Role: a.RoleName})
		}
		restrictions, err := store.ListUserRestrictions(ctx, tx)
		if err != nil {
			return err
		}
		for _, ur := range restrictions {
			u, err := RestrictionFromDefinition(ur.UserID, ur.Definition)
			if err != nil {
				return err
			}
			snap.Restrictions = append(snap.Restrictions, u)
		}
		// The owner layer of user-added MCP servers (OwnerGrant): every
		// active server, private or published (decision q7vbxlyk: the
		// owner keeps access after publishing; role denies still win).
		servers, err := store.ListAllMCPServers(ctx, tx)
		if err != nil {
			return err
		}
		for _, s := range servers {
			if s.Status != store.MCPServerActive {
				continue
			}
			snap.Owners = append(snap.Owners, OwnerGrant{UserID: s.OwnerUserID, App: s.Name})
			// The server's approval modes (ServerApproval): the enabled
			// writes of its approved snapshot set to auto. No approved
			// snapshot, or a review stored before modes existed: every
			// write asks.
			approval, err := serverApproval(ctx, tx, s)
			if err != nil {
				return err
			}
			if len(approval.AutoRun) > 0 {
				snap.Servers = append(snap.Servers, approval)
			}
		}
		return nil
	})
	return snap, err
}

// serverApproval reads the approval modes of s's approved snapshot. A
// review that does not decode counts as "every write asks" (the safe
// default) instead of failing the whole policy load; the connector
// refuses to load such a snapshot and logs it.
func serverApproval(ctx context.Context, tx store.Tx, s store.MCPServer) (ServerApproval, error) {
	out := ServerApproval{App: s.Name}
	row, err := store.ApprovedMCPSnapshot(ctx, tx, s.ID)
	if errors.Is(err, store.ErrNotFound) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	review, _, err := snapshot.DecodeReview(row.Review)
	if err != nil {
		return out, nil
	}
	out.AutoRun = review.AutoRunToolNames()
	return out, nil
}

func (p postgresStore) SaveRole(ctx context.Context, r Role) error {
	def, err := r.MarshalDefinition()
	if err != nil {
		return err
	}
	return p.st.WithJobs(ctx, func(tx store.Tx) error {
		return store.UpsertRole(ctx, tx, r.Name, r.Description, def, r.MayAddServers)
	})
}

func (p postgresStore) DeleteRole(ctx context.Context, name string) error {
	return p.st.WithJobs(ctx, func(tx store.Tx) error {
		n, err := store.CountRoleAssignments(ctx, tx, name)
		if err != nil {
			return err
		}
		if n > 0 {
			return fmt.Errorf("%w: %s (%d users)", ErrRoleAssigned, name, n)
		}
		return store.DeleteRole(ctx, tx, name)
	})
}

func (p postgresStore) SetDefaultRole(ctx context.Context, name string) error {
	return p.st.WithJobs(ctx, func(tx store.Tx) error { return store.SetDefaultRole(ctx, tx, name) })
}

func (p postgresStore) SaveVersion(ctx context.Context, v Version) (Version, error) {
	var createdBy *string
	if v.CreatedBy != "" {
		createdBy = &v.CreatedBy
	}
	source, _ := json.Marshal(map[string]any{"compiler": "mcp-gateway/policy"})
	var out Version
	err := p.st.WithJobs(ctx, func(tx store.Tx) error {
		row, err := store.EnsurePolicyVersion(ctx, tx, &store.PolicyVersion{VersionHash: v.Hash, Cedar: v.Cedar, Source: source, CreatedBy: createdBy})
		if err != nil {
			return err
		}
		out = Version{ID: row.ID, Hash: row.VersionHash, Cedar: row.Cedar, CreatedAt: row.CreatedAt}
		if row.CreatedBy != nil {
			out.CreatedBy = *row.CreatedBy
		}
		return nil
	})
	return out, err
}
