package machines

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/huynle/mcp-gateway/internal/caps"
	"github.com/huynle/mcp-gateway/internal/store"
)

// pgStore is the Store over *store.Store. Everything runs before a user
// scope exists or across users (approval, enrollment, tokens, the admin
// list) and goes through WithJobs with explicit owner filters; the owner's
// own lists and enrollment codes run WithUser (row security backs the
// filter).
type pgStore struct {
	st   *store.Store
	caps caps.Limiter
}

// NewStore adapts *store.Store (with the jobs pool) to Store; l enforces
// the machines and tunnels caps (nil: unlimited).
func NewStore(st *store.Store, l caps.Limiter) Store { return &pgStore{st: st, caps: l} }

func (p *pgStore) jobs(ctx context.Context, fn func(store.Tx) error) error {
	return p.st.WithJobs(ctx, fn)
}

func isUnique(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "23505"
}

func (p *pgStore) CreateDeviceRequest(ctx context.Context, d *store.MachineDeviceRequest) error {
	err := p.jobs(ctx, func(tx store.Tx) error { return store.CreateMachineDeviceRequest(ctx, tx, d) })
	if isUnique(err) || errors.Is(err, store.ErrUserCodeTaken) {
		return errCodeCollision
	}
	return err
}

func (p *pgStore) DeviceRequestByUserCode(ctx context.Context, hash []byte) (*store.MachineDeviceRequest, error) {
	var d *store.MachineDeviceRequest
	err := p.jobs(ctx, func(tx store.Tx) (err error) {
		d, err = store.GetMachineDeviceRequestByUserCode(ctx, tx, hash)
		return err
	})
	return d, err
}

func (p *pgStore) PollDeviceRequest(ctx context.Context, hash []byte, at time.Time, fn func(*store.MachineDeviceRequest) PollDecision) (*store.MachineDeviceRequest, error) {
	var d *store.MachineDeviceRequest
	err := p.jobs(ctx, func(tx store.Tx) error {
		var err error
		if d, err = store.LockMachineDeviceRequest(ctx, tx, hash); err != nil {
			return err
		}
		dec := fn(d)
		if err := store.TouchMachineDeviceRequestPoll(ctx, tx, d.ID, at, dec.Interval); err != nil {
			return err
		}
		if dec.Consume {
			return store.ConsumeMachineDeviceRequest(ctx, tx, d.ID)
		}
		return nil
	})
	return d, err
}

// createReplacing stores m for m.OwnerUserID inside tx: the owner must be
// active, a live machine of the same name is revoked as replaced (its
// tunnels move to m) and the machines cap applies to the rest.
func (p *pgStore) createReplacing(ctx context.Context, tx store.Tx, m *store.Machine, at time.Time) (string, error) {
	var status string
	if err := tx.QueryRow(ctx, `SELECT status FROM users WHERE id = $1 FOR SHARE`, m.OwnerUserID).Scan(&status); err != nil || status != store.UserActive {
		return "", ErrInactiveOwner
	}
	// Serialises the owner's enrollments (the cap lock is taken below
	// only when a cap applies).
	if err := store.LockUserResourceCap(ctx, tx, m.OwnerUserID, "machine_names"); err != nil {
		return "", err
	}
	replaced := ""
	old, err := store.GetLiveMachineByName(ctx, tx, m.OwnerUserID, m.Name)
	switch {
	case err == nil:
		if err := store.RevokeMachine(ctx, tx, old.ID, m.OwnerUserID, store.MachineReplaced, at); err != nil {
			return "", err
		}
		replaced = old.ID
	case !errors.Is(err, store.ErrNotFound):
		return "", err
	}
	if err := caps.Reserve(ctx, tx, p.caps, m.OwnerUserID, caps.Machines); err != nil {
		return "", err
	}
	if err := store.CreateMachine(ctx, tx, m); err != nil {
		return "", err
	}
	if replaced != "" {
		// The revoked machine's tunnels come back to life on the new one:
		// unrevoke the latest tunnel per server name and move them all.
		if _, err := tx.Exec(ctx, `UPDATE mcp_tunnels SET revoked_at = NULL WHERE machine_id = $1 AND revoked_at = $2`, replaced, at); err != nil {
			return "", err
		}
		if err := store.TransferMachineTunnels(ctx, tx, replaced, m.ID); err != nil {
			return "", err
		}
	}
	return replaced, nil
}

func (p *pgStore) ApproveDeviceRequest(ctx context.Context, requestID, approver string, at time.Time) (*store.Machine, string, error) {
	if !uuidRE.MatchString(requestID) {
		return nil, "", ErrRequestGone
	}
	var m *store.Machine
	var replaced string
	err := p.jobs(ctx, func(tx store.Tx) error {
		d, err := store.LockMachineDeviceRequestByID(ctx, tx, requestID)
		if errors.Is(err, store.ErrNotFound) {
			return ErrRequestGone
		}
		if err != nil {
			return err
		}
		if d.Status != store.MachineRequestPending || !at.Before(d.ExpiresAt) {
			return ErrRequestGone
		}
		m = &store.Machine{OwnerUserID: approver, Name: d.Name, PublicKey: d.PublicKey, Fingerprint: d.Fingerprint,
			ClientVersion: d.ClientVersion, EnrolledVia: store.MachineEnrolledDevice, EnrolledIP: d.RequestIP}
		if replaced, err = p.createReplacing(ctx, tx, m, at); err != nil {
			return err
		}
		return store.DecideMachineDeviceRequest(ctx, tx, d.ID, store.MachineRequestApproved, approver, m.ID, at)
	})
	if err != nil {
		return nil, "", err
	}
	full, err := p.Machine(ctx, m.ID)
	return full, replaced, err
}

func (p *pgStore) DenyDeviceRequest(ctx context.Context, requestID, by string, at time.Time) error {
	if !uuidRE.MatchString(requestID) {
		return ErrRequestGone
	}
	err := p.jobs(ctx, func(tx store.Tx) error {
		d, err := store.LockMachineDeviceRequestByID(ctx, tx, requestID)
		if err != nil {
			return err
		}
		if !at.Before(d.ExpiresAt) {
			return store.ErrNotFound
		}
		return store.DecideMachineDeviceRequest(ctx, tx, requestID, store.MachineRequestDenied, by, "", at)
	})
	if errors.Is(err, store.ErrNotFound) {
		return ErrRequestGone
	}
	return err
}

func (p *pgStore) Enroll(ctx context.Context, codeHash []byte, m *store.Machine, at time.Time) (string, error) {
	var replaced string
	err := p.jobs(ctx, func(tx store.Tx) error {
		c, err := store.ConsumeMachineEnrollmentCode(ctx, tx, codeHash, at)
		if errors.Is(err, store.ErrNotFound) {
			return ErrInvalidCode
		}
		if err != nil {
			return err
		}
		m.OwnerUserID = c.OwnerUserID
		if replaced, err = p.createReplacing(ctx, tx, m, at); err != nil {
			if errors.Is(err, ErrInactiveOwner) {
				return ErrInvalidCode
			}
			return err
		}
		return store.SetMachineEnrollmentCodeMachine(ctx, tx, c.ID, m.ID)
	})
	return replaced, err
}

func (p *pgStore) Machine(ctx context.Context, id string) (*store.Machine, error) {
	if !uuidRE.MatchString(id) {
		return nil, store.ErrNotFound
	}
	var m *store.Machine
	err := p.jobs(ctx, func(tx store.Tx) (err error) {
		m, err = store.GetMachine(ctx, tx, id)
		return err
	})
	return m, err
}

func (p *pgStore) RecordJTI(ctx context.Context, machineID, jti string, exp, now time.Time) (bool, error) {
	var fresh bool
	err := p.jobs(ctx, func(tx store.Tx) (err error) {
		fresh, err = store.RecordMachineAssertionJTI(ctx, tx, machineID, jti, exp, now)
		return err
	})
	return fresh, err
}

func (p *pgStore) IssueToken(ctx context.Context, hash []byte, machineID string, exp time.Time, ip string, at time.Time) error {
	return p.jobs(ctx, func(tx store.Tx) error {
		if err := store.CreateMachineAccessToken(ctx, tx, hash, machineID, exp); err != nil {
			return err
		}
		return store.TouchMachine(ctx, tx, machineID, at, ip)
	})
}

func (p *pgStore) TokenMachine(ctx context.Context, hash []byte, at time.Time) (*store.MachineAccess, error) {
	var a *store.MachineAccess
	err := p.jobs(ctx, func(tx store.Tx) (err error) {
		a, err = store.GetMachineAccessToken(ctx, tx, hash, at)
		return err
	})
	return a, err
}

func (p *pgStore) Revoke(ctx context.Context, id, ownerID, actorID, reason string, at time.Time) (*store.Machine, error) {
	var m *store.Machine
	err := p.jobs(ctx, func(tx store.Tx) error {
		var err error
		if m, err = store.GetMachine(ctx, tx, id); err != nil {
			return err
		}
		if ownerID != "" && m.OwnerUserID != ownerID {
			return store.ErrNotFound
		}
		return store.RevokeMachine(ctx, tx, id, actorID, reason, at)
	})
	return m, err
}

func (p *pgStore) ListMachines(ctx context.Context, ownerID string) ([]store.Machine, error) {
	var out []store.Machine
	err := p.st.WithUser(ctx, ownerID, func(tx store.Tx) (err error) {
		out, err = store.ListMachines(ctx, tx, ownerID)
		return err
	})
	return out, err
}

func (p *pgStore) ListAllMachines(ctx context.Context) ([]store.Machine, error) {
	var out []store.Machine
	err := p.jobs(ctx, func(tx store.Tx) (err error) {
		out, err = store.ListAllMachines(ctx, tx)
		return err
	})
	return out, err
}

func (p *pgStore) MachineTunnels(ctx context.Context, machineID string) ([]store.MCPTunnel, error) {
	var out []store.MCPTunnel
	err := p.jobs(ctx, func(tx store.Tx) (err error) {
		out, err = store.ListMachineTunnels(ctx, tx, machineID)
		return err
	})
	return out, err
}

func (p *pgStore) EnsureTunnel(ctx context.Context, m *store.Machine, server string) (*store.MCPTunnel, bool, error) {
	for attempt := 0; ; attempt++ {
		var t *store.MCPTunnel
		created := false
		err := p.jobs(ctx, func(tx store.Tx) error {
			var err error
			t, err = store.GetMachineTunnel(ctx, tx, m.ID, server)
			if err == nil || !errors.Is(err, store.ErrNotFound) {
				return err
			}
			if err := caps.Reserve(ctx, tx, p.caps, m.OwnerUserID, caps.Tunnels); err != nil {
				return err
			}
			t = &store.MCPTunnel{OwnerUserID: m.OwnerUserID, Name: m.Name + "/" + server, MachineID: m.ID, ServerName: server}
			created = true
			return store.CreateMCPTunnel(ctx, tx, t)
		})
		if isUnique(err) && attempt == 0 {
			continue // a concurrent PUT created it: read it
		}
		return t, created, err
	}
}

func (p *pgStore) RevokeTunnel(ctx context.Context, tunnelID string, at time.Time) error {
	return p.jobs(ctx, func(tx store.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE mcp_tunnels SET revoked_at = $2 WHERE id = $1 AND revoked_at IS NULL`, tunnelID, at)
		return err
	})
}

func (p *pgStore) CreateEnrollmentCode(ctx context.Context, c *store.MachineEnrollmentCode, maxUsable int, at time.Time) error {
	return p.st.WithUser(ctx, c.OwnerUserID, func(tx store.Tx) error {
		if err := store.LockUserResourceCap(ctx, tx, c.OwnerUserID, "machine_enrollment_codes"); err != nil {
			return err
		}
		n, err := store.CountUsableMachineEnrollmentCodes(ctx, tx, c.OwnerUserID, at)
		if err != nil {
			return err
		}
		if n >= maxUsable {
			return ErrTooManyCodes
		}
		return store.CreateMachineEnrollmentCode(ctx, tx, c)
	})
}

func (p *pgStore) ListEnrollmentCodes(ctx context.Context, ownerID string) ([]store.MachineEnrollmentCode, error) {
	var out []store.MachineEnrollmentCode
	err := p.st.WithUser(ctx, ownerID, func(tx store.Tx) (err error) {
		out, err = store.ListMachineEnrollmentCodes(ctx, tx, ownerID)
		return err
	})
	return out, err
}

func (p *pgStore) RevokeEnrollmentCode(ctx context.Context, ownerID, id string, at time.Time) error {
	return p.st.WithUser(ctx, ownerID, func(tx store.Tx) error { return store.RevokeMachineEnrollmentCode(ctx, tx, id, at) })
}
