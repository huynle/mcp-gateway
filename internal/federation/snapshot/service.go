package snapshot

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/huynle/mcp-gateway/internal/store"
)

// Service errors.
var (
	// ErrReviewNotAllowed: the actor may not add or approve snapshots of
	// this server (not its owner, or the server is published and the actor
	// is not on the admin path).
	ErrReviewNotAllowed = errors.New("snapshot: not allowed to review this server")
	// ErrNoActor: an Actor without a user and without the admin flag.
	ErrNoActor = errors.New("snapshot: no actor")
)

// Scoper is the part of *store.Store the Service needs.
type Scoper interface {
	WithUser(ctx context.Context, userID string, fn func(store.Tx) error) error
	WithJobs(ctx context.Context, fn func(store.Tx) error) error
}

// Actor is who a Service call runs as.
//
// A user actor (Admin false) runs under the store's user scope, so
// row-level security applies: the server must be visible to the user, only
// its owner adds snapshots, and the owner approves only while the server is
// private (decision 17iv8p3b).
//
// An admin actor (Admin true) runs through WithJobs and bypasses those
// rules. The Service does not check admin rights: set Admin only after the
// caller has authorised an admin (portal admin handlers) or for trusted
// system work (System). UserID is then recorded as the approver.
type Actor struct {
	UserID string
	Admin  bool
}

// System is the actor for trusted background work and the federation
// connector after it has checked visibility itself (WithJobs, no approver).
func System() Actor { return Actor{Admin: true} }

// Service stores snapshots and reviews through the store and answers
// whether a call may go upstream.
type Service struct {
	st  Scoper
	now func() time.Time
}

// Option configures a Service.
type Option func(*Service)

// WithClock sets the clock used for review timestamps.
func WithClock(now func() time.Time) Option { return func(s *Service) { s.now = now } }

// NewService returns a Service over st (a *store.Store).
func NewService(st Scoper, opts ...Option) *Service {
	s := &Service{st: st, now: func() time.Time { return time.Now().UTC() }}
	for _, o := range opts {
		o(s)
	}
	return s
}

func (s *Service) in(ctx context.Context, a Actor, fn func(store.Tx) error) error {
	if a.Admin {
		return s.st.WithJobs(ctx, fn)
	}
	if a.UserID == "" {
		return ErrNoActor
	}
	return s.st.WithUser(ctx, a.UserID, fn)
}

// Create discovers the server's capabilities through sess and stores them
// as a pending snapshot (the first one, or the next version). It is Refresh
// without the diff.
func (s *Service) Create(ctx context.Context, a Actor, serverID string, sess Session) (*Record, error) {
	rec, _, err := s.Refresh(ctx, a, serverID, sess)
	return rec, err
}

// Refresh discovers the server's capabilities through sess and stores them
// as a new pending snapshot, returning it and its diff against the approved
// snapshot. When nothing changed since the latest snapshot, no version is
// added and the latest is returned. Discovery runs outside the database
// transaction. Calls keep being served from the approved snapshot until a
// reviewer approves the new one.
func (s *Service) Refresh(ctx context.Context, a Actor, serverID string, sess Session) (*Record, Diff, error) {
	snap, err := Discover(ctx, sess)
	if err != nil {
		return nil, Diff{}, err
	}
	var rec *Record
	var diff Diff
	err = s.in(ctx, a, func(tx store.Tx) error {
		latest, err := loadOptional(store.LatestMCPSnapshot(ctx, tx, serverID))
		if err != nil {
			return err
		}
		if latest != nil && Compare(latest.Snapshot, snap).Empty() {
			rec = latest
		} else {
			row, err := encodeSnapshot(serverID, snap)
			if err != nil {
				return err
			}
			if err := store.CreateMCPSnapshot(ctx, tx, row); err != nil {
				return mapWriteErr(err)
			}
			if rec, err = decodeRecord(row); err != nil {
				return err
			}
		}
		approved, err := loadOptional(store.ApprovedMCPSnapshot(ctx, tx, serverID))
		if err != nil {
			return err
		}
		diff = diffRecords(approved, rec)
		return nil
	})
	if err != nil {
		return nil, Diff{}, err
	}
	return rec, diff, nil
}

// Diff compares the server's latest snapshot with its approved one
// (FromVersion 0 when none is approved; empty when the latest is the
// approved one). ErrNoSnapshot when the server has no snapshot (or is not
// visible to the actor).
func (s *Service) Diff(ctx context.Context, a Actor, serverID string) (Diff, error) {
	var diff Diff
	err := s.in(ctx, a, func(tx store.Tx) error {
		latest, err := loadOptional(store.LatestMCPSnapshot(ctx, tx, serverID))
		if err != nil {
			return err
		}
		if latest == nil {
			return ErrNoSnapshot
		}
		approved, err := loadOptional(store.ApprovedMCPSnapshot(ctx, tx, serverID))
		if err != nil {
			return err
		}
		diff = diffRecords(approved, latest)
		return nil
	})
	return diff, err
}

// Latest returns the server's newest snapshot, whatever its status (the
// one a review page shows).
func (s *Service) Latest(ctx context.Context, a Actor, serverID string) (*Record, error) {
	var rec *Record
	err := s.in(ctx, a, func(tx store.Tx) error {
		var err error
		rec, err = loadOptional(store.LatestMCPSnapshot(ctx, tx, serverID))
		if err == nil && rec == nil {
			err = ErrNoSnapshot
		}
		return err
	})
	return rec, err
}

// Current returns the server's approved snapshot and its review.
// ErrNoSnapshot when none is approved (or the server is not visible).
func (s *Service) Current(ctx context.Context, a Actor, serverID string) (*Record, error) {
	var rec *Record
	err := s.in(ctx, a, func(tx store.Tx) error {
		var err error
		rec, err = loadOptional(store.ApprovedMCPSnapshot(ctx, tx, serverID))
		if err == nil && rec == nil {
			err = ErrNoSnapshot
		}
		return err
	})
	return rec, err
}

// Approve approves snapshot version of the server with the reviewer's
// decisions (see BuildReview): the review starts from the approved
// snapshot's, so unchanged tools keep their state, and new or changed tools
// stay disabled unless enabled here. version must be the latest snapshot
// (approving a refresh) or the approved one (changing decisions);
// otherwise ErrStaleVersion. A user actor may approve only a private
// server it owns; anything else returns ErrReviewNotAllowed and changes
// nothing.
func (s *Service) Approve(ctx context.Context, a Actor, serverID string, version int, d ReviewDecisions) (*Record, error) {
	var rec *Record
	err := s.in(ctx, a, func(tx store.Tx) error {
		latest, err := loadOptional(store.LatestMCPSnapshot(ctx, tx, serverID))
		if err != nil {
			return err
		}
		if latest == nil {
			return ErrNoSnapshot
		}
		approved, err := loadOptional(store.ApprovedMCPSnapshot(ctx, tx, serverID))
		if err != nil {
			return err
		}
		var target *Record
		switch {
		case version == latest.Version:
			target = latest
		case approved != nil && version == approved.Version:
			target = approved
		default:
			return ErrStaleVersion
		}
		var base *Snapshot
		var baseReview Review
		if approved != nil {
			base, baseReview = approved.Snapshot, approved.Review
		}
		review, err := BuildReview(base, baseReview, target.Snapshot, d, a.UserID, s.now())
		if err != nil {
			return err
		}
		raw, err := encodeReview(review)
		if err != nil {
			return err
		}
		if err := store.ApproveMCPSnapshot(ctx, tx, target.ID, a.UserID, raw); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				// Visible (we just read it) but not updatable: RLS.
				return ErrReviewNotAllowed
			}
			return mapWriteErr(err)
		}
		row, err := store.GetMCPSnapshot(ctx, tx, target.ID)
		if err != nil {
			return err
		}
		rec, err = decodeRecord(row)
		return err
	})
	if err != nil {
		return nil, err
	}
	return rec, nil
}

// Allowed decides whether actor's call of tool on the server may go
// upstream: the tool must be enabled in the approved snapshot and args must
// validate against its pinned input schema (see Check). It returns the
// pinned tool and its effective kind. A server the actor cannot see, or
// one without an approved snapshot, gives ErrToolNotReviewed.
func (s *Service) Allowed(ctx context.Context, a Actor, serverID, tool string, args map[string]any) (Tool, Kind, error) {
	var rec *Record
	err := s.in(ctx, a, func(tx store.Tx) error {
		var err error
		rec, err = loadOptional(store.ApprovedMCPSnapshot(ctx, tx, serverID))
		return err
	})
	if err != nil {
		return Tool{}, "", err
	}
	if rec == nil {
		return Tool{}, "", ErrToolNotReviewed
	}
	return Check(rec.Snapshot, rec.Review, tool, args)
}

// loadOptional decodes a row, mapping store.ErrNotFound to nil.
func loadOptional(row *store.MCPSnapshot, err error) (*Record, error) {
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return decodeRecord(row)
}

// diffRecords diffs to against from (nil = nothing approved).
func diffRecords(from, to *Record) Diff {
	var fromSnap *Snapshot
	fromVersion := 0
	if from != nil {
		fromSnap, fromVersion = from.Snapshot, from.Version
	}
	d := Compare(fromSnap, to.Snapshot)
	d.FromVersion, d.ToVersion = fromVersion, to.Version
	return d
}

// mapWriteErr turns a row-level security refusal (42501) into
// ErrReviewNotAllowed.
func mapWriteErr(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "42501" {
		return ErrReviewNotAllowed
	}
	return err
}
