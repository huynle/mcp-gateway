// Package account owns the self-service account lifecycle of the public
// gateway: the data export ("Download my data" on My account) and account
// deletion (self-service with a typed confirmation and a recent sign-in,
// and the admin variant on /admin/users), both over the same service.
//
// Deletion reuses the identity disable hooks (tokens, OAuth harness
// grants, app connections revoked at the vendor) inside one transaction
// with store.DeleteUserData, which removes or empties everything personal
// and leaves a tombstone user row; audit events are kept (append-only
// legal record) under the then pseudonymous user id. Both actions are
// audited in the same transaction (user.data_exported, user.deleted).
//
// Docs: docs/user-guide.md "Your data", docs/runbooks/user-offboarding.md.
package account

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/store"
)

// Audit actions (resource["action"] of the user events).
const (
	ActionDataExported = "user.data_exported"
	ActionDeleted      = "user.deleted"
)

// Defaults.
const (
	// ExportFormat names the export document's schema.
	ExportFormat = "mcp-gateway.user-export.v1"
	// DefaultExportInterval: one export per user per this long.
	DefaultExportInterval = 10 * time.Minute
	// DefaultReauthWindow: self-service deletion needs a company sign-in
	// this recent.
	DefaultReauthWindow = 10 * time.Minute
	// DefaultRowLimit caps each export section; RowLimits overrides it for
	// the long ones.
	DefaultRowLimit = 1000
	// ConfirmPhrase must be typed to delete one's own account,
	// AdminConfirmPhrase to delete someone else's (/admin/users).
	ConfirmPhrase      = "delete my account"
	AdminConfirmPhrase = "delete this account"
)

// RowLimits are the per-section caps that differ from DefaultRowLimit
// (newest rows first; the export marks a capped section truncated).
var RowLimits = map[string]int{
	"audit_events":      10000,
	"ledger_operations": 5000,
	"approvals":         5000,
}

// Errors.
var (
	ErrExportTooSoon  = errors.New("account: export rate limited")
	ErrReauthRequired = errors.New("account: a recent sign-in is required")
	ErrBlocked        = errors.New("account: deletion blocked")
	ErrOwnAccount     = errors.New("account: admins delete their own account from My account")
)

// ExportTooSoonError is ErrExportTooSoon with the wait.
type ExportTooSoonError struct{ RetryAfter time.Duration }

func (e *ExportTooSoonError) Error() string {
	return fmt.Sprintf("account: export rate limited, retry in %s", e.RetryAfter.Round(time.Second))
}

// Is makes errors.Is(err, ErrExportTooSoon) true.
func (e *ExportTooSoonError) Is(target error) bool { return target == ErrExportTooSoon }

// BlockedError is ErrBlocked with the reasons, written for the person
// (shown on the confirm page).
type BlockedError struct{ Reasons []string }

func (e *BlockedError) Error() string {
	return "account: deletion blocked: " + strings.Join(e.Reasons, "; ")
}

// Is makes errors.Is(err, ErrBlocked) true.
func (e *BlockedError) Is(target error) bool { return target == ErrBlocked }

// Store is *store.Store.
type Store interface {
	WithUser(ctx context.Context, userID string, fn func(store.Tx) error) error
	WithJobs(ctx context.Context, fn func(store.Tx) error) error
}

// Identity is the part of *identity.Service deletion uses.
type Identity interface {
	RunDisableHooks(ctx context.Context, tx store.Tx, userID string) error
	IsBootstrapAdmin(issuer, subject string) bool
}

// Options configures New; everything is optional.
type Options struct {
	ExportInterval time.Duration
	ReauthWindow   time.Duration
	// OnDeleted runs after a deletion committed (the federation reloads
	// its servers so deleted private servers leave the tool registry).
	OnDeleted func(ctx context.Context, userID string, d *store.UserDeletion)
	Log       *slog.Logger
	Now       func() time.Time
}

// Service is the account lifecycle service.
type Service struct {
	st Store
	id Identity
	o  Options
}

// New builds the service.
func New(st Store, id Identity, o Options) *Service {
	if o.ExportInterval <= 0 {
		o.ExportInterval = DefaultExportInterval
	}
	if o.ReauthWindow <= 0 {
		o.ReauthWindow = DefaultReauthWindow
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Service{st: st, id: id, o: o}
}

// ReauthWindow is how recent a sign-in self-service deletion needs.
func (s *Service) ReauthWindow() time.Duration { return s.o.ReauthWindow }

// --- export ------------------------------------------------------------------

// Export writes userID's data as one JSON document to w, section by
// section (each section its own short user-scoped transaction, capped at
// its row limit). It first claims the export: at most one per
// ExportInterval (ExportTooSoonError otherwise), recorded as a
// user.data_exported audit event in the same transaction, so an aborted
// download still counts.
func (s *Service) Export(ctx context.Context, userID string, w io.Writer) error {
	now := s.o.Now().UTC()
	if err := s.claimExport(ctx, userID, now); err != nil {
		return err
	}
	limits := map[string]int{}
	for _, sec := range store.ExportSections {
		limits[sec] = rowLimit(sec)
	}
	head, err := json.Marshal(map[string]any{
		"format":      ExportFormat,
		"user_id":     userID,
		"exported_at": now.Format(time.RFC3339),
		"note": "Metadata of your account. Never included: tokens, secrets, credentials, approval arguments. " +
			"Each section holds at most row_limits rows, newest first; a truncated section says so.",
		"row_limits": limits,
	})
	if err != nil {
		return err
	}
	// Open the object, keep it open for "sections".
	if _, err := w.Write(append(head[:len(head)-1], []byte(`,"sections":{`)...)); err != nil {
		return err
	}
	for i, sec := range store.ExportSections {
		var rows []json.RawMessage
		var truncated bool
		err := s.st.WithUser(ctx, userID, func(tx store.Tx) error {
			var err error
			rows, truncated, err = store.ExportSection(ctx, tx, sec, userID, limits[sec])
			return err
		})
		if err != nil {
			return fmt.Errorf("account: export: %w", err)
		}
		body := struct {
			Rows      []json.RawMessage `json:"rows"`
			Truncated bool              `json:"truncated"`
			Note      string            `json:"note,omitempty"`
		}{Rows: rows, Truncated: truncated}
		if truncated {
			body.Note = "Only the newest " + strconv.Itoa(limits[sec]) + " rows are included. Ask an administrator for a complete export."
		}
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		key, _ := json.Marshal(sec)
		sep := ","
		if i == 0 {
			sep = ""
		}
		if _, err := fmt.Fprintf(w, "%s%s:%s", sep, key, b); err != nil {
			return err
		}
	}
	_, err = io.WriteString(w, "}}\n")
	return err
}

func rowLimit(section string) int {
	if n, ok := RowLimits[section]; ok {
		return n
	}
	return DefaultRowLimit
}

func (s *Service) claimExport(ctx context.Context, userID string, now time.Time) error {
	err := s.st.WithUser(ctx, userID, func(tx store.Tx) error {
		// One claim per user at a time, so two parallel requests cannot
		// both pass the check.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('mcp-gateway:export:' || $1::text))`, userID); err != nil {
			return err
		}
		last, err := store.LastUserAuditAction(ctx, tx, userID, ActionDataExported)
		if err != nil {
			return err
		}
		if last != nil {
			if wait := last.Add(s.o.ExportInterval).Sub(now); wait > 0 {
				return &ExportTooSoonError{RetryAfter: wait}
			}
		}
		return tx.Audit().Create(ctx, userEvent(ctx, userID, map[string]string{"action": ActionDataExported}))
	})
	var soon *ExportTooSoonError
	if errors.As(err, &soon) {
		return soon
	}
	if err != nil {
		return fmt.Errorf("account: export: %w", err)
	}
	s.o.Log.Info("user data exported", "event", ActionDataExported, "user_id", userID)
	return nil
}

// userEvent is the audit row of a user action, shaped like
// audit.StoreRecorder's (event_type user, details request_id only).
func userEvent(ctx context.Context, userID string, resource map[string]string) *store.AuditEvent {
	res, _ := json.Marshal(resource)
	details, _ := json.Marshal(map[string]string{"request_id": observability.RequestIDFromContext(ctx)})
	outcome := "succeeded"
	return &store.AuditEvent{
		EventType: "user", UserID: &userID, Resource: res, Decision: "allow", Outcome: &outcome, Details: details,
	}
}

// --- deletion ----------------------------------------------------------------

// Status is what the deletion confirm page shows.
type Status struct {
	DisplayName string
	LastSignIn  *time.Time
	// Fresh: the last company sign-in is within ReauthWindow.
	Fresh bool
	// Blockers explain why the account cannot be deleted now.
	Blockers []string
}

// Status reports whether userID could be deleted now.
func (s *Service) Status(ctx context.Context, userID string) (*Status, error) {
	var out *Status
	err := s.st.WithJobs(ctx, func(tx store.Tx) error {
		u, err := liveUser(ctx, tx, userID)
		if err != nil {
			return err
		}
		blockers, err := s.blockers(ctx, tx, u)
		if err != nil {
			return err
		}
		out = &Status{DisplayName: u.DisplayName, LastSignIn: u.LastCompanySignInAt, Fresh: s.fresh(u), Blockers: blockers}
		return nil
	})
	return out, err
}

// DeleteSelf deletes the caller's own account; it needs a company sign-in
// within ReauthWindow (ErrReauthRequired) and no blockers (BlockedError).
// The portal checks the typed ConfirmPhrase.
func (s *Service) DeleteSelf(ctx context.Context, userID string) error {
	return s.delete(ctx, userID, userID, true)
}

// DeleteByAdmin is the admin variant (/admin/users): same effect and
// blockers, no sign-in freshness of the target; an admin's own account
// goes through DeleteSelf (ErrOwnAccount).
func (s *Service) DeleteByAdmin(ctx context.Context, actorID, userID string) error {
	if actorID == userID {
		return ErrOwnAccount
	}
	return s.delete(ctx, actorID, userID, false)
}

func (s *Service) delete(ctx context.Context, actorID, userID string, self bool) error {
	now := s.o.Now().UTC()
	var del *store.UserDeletion
	err := s.st.WithJobs(ctx, func(tx store.Tx) error {
		if err := store.LockAccountDeletion(ctx, tx); err != nil {
			return err
		}
		u, err := liveUser(ctx, tx, userID)
		if err != nil {
			return err
		}
		if self && !s.fresh(u) {
			return ErrReauthRequired
		}
		blockers, err := s.blockers(ctx, tx, u)
		if err != nil {
			return err
		}
		if len(blockers) > 0 {
			return &BlockedError{Reasons: blockers}
		}
		if err := s.id.RunDisableHooks(ctx, tx, userID); err != nil {
			return err
		}
		if del, err = store.DeleteUserData(ctx, tx, userID, now); err != nil {
			return err
		}
		res := map[string]string{
			"action": ActionDeleted, "by": "self",
			"servers": strconv.Itoa(len(del.ServerIDs)), "tunnels": strconv.FormatInt(del.Tunnels, 10),
			"connections": strconv.FormatInt(del.Connections, 10),
		}
		if !self {
			res["by"] = "admin"
			res["target_user_id"] = userID
		}
		return tx.Audit().Create(ctx, userEvent(ctx, actorID, res))
	})
	if err != nil {
		var be *BlockedError
		if errors.As(err, &be) || errors.Is(err, ErrReauthRequired) || errors.Is(err, store.ErrNotFound) {
			return err
		}
		return fmt.Errorf("account: delete: %w", err)
	}
	s.o.Log.Info("user deleted", "event", ActionDeleted, "user_id", userID, "actor_user_id", actorID, "self", self,
		"servers", len(del.ServerIDs), "tunnels", del.Tunnels, "connections", del.Connections, "approvals", del.Approvals)
	if s.o.OnDeleted != nil {
		s.o.OnDeleted(ctx, userID, del)
	}
	return nil
}

func (s *Service) fresh(u *store.User) bool {
	if u.LastCompanySignInAt == nil {
		return false
	}
	age := s.o.Now().Sub(*u.LastCompanySignInAt)
	return age >= -time.Minute && age <= s.o.ReauthWindow
}

// liveUser loads a user that is not deleted (ErrNotFound otherwise).
func liveUser(ctx context.Context, tx store.Tx, userID string) (*store.User, error) {
	u, err := tx.Users().Get(ctx, userID)
	if err != nil {
		return nil, err
	}
	if u.Status == store.UserDeleted {
		return nil, store.ErrNotFound
	}
	return u, nil
}

// blockers: a bootstrap admin (would be recreated with admin on the next
// sign-in), the last active admin, an owner of published MCP servers
// (shared with other users: an admin unpublishes or deletes them first;
// the gateway does not transfer ownership).
func (s *Service) blockers(ctx context.Context, tx store.Tx, u *store.User) ([]string, error) {
	var out []string
	idents, err := store.ListIdentitiesForUser(ctx, tx, u.ID)
	if err != nil {
		return nil, err
	}
	for _, i := range idents {
		if s.id.IsBootstrapAdmin(i.Issuer, i.Subject) {
			out = append(out, "This account is a bootstrap admin (GATEWAY_BOOTSTRAP_ADMINS) and would get admin again on its next sign-in. Remove it from the gateway configuration first.")
			break
		}
	}
	roles, err := store.RolesForUser(ctx, tx, u.ID)
	if err != nil {
		return nil, err
	}
	if u.Status == store.UserActive && slices.ContainsFunc(roles, func(r store.Role) bool { return r.Name == identity.AdminRole }) {
		n, err := store.CountActiveUsersWithRole(ctx, tx, identity.AdminRole)
		if err != nil {
			return nil, err
		}
		if n <= 1 {
			out = append(out, "This is the last admin account. Give another user the admin role first.")
		}
	}
	names, err := store.PublishedMCPServersOwnedBy(ctx, tx, u.ID)
	if err != nil {
		return nil, err
	}
	if len(names) > 0 {
		out = append(out, "The account owns published MCP servers ("+strings.Join(names, ", ")+"), which other users rely on. An admin must unpublish or delete them first.")
	}
	return out, nil
}
