package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// Enrolled machines (migration 00030, Brain decision ldjix4y1). The token
// endpoint, enrollment, the machine API and the machine connection run
// before any user is known and use WithJobs, with explicit owner checks in
// the callers; the portal lists a user's machines and manages their
// enrollment codes under WithUser.

// Machine enrollment methods.
const (
	MachineEnrolledDevice = "device"
	MachineEnrolledCode   = "enrollment_code"
)

// Machine revocation reasons.
const (
	MachineRevokedByOwner = "owner"
	MachineRevokedByAdmin = "admin"
	MachineRevokedSelf    = "self"
	MachineReplaced       = "replaced"
	MachineOwnerDeleted   = "deleted"
)

// Device request states.
const (
	MachineRequestPending  = "pending"
	MachineRequestApproved = "approved"
	MachineRequestDenied   = "denied"
	MachineRequestConsumed = "consumed"
)

// ErrMachineNameTaken: the owner already has a live machine of that name.
var ErrMachineNameTaken = errors.New("store: machine name taken")

// Machine is an enrolled machine. OwnerName and OwnerStatus are filled by
// the lookups that join users (GetMachine, ListAllMachines, token lookup).
type Machine struct {
	ID            string
	OwnerUserID   string
	Name          string
	PublicKey     []byte
	Fingerprint   string
	ClientVersion string
	EnrolledVia   string
	EnrolledIP    string
	CreatedAt     time.Time
	LastSeenAt    *time.Time
	LastIP        string
	RevokedAt     *time.Time
	RevokedBy     string
	RevokeReason  string

	OwnerName   string
	OwnerStatus string
}

// Live reports whether the machine may act: not revoked and its owner
// active (only meaningful when OwnerStatus was loaded).
func (m *Machine) Live() bool { return m.RevokedAt == nil && m.OwnerStatus == UserActive }

const machineColumns = `m.id, m.owner_user_id, m.name, m.public_key, m.fingerprint, m.client_version, m.enrolled_via,
	m.enrolled_ip, m.created_at, m.last_seen_at, m.last_ip, m.revoked_at, m.revoked_by, m.revoke_reason`

func scanMachine(row interface{ Scan(dest ...any) error }, m *Machine, extra ...any) error {
	var by, reason *string
	dest := append([]any{&m.ID, &m.OwnerUserID, &m.Name, &m.PublicKey, &m.Fingerprint, &m.ClientVersion, &m.EnrolledVia,
		&m.EnrolledIP, &m.CreatedAt, &m.LastSeenAt, &m.LastIP, &m.RevokedAt, &by, &reason}, extra...)
	if err := row.Scan(dest...); err != nil {
		return err
	}
	m.RevokedBy, m.RevokeReason = deref(by), deref(reason)
	return nil
}

// CreateMachine stores a machine; the stored row is written back into m.
// ErrMachineNameTaken when the owner has a live machine of that name.
func CreateMachine(ctx context.Context, q Querier, m *Machine) error {
	err := scanMachine(q.QueryRow(ctx, `
		INSERT INTO machines AS m (owner_user_id, name, public_key, fingerprint, client_version, enrolled_via, enrolled_ip)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING `+machineColumns,
		m.OwnerUserID, m.Name, m.PublicKey, m.Fingerprint, m.ClientVersion, m.EnrolledVia, m.EnrolledIP), m)
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "23505" {
		return ErrMachineNameTaken
	}
	if err != nil {
		return fmt.Errorf("store: create machine: %w", err)
	}
	return nil
}

// GetMachine returns a machine with its owner's name and status.
func GetMachine(ctx context.Context, q Querier, id string) (*Machine, error) {
	var m Machine
	err := scanMachine(q.QueryRow(ctx, `SELECT `+machineColumns+`, u.display_name, u.status
		FROM machines m JOIN users u ON u.id = m.owner_user_id WHERE m.id = $1`, id), &m, &m.OwnerName, &m.OwnerStatus)
	if err != nil {
		return nil, notFound(err)
	}
	return &m, nil
}

// GetLiveMachineByName returns ownerID's live machine called name.
func GetLiveMachineByName(ctx context.Context, q Querier, ownerID, name string) (*Machine, error) {
	var m Machine
	err := scanMachine(q.QueryRow(ctx, `SELECT `+machineColumns+` FROM machines m
		WHERE m.owner_user_id = $1 AND m.name = $2 AND m.revoked_at IS NULL`, ownerID, name), &m)
	if err != nil {
		return nil, notFound(err)
	}
	return &m, nil
}

// ListMachines returns ownerID's machines, live first, newest first.
func ListMachines(ctx context.Context, q Querier, ownerID string) ([]Machine, error) {
	return listMachines(ctx, q, `SELECT `+machineColumns+`, '', '' FROM machines m WHERE m.owner_user_id = $1
		ORDER BY m.revoked_at IS NOT NULL, m.created_at DESC, m.id`, ownerID)
}

// ListAllMachines returns every machine with its owner's name (admin
// page, WithJobs), live first, newest first.
func ListAllMachines(ctx context.Context, q Querier) ([]Machine, error) {
	return listMachines(ctx, q, `SELECT `+machineColumns+`, u.display_name, u.status
		FROM machines m JOIN users u ON u.id = m.owner_user_id
		ORDER BY m.revoked_at IS NOT NULL, m.created_at DESC, m.id`)
}

func listMachines(ctx context.Context, q Querier, sql string, args ...any) ([]Machine, error) {
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list machines: %w", err)
	}
	defer rows.Close()
	var out []Machine
	for rows.Next() {
		var m Machine
		if err := scanMachine(rows, &m, &m.OwnerName, &m.OwnerStatus); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// RevokeMachine revokes a live machine and its tunnels. Its access tokens
// stay until they expire so the machine API can answer "revoked" (every
// use checks Live). by is the acting user ("" for none). ErrNotFound when
// the machine does not exist or is already revoked.
func RevokeMachine(ctx context.Context, q Querier, id, by, reason string, at time.Time) error {
	tag, err := q.Exec(ctx, `UPDATE machines SET revoked_at = $2, revoked_by = $3, revoke_reason = $4
		WHERE id = $1 AND revoked_at IS NULL`, id, at, nullString(by), reason)
	if err != nil {
		return fmt.Errorf("store: revoke machine: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if _, err := q.Exec(ctx, `UPDATE mcp_tunnels SET revoked_at = $2 WHERE machine_id = $1 AND revoked_at IS NULL`, id, at); err != nil {
		return fmt.Errorf("store: revoke machine tunnels: %w", err)
	}
	return nil
}

// TransferMachineTunnels moves every tunnel of machine from to machine to
// (same owner: a re-enrolled machine replacing an older one).
func TransferMachineTunnels(ctx context.Context, q Querier, from, to string) error {
	if _, err := q.Exec(ctx, `UPDATE mcp_tunnels SET machine_id = $2 WHERE machine_id = $1`, from, to); err != nil {
		return fmt.Errorf("store: transfer machine tunnels: %w", err)
	}
	return nil
}

// TouchMachine records that the machine was seen at at (and from ip, when
// not empty).
func TouchMachine(ctx context.Context, q Querier, id string, at time.Time, ip string) error {
	_, err := q.Exec(ctx, `UPDATE machines SET last_seen_at = $2, last_ip = CASE WHEN $3 = '' THEN last_ip ELSE $3 END
		WHERE id = $1`, id, at, ip)
	if err != nil {
		return fmt.Errorf("store: touch machine: %w", err)
	}
	return nil
}

// MachineTunnelIDs returns the machine's live tunnel ids and whether the
// machine is live (not revoked, owner active). An unknown machine is
// (nil, false, nil).
func MachineTunnelIDs(ctx context.Context, q Querier, machineID string) ([]string, bool, error) {
	var live bool
	var ids []string
	err := q.QueryRow(ctx, `SELECT m.revoked_at IS NULL AND u.status = 'active',
			coalesce(array(SELECT t.id::text FROM mcp_tunnels t WHERE t.machine_id = m.id AND t.revoked_at IS NULL ORDER BY t.id), '{}')
		FROM machines m JOIN users u ON u.id = m.owner_user_id WHERE m.id = $1`, machineID).Scan(&live, &ids)
	if err != nil {
		if errors.Is(notFound(err), ErrNotFound) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("store: machine tunnels: %w", err)
	}
	if !live {
		return nil, false, nil
	}
	return ids, true, nil
}

// GetMachineTunnel returns the machine's live tunnel for serverName.
func GetMachineTunnel(ctx context.Context, q Querier, machineID, serverName string) (*MCPTunnel, error) {
	var t MCPTunnel
	if err := scanMCPTunnel(q.QueryRow(ctx, `SELECT `+mcpTunnelColumns+` FROM mcp_tunnels
		WHERE machine_id = $1 AND server_name = $2 AND revoked_at IS NULL`, machineID, serverName), &t); err != nil {
		return nil, notFound(err)
	}
	return &t, nil
}

// ListMachineTunnels returns the machine's tunnels, revoked ones included.
func ListMachineTunnels(ctx context.Context, q Querier, machineID string) ([]MCPTunnel, error) {
	rows, err := q.Query(ctx, `SELECT `+mcpTunnelColumns+` FROM mcp_tunnels WHERE machine_id = $1
		ORDER BY server_name, created_at DESC`, machineID)
	if err != nil {
		return nil, fmt.Errorf("store: list machine tunnels: %w", err)
	}
	defer rows.Close()
	var out []MCPTunnel
	for rows.Next() {
		var t MCPTunnel
		if err := scanMCPTunnel(rows, &t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// CountUserLiveMachines counts userID's machines that are not revoked.
func CountUserLiveMachines(ctx context.Context, q Querier, userID string) (int, error) {
	return count(ctx, q, "machines", `SELECT count(*) FROM machines WHERE owner_user_id = $1 AND revoked_at IS NULL`, userID)
}

// --- device requests -------------------------------------------------------------

// MachineDeviceRequest is a pending device authorization (RFC 8628 style).
type MachineDeviceRequest struct {
	ID             string
	DeviceCodeHash []byte
	UserCodeHash   []byte
	Name           string
	PublicKey      []byte
	Fingerprint    string
	ClientVersion  string
	RequestIP      string
	CreatedAt      time.Time
	ExpiresAt      time.Time
	Interval       int
	LastPolledAt   *time.Time
	Status         string
	DecidedBy      string
	DecidedAt      *time.Time
	MachineID      string
}

const deviceRequestColumns = `id, device_code_hash, user_code_hash, name, public_key, fingerprint, client_version, request_ip,
	created_at, expires_at, interval_seconds, last_polled_at, status, decided_by, decided_at, machine_id`

func scanDeviceRequest(row interface{ Scan(dest ...any) error }, d *MachineDeviceRequest) error {
	var by, machine *string
	if err := row.Scan(&d.ID, &d.DeviceCodeHash, &d.UserCodeHash, &d.Name, &d.PublicKey, &d.Fingerprint, &d.ClientVersion,
		&d.RequestIP, &d.CreatedAt, &d.ExpiresAt, &d.Interval, &d.LastPolledAt, &d.Status, &by, &d.DecidedAt, &machine); err != nil {
		return err
	}
	d.DecidedBy, d.MachineID = deref(by), deref(machine)
	return nil
}

// CreateMachineDeviceRequest stores a device request (status pending);
// the stored row is written back into d. Requests that expired a day ago
// are deleted on the way.
func CreateMachineDeviceRequest(ctx context.Context, q Querier, d *MachineDeviceRequest) error {
	if _, err := q.Exec(ctx, `DELETE FROM machine_device_requests WHERE expires_at < now() - interval '1 day'`); err != nil {
		return fmt.Errorf("store: prune device requests: %w", err)
	}
	err := scanDeviceRequest(q.QueryRow(ctx, `
		INSERT INTO machine_device_requests (device_code_hash, user_code_hash, name, public_key, fingerprint, client_version,
			request_ip, expires_at, interval_seconds)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING `+deviceRequestColumns,
		d.DeviceCodeHash, d.UserCodeHash, d.Name, d.PublicKey, d.Fingerprint, d.ClientVersion, d.RequestIP, d.ExpiresAt, d.Interval), d)
	if err != nil {
		return fmt.Errorf("store: create device request: %w", err)
	}
	return nil
}

// GetMachineDeviceRequestByUserCode finds a request by user code hash, in
// any state.
func GetMachineDeviceRequestByUserCode(ctx context.Context, q Querier, hash []byte) (*MachineDeviceRequest, error) {
	var d MachineDeviceRequest
	if err := scanDeviceRequest(q.QueryRow(ctx, `SELECT `+deviceRequestColumns+` FROM machine_device_requests
		WHERE user_code_hash = $1`, hash), &d); err != nil {
		return nil, notFound(err)
	}
	return &d, nil
}

// LockMachineDeviceRequest finds a request by device code hash and locks
// it until the transaction ends (token endpoint polls).
func LockMachineDeviceRequest(ctx context.Context, q Querier, hash []byte) (*MachineDeviceRequest, error) {
	var d MachineDeviceRequest
	if err := scanDeviceRequest(q.QueryRow(ctx, `SELECT `+deviceRequestColumns+` FROM machine_device_requests
		WHERE device_code_hash = $1 FOR UPDATE`, hash), &d); err != nil {
		return nil, notFound(err)
	}
	return &d, nil
}

// LockMachineDeviceRequestByID locks a request by id (the approval page).
func LockMachineDeviceRequestByID(ctx context.Context, q Querier, id string) (*MachineDeviceRequest, error) {
	var d MachineDeviceRequest
	if err := scanDeviceRequest(q.QueryRow(ctx, `SELECT `+deviceRequestColumns+` FROM machine_device_requests
		WHERE id = $1 FOR UPDATE`, id), &d); err != nil {
		return nil, notFound(err)
	}
	return &d, nil
}

// TouchMachineDeviceRequestPoll records a poll and the (possibly raised)
// interval.
func TouchMachineDeviceRequestPoll(ctx context.Context, q Querier, id string, at time.Time, interval int) error {
	if _, err := q.Exec(ctx, `UPDATE machine_device_requests SET last_polled_at = $2, interval_seconds = $3 WHERE id = $1`,
		id, at, interval); err != nil {
		return fmt.Errorf("store: touch device request: %w", err)
	}
	return nil
}

// DecideMachineDeviceRequest approves (with the created machine) or
// denies a pending request; ErrNotFound when it is not pending.
func DecideMachineDeviceRequest(ctx context.Context, q Querier, id, status, by, machineID string, at time.Time) error {
	tag, err := q.Exec(ctx, `UPDATE machine_device_requests SET status = $2, decided_by = $3, machine_id = $4, decided_at = $5
		WHERE id = $1 AND status = 'pending'`, id, status, nullString(by), nullString(machineID), at)
	if err != nil {
		return fmt.Errorf("store: decide device request: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ConsumeMachineDeviceRequest marks an approved request consumed (the
// machine id is handed out once); ErrNotFound when it is not approved.
func ConsumeMachineDeviceRequest(ctx context.Context, q Querier, id string) error {
	tag, err := q.Exec(ctx, `UPDATE machine_device_requests SET status = 'consumed' WHERE id = $1 AND status = 'approved'`, id)
	if err != nil {
		return fmt.Errorf("store: consume device request: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// --- enrollment codes ------------------------------------------------------------

// MachineEnrollmentCode is a one-time code that enrolls a machine for its
// owner without a browser (headless hosts).
type MachineEnrollmentCode struct {
	ID          string
	OwnerUserID string
	CodeHash    []byte
	Label       string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	UsedAt      *time.Time
	MachineID   string
	RevokedAt   *time.Time
}

const enrollmentCodeColumns = `id, owner_user_id, code_hash, label, created_at, expires_at, used_at, machine_id, revoked_at`

func scanEnrollmentCode(row interface{ Scan(dest ...any) error }, c *MachineEnrollmentCode) error {
	var machine *string
	if err := row.Scan(&c.ID, &c.OwnerUserID, &c.CodeHash, &c.Label, &c.CreatedAt, &c.ExpiresAt, &c.UsedAt, &machine, &c.RevokedAt); err != nil {
		return err
	}
	c.MachineID = deref(machine)
	return nil
}

// CreateMachineEnrollmentCode stores a code (run as its owner).
func CreateMachineEnrollmentCode(ctx context.Context, q Querier, c *MachineEnrollmentCode) error {
	if err := scanEnrollmentCode(q.QueryRow(ctx, `
		INSERT INTO machine_enrollment_codes (owner_user_id, code_hash, label, expires_at) VALUES ($1, $2, $3, $4)
		RETURNING `+enrollmentCodeColumns, c.OwnerUserID, c.CodeHash, c.Label, c.ExpiresAt), c); err != nil {
		return fmt.Errorf("store: create enrollment code: %w", err)
	}
	return nil
}

// ListMachineEnrollmentCodes returns ownerID's codes, newest first.
func ListMachineEnrollmentCodes(ctx context.Context, q Querier, ownerID string) ([]MachineEnrollmentCode, error) {
	rows, err := q.Query(ctx, `SELECT `+enrollmentCodeColumns+` FROM machine_enrollment_codes WHERE owner_user_id = $1
		ORDER BY created_at DESC, id`, ownerID)
	if err != nil {
		return nil, fmt.Errorf("store: list enrollment codes: %w", err)
	}
	defer rows.Close()
	var out []MachineEnrollmentCode
	for rows.Next() {
		var c MachineEnrollmentCode
		if err := scanEnrollmentCode(rows, &c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// CountUsableMachineEnrollmentCodes counts ownerID's codes that are
// neither used, revoked nor expired at at.
func CountUsableMachineEnrollmentCodes(ctx context.Context, q Querier, ownerID string, at time.Time) (int, error) {
	return count(ctx, q, "enrollment codes", `SELECT count(*) FROM machine_enrollment_codes WHERE owner_user_id = $1
		AND used_at IS NULL AND revoked_at IS NULL AND expires_at > $2`, ownerID, at)
}

// RevokeMachineEnrollmentCode revokes an unused code (row security: the
// caller's own); ErrNotFound otherwise.
func RevokeMachineEnrollmentCode(ctx context.Context, q Querier, id string, at time.Time) error {
	tag, err := q.Exec(ctx, `UPDATE machine_enrollment_codes SET revoked_at = $2
		WHERE id = $1 AND used_at IS NULL AND revoked_at IS NULL`, id, at)
	if err != nil {
		return notFound(fmt.Errorf("store: revoke enrollment code: %w", err))
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ConsumeMachineEnrollmentCode marks a usable code used in one statement
// (concurrent consumers: exactly one wins) and returns it. ErrNotFound
// when the code is unknown, used, revoked, expired or its owner is not
// active. Link the machine with SetMachineEnrollmentCodeMachine in the
// same transaction.
func ConsumeMachineEnrollmentCode(ctx context.Context, q Querier, hash []byte, at time.Time) (*MachineEnrollmentCode, error) {
	var c MachineEnrollmentCode
	err := scanEnrollmentCode(q.QueryRow(ctx, `UPDATE machine_enrollment_codes SET used_at = $2
		WHERE code_hash = $1 AND used_at IS NULL AND revoked_at IS NULL AND expires_at > $2
			AND EXISTS (SELECT 1 FROM users u WHERE u.id = owner_user_id AND u.status = 'active')
		RETURNING `+enrollmentCodeColumns, hash, at), &c)
	if err != nil {
		return nil, notFound(err)
	}
	return &c, nil
}

// SetMachineEnrollmentCodeMachine records the machine a code enrolled.
func SetMachineEnrollmentCodeMachine(ctx context.Context, q Querier, codeID, machineID string) error {
	if _, err := q.Exec(ctx, `UPDATE machine_enrollment_codes SET machine_id = $2 WHERE id = $1`, codeID, machineID); err != nil {
		return fmt.Errorf("store: link enrollment code: %w", err)
	}
	return nil
}

// --- access tokens and assertions --------------------------------------------------

// MachineAccess is a valid machine access token's machine (with owner
// name and status).
type MachineAccess struct {
	Machine   Machine
	ExpiresAt time.Time
}

// Live reports whether the machine may act.
func (a *MachineAccess) Live() bool { return a.Machine.Live() }

// CreateMachineAccessToken stores an access token hash; expired tokens
// are deleted on the way.
func CreateMachineAccessToken(ctx context.Context, q Querier, hash []byte, machineID string, expires time.Time) error {
	if _, err := q.Exec(ctx, `DELETE FROM machine_access_tokens WHERE expires_at < now() - interval '1 hour'`); err != nil {
		return fmt.Errorf("store: prune machine tokens: %w", err)
	}
	if _, err := q.Exec(ctx, `INSERT INTO machine_access_tokens (token_hash, machine_id, expires_at) VALUES ($1, $2, $3)`,
		hash, machineID, expires); err != nil {
		return fmt.Errorf("store: create machine token: %w", err)
	}
	return nil
}

// GetMachineAccessToken returns the machine of an unexpired token at at.
// The caller must check Live: a revoked machine's or inactive owner's
// token is still found.
func GetMachineAccessToken(ctx context.Context, q Querier, hash []byte, at time.Time) (*MachineAccess, error) {
	var a MachineAccess
	err := scanMachine(q.QueryRow(ctx, `SELECT `+machineColumns+`, u.display_name, u.status, t.expires_at
		FROM machine_access_tokens t JOIN machines m ON m.id = t.machine_id JOIN users u ON u.id = m.owner_user_id
		WHERE t.token_hash = $1 AND t.expires_at > $2`, hash, at), &a.Machine, &a.Machine.OwnerName, &a.Machine.OwnerStatus, &a.ExpiresAt)
	if err != nil {
		return nil, notFound(err)
	}
	return &a, nil
}

// RecordMachineAssertionJTI records an assertion id until expires and
// reports whether it was new (false: a replay). Expired records are
// deleted on the way.
func RecordMachineAssertionJTI(ctx context.Context, q Querier, machineID, jti string, expires, now time.Time) (bool, error) {
	if _, err := q.Exec(ctx, `DELETE FROM machine_assertion_jtis WHERE expires_at < $1`, now); err != nil {
		return false, fmt.Errorf("store: prune assertion ids: %w", err)
	}
	tag, err := q.Exec(ctx, `INSERT INTO machine_assertion_jtis (machine_id, jti, expires_at) VALUES ($1, $2, $3)
		ON CONFLICT (machine_id, jti) DO NOTHING`, machineID, jti, expires)
	if err != nil {
		return false, fmt.Errorf("store: record assertion id: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}
