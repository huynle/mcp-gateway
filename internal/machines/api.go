package machines

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/huynle/mcp-gateway/internal/caps"
	"github.com/huynle/mcp-gateway/internal/federation/tunnel"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/store"
)

// Paths of the public machine endpoints (mounted on the top-level mux,
// outside the portal's sessions).
const (
	DeviceAuthorizationPath = "/machine/device_authorization"
	TokenPath               = "/machine/token"
	EnrollPath              = "/machine/enroll"
	ActivatePath            = "/activate"
)

// OAuth grant types of the token endpoint.
const (
	GrantDeviceCode = "urn:ietf:params:oauth:grant-type:device_code"
	GrantJWTBearer  = "urn:ietf:params:oauth:grant-type:jwt-bearer"
)

// maxJSONBody bounds a JSON request body; maxFormBody the token request.
const (
	maxJSONBody = 16 << 10
	maxFormBody = 16 << 10
)

// Mount registers the machine endpoints on mux:
//
//	POST /machine/device_authorization       start a device flow (rate limited per address)
//	POST /machine/token                      device_code or jwt-bearer grant (form)
//	POST /machine/enroll                     enroll with a one-time code (rate limited)
//	GET  /machine/v1/self                    the machine and its servers
//	PUT  /machine/v1/servers/{name}          register a server (idempotent)
//	POST /machine/v1/servers/{name}/refresh  rediscover a server (never approves)
//	POST /machine/v1/logout                  revoke this machine
//	GET  /machine/v1/connect                 the machine's WebSocket
//
// The /machine/v1 routes need a machine access token (401 invalid_token,
// 403 revoked); nothing else in the gateway accepts one.
func (s *Service) Mount(mux *http.ServeMux) {
	mux.HandleFunc("POST "+DeviceAuthorizationPath, s.serveDeviceAuthorization)
	mux.HandleFunc("POST "+TokenPath, s.serveToken)
	mux.HandleFunc("POST "+EnrollPath, s.serveEnroll)
	mux.Handle("GET /machine/v1/self", s.machine(s.serveSelf))
	mux.Handle("PUT /machine/v1/servers/{name}", s.machine(s.servePut))
	mux.Handle("POST /machine/v1/servers/{name}/refresh", s.machine(s.serveRefresh))
	mux.Handle("POST /machine/v1/logout", s.machine(s.serveLogout))
	mux.Handle("GET "+tunnel.MachineConnectPath, s.machine(s.serveConnect))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

func tooMany(w http.ResponseWriter, wait float64) {
	w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(wait))))
	writeError(w, http.StatusTooManyRequests, "too_many_requests", "too many requests from this address; retry later")
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// readJSON decodes a bounded JSON body that has exactly the known fields.
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxJSONBody))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "the body is too large or unreadable")
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil || dec.More() {
		writeError(w, http.StatusBadRequest, "invalid_request", "the body must be one JSON object with the documented fields")
		return false
	}
	return true
}

// enrollRequest is the machine part of device_authorization and enroll.
type enrollRequest struct {
	Code          string          `json:"code,omitempty"`
	Name          string          `json:"name"`
	PublicKey     json.RawMessage `json:"public_key"`
	ClientVersion string          `json:"client_version"`
}

// check validates name, key and version (writing the 400) and returns the
// public key.
func (er *enrollRequest) check(w http.ResponseWriter) (ed25519.PublicKey, bool) {
	if !ValidName(er.Name) {
		writeError(w, http.StatusBadRequest, "invalid_request", "name must be 1-63 characters of a-z, 0-9, '-' and '_', starting with a letter or digit")
		return nil, false
	}
	if len(er.ClientVersion) > maxClientVersion || !printableText(er.ClientVersion) {
		writeError(w, http.StatusBadRequest, "invalid_request", "client_version must be at most 64 printable characters")
		return nil, false
	}
	pub, err := ParsePublicKey(er.PublicKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", ErrInvalidKey.Error())
		return nil, false
	}
	return pub, true
}

func (s *Service) serveDeviceAuthorization(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	if ok, wait := s.deviceLimiter.Allow(ip); !ok {
		tooMany(w, wait.Seconds())
		return
	}
	s.deviceLimiter.Fail(ip) // every request spends the budget
	var req enrollRequest
	if !readJSON(w, r, &req) {
		return
	}
	if req.Code != "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "unexpected field code")
		return
	}
	pub, ok := req.check(w)
	if !ok {
		return
	}
	da, err := s.RequestDevice(r.Context(), req.Name, pub, req.ClientVersion, ip)
	if err != nil {
		s.fail(w, r, "device authorization", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"device_code": da.DeviceCode, "user_code": da.UserCode,
		"verification_uri":          s.base + ActivatePath,
		"verification_uri_complete": s.base + ActivatePath + "?code=" + da.UserCode,
		"expires_in":                da.ExpiresIn, "interval": da.Interval,
	})
}

func (s *Service) serveEnroll(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	if ok, wait := s.enrollLimiter.Allow(ip); !ok {
		tooMany(w, wait.Seconds())
		return
	}
	s.enrollLimiter.Fail(ip)
	var req enrollRequest
	if !readJSON(w, r, &req) {
		return
	}
	pub, ok := req.check(w)
	if !ok {
		return
	}
	m, err := s.Enroll(r.Context(), req.Code, req.Name, pub, req.ClientVersion, ip)
	var ce *caps.ExceededError
	switch {
	case errors.Is(err, ErrInvalidCode):
		s.log.Info("machine enrollment refused", "event", "machine.enroll_refused", "reason", "invalid_code")
		writeError(w, http.StatusBadRequest, "invalid_code", "the enrollment code is invalid, used, revoked or expired")
		return
	case errors.As(err, &ce):
		writeError(w, http.StatusConflict, caps.Class, ce.Error())
		return
	case err != nil:
		s.fail(w, r, "enroll", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"machine_id": m.ID, "name": m.Name, "gateway": s.base})
}

func (s *Service) serveToken(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	if ok, wait := s.tokenLimiter.Allow(ip); !ok {
		tooMany(w, wait.Seconds())
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBody)
	if err := r.ParseForm(); err != nil {
		s.tokenLimiter.Fail(ip)
		writeError(w, http.StatusBadRequest, "invalid_request", "the body must be a form")
		return
	}
	switch r.PostForm.Get("grant_type") {
	case GrantDeviceCode:
		s.deviceToken(w, r, ip)
	case GrantJWTBearer:
		s.assertionToken(w, r, ip)
	default:
		s.tokenLimiter.Fail(ip)
		writeError(w, http.StatusBadRequest, "unsupported_grant_type", "use the device_code or jwt-bearer grant")
	}
}

func (s *Service) deviceToken(w http.ResponseWriter, r *http.Request, ip string) {
	m, err := s.PollDevice(r.Context(), r.PostForm.Get("device_code"))
	switch {
	case errors.Is(err, errAuthorizationPending):
		writeError(w, http.StatusBadRequest, "authorization_pending", "waiting for the user to approve the request")
	case errors.Is(err, errSlowDown):
		writeError(w, http.StatusBadRequest, "slow_down", "polling too fast; add 5 seconds to the interval")
	case errors.Is(err, errAccessDenied):
		writeError(w, http.StatusBadRequest, "access_denied", "the request was denied")
	case errors.Is(err, errExpiredToken):
		s.tokenLimiter.Fail(ip)
		writeError(w, http.StatusBadRequest, "expired_token", "the device code is unknown, expired or already used; run login again")
	case err != nil:
		s.fail(w, r, "device token", err)
	default:
		writeJSON(w, http.StatusOK, map[string]any{"machine_id": m.ID, "name": m.Name, "gateway": s.base})
	}
}

func (s *Service) assertionToken(w http.ResponseWriter, r *http.Request, ip string) {
	tok, exp, err := s.TokenFromAssertion(r.Context(), r.PostForm.Get("assertion"), ip)
	if errors.Is(err, ErrInvalidAssertion) {
		s.tokenLimiter.Fail(ip)
		s.log.Info("machine assertion refused", "event", "machine.assertion_refused", "reason", AssertionReason(err))
		writeError(w, http.StatusBadRequest, "invalid_grant", "the assertion is invalid, expired, replayed, or the machine is revoked")
		return
	}
	if err != nil {
		s.fail(w, r, "assertion token", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": tok, "token_type": "Bearer", "expires_in": int(exp.Sub(s.now()).Seconds() + 0.5), "scope": "machine",
	})
}

// fail answers 500 without detail and logs the class.
func (s *Service) fail(w http.ResponseWriter, r *http.Request, what string, err error) {
	s.log.Error("machines: request failed", "what", what, "path", r.URL.Path,
		"request_id", observability.RequestIDFromContext(r.Context()), "error", observability.RedactError(err))
	writeError(w, http.StatusInternalServerError, "server_error", "the request could not be completed; try again")
}

// --- machine API ---------------------------------------------------------------------

type machineHandler func(w http.ResponseWriter, r *http.Request, m *store.Machine)

// machine authenticates the machine access token of a /machine/v1 route.
func (s *Service) machine(h machineHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scheme, raw, ok := strings.Cut(r.Header.Get("Authorization"), " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") {
			raw = ""
		}
		m, err := s.Authenticate(r.Context(), raw)
		switch {
		case errors.Is(err, errInvalidToken):
			w.Header().Set("WWW-Authenticate", `Bearer realm="mcp-gateway-machine", error="invalid_token"`)
			writeError(w, http.StatusUnauthorized, "invalid_token", "missing, invalid or expired machine token")
			return
		case errors.Is(err, errRevoked):
			writeError(w, http.StatusForbidden, "revoked", "the machine was revoked or its owner is not active; run mcp-gateway login again")
			return
		case err != nil:
			s.fail(w, r, "authenticate machine", err)
			return
		}
		h(w, r, m)
	})
}

func (s *Service) serveSelf(w http.ResponseWriter, r *http.Request, m *store.Machine) {
	servers, err := s.Servers(r.Context(), m)
	if err != nil {
		s.fail(w, r, "self", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"machine_id": m.ID, "name": m.Name, "owner": m.OwnerName, "servers": servers})
}

func (s *Service) servePut(w http.ResponseWriter, r *http.Request, m *store.Machine) {
	var req struct {
		Kind string `json:"kind"`
		Path string `json:"path"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	res, err := s.PutServer(r.Context(), m, r.PathValue("name"), req.Kind, req.Path)
	if s.serverError(w, r, err) {
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Service) serveRefresh(w http.ResponseWriter, r *http.Request, m *store.Machine) {
	res, err := s.RefreshServer(r.Context(), m, r.PathValue("name"))
	if s.serverError(w, r, err) {
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// serverError writes the answer for a server operation error; false when
// err is nil.
func (s *Service) serverError(w http.ResponseWriter, r *http.Request, err error) bool {
	var ce *caps.ExceededError
	switch {
	case err == nil:
		return false
	case errors.Is(err, ErrInvalidServerName):
		writeError(w, http.StatusBadRequest, "invalid_name", "a server name is 1-63 characters of a-z, 0-9, '-' and '_' and not a built-in app's name")
	case errors.Is(err, errInvalidRequest):
		writeError(w, http.StatusBadRequest, "invalid_request", `kind must be "http" or "stdio" and path empty or an absolute path`)
	case errors.Is(err, ErrServerNameTaken):
		writeError(w, http.StatusConflict, "name_taken", "a server with this name already exists and is not served by this machine; rename it in config.yaml or delete the other server")
	case errors.As(err, &ce):
		writeError(w, http.StatusConflict, caps.Class, ce.Error())
	case errors.Is(err, ErrNotPermitted):
		writeError(w, http.StatusForbidden, "not_permitted", "your roles do not allow adding MCP servers; ask an admin")
	case errors.Is(err, ErrServerLocked):
		writeError(w, http.StatusConflict, "locked", "the server is published; only an admin can change it")
	case errors.Is(err, errNoServer):
		writeError(w, http.StatusNotFound, "not_found", "this machine has no server of that name")
	case errors.Is(err, errOffline):
		writeError(w, http.StatusConflict, "offline", "the machine is not connected; run mcp-gateway up")
	case errors.Is(err, errRefreshFailed):
		writeError(w, http.StatusBadGateway, "refresh_failed", "the server could not be reached or listed an unusable capability set; see the server page")
	default:
		s.fail(w, r, "server operation", err)
	}
	return true
}

func (s *Service) serveLogout(w http.ResponseWriter, r *http.Request, m *store.Machine) {
	if err := s.Revoke(r.Context(), m.ID, m.OwnerUserID, m.OwnerUserID, store.MachineRevokedSelf); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.fail(w, r, "logout", err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) serveConnect(w http.ResponseWriter, r *http.Request, m *store.Machine) {
	s.o.Tunnels.ServeMachine(w, r, m.ID)
}
