package tunnel

import "errors"

// Class classifies a failure to reach a server through a tunnel. Messages
// built from it never contain URLs, headers, bodies or tokens.
type Class string

// Error classes.
const (
	// ClassOffline: the tunnel has no live connection on this replica, or
	// it dropped while the request was in flight.
	ClassOffline Class = "tunnel_offline"
	// ClassNotTunnel: the URL is not a tunnel URL. The tunnel transport
	// never dials anything else.
	ClassNotTunnel Class = "not_tunnel"
	// ClassTooLarge: a request or response body exceeded its bound.
	ClassTooLarge Class = "too_large"
	// ClassTimeout: no response headers within ResponseHeaderTimeout.
	ClassTimeout Class = "timeout"
	// ClassBusy: the tunnel already carries MaxStreams requests.
	ClassBusy Class = "busy"
	// ClassUnreachable: the tunnel client could not complete the response
	// (the local server failed mid-stream or the frames were invalid).
	ClassUnreachable Class = "unreachable"
)

// Error is a classified tunnel transport failure.
type Error struct {
	Class  Class
	Reason string // short machine reason, optional
	err    error
}

func (e *Error) Error() string {
	msg := "tunnel: " + string(e.Class)
	if e.Reason != "" {
		msg += " (" + e.Reason + ")"
	}
	return msg
}

// Unwrap returns the cause, if any.
func (e *Error) Unwrap() error { return e.err }

// Timeout reports whether the error is a timeout (net.Error style, so
// generic HTTP clients classify it as one).
func (e *Error) Timeout() bool { return e.Class == ClassTimeout }

func newError(c Class, reason string, cause error) *Error {
	return &Error{Class: c, Reason: reason, err: cause}
}

// Errors returned by Agent.Run that end the reconnect loop.
var (
	// ErrRejected: the gateway refused the token (HTTP 401): wrong,
	// unknown or revoked. Retrying cannot help.
	ErrRejected = errors.New("tunnel: gateway rejected the token")
	// ErrReplaced: another tunnel client connected with the same token.
	ErrReplaced = errors.New("tunnel: replaced by another connection with the same token")
	// ErrRevoked: the tunnel was revoked while connected.
	ErrRevoked = errors.New("tunnel: tunnel revoked")
)
