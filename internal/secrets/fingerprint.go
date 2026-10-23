package secrets

import "github.com/huynle/mcp-gateway/internal/secrets/ref"

// FingerprintForRequest is the 4-word fingerprint the entry page /s/<id>
// shows for the request id: ref.Fingerprint over the raw request id.
//
// The page only knows the request id (the handle is stored as a hash), so
// the fingerprint is derived from the request id on both sides. The agent
// side (the secrets.request tool, the -32042 answer) must print
// FingerprintForHandle(handle), i.e. ref.Fingerprint(RequestIDForHandle(handle)),
// never ref.Fingerprint(handle), or the words will not match.
func FingerprintForRequest(requestID string) string { return ref.Fingerprint(requestID) }

// FingerprintForHandle is the fingerprint the agent prints for handle; it
// equals FingerprintForRequest(RequestIDForHandle(handle)).
func FingerprintForHandle(handle string) string {
	return FingerprintForRequest(RequestIDForHandle(handle))
}
