package auth

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/huynle/mcp-gateway/internal/federation/client"
	"github.com/huynle/mcp-gateway/internal/store"
)

// UserFunc returns the signed-in gateway user of a request (the portal's
// session), ok=false when nobody is signed in.
type UserFunc func(r *http.Request) (userID string, ok bool)

// StartConnect handles GET /servers/{id}/connect: it redirects the
// signed-in user to the server's authorization server. Mount it with a
// pattern that defines the {id} wildcard.
func (s *Service) StartConnect(user UserFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		noStore(w)
		uid, ok := user(r)
		if !ok || uid == "" {
			http.Error(w, "sign in first", http.StatusUnauthorized)
			return
		}
		id := r.PathValue("id")
		if id == "" {
			http.Error(w, "missing server", http.StatusBadRequest)
			return
		}
		u, err := s.ConnectURL(r.Context(), uid, id)
		if err != nil {
			http.Error(w, safeMessage(err), errorStatus(err))
			return
		}
		http.Redirect(w, r, u, http.StatusFound)
	})
}

// Callback handles GET /servers/oauth/callback for the signed-in user and
// renders the outcome with Options.Finish.
func (s *Service) Callback(user UserFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		noStore(w)
		uid, ok := user(r)
		if !ok || uid == "" {
			http.Error(w, "sign in first", http.StatusUnauthorized)
			return
		}
		q := r.URL.Query()
		serverID, err := s.CompleteConnect(r.Context(), CallbackRequest{
			UserID: uid, State: q.Get("state"), Code: q.Get("code"), Iss: q.Get("iss"), Error: q.Get("error"),
		})
		s.finish(w, r, serverID, err)
	})
}

// ClientMetadataDocument serves the gateway's OAuth client ID metadata
// document (mount at ClientMetadataPath). Its URL is the client_id the
// gateway uses at authorization servers that support CIMD.
func (s *Service) ClientMetadataDocument() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		doc := s.clientMetadata(authMethodNone)
		doc["client_id"] = s.ClientMetadataURL()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		_ = json.NewEncoder(w).Encode(doc)
	})
}

func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

func defaultFinish(w http.ResponseWriter, _ *http.Request, _ string, err error) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if err != nil {
		http.Error(w, safeMessage(err), errorStatus(err))
		return
	}
	_, _ = w.Write([]byte("Connected. You can close this window and return to the gateway.\n"))
}

var publicErrors = []error{
	ErrNotConnected, ErrNeedsReconnect, ErrNotConfigured, ErrUnsupported, ErrNoOAuth, ErrPKCEUnsupported,
	ErrNoClient, ErrFlowInvalid, ErrDenied, ErrSharedCredentialRejected, ErrInvalidCredential, ErrInvalidServerURL, ErrForbidden,
}

// safeMessage is the user-facing text of err: a package sentinel, a
// federation client error (class-level, safe by construction), or a
// generic message. Never upstream text or URLs.
func safeMessage(err error) string {
	if errors.Is(err, store.ErrNotFound) {
		return "server not found"
	}
	for _, e := range publicErrors {
		if errors.Is(err, e) {
			return e.Error()
		}
	}
	var ce *client.Error
	if errors.As(err, &ce) {
		return ce.Error()
	}
	return "connection failed"
}

func errorStatus(err error) int {
	var ce *client.Error
	switch {
	case errors.Is(err, store.ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, ErrForbidden):
		return http.StatusForbidden
	case errors.Is(err, ErrFlowInvalid), errors.Is(err, ErrDenied), errors.Is(err, ErrInvalidServerURL):
		return http.StatusBadRequest
	case errors.Is(err, ErrNotConfigured), errors.Is(err, ErrUnsupported), errors.Is(err, ErrNoOAuth),
		errors.Is(err, ErrPKCEUnsupported), errors.Is(err, ErrNoClient):
		return http.StatusConflict
	case errors.As(err, &ce):
		return http.StatusBadGateway
	}
	return http.StatusInternalServerError
}
