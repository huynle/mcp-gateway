package client

import (
	"context"
	"net/http"
)

// Authorizer adds credentials to each outgoing request.
type Authorizer interface {
	Authorize(ctx context.Context, req *http.Request) error
}

// NoAuth adds nothing.
type NoAuth struct{}

// Authorize implements Authorizer.
func (NoAuth) Authorize(context.Context, *http.Request) error { return nil }
