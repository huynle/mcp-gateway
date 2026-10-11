package client

import "errors"

// ErrInvalidEndpoint is returned by Connect for a malformed Endpoint.
var ErrInvalidEndpoint = errors.New("federation client: invalid endpoint")

// Class is an error class.
type Class string

// Error is a classified error.
type Error struct {
	Class Class
}

func (e *Error) Error() string { return string(e.Class) }
