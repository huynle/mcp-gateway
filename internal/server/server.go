// Package server owns the HTTP server lifecycle: listening, and graceful
// shutdown that stops accepting new connections, drains in-flight requests
// for a bounded period and then cuts off whatever is still running.
//
// Design: Brain plan 36bakiw8 section 3 and decisions ysorv868, dovthftx
// (graceful shutdown drains in-flight calls within the termination grace
// period; anything still running afterwards is cut off and the ledger's
// stale in_progress sweep handles the consequences).
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"
)

// ErrDrainTimeout is returned by Serve when the drain period elapsed while
// requests were still in flight; those requests were forcibly closed.
var ErrDrainTimeout = errors.New("server: drain period elapsed with requests still in flight")

// Server wraps http.Server with context-driven graceful shutdown.
type Server struct {
	http  *http.Server
	drain time.Duration
	log   *slog.Logger

	// requestsCtx is the parent of every request context; cancelling it
	// tells in-flight handlers that the drain period is over.
	requestsCtx    context.Context
	cancelRequests context.CancelFunc
}

// New builds a Server for handler. drain bounds how long shutdown waits for
// in-flight requests before cutting them off.
func New(handler http.Handler, drain time.Duration, log *slog.Logger) *Server {
	if drain <= 0 {
		panic("server: drain period must be positive")
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{
		drain:          drain,
		log:            log,
		requestsCtx:    ctx,
		cancelRequests: cancel,
	}
	s.http = &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	return s
}

// ListenAndServe binds addr and calls Serve. Bind failures are returned
// immediately.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	var lc net.ListenConfig
	l, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("server: listen %s: %w", addr, err)
	}
	return s.Serve(ctx, l)
}

// Serve accepts connections on l until ctx is cancelled, then shuts down:
// the listener closes immediately (new connections are refused), idle
// connections close, and in-flight requests get up to the drain period to
// finish. If they do, Serve returns nil. Otherwise every request context is
// cancelled, remaining connections are closed, and Serve returns
// ErrDrainTimeout. Listener failures are returned as-is.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	defer s.cancelRequests()

	serveErr := make(chan error, 1)
	go func() {
		err := s.http.Serve(l)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		serveErr <- err
	}()

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
	}

	s.log.Info("shutdown: draining in-flight requests", "drain", s.drain, "addr", l.Addr().String())
	drainCtx, cancel := context.WithTimeout(context.Background(), s.drain)
	defer cancel()

	err := s.http.Shutdown(drainCtx)
	<-serveErr // Serve has returned once Shutdown is called.
	if err == nil {
		s.log.Info("shutdown: drained cleanly")
		return nil
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("server: shutdown: %w", err)
	}

	s.log.Warn("shutdown: drain period elapsed, cutting off in-flight requests", "drain", s.drain)
	s.cancelRequests()
	if cerr := s.http.Close(); cerr != nil {
		s.log.Warn("shutdown: close", "error", cerr)
	}
	return ErrDrainTimeout
}
