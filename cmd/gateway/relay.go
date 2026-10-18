package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/federation/connector"
	"github.com/huynle/mcp-gateway/internal/federation/tunnel"
	"github.com/huynle/mcp-gateway/internal/server"
)

// The cross-replica tunnel relay (decision efq0ncag item 5, docs/tunnel.md
// "Multiple replicas"): with GATEWAY_RELAY_LISTEN_ADDR,
// GATEWAY_RELAY_ADVERTISE_ADDR and GATEWAY_RELAY_SECRET set, each replica
// records itself as the holder of the tunnels connected to it and serves
// peers' forwarded tunnel requests on a separate, internal listener that
// is never part of the public mux.

// tunnelRelayOptions returns the relay settings for connector.Wire, or nil
// when the relay is not configured (single replica).
func tunnelRelayOptions(cfg config.Config) *tunnel.RelayOptions {
	if !cfg.RelayEnabled() {
		return nil
	}
	return &tunnel.RelayOptions{Advertise: cfg.RelayAdvertiseAddr, Secret: []byte(cfg.RelaySecret), HTTPClient: relayHTTPClient()}
}

// relayHTTPClient dials peer replicas' relay listeners: pod addresses on
// the cluster network, never a proxy. No overall timeout (event streams
// flow through it); the tunnel package bounds the wait for the head.
func relayHTTPClient() *http.Client {
	return &http.Client{Transport: &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns:          64,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: time.Second,
	}}
}

// newRelayHandler is the relay listener's whole handler: tunnel.RelayPath
// and nothing else (no health, metrics or portal routes).
func newRelayHandler(fed *connector.Federation) http.Handler {
	return fed.Tunnels.RelayHandler()
}

// serveRelay binds GATEWAY_RELAY_LISTEN_ADDR (a bind failure is returned
// at once) and serves the relay until ctx ends, draining like the public
// server.
func serveRelay(ctx context.Context, cfg config.Config, fed *connector.Federation, log *slog.Logger) error {
	var lc net.ListenConfig
	l, err := lc.Listen(ctx, "tcp", cfg.RelayListenAddr)
	if err != nil {
		return fmt.Errorf("tunnel relay: listen %s: %w", cfg.RelayListenAddr, err)
	}
	srv := server.New(newRelayHandler(fed), cfg.DrainTimeout, log)
	go func() {
		if err := srv.Serve(ctx, l); err != nil {
			log.Error("tunnel relay listener stopped", "error", err)
		}
	}()
	log.Info("tunnel relay ready", "addr", cfg.RelayListenAddr, "advertise", cfg.RelayAdvertiseAddr, "path", tunnel.RelayPath)
	return nil
}
