// Package observability owns the operational surface shared by every module:
// structured logging bootstrap (log/slog, redaction of tokens, codes,
// arguments and content), the /healthz liveness and /readyz readiness
// handlers with their registry of named checks, and later the private
// Prometheus metrics endpoint and optional OpenTelemetry wiring.
//
// Design: Brain plan 36bakiw8 section 6; decisions ysorv868, v6piaxdb.
package observability
