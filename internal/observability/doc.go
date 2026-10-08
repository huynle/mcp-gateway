// Package observability owns the operational surface shared by every module:
// structured logging bootstrap (log/slog with the RedactingHandler that
// scrubs tokens, codes, arguments and content from every record), the
// pseudonymous user attribute, the X-Request-Id middleware, the /healthz
// liveness and /readyz readiness handlers with their registry of named
// checks, and the private Prometheus metrics registry with its own
// listener. Optional OpenTelemetry wiring comes later.
//
// Design: Brain plan 36bakiw8 section 6; decisions ysorv868, v6piaxdb.
// Wiring: docs/observability.md.
package observability
