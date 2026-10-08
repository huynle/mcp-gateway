//go:build integration

package store_test

import (
	"net"
	"net/url"
	"os"
	"testing"
)

// TestIntegrationPostgresReachable is the placeholder integration test that
// proves the `make test-integration` / CI wiring works end to end. The store
// task replaces it with real migration and row-level-security tests over a
// PostgreSQL driver; until then it only checks the configured server accepts
// TCP connections.
func TestIntegrationPostgresReachable(t *testing.T) {
	raw := os.Getenv("GATEWAY_TEST_DATABASE_URL")
	if raw == "" {
		t.Skip("GATEWAY_TEST_DATABASE_URL not set; skipping integration test")
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("GATEWAY_TEST_DATABASE_URL is not a URL: %v", err)
	}
	if u.Scheme != "postgres" && u.Scheme != "postgresql" {
		t.Fatalf("GATEWAY_TEST_DATABASE_URL scheme = %q, want postgres", u.Scheme)
	}
	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), "5432")
	}
	var d net.Dialer
	conn, err := d.DialContext(t.Context(), "tcp", host)
	if err != nil {
		t.Fatalf("PostgreSQL at %s not reachable: %v", host, err)
	}
	_ = conn.Close()
}
