package netguard

import (
	"context"
	"net/url"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/huynle/mcp-gateway/internal/observability"
)

func TestPrometheusMetricsOnGatewayRegistry(t *testing.T) {
	gm := observability.NewMetrics()
	m, err := NewPrometheusMetrics(gm.Registry())
	if err != nil {
		t.Fatalf("NewPrometheusMetrics: %v", err)
	}
	g := New(Options{Metrics: m})
	for _, raw := range []string{"https://127.0.0.1/", "http://2130706433/", "https://169.254.169.254/"} {
		u, _ := url.Parse(raw)
		_ = g.CheckURL(context.Background(), u)
	}

	got := map[string]float64{}
	help := ""
	mfs, err := gm.Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() != "blocked_dials_total" {
			continue
		}
		help = mf.GetHelp()
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "reason" {
					got[l.GetValue()] = m.GetCounter().GetValue()
				}
			}
		}
	}
	if help == "" || len(got) != 2 || got["loopback"] != 2 || got["metadata"] != 1 {
		t.Fatalf("blocked_dials_total = %v (help %q), want loopback=2 metadata=1", got, help)
	}

	// Registering twice on one registry is a wiring error, reported not panicked.
	if _, err := NewPrometheusMetrics(gm.Registry()); err == nil {
		t.Fatal("second registration: want error")
	}
	if _, err := NewPrometheusMetrics(prometheus.NewRegistry()); err != nil {
		t.Fatalf("fresh registry: %v", err)
	}
}
