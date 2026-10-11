package netguard

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
)

// PrometheusMetrics implements Metrics as the counter
// blocked_dials_total{reason}. The label is always a Reason constant, never
// a host or URL. Register it on the gateway's private registry
// (observability.Metrics.Registry()).
type PrometheusMetrics struct {
	blocked *prometheus.CounterVec
}

// NewPrometheusMetrics registers blocked_dials_total on reg. It fails when
// the counter is already registered there.
func NewPrometheusMetrics(reg prometheus.Registerer) (*PrometheusMetrics, error) {
	m := &PrometheusMetrics{
		blocked: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "blocked_dials_total",
			Help: "Outbound requests, redirects and dials refused by the SSRF guard, by reason.",
		}, []string{"reason"}),
	}
	if err := reg.Register(m.blocked); err != nil {
		return nil, fmt.Errorf("netguard: register metrics: %w", err)
	}
	return m, nil
}

// BlockedDial counts one refusal.
func (m *PrometheusMetrics) BlockedDial(reason Reason) {
	m.blocked.WithLabelValues(string(reason)).Inc()
}
