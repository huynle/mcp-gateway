package connections

import (
	"net/url"
	"strconv"

	"github.com/huynle/mcp-gateway/internal/caps"
)

// SetCaps limits how many app connections each user may hold, per vendor
// app and in total (caps.ConnectionsPerApp, caps.ConnectionsTotal). Only
// a new connection, or the revival of a disconnected one, is checked;
// reconnecting or granting more access to a live connection never is.
// nil (the default) is unlimited.
func (s *Service) SetCaps(l caps.Limiter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.caps = l
}

func (s *Service) limiter() caps.Limiter {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.caps
}

// flowErrorText is the connections page's message for the error carried
// in the query string. A cap refusal carries its resource and limit; both
// are validated so the page never echoes arbitrary text.
func flowErrorText(q url.Values) string {
	if q.Get("error") != caps.Class {
		return flowErrorMessage(q.Get("error"))
	}
	r := caps.Resource(q.Get("resource"))
	n, err := strconv.Atoi(q.Get("limit"))
	if (r != caps.ConnectionsPerApp && r != caps.ConnectionsTotal) || err != nil || n <= 0 || n > caps.Max {
		return "You have reached the limit of connected accounts. Disconnect an account you no longer need, or ask an admin to raise the limit."
	}
	return (&caps.ExceededError{Resource: r, Limit: n}).Error()
}
