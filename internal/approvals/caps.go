package approvals

import "github.com/huynle/mcp-gateway/internal/caps"

type capsHolder struct{ l caps.Limiter }

// SetCaps limits how many pending, unexpired approvals each user may hold
// (caps.PendingApprovals): Create refuses with *caps.ExceededError at the
// cap, and the confirm handler answers class cap_exceeded. nil (the
// default) is unlimited.
func (s *Service) SetCaps(l caps.Limiter) { s.caps.Store(&capsHolder{l}) }

func (s *Service) limiter() caps.Limiter {
	if h := s.caps.Load(); h != nil {
		return h.l
	}
	return nil
}
