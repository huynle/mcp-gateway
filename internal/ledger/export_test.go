package ledger

// SetAfterConsume injects a hook that runs after the approval consume and
// before the in_progress insert, inside Begin's transaction (the
// integration suite proves the two commit or roll back together).
func SetAfterConsume(s *Service, fn func() error) { s.afterConsume = fn }
