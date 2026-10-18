package main

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/identity/identitytest"
)

type signupRecorder struct {
	mu     sync.Mutex
	events []audit.Event
}

func (r *signupRecorder) Record(_ context.Context, ev audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
	return nil
}

func TestSignupAuditIsWired(t *testing.T) {
	const iss = "http://localhost:15556/dex"
	svc, err := identity.New(identity.Config{
		BaseURL:         "http://localhost:18080",
		Providers:       []config.OIDCProvider{{Name: "dex", Issuer: iss, ClientID: "c", ClientSecret: "s", AllowedDomains: []string{"example.com"}}},
		DefaultRole:     "member",
		IdleTimeout:     time.Hour,
		AbsoluteTimeout: 2 * time.Hour,
		SignupMode:      config.SignupApproval,
	}, identitytest.NewMemStore(), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	rec := &signupRecorder{}
	withSignupAudit(rec)(svc, nil, nil, slog.New(slog.DiscardHandler))
	res, err := svc.SignIn(context.Background(), "dex", identity.Claims{Issuer: iss, Subject: "s", Email: "a@example.com", EmailVerified: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ApproveUser(context.Background(), "", res.PendingUser.UserID); err != nil {
		t.Fatal(err)
	}
	var actions []string
	for _, ev := range rec.events {
		actions = append(actions, ev.ResourceIdentity["action"])
	}
	if len(actions) != 2 || actions[0] != "user.signed_up" || actions[1] != "user.approved" {
		t.Errorf("audited actions = %v", actions)
	}
	withSignupAudit(nil)(svc, nil, nil, nil) // nil recorder is a no-op
}
