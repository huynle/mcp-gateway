package tunnel

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
)

func TestGenerateTokenShapeAndHash(t *testing.T) {
	raw, hash, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^` + TokenScanPattern + `$`).MatchString(raw) {
		t.Fatalf("token %q does not match %s", raw, TokenScanPattern)
	}
	if !strings.HasPrefix(raw, TokenPrefix) {
		t.Fatalf("token lacks prefix %q", TokenPrefix)
	}
	if string(HashToken(raw)) != string(hash) || len(hash) != 32 {
		t.Fatalf("hash mismatch")
	}
	raw2, _, _ := GenerateToken()
	if raw == raw2 {
		t.Fatal("two tokens are equal")
	}
}

func TestParseTokenRejectsMalformed(t *testing.T) {
	raw, _, _ := GenerateToken()
	if err := ParseToken(raw); err != nil {
		t.Fatalf("valid token refused: %v", err)
	}
	for _, bad := range []string{
		"", "mgt_", raw + "x", " " + raw, "mgw_" + raw[4:], strings.Replace(raw, "_", "-", 2),
		raw[:len(raw)-1] + "!",
	} {
		if err := ParseToken(bad); !errors.Is(err, ErrMalformedToken) {
			t.Errorf("ParseToken(%q) = %v, want ErrMalformedToken", bad, err)
		}
	}
}

func newTestService(t *testing.T) (*Service, *memStore) {
	t.Helper()
	ms := newMemStore()
	s, err := NewService(Options{Store: ms})
	if err != nil {
		t.Fatal(err)
	}
	return s, ms
}

func TestCreateAuthenticateRevoke(t *testing.T) {
	ctx := context.Background()
	s, ms := newTestService(t)
	tun, raw, err := s.CreateTunnel(ctx, ownerA, "laptop")
	if err != nil {
		t.Fatal(err)
	}
	if tun.OwnerUserID != ownerA || tun.Name != "laptop" || tun.ID == "" {
		t.Fatalf("tunnel = %+v", tun)
	}
	stored, _ := ms.Tunnel(ctx, tun.ID)
	if strings.Contains(string(stored.TokenHash), raw) || string(stored.TokenHash) != string(HashToken(raw)) {
		t.Fatal("store must hold only the hash of the token")
	}
	got, err := s.Authenticate(ctx, raw)
	if err != nil || got.ID != tun.ID {
		t.Fatalf("Authenticate = %v, %v", got, err)
	}
	other, _, _ := GenerateToken()
	for _, bad := range []string{"", "nonsense", other} {
		if _, err := s.Authenticate(ctx, bad); !errors.Is(err, ErrUnauthorized) {
			t.Errorf("Authenticate(%q) = %v, want ErrUnauthorized", bad, err)
		}
	}
	if err := s.Revoke(ctx, ownerB, tun.ID); err == nil {
		t.Fatal("another user revoked the tunnel")
	}
	if err := s.Revoke(ctx, ownerA, tun.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, raw); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked token: %v, want ErrUnauthorized", err)
	}
}

func TestCreateTunnelValidatesName(t *testing.T) {
	s, _ := newTestService(t)
	for _, name := range []string{"", strings.Repeat("x", 101), "bad\nname"} {
		if _, _, err := s.CreateTunnel(context.Background(), ownerA, name); !errors.Is(err, ErrInvalidName) {
			t.Errorf("CreateTunnel(%q) = %v, want ErrInvalidName", name, err)
		}
	}
}

func TestAuthorizeOwnerOnly(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestService(t)
	tun, _, _ := s.CreateTunnel(ctx, ownerA, "laptop")
	if err := s.Authorize(ctx, ownerA, tun.ID); err != nil {
		t.Fatalf("owner refused: %v", err)
	}
	if err := s.Authorize(ctx, ownerB, tun.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("other owner: %v, want ErrForbidden", err)
	}
	if err := s.Authorize(ctx, ownerA, "00000000-0000-4000-8000-999999999999"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("unknown tunnel: %v, want ErrForbidden", err)
	}
	_ = s.Revoke(ctx, ownerA, tun.ID)
	if err := s.Authorize(ctx, ownerA, tun.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("revoked tunnel: %v, want ErrForbidden", err)
	}
}

// A user cannot have two live tunnels with the same name (case and
// surrounding space ignored); a revoked one frees the name, and another
// user may use it.
func TestCreateTunnelRefusesDuplicateLiveName(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestService(t)
	first, _, err := s.CreateTunnel(ctx, ownerA, "laptop")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"laptop", "Laptop", " laptop "} {
		if _, _, err := s.CreateTunnel(ctx, ownerA, name); !errors.Is(err, ErrNameTaken) {
			t.Errorf("CreateTunnel(%q) = %v, want ErrNameTaken", name, err)
		}
	}
	if _, _, err := s.CreateTunnel(ctx, ownerB, "laptop"); err != nil {
		t.Errorf("other owner, same name: %v", err)
	}
	if err := s.Revoke(ctx, ownerA, first.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.CreateTunnel(ctx, ownerA, "laptop"); err != nil {
		t.Errorf("name after revoke: %v", err)
	}
}
