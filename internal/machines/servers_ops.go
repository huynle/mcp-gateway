package machines

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"strings"

	"github.com/huynle/mcp-gateway/internal/federation/connector"
	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/federation/tunnel"
	"github.com/huynle/mcp-gateway/internal/store"
)

// Server kinds a machine registers (what the client runs locally; the
// gateway serves both the same way).
const (
	KindHTTP  = "http"
	KindStdio = "stdio"
)

// maxServerPath bounds a server's path behind its tunnel.
const maxServerPath = 512

// Errors of the server operations.
var (
	errInvalidRequest = errors.New("machines: invalid request")
	errOffline        = errors.New("machines: the machine is not connected")
	errNoServer       = errors.New("machines: no such server on this machine")
	errRefreshFailed  = errors.New("machines: refresh failed")
)

// ServerView is one server of a machine (GET /machine/v1/self).
type ServerView struct {
	Name          string `json:"name"`
	ServerID      string `json:"server_id"`
	TunnelID      string `json:"tunnel_id"`
	Status        string `json:"status"` // online | offline
	ApprovedTools int    `json:"approved_tools"`
	PendingReview bool   `json:"pending_review"`
	ReviewURL     string `json:"review_url"`
}

// PutResult answers PUT /machine/v1/servers/{name}.
type PutResult struct {
	Name      string `json:"name"`
	ServerID  string `json:"server_id"`
	TunnelID  string `json:"tunnel_id"`
	Created   bool   `json:"created"`
	ReviewURL string `json:"review_url"`
}

// RefreshResult answers POST /machine/v1/servers/{name}/refresh. Added,
// Changed and Removed are tool names (display form).
type RefreshResult struct {
	Version   int      `json:"version"`
	Added     []string `json:"added"`
	Changed   []string `json:"changed"`
	Removed   []string `json:"removed"`
	ReviewURL string   `json:"review_url"`
}

// validServerPath checks the path of a server behind its tunnel: "" or an
// absolute path (with an optional query), never another host.
func validServerPath(p string) bool {
	if p == "" {
		return true
	}
	if len(p) > maxServerPath || !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.ContainsAny(p, "#\\ \t\r\n") {
		return false
	}
	u, err := url.ParseRequestURI(p)
	return err == nil && u.Host == "" && u.Scheme == ""
}

// machineServer finds the owner's server called name if it is backed by a
// tunnel of machine m (any tunnel of m for that server name, revoked or
// not); errNoServer when the owner has no such server, ErrServerNameTaken
// when the name is used otherwise.
func (s *Service) machineServer(ctx context.Context, m *store.Machine, name string) (*store.MCPServer, []store.MCPTunnel, error) {
	tunnels, err := s.o.Store.MachineTunnels(ctx, m.ID)
	if err != nil {
		return nil, nil, err
	}
	srv, err := s.o.Servers.OwnServer(ctx, m.OwnerUserID, name)
	if errors.Is(err, store.ErrNotFound) {
		return nil, tunnels, errNoServer
	}
	if err != nil {
		return nil, nil, err
	}
	tid, _, err := tunnel.ParseURL(srv.URL)
	if err != nil || !slices.ContainsFunc(tunnels, func(t store.MCPTunnel) bool { return t.ID == tid && t.ServerName == name }) {
		return nil, tunnels, ErrServerNameTaken
	}
	return srv, tunnels, nil
}

// PutServer ensures machine m's server name: a live tunnel linked to the
// machine and the owner's private server at tunnel://<tunnel>/<path>
// with no upstream authentication. Idempotent.
func (s *Service) PutServer(ctx context.Context, m *store.Machine, name, kind, path string) (*PutResult, error) {
	if err := connector.ValidateServerName(name); err != nil {
		return nil, ErrInvalidServerName
	}
	if (kind != KindHTTP && kind != KindStdio) || !validServerPath(path) {
		return nil, errInvalidRequest
	}
	srv, _, err := s.machineServer(ctx, m, name)
	if err != nil && !errors.Is(err, errNoServer) {
		return nil, err
	}
	t, created, err := s.o.Store.EnsureTunnel(ctx, m, name)
	if err != nil {
		return nil, err
	}
	u := tunnel.URL(t.ID, path)
	res := &PutResult{Name: name, TunnelID: t.ID}
	if srv != nil {
		if srv.URL != u {
			srv.URL = u
			if err := s.o.Servers.SetServerURL(ctx, m.OwnerUserID, srv); err != nil {
				return nil, err
			}
		}
	} else {
		srv = &store.MCPServer{
			Name: name, URL: u, OwnerUserID: m.OwnerUserID, Transport: store.MCPTransportAuto,
			CredentialMode: store.MCPCredentialPerUser, AuthKind: store.MCPAuthNone,
			AuthConfig: []byte(`{}`), HeaderConfig: []byte(`{}`),
		}
		if err := s.o.Servers.CreateServer(ctx, srv); err != nil {
			if created {
				if rerr := s.o.Store.RevokeTunnel(context.WithoutCancel(ctx), t.ID, s.now()); rerr != nil {
					s.log.Warn("machines: tunnel of a failed registration not revoked", "tunnel_id", t.ID, "error", rerr)
				}
			}
			return nil, err
		}
		res.Created = true
	}
	res.ServerID, res.ReviewURL = srv.ID, s.ReviewURL(srv.ID)
	if created {
		s.o.Tunnels.SyncMachine(m.ID)
	}
	s.log.Info("machine server registered", "event", "machine.server_registered", "machine_id", m.ID, "server_id", srv.ID,
		"tunnel_id", t.ID, "created", res.Created)
	return res, nil
}

// RefreshServer rediscovers machine m's server name through its live
// connection; it never approves anything.
func (s *Service) RefreshServer(ctx context.Context, m *store.Machine, name string) (*RefreshResult, error) {
	srv, tunnels, err := s.machineServer(ctx, m, name)
	if errors.Is(err, ErrServerNameTaken) {
		return nil, errNoServer
	}
	if err != nil {
		return nil, err
	}
	tid, _, _ := tunnel.ParseURL(srv.URL)
	live := slices.ContainsFunc(tunnels, func(t store.MCPTunnel) bool { return t.ID == tid && t.RevokedAt == nil })
	if !live || !s.o.Tunnels.Online(tid) {
		return nil, errOffline
	}
	version, d, err := s.o.Servers.Refresh(ctx, m.OwnerUserID, srv)
	if err != nil {
		var te *tunnel.Error
		if errors.As(err, &te) && te.Class == tunnel.ClassOffline {
			return nil, errOffline
		}
		s.log.Info("machine server refresh failed", "event", "machine.server_refresh_failed", "machine_id", m.ID, "server_id", srv.ID,
			"error", err.Error())
		return nil, errRefreshFailed
	}
	res := &RefreshResult{Version: version, Added: display(d.Added), Removed: display(d.Removed), Changed: []string{}, ReviewURL: s.ReviewURL(srv.ID)}
	for _, c := range d.Changed {
		res.Changed = append(res.Changed, snapshot.DisplayName(c.Name))
	}
	s.log.Info("machine server refreshed", "event", "machine.server_refreshed", "machine_id", m.ID, "server_id", srv.ID, "version", version)
	return res, nil
}

func display(names []string) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, snapshot.DisplayName(n))
	}
	return out
}

// Servers lists machine m's servers (its live tunnels whose server is
// still the owner's).
func (s *Service) Servers(ctx context.Context, m *store.Machine) ([]ServerView, error) {
	tunnels, err := s.o.Store.MachineTunnels(ctx, m.ID)
	if err != nil {
		return nil, err
	}
	out := []ServerView{}
	for _, t := range tunnels {
		if t.RevokedAt != nil {
			continue
		}
		srv, err := s.o.Servers.OwnServer(ctx, m.OwnerUserID, t.ServerName)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if tid, _, err := tunnel.ParseURL(srv.URL); err != nil || tid != t.ID {
			continue
		}
		v := ServerView{Name: t.ServerName, ServerID: srv.ID, TunnelID: t.ID, Status: "offline", ReviewURL: s.ReviewURL(srv.ID)}
		if s.o.Tunnels.Online(t.ID) {
			v.Status = "online"
		}
		if v.ApprovedTools, v.PendingReview, err = s.o.Servers.Review(ctx, m.OwnerUserID, srv.ID); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
