package portal

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/huynle/mcp-gateway/internal/federation/auth"
	"github.com/huynle/mcp-gateway/internal/federation/client"
	"github.com/huynle/mcp-gateway/internal/federation/tunnel"
	"github.com/huynle/mcp-gateway/internal/store"
)

// Credentials is the part of *auth.Service the default factory uses.
type Credentials interface {
	ForUser(ctx context.Context, server *store.MCPServer, userID string) (auth.Authorizer, error)
}

// TunnelDialer is the part of *tunnel.Service the default factory uses.
type TunnelDialer interface {
	Authorize(ctx context.Context, serverOwnerID, tunnelID string) error
	HTTPClient(base *http.Client) *http.Client
}

// FactoryOptions configure NewClientFactory. Credentials, Tunnels and
// HTTPClient (netguard's client) are required.
type FactoryOptions struct {
	Credentials Credentials
	Tunnels     TunnelDialer
	HTTPClient  *http.Client
	// Timeout per upstream operation (client default when zero).
	Timeout time.Duration
	Log     *slog.Logger
}

type clientFactory struct{ o FactoryOptions }

// NewClientFactory returns the ClientFactory the portal uses to talk to an
// upstream as a user: the user's (or the shared) credential from the auth
// service, https servers through netguard's client, tunnel:// servers only
// through the server owner's live tunnel (tunnel.Service.Authorize, then its
// tunnel-only transport), static headers from header_config, and one
// refresh-and-retry on a 401 (auth.Reauth).
func NewClientFactory(o FactoryOptions) (ClientFactory, error) {
	if o.Credentials == nil || o.Tunnels == nil || o.HTTPClient == nil {
		return nil, errors.New("federation portal: FactoryOptions.Credentials, Tunnels and HTTPClient are required")
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	return &clientFactory{o: o}, nil
}

func (f *clientFactory) Open(ctx context.Context, server *store.MCPServer, userID string) (Session, error) {
	az, err := f.o.Credentials.ForUser(ctx, server, userID)
	if err != nil {
		return nil, err
	}
	hc, u := f.o.HTTPClient, server.URL
	if tunnel.IsTunnelURL(server.URL) {
		id, _, err := tunnel.ParseURL(server.URL)
		if err != nil {
			return nil, err
		}
		if err := f.o.Tunnels.Authorize(ctx, server.OwnerUserID, id); err != nil {
			return nil, err
		}
		if u, err = tunnel.ClientURL(server.URL); err != nil {
			return nil, err
		}
		hc = f.o.Tunnels.HTTPClient(f.o.HTTPClient)
	}
	c, err := client.New(client.Options{HTTPClient: hc, Authorizer: az, Timeout: f.o.Timeout, Log: f.o.Log})
	if err != nil {
		return nil, err
	}
	ep := client.Endpoint{URL: u, Transport: client.Transport(server.Transport), Headers: parseHeaderConfig(server.HeaderConfig).Static, Label: server.ID}
	var sess *client.Session
	err = auth.Reauth(ctx, az, func() error {
		var err error
		sess, err = c.Connect(ctx, ep)
		return err
	})
	if err != nil {
		return nil, err
	}
	return sess, nil
}
