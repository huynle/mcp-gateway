package machineclient

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"
)

// StatusOptions configure Status.
type StatusOptions struct {
	ConfigPath string
	StateDir   string
	Version    string
	Out        io.Writer
	Log        *slog.Logger
	// Now is the clock (nil: time.Now).
	Now func() time.Time

	newKeyStore func(name, dir string) (KeyStore, error)
}

// Status validates the config, shows the machine and checks its
// credentials against the gateway (GET /machine/v1/self), listing the
// servers with their review links. It reports every section and returns
// the first problem.
func Status(ctx context.Context, o StatusOptions) error {
	if o.newKeyStore == nil {
		o.newKeyStore = NewKeyStore
	}
	var first error
	fail := func(err error) {
		if first == nil {
			first = err
		}
	}
	cfg, err := LoadConfig(o.ConfigPath)
	if err != nil {
		say(o.Out, "config:   %v\n", err)
		fail(err)
	} else {
		say(o.Out, "config:   %s: %d servers (%s)\n", o.ConfigPath, len(cfg.Servers), strings.Join(cfg.ServerNames(), ", "))
	}

	st, err := LoadState(o.StateDir)
	if err != nil {
		say(o.Out, "machine:  %v\n", err)
		fail(err)
		return first
	}
	say(o.Out, "machine:  %q (%s) on %s\n", st.Name, st.MachineID, st.Gateway)
	if cfg != nil && cfg.Gateway != "" && cfg.Gateway != st.Gateway {
		err := fmt.Errorf("the config names gateway %s but this machine is logged in to %s", cfg.Gateway, st.Gateway)
		say(o.Out, "          %v\n", err)
		fail(err)
	}
	ks, err := o.newKeyStore(st.KeyStore, o.StateDir)
	if err != nil {
		say(o.Out, "key:      %v\n", err)
		fail(err)
		return first
	}
	key, err := ks.Load(ctx, st.MachineID)
	if err != nil {
		say(o.Out, "key:      %s store: %v\n", st.KeyStore, err)
		fail(err)
		return first
	}
	say(o.Out, "key:      %s store, fingerprint %s\n", st.KeyStore, FormatFingerprint(Thumbprint(key.Public().(ed25519.PublicKey))))

	client := NewClient(st.Gateway, o.Version, o.Log)
	api := &MachineAPI{Client: client, Tokens: &TokenSource{Client: client, MachineID: st.MachineID, Key: key, Now: o.Now}}
	self, err := api.Self(ctx)
	if err != nil {
		say(o.Out, "gateway:  %v\n", err)
		fail(err)
		return first
	}
	say(o.Out, "gateway:  credentials OK; owner %s\n", self.Owner)
	registered := map[string]bool{}
	say(o.Out, "servers:\n")
	for _, s := range self.Servers {
		registered[s.Name] = true
		say(o.Out, "  %-20s %s, %d approved tools; review at %s\n", s.Name, s.Status, s.ApprovedTools, s.ReviewURL)
	}
	if cfg != nil {
		for _, name := range cfg.ServerNames() {
			if !registered[name] {
				say(o.Out, "  %-20s not registered (run `mcp-gateway up`)\n", name)
			}
		}
	}
	return first
}

// LogoutOptions configure Logout.
type LogoutOptions struct {
	StateDir string
	Version  string
	Out      io.Writer
	Log      *slog.Logger
	// Now is the clock (nil: time.Now).
	Now func() time.Time

	newKeyStore func(name, dir string) (KeyStore, error)
}

// Logout revokes the machine on the gateway (POST /machine/v1/logout) and
// deletes its key and machine.json. When the gateway cannot be told, the
// local credentials are still deleted and the user is told to revoke the
// machine in the portal.
func Logout(ctx context.Context, o LogoutOptions) error {
	if o.newKeyStore == nil {
		o.newKeyStore = NewKeyStore
	}
	st, err := LoadState(o.StateDir)
	if err != nil {
		return err
	}
	ks, err := o.newKeyStore(st.KeyStore, o.StateDir)
	if err != nil {
		return err
	}
	portal := st.Gateway + "/machines"
	key, err := ks.Load(ctx, st.MachineID)
	switch {
	case err != nil:
		say(o.Out, "cannot sign in as the machine (%v); revoke %q on the Machines page: %s\n", err, st.Name, portal)
	default:
		client := NewClient(st.Gateway, o.Version, o.Log)
		api := &MachineAPI{Client: client, Tokens: &TokenSource{Client: client, MachineID: st.MachineID, Key: key, Now: o.Now}}
		switch err := api.Logout(ctx); {
		case err == nil:
			say(o.Out, "revoked machine %q on %s\n", st.Name, st.Gateway)
		case errors.Is(err, ErrRevoked) || errors.Is(err, ErrMachineRejected):
			say(o.Out, "the gateway no longer accepts machine %q (already revoked)\n", st.Name)
		default:
			say(o.Out, "could not revoke the machine on the gateway (%v); revoke %q on the Machines page: %s\n", err, st.Name, portal)
		}
		if err := ks.Delete(ctx, st.MachineID); err != nil {
			return err
		}
	}
	if err := DeleteState(o.StateDir); err != nil {
		return err
	}
	say(o.Out, "deleted the machine key and %s\n", stateFileName)
	return nil
}
