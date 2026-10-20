package machineclient

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"strings"
	"time"
)

var (
	// ErrLoginDenied: the user denied the machine on /activate.
	ErrLoginDenied = errors.New("the machine was denied on the gateway")
	// ErrLoginExpired: the code expired before it was approved.
	ErrLoginExpired = errors.New("the login code expired before it was approved; run `mcp-gateway login` again")
)

// LoginOptions configure Login.
type LoginOptions struct {
	// Gateway is the gateway base URL (required).
	Gateway string
	// Name is the machine name to request.
	Name string
	// EnrollCode (mge_...) enrolls without the browser; "" runs the device flow.
	EnrollCode string
	// KeyStore is KeyStoreKeychain or KeyStoreFile.
	KeyStore string
	// StateDir holds machine.json (and machine.key for the file store).
	StateDir string
	// Version is the client version sent to the gateway.
	Version string
	// Out gets the instructions for the user.
	Out io.Writer
	// Log gets debug lines (never secrets); nil: none.
	Log *slog.Logger
	// OpenBrowser opens the approval page; nil: print it only.
	OpenBrowser func(url string) error
	// Now and Sleep are the clock (nil: real time).
	Now   func() time.Time
	Sleep func(ctx context.Context, d time.Duration) error

	newKeyStore func(name, dir string) (KeyStore, error) // tests
}

// defaultInterval is RFC 8628's polling interval when the server sends none.
const defaultInterval = 5 * time.Second

// Login enrolls this machine: it creates a key, has the gateway approve
// it (device flow, approved by the user at /activate, or a one-time
// enrollment code) and stores the key and machine.json. The device code,
// the enrollment code and the key are never printed or logged.
func Login(ctx context.Context, o LoginOptions) (*State, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Sleep == nil {
		o.Sleep = sleepCtx
	}
	if o.newKeyStore == nil {
		o.newKeyStore = NewKeyStore
	}
	if o.Gateway == "" {
		return nil, errors.New("no gateway: pass --gateway or set gateway in config.yaml")
	}
	gw, err := GatewayURL(o.Gateway)
	if err != nil {
		return nil, err
	}
	if err := ValidateMachineName(o.Name); err != nil {
		return nil, err
	}
	if o.EnrollCode != "" && !strings.HasPrefix(o.EnrollCode, "mge_") {
		return nil, errors.New("the enrollment code is malformed (expected mge_...)")
	}
	ks, err := o.newKeyStore(o.KeyStore, o.StateDir)
	if err != nil {
		return nil, err
	}
	switch st, err := LoadState(o.StateDir); {
	case err == nil:
		return nil, fmt.Errorf("already logged in as machine %q on %s; run `mcp-gateway logout` first", st.Name, st.Gateway)
	case !errors.Is(err, ErrNotLoggedIn):
		return nil, fmt.Errorf("cannot read the machine state: %w", err)
	}

	key, err := GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generate the machine key: %w", err)
	}
	pub := key.Public().(ed25519.PublicKey)
	c := NewClient(gw, o.Version, o.Log)
	var enr *Enrollment
	if o.EnrollCode != "" {
		if enr, err = c.Enroll(ctx, o.EnrollCode, o.Name, PublicJWK(pub)); err != nil {
			return nil, fmt.Errorf("enroll with the code: %w", err)
		}
	} else if enr, err = deviceFlow(ctx, c, o, pub); err != nil {
		return nil, err
	}
	if enr.Gateway != "" {
		if gw, err = sameGateway(gw, enr.Gateway); err != nil {
			return nil, err
		}
	}
	if err := ks.Save(ctx, enr.MachineID, key); err != nil {
		return nil, fmt.Errorf("the gateway approved the machine but its key could not be stored (revoke %q on the Machines page and log in again): %w", enr.Name, err)
	}
	st := &State{Gateway: gw, MachineID: enr.MachineID, Name: enr.Name, KeyStore: ks.Name()}
	if err := SaveState(o.StateDir, st); err != nil {
		_ = ks.Delete(ctx, enr.MachineID)
		return nil, fmt.Errorf("save the machine state: %w", err)
	}
	say(o.Out, "Logged in: machine %q (%s) on %s; key in the %s store.\n", st.Name, st.MachineID, st.Gateway, st.KeyStore)
	return st, nil
}

// sameGateway accepts the base URL the gateway reports for itself when it
// is on the same host (the assertion audience must be the gateway's own
// URL); another host is refused.
func sameGateway(ours, reported string) (string, error) {
	rep, err := GatewayURL(reported)
	if err != nil {
		return "", fmt.Errorf("the gateway reported an invalid base URL: %w", err)
	}
	a, _ := url.Parse(ours)
	b, _ := url.Parse(rep)
	if a.Scheme != b.Scheme || !strings.EqualFold(a.Host, b.Host) {
		return "", fmt.Errorf("the gateway says its URL is %s, not %s; log in with --gateway %s", rep, ours, rep)
	}
	return rep, nil
}

// deviceFlow runs RFC 8628: print the code, then poll at the interval
// (slow_down adds 5 s for good) until approved, denied or expired.
func deviceFlow(ctx context.Context, c *Client, o LoginOptions, pub ed25519.PublicKey) (*Enrollment, error) {
	da, err := c.DeviceAuthorization(ctx, o.Name, PublicJWK(pub))
	if err != nil {
		return nil, fmt.Errorf("start the login: %w", err)
	}
	say(o.Out, "To approve this machine, open %s\nand enter the code:  %s\n\n", da.VerificationURI, da.UserCode)
	say(o.Out, "Check that the page shows machine %q with fingerprint %s.\n", o.Name, FormatFingerprint(Thumbprint(pub)))
	if da.VerificationURIComplete != "" && o.OpenBrowser != nil {
		if err := o.OpenBrowser(da.VerificationURIComplete); err == nil {
			say(o.Out, "(opened in your browser)\n")
		}
	}
	say(o.Out, "Waiting for approval...\n")

	interval := time.Duration(da.Interval) * time.Second
	if interval <= 0 {
		interval = defaultInterval
	}
	expires := da.ExpiresIn
	if expires <= 0 {
		expires = 600
	}
	deadline := o.Now().Add(time.Duration(expires) * time.Second)
	for {
		if err := o.Sleep(ctx, interval); err != nil {
			return nil, err
		}
		if !o.Now().Before(deadline) {
			return nil, ErrLoginExpired
		}
		enr, err := c.PollDeviceToken(ctx, da.DeviceCode)
		var ae *APIError
		switch {
		case err == nil:
			return enr, nil
		case ctx.Err() != nil:
			return nil, ctx.Err()
		case !errors.As(err, &ae):
			// A network error: keep polling until the code expires.
			if o.Log != nil {
				o.Log.Debug("login poll failed; retrying", "error", err)
			}
		case ae.Code == "authorization_pending":
		case ae.Code == "slow_down":
			interval += 5 * time.Second
		case ae.Code == "access_denied":
			return nil, ErrLoginDenied
		case ae.Code == "expired_token":
			return nil, ErrLoginExpired
		default:
			return nil, fmt.Errorf("login: %w", err)
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// say writes a line for the user; a failing writer is not worth handling.
func say(w io.Writer, format string, args ...any) {
	if w != nil {
		_, _ = fmt.Fprintf(w, format, args...)
	}
}
