package connectors

import (
	"errors"
	"fmt"
	"sort"
)

// ErrAppTaken reports an app name that is already used the other way: a
// server (dynamic) app whose name a built-in connector registered, or a
// built-in registration under a server app's name. Server names are also
// reserved at the service layer (internal/federation/connector), so this
// is the registry's own last line of defence.
var ErrAppTaken = errors.New("connectors: app name already taken")

// Server (dynamic) apps: the tools of a user-added MCP server live under
// the server's name ("<server>.<tool>") and change at run time, when a
// snapshot is approved or the server is disabled or deleted (Brain plan
// 0omkv2e1, task fybs78bs). Built-in connectors register once at start-up
// with Register / RegisterConnector; the two kinds of app never share a
// name.

// AddServerTools sets the tools of the server app named app, replacing any
// it had: readers see either the old or the new set, never a mix. Every
// tool must belong to app, be valid (Registry.Register's rules) and have a
// unique name; an empty set registers the app with no tools. On any error
// nothing changes. ErrAppTaken when a built-in connector owns app.
func (r *Registry) AddServerTools(app string, tools []Tool) error {
	if !identRE.MatchString(app) {
		return fmt.Errorf("%w: app %q must match %s", ErrInvalidTool, app, identRE)
	}
	seen := make(map[string]bool, len(tools))
	for _, t := range tools {
		if t.App != app {
			return fmt.Errorf("%w: %s: tool of app %q added to server %q", ErrInvalidTool, t.FullName(), t.App, app)
		}
		if err := t.validate(); err != nil {
			return err
		}
		if seen[t.Name] {
			return fmt.Errorf("%w: %s", ErrDuplicateTool, t.FullName())
		}
		seen[t.Name] = true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.static[app] {
		return fmt.Errorf("%w: %q is a built-in app", ErrAppTaken, app)
	}
	r.dropAppLocked(app)
	for _, t := range tools {
		r.tools[t.FullName()] = t
	}
	r.servers[app] = true
	return nil
}

// RemoveServerTools removes the server app named app and all its tools.
// It does nothing for an unknown app or a built-in one.
func (r *Registry) RemoveServerTools(app string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.servers[app] {
		return
	}
	r.dropAppLocked(app)
	delete(r.servers, app)
}

// IsServerApp reports whether app is a server (dynamic) app.
func (r *Registry) IsServerApp(app string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.servers[app]
}

// ServerApps returns the server app names, sorted.
func (r *Registry) ServerApps() []string {
	r.mu.RLock()
	out := make([]string, 0, len(r.servers))
	for app := range r.servers {
		out = append(out, app)
	}
	r.mu.RUnlock()
	sort.Strings(out)
	return out
}

// dropAppLocked deletes every tool of app. The caller holds the write lock.
func (r *Registry) dropAppLocked(app string) {
	for name, t := range r.tools {
		if t.App == app {
			delete(r.tools, name)
		}
	}
}
