package slack

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	goslack "github.com/slack-go/slack"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Identity resolution for policy (connectors.IdentityResolver). The
// tools' resource identity is a pure function of the arguments: a
// channel given by name yields channel=name, by id channel=id. A rule
// "deny when channel equals eng-secrets" must hold for the id of
// #eng-secrets too, so the policy stage asks the connector to name the
// channel before it decides. The lookup is the same users.conversations
// walk resolveChannel makes for a name (public and private channels and
// group DMs the account is a member of, pages of resolveLimit, at most
// MaxResolvePages) and its result is cached per (account, id) for
// IdentityCacheTTL in a map bounded to IdentityCacheMax entries; only
// hits are cached, a miss is asked again. A direct-message id (D...)
// has no name a rule could be written against and passes through
// unchanged. Any failure (the id is not among the account's
// conversations, Slack errs, the token cannot be fetched) is an error:
// the policy stage then denies the call (identity_unresolved) rather
// than evaluate the raw id against name conditions.

// Identity cache parameters.
const (
	// IdentityCacheTTL is how long a resolved (account, id) -> name
	// entry is served without asking Slack again.
	IdentityCacheTTL = 5 * time.Minute
	// IdentityCacheMax bounds the cache; past it, expired entries are
	// dropped and then arbitrary ones.
	IdentityCacheMax = 4096
)

// resolveTypes are the conversation types a channel id is looked up
// among: the ones the app's user scopes cover (channels:read,
// groups:read). Group DMs (mpim) need mpim:read, which the app does not
// request; asking for them made users.conversations fail with
// missing_scope and every call naming a channel by id was denied. A
// group-DM id is now not found and denied (fail closed), as before.
var resolveTypes = []string{"public_channel", "private_channel"}

// ResolveIdentity implements connectors.IdentityResolver: when identity
// names a channel by id (channel_id set, not a direct message), the id
// is resolved to its name and channel becomes that name (lower-cased),
// channel_id staying as it was; everything else comes back as given.
// The input map is never modified.
func (c *Connector) ResolveIdentity(ctx context.Context, call connectors.Call, identity map[string]string) (map[string]string, error) {
	id := identity["channel_id"]
	if id == "" || strings.HasPrefix(id, "D") {
		return identity, nil
	}
	name, err := c.channelName(ctx, call, id)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(identity))
	for k, v := range identity {
		out[k] = v
	}
	out["channel"] = name
	return out, nil
}

// channelName returns the lower-cased name of the channel id for the
// call's account, from the cache or from Slack.
func (c *Connector) channelName(ctx context.Context, call connectors.Call, id string) (string, error) {
	key := call.Account + "/" + id
	if name, ok := c.names.get(key); ok {
		return name, nil
	}
	if call.Account == "" {
		return "", &Error{Class: ClassNoAccount, Message: "no connected Slack account: connect one on the portal (Connections)"}
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	api, err := c.client(ctx, call)
	if err != nil {
		return "", err
	}
	ch, err := c.findConversation(ctx, api, resolveTypes, func(ch goslack.Channel) bool { return strings.EqualFold(ch.ID, id) })
	if err != nil {
		return "", err
	}
	if ch == nil {
		return "", &Error{Class: ClassNotFound, Message: fmt.Sprintf("channel %s not found among the conversations this account is a member of (first %d pages)", id, MaxResolvePages)}
	}
	name := strings.ToLower(ch.Name)
	if name == "" {
		name = strings.ToLower(ch.NameNormalized)
	}
	if name == "" {
		return "", &Error{Class: ClassNotFound, Message: fmt.Sprintf("channel %s has no name", id)}
	}
	c.names.put(key, name)
	return name, nil
}

// findConversation walks the account's conversations of the given
// types (pages of resolveLimit, at most MaxResolvePages) and returns
// the first one match accepts; nil when none did within the bound.
func (c *Connector) findConversation(ctx context.Context, api *goslack.Client, types []string, match func(goslack.Channel) bool) (*goslack.Channel, error) {
	params := &goslack.GetConversationsForUserParameters{Types: types, Limit: resolveLimit}
	for page := 1; page <= MaxResolvePages; page++ {
		channels, next, err := api.GetConversationsForUserContext(ctx, params)
		if err := classify("resolve channel", err); err != nil {
			return nil, err
		}
		for i := range channels {
			if match(channels[i]) {
				return &channels[i], nil
			}
		}
		if next == "" {
			break
		}
		params.Cursor = next
	}
	return nil, nil
}

// nameCache is the bounded, expiring (account, id) -> name map.
type nameCache struct {
	mu      sync.Mutex
	entries map[string]nameEntry
	ttl     time.Duration
	max     int
	now     func() time.Time
}

type nameEntry struct {
	name    string
	expires time.Time
}

func newNameCache(ttl time.Duration, max int) *nameCache {
	return &nameCache{entries: map[string]nameEntry{}, ttl: ttl, max: max, now: time.Now}
}

// get returns a live entry.
func (n *nameCache) get(key string) (string, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	e, ok := n.entries[key]
	if !ok {
		return "", false
	}
	if !n.now().Before(e.expires) {
		delete(n.entries, key)
		return "", false
	}
	return e.name, true
}

// put stores an entry, making room first: expired entries go, then
// arbitrary ones until the map is below its bound.
func (n *nameCache) put(key, name string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	now := n.now()
	if _, exists := n.entries[key]; !exists && len(n.entries) >= n.max {
		for k, e := range n.entries {
			if !now.Before(e.expires) {
				delete(n.entries, k)
			}
		}
		for k := range n.entries {
			if len(n.entries) < n.max {
				break
			}
			delete(n.entries, k)
		}
	}
	n.entries[key] = nameEntry{name: name, expires: now.Add(n.ttl)}
}

// len reports the number of entries, live or not.
func (n *nameCache) len() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.entries)
}
