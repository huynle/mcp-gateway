package google

import (
	"context"
	"net/url"
	"strings"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Increment 5 edit helpers: one batchUpdate request built from typed
// arguments, sent and answered like the raw batch_update (BatchUpdated:
// Google's reply and the new revision).

// buildRequest validates a helper's arguments and builds its one request
// ({"<kind>": {...}}); it runs before the token is fetched.
type buildRequest func(args map[string]any) (kind string, params map[string]any, err error)

// helperTool declares an edit helper of api: the id argument and
// required_revision_id (when the API takes a writeControl) are added to
// props; identity is the id alone (never text, uris or indexes).
func (c *Connector) helperTool(api batchAPI, name, description string, props []property, required []string) connectors.Tool {
	tool := c.batchTool(api)
	all := []property{{api.idArg, "string", "The " + api.noun + "'s id (from drive.search, or the id in its URL).", nil}}
	all = append(all, props...)
	if api.writeControl {
		all = append(all, property{"required_revision_id", "string", "Apply only if the " + api.noun + " is still at this revision " +
			"(revision_id of a previous read or write); Google refuses the change otherwise.", nil})
	}
	idArg := api.idArg
	tool.Name, tool.Description = name, description+" Cannot be verified after an unknown outcome: check the "+api.noun+"."
	tool.InputSchema = objectSchema(all, append([]string{api.idArg}, required...))
	tool.ResourceIdentity = func(args map[string]any) map[string]string { return identityOf(args, idArg) }
	return tool
}

// helperHandler runs an edit helper: validate, build, send.
func (c *Connector) helperHandler(api batchAPI, build buildRequest) handler {
	return func(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
		id, err := idArg(call.Args, api.idArg)
		if err != nil {
			return connectors.Result{}, err
		}
		kind, params, err := build(call.Args)
		if err != nil {
			return connectors.Result{}, err
		}
		body := map[string]any{"requests": []any{map[string]any{kind: params}}}
		if api.writeControl {
			rev, err := idArgDefault(call.Args, "required_revision_id", "")
			if err != nil {
				return connectors.Result{}, err
			}
			if rev != "" {
				body["writeControl"] = map[string]string{"requiredRevisionId": rev}
			}
		}
		out := BatchUpdated{RequestCount: 1, RequestKinds: []string{kind}}
		out.setTarget(api.idArg, id)
		return c.runBatch(ctx, cl, api, id, body, out)
	}
}

// intArg reads an integer argument within [lo, hi]; present is false
// when it is absent (then required makes it an error).
func intArg(args map[string]any, name string, required bool, lo, hi int) (value int, present bool, err error) {
	v, ok := args[name]
	if !ok || v == nil {
		if required {
			return 0, false, invalid("%s is required", name)
		}
		return 0, false, nil
	}
	n, err := toInt(v)
	if err != nil || n < lo || n > hi {
		return 0, false, invalid("%s must be an integer from %d to %d", name, lo, hi)
	}
	return n, true, nil
}

// numberArg reads an optional positive number argument (points).
func numberArg(args map[string]any, name string) (float64, bool, error) {
	v, ok := args[name]
	if !ok || v == nil {
		return 0, false, nil
	}
	var f float64
	switch n := v.(type) {
	case float64:
		f = n
	case int:
		f = float64(n)
	case int64:
		f = float64(n)
	default:
		return 0, false, invalid("%s must be a number", name)
	}
	if f <= 0 || f > 10000 {
		return 0, false, invalid("%s must be a positive number of points", name)
	}
	return f, true, nil
}

// imageURIArg reads a required public http(s) image URL.
func imageURIArg(args map[string]any, name string) (string, error) {
	raw, err := requiredString(args, name)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || strings.ContainsAny(raw, " \t\n") {
		return "", invalid("%s must be a public http(s) URL of the image", name)
	}
	if len(raw) > 2048 {
		return "", invalid("%s is longer than 2 kB", name)
	}
	return raw, nil
}
