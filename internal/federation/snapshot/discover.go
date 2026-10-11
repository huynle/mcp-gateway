package snapshot

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Discover lists a server's capabilities through sess into a Snapshot. Only
// the capabilities the server advertised are listed (a server without
// resources is not asked for them). Every list is sorted by key; empty or
// duplicate keys return ErrInvalidSnapshot. List errors are returned
// wrapped (they are the federation client's class-level errors).
func Discover(ctx context.Context, sess Session) (*Snapshot, error) {
	caps := sess.Capabilities()
	snap := &Snapshot{}
	if caps == nil {
		return snap, nil
	}
	if caps.Tools != nil {
		tools, err := sess.ListTools(ctx)
		if err != nil {
			return nil, fmt.Errorf("snapshot: discover tools: %w", err)
		}
		if snap.Tools, err = convertTools(tools); err != nil {
			return nil, err
		}
	}
	if caps.Resources != nil {
		rs, err := sess.ListResources(ctx)
		if err != nil {
			return nil, fmt.Errorf("snapshot: discover resources: %w", err)
		}
		if snap.Resources, err = convert(rs, "resource", func(r *mcp.Resource) (Resource, string) {
			return Resource{URI: r.URI, Name: r.Name, Title: r.Title, Description: r.Description, MIMEType: r.MIMEType}, r.URI
		}); err != nil {
			return nil, err
		}
		ts, err := sess.ListResourceTemplates(ctx)
		if err != nil {
			return nil, fmt.Errorf("snapshot: discover resource templates: %w", err)
		}
		if snap.ResourceTemplates, err = convert(ts, "resource template", func(r *mcp.ResourceTemplate) (ResourceTemplate, string) {
			return ResourceTemplate{URITemplate: r.URITemplate, Name: r.Name, Title: r.Title, Description: r.Description, MIMEType: r.MIMEType}, r.URITemplate
		}); err != nil {
			return nil, err
		}
	}
	if caps.Prompts != nil {
		ps, err := sess.ListPrompts(ctx)
		if err != nil {
			return nil, fmt.Errorf("snapshot: discover prompts: %w", err)
		}
		if snap.Prompts, err = convert(ps, "prompt", convertPrompt); err != nil {
			return nil, err
		}
	}
	return snap, nil
}

func convertPrompt(p *mcp.Prompt) (Prompt, string) {
	out := Prompt{Name: p.Name, Title: p.Title, Description: p.Description}
	for _, a := range p.Arguments {
		if a == nil {
			continue
		}
		out.Arguments = append(out.Arguments, PromptArgument{Name: a.Name, Title: a.Title, Description: a.Description, Required: a.Required})
	}
	return out, p.Name
}

func convertTools(in []*mcp.Tool) ([]Tool, error) {
	var conv error
	out, err := convert(in, "tool", func(t *mcp.Tool) (Tool, string) {
		tool := Tool{Name: t.Name, Title: t.Title, Description: t.Description}
		var e error
		if tool.InputSchema, e = rawSchema(t.InputSchema); e != nil && conv == nil {
			conv = e
		}
		if tool.OutputSchema, e = rawSchema(t.OutputSchema); e != nil && conv == nil {
			conv = e
		}
		if a := t.Annotations; a != nil {
			tool.Annotations = &Annotations{
				Title:           a.Title,
				ReadOnlyHint:    a.ReadOnlyHint,
				DestructiveHint: a.DestructiveHint,
				IdempotentHint:  a.IdempotentHint,
				OpenWorldHint:   a.OpenWorldHint,
			}
		}
		return tool, t.Name
	})
	if err != nil {
		return nil, err
	}
	if conv != nil {
		return nil, conv
	}
	return out, nil
}

// rawSchema marshals a schema as the client returned it (a map[string]any,
// or anything that marshals to JSON). A missing schema stays nil.
func rawSchema(v any) (json.RawMessage, error) {
	if v == nil {
		return nil, nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("%w: unencodable schema", ErrInvalidSnapshot)
	}
	if bytes.Equal(b, []byte("null")) {
		return nil, nil
	}
	return b, nil
}

// convert maps a list, rejecting nil items and empty or duplicate keys, and
// sorts it by key.
func convert[In any, Out any](in []*In, what string, f func(*In) (Out, string)) ([]Out, error) {
	if len(in) == 0 {
		return nil, nil
	}
	type keyed struct {
		key string
		v   Out
	}
	items := make([]keyed, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, x := range in {
		if x == nil {
			return nil, fmt.Errorf("%w: empty %s entry", ErrInvalidSnapshot, what)
		}
		v, key := f(x)
		if key == "" {
			return nil, fmt.Errorf("%w: %s without a name", ErrInvalidSnapshot, what)
		}
		if seen[key] {
			// The key is upstream text: never echo it.
			return nil, fmt.Errorf("%w: duplicate %s", ErrInvalidSnapshot, what)
		}
		seen[key] = true
		items = append(items, keyed{key, v})
	}
	slices.SortFunc(items, func(a, b keyed) int { return cmp.Compare(a.key, b.key) })
	out := make([]Out, len(items))
	for i, it := range items {
		out[i] = it.v
	}
	return out, nil
}
