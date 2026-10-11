package portal

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/store"
)

// Preview bounds: upstream content is shown as escaped, sanitized text of
// at most maxPreviewRunes per item and maxPreviewItems items.
const (
	maxPreviewRunes = 8192
	maxPreviewItems = 20
)

type resourceView struct {
	URI, Name, Title, Description, MIMEType string
	// RawURI is posted back by the Read button (matched exactly against
	// the snapshot; attribute-escaped by the template).
	RawURI string
}

type templateView struct {
	URITemplate, Name, Title, Description, MIMEType string
}

type argView struct {
	Index       int
	Name        string
	Title       string
	Description string
	Required    bool
	Value       string
}

type promptView struct {
	Name, Path, Title, Description string
	Args                           []argView
}

// previewItem is one piece of live upstream content.
type previewItem struct {
	Label     string // resource URI or message role
	MIMEType  string
	Text      string
	Truncated bool
	Bytes     int // binary content: its size, not its bytes
	Note      string
}

type browseData struct {
	Title       string
	Caller      caller
	Server      serverView
	HasSnapshot bool
	Version     int
	Resources   []resourceView
	Templates   []templateView
	Prompts     []promptView
	ReadURI     string
	Preview     []previewItem
	Error       string
}

// approvedSnapshot returns the approved snapshot (nil when none).
func (p *Portal) approvedSnapshot(ctx context.Context, c caller, serverID string) (*snapshot.Record, error) {
	rec, err := p.d.Snapshots.Current(ctx, c.snapActor(), serverID)
	if errors.Is(err, snapshot.ErrNoSnapshot) {
		return nil, nil
	}
	return rec, err
}

func newPromptView(pr snapshot.Prompt) promptView {
	v := promptView{Name: snapshot.DisplayName(pr.Name), Path: url.PathEscape(pr.Name), Title: snapshot.DisplayTitle(pr.Title),
		Description: snapshot.DisplayDescription(pr.Description)}
	for i, a := range pr.Arguments {
		v.Args = append(v.Args, argView{Index: i, Name: snapshot.DisplayName(a.Name), Title: snapshot.DisplayTitle(a.Title),
			Description: snapshot.DisplayDescription(a.Description), Required: a.Required})
	}
	return v
}

func (p *Portal) browseData(ctx context.Context, c caller, s *store.MCPServer, rec *snapshot.Record) browseData {
	d := browseData{Title: s.Name + ": resources and prompts", Caller: c, Server: p.view(ctx, c, s)}
	if rec == nil || rec.Snapshot == nil {
		return d
	}
	d.HasSnapshot, d.Version = true, rec.Version
	for _, r := range rec.Snapshot.Resources {
		d.Resources = append(d.Resources, resourceView{URI: snapshot.DisplayTitle(r.URI), RawURI: r.URI, Name: snapshot.DisplayName(r.Name),
			Title: snapshot.DisplayTitle(r.Title), Description: snapshot.DisplayDescription(r.Description), MIMEType: snapshot.DisplayName(r.MIMEType)})
	}
	for _, t := range rec.Snapshot.ResourceTemplates {
		d.Templates = append(d.Templates, templateView{URITemplate: snapshot.DisplayTitle(t.URITemplate), Name: snapshot.DisplayName(t.Name),
			Title: snapshot.DisplayTitle(t.Title), Description: snapshot.DisplayDescription(t.Description), MIMEType: snapshot.DisplayName(t.MIMEType)})
	}
	for _, pr := range rec.Snapshot.Prompts {
		d.Prompts = append(d.Prompts, newPromptView(pr))
	}
	return d
}

func (p *Portal) resources(w http.ResponseWriter, r *http.Request, c caller, s *store.MCPServer) {
	rec, err := p.approvedSnapshot(r.Context(), c, s.ID)
	if err != nil {
		p.fail(w, r, "approved snapshot", err)
		return
	}
	p.render(w, r, http.StatusOK, "resources.html", p.browseData(r.Context(), c, s, rec))
}

// readResource reads one resource of the approved snapshot live with the
// caller's credential and shows a bounded preview.
func (p *Portal) readResource(w http.ResponseWriter, r *http.Request, c caller, s *store.MCPServer) {
	ctx := r.Context()
	rec, err := p.approvedSnapshot(ctx, c, s.ID)
	if err != nil {
		p.fail(w, r, "approved snapshot", err)
		return
	}
	data := p.browseData(ctx, c, s, rec)
	uri := r.PostForm.Get("uri")
	listed := rec != nil && rec.Snapshot != nil && func() bool {
		for _, res := range rec.Snapshot.Resources {
			if res.URI == uri {
				return true
			}
		}
		return false
	}()
	if !listed {
		data.Error = "That is not a resource of the reviewed snapshot."
		p.render(w, r, http.StatusUnprocessableEntity, "resources.html", data)
		return
	}
	data.ReadURI = snapshot.DisplayTitle(uri)
	var res *mcp.ReadResourceResult
	err = p.withSession(ctx, c, s, func(sess Session) error {
		var err error
		res, err = sess.ReadResource(ctx, uri)
		return err
	})
	if err != nil {
		p.log.Info("read resource failed", "event", "federation.portal_read_failed", "user_id", c.UserID, "server_id", s.ID, "error", err.Error())
		data.Error = "Reading the resource failed: " + sessionMessage(err)
		p.render(w, r, http.StatusBadGateway, "resources.html", data)
		return
	}
	for i, rc := range res.Contents {
		if i == maxPreviewItems {
			data.Preview = append(data.Preview, previewItem{Note: fmt.Sprintf("%d more items not shown.", len(res.Contents)-i)})
			break
		}
		if rc != nil {
			data.Preview = append(data.Preview, contentsPreview(snapshot.DisplayTitle(rc.URI), rc))
		}
	}
	p.render(w, r, http.StatusOK, "resources.html", data)
}

func textPreview(label, mime, text string) previewItem {
	return previewItem{Label: label, MIMEType: snapshot.DisplayName(mime), Text: snapshot.DisplayMultiline(text, maxPreviewRunes),
		Truncated: utf8.RuneCountInString(text) > maxPreviewRunes}
}

func contentsPreview(label string, rc *mcp.ResourceContents) previewItem {
	if rc.Blob != nil {
		return previewItem{Label: label, MIMEType: snapshot.DisplayName(rc.MIMEType), Bytes: len(rc.Blob), Note: "binary content"}
	}
	return textPreview(label, rc.MIMEType, rc.Text)
}

// contentPreview previews one prompt message's content.
func contentPreview(role string, c mcp.Content) previewItem {
	switch v := c.(type) {
	case *mcp.TextContent:
		return textPreview(role, "text/plain", v.Text)
	case *mcp.ImageContent:
		return previewItem{Label: role, MIMEType: snapshot.DisplayName(v.MIMEType), Bytes: len(v.Data), Note: "image"}
	case *mcp.AudioContent:
		return previewItem{Label: role, MIMEType: snapshot.DisplayName(v.MIMEType), Bytes: len(v.Data), Note: "audio"}
	case *mcp.EmbeddedResource:
		if v.Resource != nil {
			return contentsPreview(role+" · "+snapshot.DisplayTitle(v.Resource.URI), v.Resource)
		}
	case *mcp.ResourceLink:
		return previewItem{Label: role, MIMEType: snapshot.DisplayName(v.MIMEType), Note: "link to " + snapshot.DisplayTitle(v.URI)}
	}
	return previewItem{Label: role, Note: "content not shown"}
}

// withSession opens a session as the caller, runs fn and closes it.
func (p *Portal) withSession(ctx context.Context, c caller, s *store.MCPServer, fn func(Session) error) error {
	sess, err := p.d.ClientFactory.Open(ctx, s, c.UserID)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := sess.Close(); cerr != nil {
			p.log.Debug("close upstream session", "server_id", s.ID, "error", cerr.Error())
		}
	}()
	return fn(sess)
}

type promptData struct {
	Title   string
	Caller  caller
	Server  serverView
	Prompt  promptView
	Run     bool
	Preview []previewItem
	Summary string
	Error   string
}

// prompt shows a prompt of the approved snapshot with its argument form
// (GET), and on POST gets it live with the entered arguments.
func (p *Portal) prompt(w http.ResponseWriter, r *http.Request, c caller, s *store.MCPServer) {
	ctx := r.Context()
	rec, err := p.approvedSnapshot(ctx, c, s.ID)
	if err != nil {
		p.fail(w, r, "approved snapshot", err)
		return
	}
	name := r.PathValue("name")
	var pr *snapshot.Prompt
	if rec != nil && rec.Snapshot != nil {
		for i := range rec.Snapshot.Prompts {
			if rec.Snapshot.Prompts[i].Name == name {
				pr = &rec.Snapshot.Prompts[i]
			}
		}
	}
	if pr == nil {
		p.notFound(w, r)
		return
	}
	data := promptData{Title: s.Name + ": prompt", Caller: c, Server: p.view(ctx, c, s), Prompt: newPromptView(*pr)}
	if r.Method != http.MethodPost {
		p.render(w, r, http.StatusOK, "prompt.html", data)
		return
	}
	args := map[string]string{}
	for i, a := range pr.Arguments {
		v := strings.TrimSpace(r.PostForm.Get("arg_" + strconv.Itoa(i)))
		if len(v) > maxFieldValue {
			v = v[:maxFieldValue]
		}
		data.Prompt.Args[i].Value = v
		switch {
		case v != "":
			args[a.Name] = v
		case a.Required && data.Error == "":
			data.Error = fmt.Sprintf("Argument %q is required.", snapshot.DisplayName(a.Name))
		}
	}
	if data.Error != "" {
		p.render(w, r, http.StatusUnprocessableEntity, "prompt.html", data)
		return
	}
	var res *mcp.GetPromptResult
	err = p.withSession(ctx, c, s, func(sess Session) error {
		var err error
		res, err = sess.GetPrompt(ctx, pr.Name, args)
		return err
	})
	if err != nil {
		p.log.Info("get prompt failed", "event", "federation.portal_prompt_failed", "user_id", c.UserID, "server_id", s.ID, "error", err.Error())
		data.Error = "Getting the prompt failed: " + sessionMessage(err)
		p.render(w, r, http.StatusBadGateway, "prompt.html", data)
		return
	}
	data.Run = true
	data.Summary = snapshot.DisplayDescription(res.Description)
	for i, m := range res.Messages {
		if i == maxPreviewItems {
			data.Preview = append(data.Preview, previewItem{Note: fmt.Sprintf("%d more messages not shown.", len(res.Messages)-i)})
			break
		}
		if m != nil {
			data.Preview = append(data.Preview, contentPreview(snapshot.DisplayName(string(m.Role)), m.Content))
		}
	}
	p.render(w, r, http.StatusOK, "prompt.html", data)
}
