package slack

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"unicode/utf8"

	goslack "github.com/slack-go/slack"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// ToolUploadFile is the file-upload write.
const ToolUploadFile = "upload_file"

// ScopeFilesWrite is the user-token scope upload_file needs.
const ScopeFilesWrite = "files:write"

// MaxUploadBytes bounds upload_file's decoded content (5 MiB): the
// content travels inside the tool call's JSON arguments, so a larger file
// belongs in a real file-sharing flow, not in a model's context.
const MaxUploadBytes = 5 << 20

// maxFilenameLen bounds the file name.
const maxFilenameLen = 255

// UploadedFile is upload_file's result: the new file's id, title, the
// channel (and thread) it was shared to and its size in bytes.
type UploadedFile struct {
	File     string `json:"file"`
	Title    string `json:"title,omitempty"`
	Channel  string `json:"channel"`
	ThreadTS string `json:"thread_ts,omitempty"`
	Size     int    `json:"size"`
}

func (c *Connector) fileTools() []connectors.Tool {
	return []connectors.Tool{{
		App: App, Name: ToolUploadFile, Kind: connectors.KindWrite,
		Description: fmt.Sprintf("Upload a file as the connected user and share it in a channel (or a thread with thread_ts). "+
			"content is the file's text, or its bytes in base64 with content_encoding base64; at most %d MiB decoded. "+
			"Returns the file id.", MaxUploadBytes>>20),
		InputSchema: objectSchema([]property{
			channelProperty,
			{"filename", "string", "File name including its extension (e.g. notes.md, report.csv, chart.png); no directories.", nil},
			{"content", "string", "The file content: plain text, or base64 when content_encoding is base64.", nil},
			{"content_encoding", "string", "How content is encoded: text (default) or base64.", []string{"text", "base64"}},
			{"title", "string", "Optional title shown in Slack (default: the file name).", nil},
			{"initial_comment", "string", "Optional message posted with the file.", nil},
			{"thread_ts", "string", "Optional: the parent message timestamp to share the file in that thread.", nil},
		}, []string{"channel", "filename", "content"}),
		RequiredScopes:   []string{ScopeFilesWrite},
		ResourceIdentity: identityWith(filenameIdentity),
		Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileNone},
		ResultIDs:        uploadedIDs,
		Bounds:           connectors.Bounds{MaxResultBytes: c.bounds.MaxResultBytes},
	}}
}

func (c *Connector) fileHandlers() map[string]handler {
	return map[string]handler{ToolUploadFile: c.uploadFile}
}

func filenameIdentity(args map[string]any, out map[string]string) {
	if name, err := filenameArg(args); err == nil {
		out["filename"] = name
	}
	if ts, _ := args["thread_ts"].(string); tsRE.MatchString(strings.TrimSpace(ts)) {
		out["thread_ts"] = strings.TrimSpace(ts)
	}
}

func uploadedIDs(res connectors.Result) map[string]string {
	v, ok := res.Content.(UploadedFile)
	if !ok || v.File == "" {
		return nil
	}
	return map[string]string{"file": v.File, "channel": v.Channel}
}

func filenameArg(args map[string]any) (string, error) {
	s, _ := args["filename"].(string)
	s = strings.TrimSpace(s)
	if s == "" || s == "." || s == ".." || strings.ContainsAny(s, "/\\\x00") || len(s) > maxFilenameLen || !utf8.ValidString(s) {
		return "", invalid("filename is required: a file name such as notes.md, without directories, at most %d bytes", maxFilenameLen)
	}
	return s, nil
}

// contentArg decodes the content argument within MaxUploadBytes.
func contentArg(args map[string]any) ([]byte, error) {
	s, ok := args["content"].(string)
	if !ok || s == "" {
		return nil, invalid("content is required: the file's text, or base64 with content_encoding base64")
	}
	enc, _ := args["content_encoding"].(string)
	if v, ok := args["content_encoding"]; ok && v != nil {
		if _, isString := v.(string); !isString {
			return nil, invalid("content_encoding must be text or base64")
		}
	}
	tooBig := invalid("content is larger than %d bytes (%d MiB); upload_file is for small files", MaxUploadBytes, MaxUploadBytes>>20)
	switch strings.ToLower(strings.TrimSpace(enc)) {
	case "", "text":
		if len(s) > MaxUploadBytes {
			return nil, tooBig
		}
		return []byte(s), nil
	case "base64":
		if base64.StdEncoding.DecodedLen(len(s)) > MaxUploadBytes+3 {
			return nil, tooBig
		}
		b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
		if err != nil {
			return nil, invalid("content is not valid base64")
		}
		if len(b) == 0 {
			return nil, invalid("content is empty")
		}
		if len(b) > MaxUploadBytes {
			return nil, tooBig
		}
		return b, nil
	}
	return nil, invalid("content_encoding must be text or base64")
}

// uploadURLAllowed accepts Slack's own upload hosts (https, slack.com or
// a subdomain) and the configured API host; the token travels to it as a
// bearer header, so a URL elsewhere is refused before any byte is sent.
func (c *Connector) uploadURLAllowed(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if u.Scheme == "https" && (host == "slack.com" || strings.HasSuffix(host, ".slack.com")) {
		return true
	}
	base, err := url.Parse(c.baseURL)
	return err == nil && u.Scheme == base.Scheme && strings.EqualFold(u.Host, base.Host)
}

// uploadFile runs Slack's three-step upload: files.getUploadURLExternal
// and the upload itself leave nothing visible (their failures are known
// outcomes); files.completeUploadExternal shares the file and is the
// write whose failure may leave the outcome open.
func (c *Connector) uploadFile(ctx context.Context, api *goslack.Client, call connectors.Call) (connectors.Result, error) {
	filename, err := filenameArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	content, err := contentArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	title, err := optionalString(call.Args, "title")
	if err != nil {
		return connectors.Result{}, err
	}
	comment, err := optionalString(call.Args, "initial_comment")
	if err != nil {
		return connectors.Result{}, err
	}
	threadTS, err := optionalTS(call.Args, "thread_ts")
	if err != nil {
		return connectors.Result{}, err
	}
	id, err := c.channelTarget(ctx, api, call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	up, err := api.GetUploadURLExternalContext(ctx, goslack.GetUploadURLExternalParameters{FileName: filename, FileSize: len(content)})
	if err := classify("upload file", err); err != nil {
		return connectors.Result{}, err
	}
	if up == nil || up.FileID == "" || !c.uploadURLAllowed(up.UploadURL) {
		return connectors.Result{}, &Error{Class: ClassVendorError, Message: "upload file: Slack returned no usable upload URL; nothing was uploaded"}
	}
	err = api.UploadToURL(ctx, goslack.UploadToURLParameters{UploadURL: up.UploadURL, Reader: bytes.NewReader(content), Filename: filename})
	if err := classify("upload file content", err); err != nil {
		return connectors.Result{}, err
	}
	title = strings.TrimSpace(title)
	if title == "" {
		title = filename
	}
	done, err := api.CompleteUploadExternalContext(ctx, goslack.CompleteUploadExternalParameters{
		Files: []goslack.FileSummary{{ID: up.FileID, Title: title}}, Channel: id, InitialComment: comment, ThreadTimestamp: threadTS,
	})
	if err := ClassifyWrite("share file", err); err != nil {
		return connectors.Result{}, err
	}
	out := UploadedFile{File: up.FileID, Title: title, Channel: id, ThreadTS: threadTS, Size: len(content)}
	if done != nil && len(done.Files) == 1 && done.Files[0].ID != "" {
		out.File = done.Files[0].ID
	}
	return connectors.Result{Content: out}, nil
}
