package google

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/textproto"
	"path"
	"strconv"
	"strings"
	"time"
	"unicode"

	"google.golang.org/api/gmail/v1"
	"google.golang.org/api/googleapi"
)

// Attachments of gmail.send, gmail.create_draft and gmail.update_draft
// (increment 5). A message with attachments is multipart/mixed (the body
// first, then one base64 part per attachment) and is uploaded as
// message/rfc822 (uploadType=multipart: one request carrying the thread
// id and the message) rather than as the JSON "raw" field.

// MaxAttachmentBytes bounds the decoded content of every attachment of
// one message together (and of a forwarded message's attachments).
const MaxAttachmentBytes = 5 << 20

// MaxAttachments bounds how many attachments one message carries.
const MaxAttachments = 50

// Values of an attachment's content_encoding.
var contentEncodings = []string{EncodingText, EncodingBase64}

// attachmentsProperty is the attachments argument of the composing tools.
var attachmentsProperty = property{"attachments", "attachments", fmt.Sprintf(
	"Files to attach (at most %d, %d MiB together): filename, content, content_encoding (text = default, or base64 for binary files) "+
		"and mime_type (guessed from the filename when omitted).", MaxAttachments, MaxAttachmentBytes>>20), nil}

func init() {
	schemaTypes["attachments"] = map[string]any{
		"type": "array",
		"items": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"filename":         map[string]any{"type": "string", "description": "File name shown to the recipient (no path)."},
				"content":          map[string]any{"type": "string", "description": "The file's content: text, or base64 with content_encoding base64."},
				"content_encoding": map[string]any{"type": "string", "enum": contentEncodings, "description": "text (default) or base64."},
				"mime_type":        map[string]any{"type": "string", "description": "MIME type, e.g. application/pdf; guessed from the filename when omitted."},
			},
			"required":             []string{"filename", "content"},
			"additionalProperties": false,
		},
	}
}

// attachment is one validated attachment.
type attachment struct {
	filename, mimeType string
	data               []byte
}

// extensionTypes are the MIME types of common extensions, checked before
// the system table (mime.TypeByExtension) so the guess does not depend
// on the host.
var extensionTypes = map[string]string{
	".txt": "text/plain; charset=utf-8", ".md": "text/markdown; charset=utf-8", ".csv": "text/csv; charset=utf-8",
	".tsv": "text/tab-separated-values; charset=utf-8", ".ics": "text/calendar; charset=utf-8", ".html": "text/html; charset=utf-8",
	".htm": "text/html; charset=utf-8", ".json": "application/json", ".xml": "application/xml", ".pdf": "application/pdf",
	".zip": "application/zip", ".gz": "application/gzip", ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
	".gif": "image/gif", ".webp": "image/webp", ".svg": "image/svg+xml",
	".doc": "application/msword", ".xls": "application/vnd.ms-excel", ".ppt": "application/vnd.ms-powerpoint",
	".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
	".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
	".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
}

// guessType returns the MIME type of a file name.
func guessType(filename string) string {
	ext := strings.ToLower(path.Ext(filename))
	if t, ok := extensionTypes[ext]; ok {
		return t
	}
	if t := mime.TypeByExtension(ext); t != "" {
		return t
	}
	return "application/octet-stream"
}

// validFilename reports whether name can be an attachment's file name:
// no path, no control characters.
func validFilename(name string) bool {
	if strings.TrimSpace(name) == "" || strings.ContainsAny(name, `/\`) || name == "." || name == ".." {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// attachmentsArg reads and validates the attachments argument.
func attachmentsArg(args map[string]any) ([]attachment, error) {
	v, ok := args["attachments"]
	if !ok || v == nil {
		return nil, nil
	}
	list, ok := v.([]any)
	if !ok {
		return nil, invalid("attachments must be an array of {filename, content, content_encoding, mime_type} objects")
	}
	if len(list) > MaxAttachments {
		return nil, invalid("at most %d attachments", MaxAttachments)
	}
	out := make([]attachment, 0, len(list))
	total := 0
	for i, item := range list {
		obj, ok := item.(map[string]any)
		if !ok {
			return nil, invalid("attachments[%d] must be an object {filename, content, content_encoding, mime_type}", i)
		}
		for k := range obj {
			switch k {
			case "filename", "content", "content_encoding", "mime_type":
			default:
				return nil, invalid("attachments[%d]: unknown field %q", i, k)
			}
		}
		name, _ := obj["filename"].(string)
		if !validFilename(name) {
			return nil, invalid("attachments[%d].filename must be a file name without a path or control characters", i)
		}
		content, ok := obj["content"].(string)
		if !ok {
			return nil, invalid("attachments[%d].content must be a string", i)
		}
		enc, _ := obj["content_encoding"].(string)
		if _, given := obj["content_encoding"]; given && enc == "" {
			return nil, invalid("attachments[%d].content_encoding must be text or base64", i)
		}
		var data []byte
		switch enc {
		case "", EncodingText:
			data = []byte(content)
		case EncodingBase64:
			compact := strings.Join(strings.Fields(content), "")
			b, err := base64.StdEncoding.DecodeString(compact)
			if err != nil {
				if b, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(compact, "=")); err != nil {
					return nil, invalid("attachments[%d].content is not valid base64", i)
				}
			}
			data = b
		default:
			return nil, invalid("attachments[%d].content_encoding must be text or base64", i)
		}
		mt := guessType(name)
		if raw, given := obj["mime_type"]; given {
			s, _ := raw.(string)
			base, _, err := mime.ParseMediaType(s)
			if err != nil || !strings.Contains(base, "/") {
				return nil, invalid("attachments[%d].mime_type must be a MIME type such as application/pdf", i)
			}
			mt = s
		}
		if total += len(data); total > MaxAttachmentBytes {
			return nil, invalid("the attachments are larger than %d bytes (%d MiB) together", MaxAttachmentBytes, MaxAttachmentBytes>>20)
		}
		out = append(out, attachment{filename: name, mimeType: mt, data: data})
	}
	return out, nil
}

// attachmentCount counts the attachments argument for the resource
// identity (0 when absent or not a list); never names or content.
func attachmentCount(args map[string]any) int {
	list, _ := args["attachments"].([]any)
	return len(list)
}

// --- rendering --------------------------------------------------------------------

// writeBase64 writes b in base64, 76 characters per line.
func writeBase64(w *bytes.Buffer, b []byte) {
	encoded := base64.StdEncoding.EncodeToString(b)
	for len(encoded) > 76 {
		w.WriteString(encoded[:76] + "\r\n")
		encoded = encoded[76:]
	}
	w.WriteString(encoded + "\r\n")
}

// rfc822 renders the message as RFC 5322 text: a single text part, or
// multipart/mixed with the attachments.
func (m outgoing) rfc822() []byte {
	var b bytes.Buffer
	write := func(name, value string) {
		if value != "" {
			b.WriteString(name + ": " + value + "\r\n")
		}
	}
	write("To", strings.Join(m.to, ", "))
	write("Cc", strings.Join(m.cc, ", "))
	write("Bcc", strings.Join(m.bcc, ", "))
	write("Subject", mime.QEncoding.Encode("utf-8", m.subject))
	write("Message-ID", m.messageID)
	write("In-Reply-To", m.inReplyTo)
	write("References", m.refs)
	write("Date", time.Now().UTC().Format(time.RFC1123Z))
	write("MIME-Version", "1.0")
	bodyType := "text/plain; charset=UTF-8"
	if m.html {
		bodyType = "text/html; charset=UTF-8"
	}
	if len(m.attachments) == 0 {
		write("Content-Type", bodyType)
		write("Content-Transfer-Encoding", "base64")
		b.WriteString("\r\n")
		writeBase64(&b, []byte(m.body))
		return b.Bytes()
	}
	var parts bytes.Buffer
	mw := multipart.NewWriter(&parts)
	part := func(h textproto.MIMEHeader, data []byte) {
		h.Set("Content-Transfer-Encoding", "base64")
		w, _ := mw.CreatePart(h) // writes to a bytes.Buffer: cannot fail
		var enc bytes.Buffer
		writeBase64(&enc, data)
		_, _ = w.Write(enc.Bytes())
	}
	part(textproto.MIMEHeader{"Content-Type": {bodyType}}, []byte(m.body))
	for _, a := range m.attachments {
		base, params, _ := mime.ParseMediaType(a.mimeType) // validated by attachmentsArg
		if params == nil {
			params = map[string]string{}
		}
		params["name"] = a.filename
		part(textproto.MIMEHeader{
			"Content-Type":        {mime.FormatMediaType(base, params)},
			"Content-Disposition": {mime.FormatMediaType("attachment", map[string]string{"filename": a.filename, "size": strconv.Itoa(len(a.data))})},
		}, a.data)
	}
	_ = mw.Close()
	write("Content-Type", mime.FormatMediaType("multipart/mixed", map[string]string{"boundary": mw.Boundary()}))
	b.WriteString("\r\n")
	b.Write(parts.Bytes())
	return b.Bytes()
}

// raw renders the message base64url-encoded, as the Gmail API's JSON
// "raw" field expects.
func (m outgoing) raw() string { return base64.RawURLEncoding.EncodeToString(m.rfc822()) }

// message is the Gmail message resource to send or draft: the raw
// message, or only the thread id when the message goes as media (media).
func (m outgoing) message() *gmail.Message {
	if len(m.attachments) > 0 {
		return &gmail.Message{ThreadId: m.threadID}
	}
	return &gmail.Message{Raw: m.raw(), ThreadId: m.threadID}
}

// media returns the message as message/rfc822 media when it has
// attachments (uploaded with uploadType=multipart), nil otherwise.
func (m outgoing) media() (io.Reader, googleapi.MediaOption) {
	if len(m.attachments) == 0 {
		return nil, nil
	}
	return bytes.NewReader(m.rfc822()), googleapi.ContentType("message/rfc822")
}
