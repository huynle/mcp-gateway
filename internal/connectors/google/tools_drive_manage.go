package google

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"regexp"
	"slices"
	"strings"

	"google.golang.org/api/drive/v3"
	"google.golang.org/api/googleapi"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Drive management tool names.
const (
	ToolGetContent      = "get_content"
	ToolListFolder      = "list_folder"
	ToolListPermissions = "list_permissions"
	ToolListComments    = "list_comments"
	ToolCreateFile      = "create_file"
	ToolUpdateFile      = "update_file"
	ToolShare           = "share"
	ToolAddComment      = "add_comment"
)

// googleAppsPrefix starts the MIME type of every Google-native file
// (Docs, Sheets, Slides, ...), which has no bytes of its own and must be
// exported.
const googleAppsPrefix = "application/vnd.google-apps."

// defaultExports is the format get_content exports a Google-native file
// to when the harness names none; a type missing here (folders, forms,
// sites, shortcuts) cannot be exported.
var defaultExports = map[string]string{
	googleAppsPrefix + "document":     "text/plain",
	googleAppsPrefix + "spreadsheet":  "text/csv",
	googleAppsPrefix + "presentation": "text/plain",
	googleAppsPrefix + "drawing":      "image/png",
	googleAppsPrefix + "script":       googleAppsPrefix + "script+json",
}

// mimeRE is the shape of a MIME type argument.
var mimeRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_-]*/[A-Za-z0-9][A-Za-z0-9.+_-]*$`)

// Values of share's role and type.
var (
	shareRoles = []string{"reader", "commenter", "writer"}
	shareTypes = []string{"user", "group", "domain", "anyone"}
)

// DriveContent is get_content's result.
type DriveContent struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	MimeType   string `json:"mime_type"`
	ExportedAs string `json:"exported_as,omitempty"`
	Size       int    `json:"size"`
	Encoding   string `json:"encoding"`
	Content    string `json:"content"`
}

// FolderPage is list_folder's result.
type FolderPage struct {
	FolderID      string      `json:"folder_id"`
	MaxResults    int         `json:"max_results"`
	NextPageToken string      `json:"next_page_token,omitempty"`
	HasMore       bool        `json:"has_more"`
	Truncated     bool        `json:"truncated,omitempty"`
	Items         []DriveFile `json:"items"`
}

// FilePermission is one list_permissions item.
type FilePermission struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	Role        string `json:"role"`
	Email       string `json:"email,omitempty"`
	Domain      string `json:"domain,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	Expires     string `json:"expires,omitempty"`
}

// PermissionsPage is list_permissions's result.
type PermissionsPage struct {
	FileID        string           `json:"file_id"`
	NextPageToken string           `json:"next_page_token,omitempty"`
	HasMore       bool             `json:"has_more"`
	Truncated     bool             `json:"truncated,omitempty"`
	Items         []FilePermission `json:"items"`
}

// CommentReply is one reply of a comment.
type CommentReply struct {
	ID      string `json:"id"`
	Content string `json:"content"`
	Author  string `json:"author,omitempty"`
	Created string `json:"created,omitempty"`
}

// FileComment is one list_comments item.
type FileComment struct {
	ID       string         `json:"id"`
	Content  string         `json:"content"`
	Author   string         `json:"author,omitempty"`
	Email    string         `json:"email,omitempty"`
	Created  string         `json:"created,omitempty"`
	Modified string         `json:"modified,omitempty"`
	Resolved bool           `json:"resolved,omitempty"`
	Quoted   string         `json:"quoted,omitempty"`
	Replies  []CommentReply `json:"replies,omitempty"`
}

// CommentsPage is list_comments's result.
type CommentsPage struct {
	FileID        string        `json:"file_id"`
	MaxResults    int           `json:"max_results"`
	NextPageToken string        `json:"next_page_token,omitempty"`
	HasMore       bool          `json:"has_more"`
	Truncated     bool          `json:"truncated,omitempty"`
	Items         []FileComment `json:"items"`
}

// CreatedFile is create_file's and update_file's result.
type CreatedFile struct {
	ID       string   `json:"id"`
	Name     string   `json:"name,omitempty"`
	MimeType string   `json:"mime_type,omitempty"`
	URL      string   `json:"url,omitempty"`
	Parents  []string `json:"parents,omitempty"`
	DriveID  string   `json:"drive_id,omitempty"`
}

// SharedFile is share's result.
type SharedFile struct {
	FileID       string `json:"file_id"`
	PermissionID string `json:"permission_id"`
	Type         string `json:"type"`
	Role         string `json:"role"`
	Email        string `json:"email,omitempty"`
	Domain       string `json:"domain,omitempty"`
}

// CreatedComment is add_comment's result.
type CreatedComment struct {
	FileID    string `json:"file_id"`
	CommentID string `json:"comment_id"`
	Created   string `json:"created,omitempty"`
}

var fileIDProperty = property{"file_id", "string", "The file's id (from drive.search or list_folder, or the id in its URL).", nil}

func (c *Connector) driveManageReadTools() []connectors.Tool {
	return []connectors.Tool{
		{
			App: AppDrive, Name: ToolGetContent, Kind: connectors.KindRead,
			Description: fmt.Sprintf("Read a Drive file's content, at most %d MiB: Google Docs and Slides are exported as plain text, Sheets as CSV "+
				"(the first sheet), drawings as PNG, unless export_mime_type names another export format (application/pdf, text/html, "+
				"application/vnd.openxmlformats-officedocument.wordprocessingml.document, ...); other files are downloaded as they are. "+
				"encoding text gives the content as text, encoding base64 its bytes in base64. Larger files are refused.", MaxDownloadBytes>>20),
			InputSchema: objectSchema([]property{
				fileIDProperty,
				{"export_mime_type", "string", "Export format of a Google Doc, Sheet, Slides or drawing; ignored for other files.", nil},
			}, []string{"file_id"}),
			RequiredScopes:   []string{ScopeDriveReadonly},
			ResourceIdentity: fileIdentity,
			Bounds:           connectors.Bounds{MaxResultBytes: MaxDownloadResultBytes},
		},
		{
			App: AppDrive, Name: ToolListFolder, Kind: connectors.KindRead,
			Description: "List the files and folders directly inside a Drive folder (the root of My Drive when folder_id is omitted; " +
				"a shared drive's id lists its root), folders first then by name, trashed items left out. " +
				"Each item has id, name, mime_type, modified, url and size; has_more and next_page_token say whether another page exists.",
			InputSchema: objectSchema([]property{
				{"folder_id", "string", "Folder id; \"root\" (default) is My Drive's root.", nil},
				{"max_results", "integer", "Items per page (1-100; default 25); clamped to the tool's maximum.", nil},
				{"page_token", "string", "Token of the page to fetch (next_page_token of the previous result).", nil},
			}, nil),
			RequiredScopes: []string{ScopeDriveMetadataReadonly},
			ResourceIdentity: func(args map[string]any) map[string]string {
				id, _ := args["folder_id"].(string)
				if id = strings.TrimSpace(id); id == "" {
					id = "root"
				}
				return map[string]string{"folder_id": id}
			},
			Bounds: c.pagedBounds(),
		},
		{
			App: AppDrive, Name: ToolListPermissions, Kind: connectors.KindRead,
			Description: "List who a Drive file is shared with: each permission's id, type (user, group, domain, anyone), role " +
				"(owner, organizer, fileOrganizer, writer, commenter, reader), email or domain and display name.",
			InputSchema: objectSchema([]property{
				fileIDProperty,
				{"page_token", "string", "Token of the page to fetch (next_page_token of the previous result).", nil},
			}, []string{"file_id"}),
			RequiredScopes:   []string{ScopeDriveMetadataReadonly},
			ResourceIdentity: fileIdentity,
			Bounds:           c.pagedBounds(),
		},
		{
			App: AppDrive, Name: ToolListComments, Kind: connectors.KindRead,
			Description: "List the comments on a Drive file (a Doc, Sheet, Slides or any file): content, author, created, resolved, " +
				"the quoted text and the replies. has_more and next_page_token say whether another page exists.",
			InputSchema: objectSchema([]property{
				fileIDProperty,
				{"max_results", "integer", "Comments per page (1-100; default 25); clamped to the tool's maximum.", nil},
				{"page_token", "string", "Token of the page to fetch (next_page_token of the previous result).", nil},
			}, []string{"file_id"}),
			RequiredScopes:   []string{ScopeDriveReadonly},
			ResourceIdentity: fileIdentity,
			Bounds:           c.pagedBounds(),
		},
	}
}

func (c *Connector) driveManageReadHandlers() map[string]handler {
	return map[string]handler{ToolGetContent: c.getContent, ToolListFolder: c.listFolder, ToolListPermissions: c.listPermissions, ToolListComments: c.listComments}
}

func (c *Connector) driveManageWriteTools() []connectors.Tool {
	return []connectors.Tool{
		{
			App: AppDrive, Name: ToolCreateFile, Kind: connectors.KindWrite,
			Description: fmt.Sprintf("Upload a new file to Google Drive (at most %d MiB): name, content (text, or bytes in base64 with "+
				"content_encoding base64), mime_type, in the root of My Drive, under parent_id, or in the shared drive drive_id. "+
				"Returns the new file's id and url.", MaxDownloadBytes>>20),
			InputSchema: objectSchema([]property{
				{"name", "string", "File name, with its extension.", nil},
				{"content", "string", "The file's content: text, or base64 when content_encoding is base64.", nil},
				{"content_encoding", "string", "text (default) or base64.", []string{EncodingText, EncodingBase64}},
				{"mime_type", "string", "MIME type of the content (text/plain when omitted for text; Drive guesses from the name otherwise).", nil},
				{"parent_id", "string", "Id of the folder to create the file in; the root of My Drive (or of drive_id) when omitted.", nil},
				{"drive_id", "string", "Shared drive to create the file in (its root when parent_id is omitted).", nil},
			}, []string{"name", "content"}),
			RequiredScopes:   []string{ScopeDriveFile},
			ResourceIdentity: driveIdentity(true),
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileMarker, Check: c.checkDriveMarker},
			ResultIDs:        createdFileResultIDs,
			Bounds:           c.singleBounds(),
		},
		{
			App: AppDrive, Name: ToolUpdateFile, Kind: connectors.KindWrite,
			Description: "Rename a Drive file or folder, change its description, or move it into another folder (parent_id: it leaves " +
				"its current folders). Only the fields given change. Returns the file's id, name, url and parents.",
			InputSchema: objectSchema([]property{
				fileIDProperty,
				{"name", "string", "New name.", nil},
				{"description", "string", "New description (empty clears it).", nil},
				{"parent_id", "string", "Folder to move the file into.", nil},
			}, []string{"file_id"}),
			RequiredScopes:   []string{ScopeDriveFile},
			ResourceIdentity: updateFileIdentity,
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileMarker, Check: c.checkFileMarker},
			ResultIDs:        createdFileResultIDs,
			Bounds:           c.singleBounds(),
		},
		{
			App: AppDrive, Name: ToolShare, Kind: connectors.KindWrite,
			Description: "Share a Drive file: give a user or group (email), a whole domain (domain) or anyone with the link (type anyone) " +
				"the role reader, commenter or writer. Users and groups get Google's notification email (send_notification, default true) " +
				"with an optional message. Cannot be verified after an unknown outcome: check the file's sharing.",
			InputSchema: objectSchema([]property{
				fileIDProperty,
				{"role", "string", "reader, commenter or writer.", shareRoles},
				{"type", "string", "user (default), group, domain or anyone.", shareTypes},
				{"email", "string", "Address of the user or group (type user or group).", nil},
				{"domain", "string", "Domain to share with (type domain).", nil},
				{"send_notification", "boolean", "Email the user or group. Default true.", nil},
				{"message", "string", "Message for the notification email.", nil},
			}, []string{"file_id", "role"}),
			RequiredScopes:   []string{ScopeDriveFile},
			ResourceIdentity: shareIdentity,
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileNone},
			ResultIDs:        sharedFileResultIDs,
			Bounds:           c.singleBounds(),
		},
		{
			App: AppDrive, Name: ToolAddComment, Kind: connectors.KindWrite,
			Description: "Add a comment to a Drive file (a Doc, Sheet, Slides or any file), not anchored to a range. Returns the comment's id. " +
				"Cannot be verified after an unknown outcome: check the file's comments.",
			InputSchema: objectSchema([]property{
				fileIDProperty,
				{"content", "string", "The comment's text.", nil},
			}, []string{"file_id", "content"}),
			RequiredScopes:   []string{ScopeDriveFile},
			ResourceIdentity: fileIdentity,
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileNone},
			ResultIDs:        createdCommentResultIDs,
			Bounds:           c.singleBounds(),
		},
	}
}

func (c *Connector) driveManageWriteHandlers() map[string]handler {
	return map[string]handler{ToolCreateFile: c.createFile, ToolUpdateFile: c.updateFile, ToolShare: c.share, ToolAddComment: c.addComment}
}

// updateFileIdentity is file_id plus folder_id (the folder moved into).
func updateFileIdentity(args map[string]any) map[string]string {
	out := fileIdentity(args)
	if id, _ := args["parent_id"].(string); strings.TrimSpace(id) != "" {
		out["folder_id"] = strings.TrimSpace(id)
	}
	return out
}

// shareIdentity is file_id, role, type ("user" when omitted) and
// grantee_domain (the email's domain, or the domain shared with): policy
// can confirm or deny sharing outside the company; never the address.
func shareIdentity(args map[string]any) map[string]string {
	out := fileIdentity(args)
	if v, _ := args["role"].(string); strings.TrimSpace(v) != "" {
		out["role"] = strings.TrimSpace(v)
	}
	typ, _ := args["type"].(string)
	if typ = strings.TrimSpace(typ); typ == "" {
		typ = "user"
	}
	out["type"] = typ
	if email, _ := args["email"].(string); domainOf(email) != "" {
		out["grantee_domain"] = domainOf(email)
	} else if d, _ := args["domain"].(string); strings.TrimSpace(d) != "" {
		out["grantee_domain"] = strings.ToLower(strings.TrimSpace(d))
	}
	return out
}

func createdFileResultIDs(res connectors.Result) map[string]string {
	v, ok := res.Content.(CreatedFile)
	if !ok || v.ID == "" {
		return nil
	}
	return map[string]string{"id": v.ID, "url": v.URL}
}

func sharedFileResultIDs(res connectors.Result) map[string]string {
	v, ok := res.Content.(SharedFile)
	if !ok || v.PermissionID == "" {
		return nil
	}
	return map[string]string{"file_id": v.FileID, "permission_id": v.PermissionID}
}

func createdCommentResultIDs(res connectors.Result) map[string]string {
	v, ok := res.Content.(CreatedComment)
	if !ok || v.CommentID == "" {
		return nil
	}
	return map[string]string{"file_id": v.FileID, "comment_id": v.CommentID}
}

// --- reads ------------------------------------------------------------------------

// readLimited reads at most MaxDownloadBytes of a download, refusing more.
func readLimited(res *http.Response, action string) ([]byte, error) {
	defer func() { _ = res.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(res.Body, MaxDownloadBytes+1))
	if err != nil {
		return nil, classify(action, err)
	}
	if len(b) > MaxDownloadBytes {
		return nil, tooLarge(int64(len(b)))
	}
	return b, nil
}

func (c *Connector) getContent(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	fileID, err := idArg(call.Args, "file_id")
	if err != nil {
		return connectors.Result{}, err
	}
	exportAs, err := optionalString(call.Args, "export_mime_type")
	if err != nil {
		return connectors.Result{}, err
	}
	if exportAs = strings.TrimSpace(exportAs); exportAs != "" && !mimeRE.MatchString(exportAs) {
		return connectors.Result{}, invalid("export_mime_type must be a MIME type such as application/pdf")
	}
	svc, err := cl.drive(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	f, err := svc.Files.Get(fileID).Context(ctx).Fields("id,name,mimeType,size").SupportsAllDrives(true).Do()
	if err := classify("get file metadata", err); err != nil {
		return connectors.Result{}, err
	}
	out := DriveContent{ID: f.Id, Name: f.Name, MimeType: f.MimeType}
	if out.ID == "" {
		out.ID = fileID
	}
	var resp *http.Response
	if strings.HasPrefix(f.MimeType, googleAppsPrefix) {
		if exportAs == "" {
			exportAs = defaultExports[f.MimeType]
		}
		if exportAs == "" {
			return connectors.Result{}, invalid("a %s cannot be exported; only Docs, Sheets, Slides, drawings and Apps Script files have content", f.MimeType)
		}
		out.ExportedAs = exportAs
		resp, err = svc.Files.Export(fileID, exportAs).Context(ctx).Download()
	} else {
		if f.Size > MaxDownloadBytes {
			return connectors.Result{}, tooLarge(f.Size)
		}
		resp, err = svc.Files.Get(fileID).Context(ctx).SupportsAllDrives(true).Download()
	}
	if err := classify("read file content", err); err != nil {
		return connectors.Result{}, err
	}
	raw, err := readLimited(resp, "read file content")
	if err != nil {
		return connectors.Result{}, err
	}
	out.Size = len(raw)
	out.Encoding, out.Content = downloadContent(raw)
	return connectors.Result{Content: out, Empty: len(raw) == 0}, nil
}

func (c *Connector) listFolder(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	folderID, err := idArgDefault(call.Args, "folder_id", "root")
	if err != nil {
		return connectors.Result{}, err
	}
	maxResults, pageToken, clamped, err := c.pageArgs(call.Args, defaultFilesPerPage)
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.drive(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	req := svc.Files.List().Context(ctx).Q("'" + driveQueryEscape(folderID) + "' in parents and trashed = false").
		Corpora("allDrives").IncludeItemsFromAllDrives(true).SupportsAllDrives(true).OrderBy("folder,name").
		PageSize(int64(maxResults)).Fields("nextPageToken,files(" + fileFields + ")")
	if pageToken != "" {
		req = req.PageToken(pageToken)
	}
	list, err := req.Do()
	if err := classify("list folder", err); err != nil {
		return connectors.Result{}, err
	}
	out := FolderPage{FolderID: folderID, MaxResults: maxResults, NextPageToken: list.NextPageToken, HasMore: list.NextPageToken != "", Items: make([]DriveFile, 0, len(list.Files))}
	for _, f := range list.Files {
		if f != nil {
			out.Items = append(out.Items, toDriveFile(f))
		}
	}
	res := connectors.Result{Partial: clamped, Empty: len(out.Items) == 0}
	for encodedSize(out) > c.bounds.MaxResultBytes && len(out.Items) > 1 {
		out.Items = out.Items[:len(out.Items)-1]
		out.Truncated, res.Partial = true, true
	}
	res.Content = out
	return res, nil
}

func (c *Connector) listPermissions(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	fileID, err := idArg(call.Args, "file_id")
	if err != nil {
		return connectors.Result{}, err
	}
	pageToken, err := optionalString(call.Args, "page_token")
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.drive(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	req := svc.Permissions.List(fileID).Context(ctx).SupportsAllDrives(true).PageSize(maxPerPage).
		Fields("nextPageToken,permissions(id,type,role,emailAddress,domain,displayName,expirationTime)")
	if pageToken = strings.TrimSpace(pageToken); pageToken != "" {
		req = req.PageToken(pageToken)
	}
	list, err := req.Do()
	if err := classify("list permissions", err); err != nil {
		return connectors.Result{}, err
	}
	out := PermissionsPage{FileID: fileID, NextPageToken: list.NextPageToken, HasMore: list.NextPageToken != "", Items: make([]FilePermission, 0, len(list.Permissions))}
	for _, p := range list.Permissions {
		if p != nil {
			out.Items = append(out.Items, FilePermission{ID: p.Id, Type: p.Type, Role: p.Role, Email: p.EmailAddress, Domain: p.Domain, DisplayName: p.DisplayName, Expires: normalizeTimestamp(p.ExpirationTime)})
		}
	}
	res := connectors.Result{Empty: len(out.Items) == 0}
	for encodedSize(out) > c.bounds.MaxResultBytes && len(out.Items) > 1 {
		out.Items = out.Items[:len(out.Items)-1]
		out.Truncated, res.Partial = true, true
	}
	res.Content = out
	return res, nil
}

func (c *Connector) listComments(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	fileID, err := idArg(call.Args, "file_id")
	if err != nil {
		return connectors.Result{}, err
	}
	maxResults, pageToken, clamped, err := c.pageArgs(call.Args, defaultFilesPerPage)
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.drive(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	req := svc.Comments.List(fileID).Context(ctx).PageSize(int64(maxResults)).
		Fields("nextPageToken,comments(id,content,author(displayName,emailAddress),createdTime,modifiedTime,resolved,quotedFileContent(value),replies(id,content,author(displayName),createdTime))")
	if pageToken != "" {
		req = req.PageToken(pageToken)
	}
	list, err := req.Do()
	if err := classify("list comments", err); err != nil {
		return connectors.Result{}, err
	}
	out := CommentsPage{FileID: fileID, MaxResults: maxResults, NextPageToken: list.NextPageToken, HasMore: list.NextPageToken != "", Items: make([]FileComment, 0, len(list.Comments))}
	for _, cm := range list.Comments {
		if cm == nil {
			continue
		}
		item := FileComment{ID: cm.Id, Content: cm.Content, Created: normalizeTimestamp(cm.CreatedTime), Modified: normalizeTimestamp(cm.ModifiedTime), Resolved: cm.Resolved}
		if cm.Author != nil {
			item.Author, item.Email = cm.Author.DisplayName, cm.Author.EmailAddress
		}
		if cm.QuotedFileContent != nil {
			item.Quoted = cm.QuotedFileContent.Value
		}
		for _, r := range cm.Replies {
			if r == nil {
				continue
			}
			reply := CommentReply{ID: r.Id, Content: r.Content, Created: normalizeTimestamp(r.CreatedTime)}
			if r.Author != nil {
				reply.Author = r.Author.DisplayName
			}
			item.Replies = append(item.Replies, reply)
		}
		out.Items = append(out.Items, item)
	}
	res := connectors.Result{Partial: clamped, Empty: len(out.Items) == 0}
	for encodedSize(out) > c.bounds.MaxResultBytes && len(out.Items) > 1 {
		out.Items = out.Items[:len(out.Items)-1]
		out.Truncated, res.Partial = true, true
	}
	res.Content = out
	return res, nil
}

// --- writes -----------------------------------------------------------------------

// uploadContent reads content and content_encoding: the bytes to upload,
// at most MaxDownloadBytes.
func uploadContent(args map[string]any) ([]byte, string, error) {
	v, ok := args["content"]
	if !ok || v == nil {
		return nil, "", invalid("content is required")
	}
	content, ok := v.(string)
	if !ok {
		return nil, "", invalid("content must be a string")
	}
	encoding, err := optionalString(args, "content_encoding")
	if err != nil {
		return nil, "", err
	}
	var raw []byte
	switch strings.TrimSpace(encoding) {
	case "", EncodingText:
		raw, encoding = []byte(content), EncodingText
	case EncodingBase64:
		if raw, err = base64.StdEncoding.DecodeString(strings.TrimSpace(content)); err != nil {
			return nil, "", invalid("content is not valid base64")
		}
	default:
		return nil, "", invalid("content_encoding must be text or base64")
	}
	if len(raw) > MaxDownloadBytes {
		return nil, "", invalid("content is %d bytes; at most %d bytes (%d MiB) per file", len(raw), MaxDownloadBytes, MaxDownloadBytes>>20)
	}
	return raw, encoding, nil
}

func (c *Connector) createFile(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	name, err := requiredString(call.Args, "name")
	if err != nil {
		return connectors.Result{}, err
	}
	raw, encoding, err := uploadContent(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	mimeType, err := optionalString(call.Args, "mime_type")
	if err != nil {
		return connectors.Result{}, err
	}
	if mimeType = strings.TrimSpace(mimeType); mimeType != "" && !mimeRE.MatchString(mimeType) {
		return connectors.Result{}, invalid("mime_type must be a MIME type such as text/plain")
	}
	if mimeType == "" && encoding == EncodingText && !strings.Contains(name, ".") {
		mimeType = "text/plain"
	}
	f, err := newDriveFile(call, name, mimeType)
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.drive(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	var opts []googleapi.MediaOption
	if mimeType != "" {
		opts = append(opts, googleapi.ContentType(mimeType))
	}
	created, err := svc.Files.Create(f).Context(ctx).Media(bytes.NewReader(raw), opts...).SupportsAllDrives(true).Fields(createdFileFields + ",name").Do()
	if err := classifyWrite("upload file", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: CreatedFile{ID: created.Id, Name: created.Name, MimeType: created.MimeType, URL: created.WebViewLink, Parents: created.Parents, DriveID: created.DriveId}}, nil
}

// updateFile patches name and description with the operation's marker
// in appProperties; a move first reads the current parents (a read: its
// failure is a known outcome) and swaps them in the same request.
func (c *Connector) updateFile(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	fileID, err := idArg(call.Args, "file_id")
	if err != nil {
		return connectors.Result{}, err
	}
	patch := &drive.File{AppProperties: map[string]string{DriveMarkerKey: call.OperationID}}
	changed := false
	if _, ok := call.Args["name"]; ok {
		if patch.Name, err = requiredString(call.Args, "name"); err != nil {
			return connectors.Result{}, invalid("name must not be blank")
		}
		changed = true
	}
	if _, ok := call.Args["description"]; ok {
		if patch.Description, err = optionalString(call.Args, "description"); err != nil {
			return connectors.Result{}, err
		}
		if patch.Description == "" {
			patch.ForceSendFields = append(patch.ForceSendFields, "Description")
		}
		changed = true
	}
	parentID, err := idArgDefault(call.Args, "parent_id", "")
	if err != nil {
		return connectors.Result{}, err
	}
	if !changed && parentID == "" {
		return connectors.Result{}, invalid("nothing to change: give name, description or parent_id")
	}
	svc, err := cl.drive(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	req := svc.Files.Update(fileID, patch).Context(ctx).SupportsAllDrives(true).Fields(createdFileFields + ",name")
	if parentID != "" {
		cur, err := svc.Files.Get(fileID).Context(ctx).Fields("id,parents").SupportsAllDrives(true).Do()
		if err := classify("look up the file's folders", err); err != nil {
			return connectors.Result{}, err
		}
		var remove []string
		for _, p := range cur.Parents {
			if p != parentID {
				remove = append(remove, p)
			}
		}
		req = req.AddParents(parentID)
		if len(remove) > 0 {
			req = req.RemoveParents(strings.Join(remove, ","))
		}
	}
	updated, err := req.Do()
	if err := classifyWrite("update file", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: CreatedFile{ID: fileID, Name: updated.Name, MimeType: updated.MimeType, URL: updated.WebViewLink, Parents: updated.Parents, DriveID: updated.DriveId}}, nil
}

func (c *Connector) share(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	fileID, err := idArg(call.Args, "file_id")
	if err != nil {
		return connectors.Result{}, err
	}
	role, err := requiredString(call.Args, "role")
	if err != nil {
		return connectors.Result{}, err
	}
	if !slices.Contains(shareRoles, role) {
		return connectors.Result{}, invalid("role must be reader, commenter or writer")
	}
	typ, err := optionalString(call.Args, "type")
	if err != nil {
		return connectors.Result{}, err
	}
	if typ = strings.TrimSpace(typ); typ == "" {
		typ = "user"
	}
	if !slices.Contains(shareTypes, typ) {
		return connectors.Result{}, invalid("type must be user, group, domain or anyone")
	}
	email, _ := optionalString(call.Args, "email")
	domain, _ := optionalString(call.Args, "domain")
	email, domain = strings.TrimSpace(email), strings.ToLower(strings.TrimSpace(domain))
	p := &drive.Permission{Type: typ, Role: role}
	switch typ {
	case "user", "group":
		addr, err := mail.ParseAddress(email)
		if email == "" || err != nil || domain != "" {
			return connectors.Result{}, invalid("type %s needs email (an address) and no domain", typ)
		}
		p.EmailAddress = addr.Address
	case "domain":
		if domain == "" || email != "" || strings.ContainsAny(domain, " /@") {
			return connectors.Result{}, invalid("type domain needs domain (example.com) and no email")
		}
		p.Domain = domain
	case "anyone":
		if email != "" || domain != "" {
			return connectors.Result{}, invalid("type anyone takes neither email nor domain")
		}
	}
	notify, err := optionalBool(call.Args, "send_notification", true)
	if err != nil {
		return connectors.Result{}, err
	}
	message, err := optionalString(call.Args, "message")
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.drive(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	req := svc.Permissions.Create(fileID, p).Context(ctx).SupportsAllDrives(true).Fields("id,type,role,emailAddress,domain")
	if typ == "user" || typ == "group" {
		req = req.SendNotificationEmail(notify)
		if message = strings.TrimSpace(message); notify && message != "" {
			req = req.EmailMessage(message)
		}
	}
	created, err := req.Do()
	if err := classifyWrite("share file", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: SharedFile{FileID: fileID, PermissionID: created.Id, Type: created.Type, Role: created.Role, Email: created.EmailAddress, Domain: created.Domain}}, nil
}

func (c *Connector) addComment(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	fileID, err := idArg(call.Args, "file_id")
	if err != nil {
		return connectors.Result{}, err
	}
	content, err := textArg(call.Args, "content", true)
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.drive(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	created, err := svc.Comments.Create(fileID, &drive.Comment{Content: content}).Context(ctx).Fields("id,createdTime").Do()
	if err := classifyWrite("add comment", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: CreatedComment{FileID: fileID, CommentID: created.Id, Created: normalizeTimestamp(created.CreatedTime)}}, nil
}

// --- reconciliation ---------------------------------------------------------------

// checkFileMarker is update_file's marker reconciliation: the file's
// appProperties entry DriveMarkerKey equal to the operation id is found,
// none is not_found, another operation's (a later update replaced ours)
// or any error is "cannot tell yet".
func (c *Connector) checkFileMarker(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	tg, err := c.target(in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	fileID := in.ResourceIdentity["file_id"]
	if fileID == "" || !idRE.MatchString(fileID) {
		return connectors.ReconcileResult{}, fmt.Errorf("%w: resource identity has no file", ErrNotReconcilable)
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	svc, err := tg.client.drive(ctx)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	f, err := svc.Files.Get(fileID).Context(ctx).Fields("id,appProperties").SupportsAllDrives(true).Do()
	if err := classify("reconcile: get file", err); err != nil {
		return connectors.ReconcileResult{}, err
	}
	switch f.AppProperties[DriveMarkerKey] {
	case tg.operationID:
		return found(fileID), nil
	case "":
		return notFound, nil
	}
	return connectors.ReconcileResult{}, fmt.Errorf("google: reconcile: the file carries another operation's marker; cannot tell")
}
