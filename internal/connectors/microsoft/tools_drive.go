package microsoft

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/microsoft/graph"
)

// OneDrive tools beyond search / create folder: folder listing, file
// content (bounded), small uploads and sharing links.
const (
	ToolDriveListChildren     = "drive_list_children"
	ToolDriveGetFileContent   = "drive_get_file_content"
	ToolDriveUploadFile       = "drive_upload_file"
	ToolDriveCreateShareLink  = "drive_create_share_link"
	conflictBehaviorParameter = "@microsoft.graph.conflictBehavior"
)

// FileContent is drive_get_file_content's result: the item and its
// content as text or base64 (Encoding).
type FileContent struct {
	DriveItem
	Encoding string `json:"encoding"`
	Content  string `json:"content"`
}

// UploadedFile is drive_upload_file's result.
type UploadedFile struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Size     int64  `json:"size"`
	WebURL   string `json:"web_url,omitempty"`
	DriveID  string `json:"drive_id,omitempty"`
	ParentID string `json:"parent_id,omitempty"`
}

// ShareLink is drive_create_share_link's result.
type ShareLink struct {
	ID     string `json:"id"`
	URL    string `json:"url"`
	Type   string `json:"type"`
	Scope  string `json:"scope,omitempty"`
	ItemID string `json:"item_id"`
}

// driveRoot is the Graph path of drive ("me/drive" for the user's own).
func driveRoot(drive string) string {
	if drive == "" || drive == driveDefaultName {
		return "me/drive"
	}
	return "drives/" + drive
}

func (c *Connector) driveDefs() []toolDef {
	paged := connectors.Bounds{MaxPageSize: c.bounds.MaxPageSize, MaxResultBytes: c.bounds.MaxResultBytes}
	single := connectors.Bounds{MaxResultBytes: c.bounds.MaxResultBytes}
	driveID := property{"drive_id", "string", "Drive id; the user's OneDrive when omitted.", nil}
	itemID := property{"item_id", "string", "The drive item id (from drive_search or drive_list_children).", nil}
	withDrive := func(extra func(map[string]any) map[string]string) func(map[string]any) map[string]string {
		return func(args map[string]any) map[string]string {
			out := driveIdentity(args)
			for k, v := range extra(args) {
				out[k] = v
			}
			return out
		}
	}
	return []toolDef{
		{Tool: connectors.Tool{
			App: App, Name: ToolDriveListChildren, Kind: connectors.KindRead,
			Description: "List the files and folders in a OneDrive folder (folder_id; the drive's root when omitted) of the user's OneDrive or " +
				"drive_id: id, name, folder flag, size, type, web url per item.",
			InputSchema:    objectSchema([]property{{"folder_id", "string", "Folder item id; the drive root when omitted.", nil}, driveID, topProperty}, nil),
			RequiredScopes: []string{ScopeFilesReadAll},
			ResourceIdentity: withDrive(func(args map[string]any) map[string]string {
				p := strings.TrimSpace(stringArg(args, "folder_id"))
				if p == "" {
					p = "root"
				}
				return map[string]string{"parent": p}
			}),
			Bounds: paged,
		}, run: c.driveListChildren},
		{Tool: connectors.Tool{
			App: App, Name: ToolDriveGetFileContent, Kind: connectors.KindRead,
			Description: "Download a OneDrive file (at most 5 MiB) as stored: text files come back as text, others as base64 (encoding says " +
				"which). Office documents are their raw .docx/.xlsx bytes. Larger files are refused with their web url.",
			InputSchema:      objectSchema([]property{itemID, driveID}, []string{"item_id"}),
			RequiredScopes:   []string{ScopeFilesReadAll},
			ResourceIdentity: withDrive(identity("item_id", "item")),
			Bounds:           connectors.Bounds{MaxResultBytes: contentResultBytes},
		}, run: c.driveGetFileContent},
		{Tool: connectors.Tool{
			App: App, Name: ToolDriveUploadFile, Kind: connectors.KindWrite,
			Description: "Upload a new small file (at most 5 MiB) to a OneDrive folder (parent_id; the root when omitted): content is the " +
				"file's text, or its bytes in base64 with content_encoding base64. Fails when an item of that name exists there.",
			InputSchema: objectSchema([]property{
				{"name", "string", "File name.", nil},
				{"content", "string", "The file content: text, or base64 when content_encoding is base64.", nil},
				{"content_encoding", "string", "text (default) or base64.", []string{"text", "base64"}},
				{"parent_id", "string", "Parent folder item id; the drive root when omitted.", nil},
				driveID,
			}, []string{"name", "content"}),
			RequiredScopes: []string{ScopeFilesReadWrite},
			ResourceIdentity: withDrive(func(args map[string]any) map[string]string {
				out := map[string]string{"parent": "root"}
				if p := strings.TrimSpace(stringArg(args, "parent_id")); p != "" {
					out["parent"] = p
				}
				if n := strings.TrimSpace(stringArg(args, "name")); n != "" {
					out["file"] = n
				}
				return out
			}),
			Reconcile: connectors.Reconciliation{Kind: connectors.ReconcileMarker, Check: c.checkFile},
			ResultIDs: resultIDs("id", "web_url"),
			Bounds:    single,
		}, run: c.driveUploadFile},
		{Tool: connectors.Tool{
			App: App, Name: ToolDriveCreateShareLink, Kind: connectors.KindWrite,
			Description: "Create (or get the existing) sharing link of a OneDrive item: type view (default) or edit; scope organization or " +
				"anonymous (the tenant's default when omitted; personal accounts only have anonymous links).",
			InputSchema: objectSchema([]property{itemID, driveID,
				{"type", "string", "view (default) or edit.", []string{"view", "edit"}},
				{"scope", "string", "organization or anonymous.", []string{"organization", "anonymous"}},
			}, []string{"item_id"}),
			RequiredScopes: []string{ScopeFilesReadWrite},
			ResourceIdentity: withDrive(func(args map[string]any) map[string]string {
				out := identity("item_id", "item")(args)
				lt := strings.ToLower(strings.TrimSpace(stringArg(args, "type")))
				if lt == "" {
					lt = "view"
				}
				out["link_type"] = lt
				return out
			}),
			Reconcile: connectors.Reconciliation{Kind: connectors.ReconcileNone},
			ResultIDs: resultIDs("id", "url"),
			Bounds:    single,
		}, run: c.driveCreateShareLink},
	}
}

func (c *Connector) driveListChildren(ctx context.Context, client *graph.Client, call connectors.Call) (connectors.Result, error) {
	folder, err := idArg(call.Args, "folder_id")
	if err != nil {
		return connectors.Result{}, err
	}
	drive, err := idArg(call.Args, "drive_id")
	if err != nil {
		return connectors.Result{}, err
	}
	top, clamped, err := c.topArg(call.Args, maxTop)
	if err != nil {
		return connectors.Result{}, err
	}
	q := url.Values{"$top": {strconv.Itoa(top)}, "$select": {driveItemSelect}}
	return listRead(ctx, c, client, "list folder", childrenPath(drive, folder), q, nil, top, clamped, toDriveItem)
}

func (c *Connector) driveGetFileContent(ctx context.Context, client *graph.Client, call connectors.Call) (connectors.Result, error) {
	item, err := requiredID(call.Args, "item_id")
	if err != nil {
		return connectors.Result{}, err
	}
	drive, err := idArg(call.Args, "drive_id")
	if err != nil {
		return connectors.Result{}, err
	}
	path := driveRoot(drive) + "/items/" + item
	var meta graphDriveItem
	if err := classify("get file", client.Get(ctx, path, url.Values{"$select": {driveItemSelect}}, &meta)); err != nil {
		return connectors.Result{}, err
	}
	if meta.Folder != nil || meta.File == nil {
		return connectors.Result{}, invalid("item %s is not a file; list a folder with drive_list_children", item)
	}
	if meta.Size > MaxContentBytes {
		return connectors.Result{}, tooLarge("the file", meta.Size, meta.WebURL)
	}
	raw, _, err := client.Download(ctx, path+"/content", nil, MaxContentBytes)
	if errors.Is(err, graph.ErrTooLarge) {
		return connectors.Result{}, tooLarge("the file", MaxContentBytes+1, meta.WebURL)
	}
	if err := classify("download file", err); err != nil {
		return connectors.Result{}, err
	}
	out := FileContent{DriveItem: toDriveItem(meta)}
	out.Encoding, out.Content = encodeContent(raw, out.MimeType)
	return connectors.Result{Content: out}, nil
}

// uploadContent decodes the content argument within MaxContentBytes.
func uploadContent(args map[string]any) ([]byte, error) {
	s, ok := args["content"].(string)
	if !ok || s == "" {
		return nil, invalid("content is required: the file's text, or base64 with content_encoding base64")
	}
	enc, err := optionalString(args, "content_encoding")
	if err != nil {
		return nil, err
	}
	tooBig := invalid("content is larger than %d MiB; drive_upload_file is for small files", MaxContentBytes>>20)
	switch strings.ToLower(strings.TrimSpace(enc)) {
	case "", "text":
		if len(s) > MaxContentBytes {
			return nil, tooBig
		}
		return []byte(s), nil
	case "base64":
		if base64.StdEncoding.DecodedLen(len(s)) > MaxContentBytes+3 {
			return nil, tooBig
		}
		b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
		if err != nil || len(b) == 0 {
			return nil, invalid("content is not valid, non-empty base64")
		}
		if len(b) > MaxContentBytes {
			return nil, tooBig
		}
		return b, nil
	}
	return nil, invalid("content_encoding must be text or base64")
}

func (c *Connector) driveUploadFile(ctx context.Context, client *graph.Client, call connectors.Call) (connectors.Result, error) {
	name, err := folderNameArg(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	parent, err := idArg(call.Args, "parent_id")
	if err != nil {
		return connectors.Result{}, err
	}
	drive, err := idArg(call.Args, "drive_id")
	if err != nil {
		return connectors.Result{}, err
	}
	data, err := uploadContent(call.Args)
	if err != nil {
		return connectors.Result{}, err
	}
	path := driveRoot(drive) + "/root:/" + name + ":/content"
	if parent != "" && parent != "root" {
		path = driveRoot(drive) + "/items/" + parent + ":/" + name + ":/content"
	}
	var created graphDriveItem
	_, err = client.Do(ctx, graph.Request{
		Method: http.MethodPut, Path: path, Query: url.Values{conflictBehaviorParameter: {"fail"}},
		RawBody: data, ContentType: "application/octet-stream",
	}, &created)
	if err != nil {
		err = classifyWrite("upload file", err)
		if statusOf(err) == http.StatusConflict {
			return connectors.Result{}, &Error{Status: http.StatusConflict, Class: ClassInvalidArgument, Message: "upload file: an item named " + name + " already exists in that folder", Err: err}
		}
		return connectors.Result{}, err
	}
	if created.ID == "" {
		return connectors.Result{}, errNoID("upload file", "item")
	}
	out := UploadedFile{ID: created.ID, Name: created.Name, Size: created.Size, WebURL: created.WebURL}
	if created.ParentReference != nil {
		out.DriveID, out.ParentID = created.ParentReference.DriveID, created.ParentReference.ID
	}
	return connectors.Result{Content: out}, nil
}

func (c *Connector) driveCreateShareLink(ctx context.Context, client *graph.Client, call connectors.Call) (connectors.Result, error) {
	item, err := requiredID(call.Args, "item_id")
	if err != nil {
		return connectors.Result{}, err
	}
	drive, err := idArg(call.Args, "drive_id")
	if err != nil {
		return connectors.Result{}, err
	}
	linkType, err := optionalString(call.Args, "type")
	if err != nil {
		return connectors.Result{}, err
	}
	switch linkType = strings.ToLower(strings.TrimSpace(linkType)); linkType {
	case "":
		linkType = "view"
	case "view", "edit":
	default:
		return connectors.Result{}, invalid("type must be view or edit")
	}
	scope, err := optionalString(call.Args, "scope")
	if err != nil {
		return connectors.Result{}, err
	}
	req := map[string]any{"type": linkType}
	switch scope = strings.ToLower(strings.TrimSpace(scope)); scope {
	case "":
	case "organization", "anonymous":
		req["scope"] = scope
	default:
		return connectors.Result{}, invalid("scope must be organization or anonymous")
	}
	var perm struct {
		ID   string `json:"id"`
		Link struct {
			Type   string `json:"type"`
			Scope  string `json:"scope"`
			WebURL string `json:"webUrl"`
		} `json:"link"`
	}
	if _, err := client.Post(ctx, driveRoot(drive)+"/items/"+item+"/createLink", req, &perm); err != nil {
		return connectors.Result{}, classifyWrite("create sharing link", err)
	}
	if perm.Link.WebURL == "" {
		return connectors.Result{}, errNoID("create sharing link", "link")
	}
	return connectors.Result{Content: ShareLink{ID: perm.ID, URL: perm.Link.WebURL, Type: perm.Link.Type, Scope: perm.Link.Scope, ItemID: item}}, nil
}
