package google

import (
	"context"
	"strings"

	"google.golang.org/api/drive/v3"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Drive tool names.
const (
	ToolSearchFiles     = "search"
	ToolGetFileMetadata = "get_file_metadata"
	ToolCreateFolder    = "create_folder"
)

// DriveMy is the "drive" resource identity of the account's own My Drive
// (when no shared drive id is given).
const DriveMy = "my"

// Google Workspace MIME types the connector creates.
const (
	MimeFolder   = "application/vnd.google-apps.folder"
	MimeDocument = "application/vnd.google-apps.document"
)

// defaultFilesPerPage is drive.search's page size when the harness gives
// none, capped by the bounds.
const defaultFilesPerPage = 25

// fileFields are the file fields every Drive read asks for (never
// content, never appProperties).
const fileFields = "id,name,mimeType,createdTime,modifiedTime,webViewLink,size,parents,driveId,trashed,shared,ownedByMe,description,owners(emailAddress)"

// createdFileFields are the fields the writes ask for: identifiers only.
const createdFileFields = "id,webViewLink,parents,driveId,mimeType"

// DriveMarkerKey is the appProperties key drive.create_folder and
// docs.create set on the file they create; its value is the ledger
// operation id. appProperties are private to the gateway's OAuth
// client: no other app, and no user, sees or changes them.
const DriveMarkerKey = "mcp-gateway-op"

// DriveMarkerQuery is the Drive files.list query that finds the file an
// operation created by its marker.
func DriveMarkerQuery(operationID string) string {
	return "appProperties has { key='" + DriveMarkerKey + "' and value='" + driveQueryEscape(operationID) + "' }"
}

// driveQueryEscape escapes a value for a single-quoted Drive query string.
func driveQueryEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s)
}

var driveIDProperty = property{"drive_id", "string", "Shared drive id (from a file's drive_id); the account's My Drive and the files shared with it when omitted.", nil}

// DriveFile is get_file_metadata's result and one search item: metadata
// only, never content.
type DriveFile struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	MimeType    string   `json:"mime_type,omitempty"`
	Created     string   `json:"created,omitempty"`
	Modified    string   `json:"modified,omitempty"`
	URL         string   `json:"url,omitempty"`
	Size        int64    `json:"size,omitempty"`
	Parents     []string `json:"parents,omitempty"`
	DriveID     string   `json:"drive_id,omitempty"`
	Trashed     bool     `json:"trashed,omitempty"`
	Shared      bool     `json:"shared,omitempty"`
	OwnedByMe   bool     `json:"owned_by_me,omitempty"`
	Owners      []string `json:"owners,omitempty"`
	Description string   `json:"description,omitempty"`
	// Truncated says the description was cut to fit the result bounds.
	Truncated bool `json:"truncated,omitempty"`
}

// FilesPage is search's result.
type FilesPage struct {
	Query         string      `json:"query,omitempty"`
	Drive         string      `json:"drive"`
	MaxResults    int         `json:"max_results"`
	NextPageToken string      `json:"next_page_token,omitempty"`
	HasMore       bool        `json:"has_more"`
	Truncated     bool        `json:"truncated,omitempty"`
	Items         []DriveFile `json:"items"`
}

// CreatedFolder is create_folder's result: the identifiers of the new
// folder.
type CreatedFolder struct {
	ID       string `json:"id"`
	URL      string `json:"url,omitempty"`
	ParentID string `json:"parent_id,omitempty"`
	DriveID  string `json:"drive_id,omitempty"`
}

func toDriveFile(f *drive.File) DriveFile {
	out := DriveFile{
		ID: f.Id, Name: f.Name, MimeType: f.MimeType, Created: normalizeTimestamp(f.CreatedTime), Modified: normalizeTimestamp(f.ModifiedTime),
		URL: f.WebViewLink, Size: f.Size, Parents: f.Parents, DriveID: f.DriveId, Trashed: f.Trashed, Shared: f.Shared, OwnedByMe: f.OwnedByMe,
		Description: f.Description,
	}
	for _, o := range f.Owners {
		if o != nil && o.EmailAddress != "" {
			out.Owners = append(out.Owners, o.EmailAddress)
		}
	}
	return out
}

// driveReadTools declares the Drive reads.
func (c *Connector) driveReadTools() []connectors.Tool {
	return []connectors.Tool{
		{
			App: AppDrive, Name: ToolSearchFiles, Kind: connectors.KindRead,
			Description: "Search Google Drive with the Drive query syntax (name contains 'budget', fullText contains 'quarterly', " +
				"mimeType = 'application/vnd.google-apps.document', '<folder id>' in parents, modifiedTime > '2026-01-01T00:00:00'); " +
				"every file when q is omitted. Each item has id, name, mime_type, modified, url, size, parents and drive_id; trashed files are " +
				"left out unless include_trashed is true. Searches My Drive and the files shared with the account, or one shared drive (drive_id). " +
				"has_more and next_page_token say whether another page exists (pass page_token).",
			InputSchema: objectSchema([]property{
				{"q", "string", "Drive search query (files.list q syntax). Omit for every file.", nil},
				driveIDProperty,
				{"include_trashed", "boolean", "Include files in the trash. Default false.", nil},
				{"max_results", "integer", "Files per page (1-100; default 25); clamped to the tool's maximum.", nil},
				{"page_token", "string", "Token of the page to fetch (next_page_token of the previous result).", nil},
			}, nil),
			RequiredScopes:   []string{ScopeDriveMetadataReadonly},
			ResourceIdentity: driveIdentity(false),
			Bounds:           c.pagedBounds(),
		},
		{
			App: AppDrive, Name: ToolGetFileMetadata, Kind: connectors.KindRead,
			Description: "Get the metadata of one Drive file or folder by id: name, mime_type, created, modified, url, size, parents, drive_id, " +
				"owners, shared, trashed and description. Never the file's content.",
			InputSchema: objectSchema([]property{
				{"file_id", "string", "The file's id (from search, or the id in its Drive URL).", nil},
			}, []string{"file_id"}),
			RequiredScopes:   []string{ScopeDriveMetadataReadonly},
			ResourceIdentity: fileIdentity,
			Bounds:           c.singleBounds(),
		},
	}
}

func (c *Connector) driveReadHandlers() map[string]handler {
	return map[string]handler{ToolSearchFiles: c.searchFiles, ToolGetFileMetadata: c.getFileMetadata}
}

// driveWriteTools declares drive.create_folder.
func (c *Connector) driveWriteTools() []connectors.Tool {
	return []connectors.Tool{{
		App: AppDrive, Name: ToolCreateFolder, Kind: connectors.KindWrite,
		Description: "Create a folder in Google Drive: in the root of My Drive, under parent_id, or in the shared drive drive_id. " +
			"Returns the new folder's id and url.",
		InputSchema: objectSchema([]property{
			{"name", "string", "Folder name.", nil},
			{"parent_id", "string", "Id of the parent folder; the root of My Drive (or of drive_id) when omitted.", nil},
			{"drive_id", "string", "Shared drive to create the folder in (its root when parent_id is omitted).", nil},
		}, []string{"name"}),
		RequiredScopes:   []string{ScopeDriveFile},
		ResourceIdentity: driveIdentity(true),
		Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileMarker, Check: c.checkDriveMarker},
		ResultIDs:        folderResultIDs,
		Bounds:           c.singleBounds(),
	}}
}

func (c *Connector) driveWriteHandlers() map[string]handler {
	return map[string]handler{ToolCreateFolder: c.createFolder}
}

// driveIdentity extracts drive ("my", or the shared drive id) and, when
// withParent, folder_id (the parent folder) from the arguments; never a
// query or a name.
func driveIdentity(withParent bool) func(map[string]any) map[string]string {
	return func(args map[string]any) map[string]string {
		out := map[string]string{"drive": DriveMy}
		if id, _ := args["drive_id"].(string); strings.TrimSpace(id) != "" {
			out["drive"] = strings.TrimSpace(id)
		}
		if withParent {
			if id, _ := args["parent_id"].(string); strings.TrimSpace(id) != "" {
				out["folder_id"] = strings.TrimSpace(id)
			}
		}
		return out
	}
}

// fileIdentity extracts file_id from the arguments.
func fileIdentity(args map[string]any) map[string]string {
	out := map[string]string{}
	if id, _ := args["file_id"].(string); strings.TrimSpace(id) != "" {
		out["file_id"] = strings.TrimSpace(id)
	}
	return out
}

func folderResultIDs(res connectors.Result) map[string]string {
	v, ok := res.Content.(CreatedFolder)
	if !ok || v.ID == "" {
		return nil
	}
	return map[string]string{"id": v.ID, "url": v.URL}
}

// --- handlers -------------------------------------------------------------------

func (c *Connector) searchFiles(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	q, err := optionalString(call.Args, "q")
	if err != nil {
		return connectors.Result{}, err
	}
	driveID, err := idArgDefault(call.Args, "drive_id", "")
	if err != nil {
		return connectors.Result{}, err
	}
	includeTrashed, err := optionalBool(call.Args, "include_trashed", false)
	if err != nil {
		return connectors.Result{}, err
	}
	maxResults, pageToken, clamped, err := c.pageArgs(call.Args, defaultFilesPerPage)
	if err != nil {
		return connectors.Result{}, err
	}
	var terms []string
	if q = strings.TrimSpace(q); q != "" {
		terms = append(terms, "("+q+")")
	}
	if !includeTrashed {
		terms = append(terms, "trashed = false")
	}
	svc, err := cl.drive(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	req := svc.Files.List().Context(ctx).Q(strings.Join(terms, " and ")).PageSize(int64(maxResults)).
		Fields("nextPageToken,files(" + fileFields + ")").SupportsAllDrives(true)
	drv := DriveMy
	if driveID != "" {
		drv = driveID
		req = req.Corpora("drive").DriveId(driveID).IncludeItemsFromAllDrives(true)
	} else {
		req = req.Corpora("user")
	}
	if pageToken != "" {
		req = req.PageToken(pageToken)
	}
	list, err := req.Do()
	if err := classify("search files", err); err != nil {
		return connectors.Result{}, err
	}
	out := FilesPage{Query: q, Drive: drv, MaxResults: maxResults, NextPageToken: list.NextPageToken, HasMore: list.NextPageToken != "", Items: make([]DriveFile, 0, len(list.Files))}
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

func (c *Connector) getFileMetadata(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	fileID, err := idArg(call.Args, "file_id")
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.drive(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	f, err := svc.Files.Get(fileID).Context(ctx).Fields(fileFields).SupportsAllDrives(true).Do()
	if err := classify("get file metadata", err); err != nil {
		return connectors.Result{}, err
	}
	out := toDriveFile(f)
	fitBody(&out.Description, &out.Truncated, c.bounds.MaxResultBytes, func() any { return out })
	return connectors.Result{Content: out, Partial: out.Truncated}, nil
}

// createFolder creates the folder with the operation's marker in its
// appProperties, in one request: the marker and the folder exist
// together or not at all.
func (c *Connector) createFolder(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	name, err := requiredString(call.Args, "name")
	if err != nil {
		return connectors.Result{}, err
	}
	f, err := newDriveFile(call, name, MimeFolder)
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.drive(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	created, err := svc.Files.Create(f).Context(ctx).SupportsAllDrives(true).Fields(createdFileFields).Do()
	if err := classifyWrite("create folder", err); err != nil {
		return connectors.Result{}, err
	}
	out := CreatedFolder{ID: created.Id, URL: created.WebViewLink, DriveID: created.DriveId}
	if len(created.Parents) > 0 {
		out.ParentID = created.Parents[0]
	}
	return connectors.Result{Content: out}, nil
}

// newDriveFile builds the file a create writes: name, MIME type, the
// operation's marker and the parent (parent_id, else the shared drive's
// root when drive_id is given, else My Drive's root).
func newDriveFile(call connectors.Call, name, mimeType string) (*drive.File, error) {
	parentID, err := idArgDefault(call.Args, "parent_id", "")
	if err != nil {
		return nil, err
	}
	driveID, err := idArgDefault(call.Args, "drive_id", "")
	if err != nil {
		return nil, err
	}
	f := &drive.File{Name: name, MimeType: mimeType, AppProperties: map[string]string{DriveMarkerKey: call.OperationID}}
	switch {
	case parentID != "":
		f.Parents = []string{parentID}
	case driveID != "":
		f.Parents = []string{driveID}
	}
	return f, nil
}
