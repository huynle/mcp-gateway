package google

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"

	"google.golang.org/api/drive/v3"
	"google.golang.org/api/googleapi"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Drive file lifecycle tool names (increment 5).
const (
	ToolCopyFile         = "copy_file"
	ToolDriveTrash       = "trash"
	ToolUntrash          = "untrash"
	ToolDeleteFile       = "delete"
	ToolEmptyTrash       = "empty_trash"
	ToolCreateShortcut   = "create_shortcut"
	ToolUploadNewVersion = "upload_new_version"
)

// MimeShortcut is the Drive shortcut MIME type create_shortcut creates.
const MimeShortcut = "application/vnd.google-apps.shortcut"

// TrashedFile is trash's and untrash's result.
type TrashedFile struct {
	ID      string `json:"id"`
	Name    string `json:"name,omitempty"`
	Trashed bool   `json:"trashed"`
}

// DeletedFile is delete's result.
type DeletedFile struct {
	ID      string `json:"id"`
	Deleted bool   `json:"deleted"`
}

// EmptiedTrash is empty_trash's result.
type EmptiedTrash struct {
	Drive   string `json:"drive"`
	Emptied bool   `json:"emptied"`
}

func (c *Connector) driveFilesWriteTools() []connectors.Tool {
	creates := func(args map[string]any) map[string]string {
		out := driveIdentity(args)
		for k, v := range fileIdentity(args) {
			out[k] = v
		}
		return out
	}
	trashTool := func(name string, trashed bool) connectors.Tool {
		desc := "Move a Drive file or folder to the trash (it can be restored with untrash for 30 days, then Drive deletes it)."
		if !trashed {
			desc = "Restore a Drive file or folder from the trash."
		}
		return connectors.Tool{
			App: AppDrive, Name: name, Kind: connectors.KindWrite,
			Description:      desc + " Returns the file's id and trashed state.",
			InputSchema:      objectSchema([]property{fileIDProperty}, []string{"file_id"}),
			RequiredScopes:   []string{ScopeDriveFile},
			ResourceIdentity: fileIdentity,
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: c.checkFileTrashed(trashed)},
			ResultIDs: func(res connectors.Result) map[string]string {
				if v, ok := res.Content.(TrashedFile); ok && v.ID != "" {
					return map[string]string{"id": v.ID}
				}
				return nil
			},
			Bounds: c.singleBounds(),
		}
	}
	return []connectors.Tool{
		{
			App: AppDrive, Name: ToolCopyFile, Kind: connectors.KindWrite,
			Description: "Copy a Drive file (not a folder): optional new name (Drive's \"Copy of ...\" when omitted), into parent_id or the " +
				"shared drive drive_id (next to the original when both are omitted). Returns the copy's id and url.",
			InputSchema: objectSchema([]property{
				fileIDProperty,
				{"name", "string", "Name of the copy.", nil},
				{"parent_id", "string", "Folder to put the copy in.", nil},
				{"drive_id", "string", "Shared drive to put the copy in (its root when parent_id is omitted).", nil},
			}, []string{"file_id"}),
			RequiredScopes:   []string{ScopeDriveFile},
			ResourceIdentity: creates,
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileMarker, Check: c.checkDriveMarker},
			ResultIDs:        createdFileResultIDs,
			Bounds:           c.singleBounds(),
		},
		trashTool(ToolDriveTrash, true),
		trashTool(ToolUntrash, false),
		{
			App: AppDrive, Name: ToolDeleteFile, Kind: connectors.KindWrite,
			Description: "Permanently delete a Drive file or folder (a folder with everything in it), skipping the trash: it cannot be restored. " +
				"Use trash to keep it restorable.",
			InputSchema:      objectSchema([]property{fileIDProperty}, []string{"file_id"}),
			RequiredScopes:   []string{ScopeDriveFile},
			ResourceIdentity: fileIdentity,
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: c.checkFileDeleted},
			ResultIDs: func(res connectors.Result) map[string]string {
				if v, ok := res.Content.(DeletedFile); ok && v.ID != "" {
					return map[string]string{"id": v.ID}
				}
				return nil
			},
			Bounds: c.singleBounds(),
		},
		{
			App: AppDrive, Name: ToolEmptyTrash, Kind: connectors.KindWrite,
			Description: "Permanently delete every file in the trash of My Drive (or of the shared drive drive_id): they cannot be restored. " +
				"Cannot be verified after an unknown outcome: check the trash.",
			InputSchema: objectSchema([]property{
				{"drive_id", "string", "Shared drive whose trash to empty; My Drive's when omitted.", nil},
			}, nil),
			RequiredScopes: []string{ScopeDrive},
			ResourceIdentity: func(args map[string]any) map[string]string {
				return map[string]string{"drive": driveIdentity(args)["drive"]}
			},
			Reconcile: connectors.Reconciliation{Kind: connectors.ReconcileNone},
			ResultIDs: func(res connectors.Result) map[string]string {
				if v, ok := res.Content.(EmptiedTrash); ok && v.Drive != "" {
					return map[string]string{"drive": v.Drive}
				}
				return nil
			},
			Bounds: c.singleBounds(),
		},
		{
			App: AppDrive, Name: ToolCreateShortcut, Kind: connectors.KindWrite,
			Description: "Create a Drive shortcut to a file or folder (file_id) in parent_id or the shared drive drive_id (the root of My Drive " +
				"when both are omitted); named like the target unless name is given. Returns the shortcut's id and url.",
			InputSchema: objectSchema([]property{
				{"file_id", "string", "Id of the file or folder the shortcut points to.", nil},
				{"name", "string", "The shortcut's name (the target's name when omitted).", nil},
				{"parent_id", "string", "Folder to create the shortcut in.", nil},
				{"drive_id", "string", "Shared drive to create the shortcut in (its root when parent_id is omitted).", nil},
			}, []string{"file_id"}),
			RequiredScopes:   []string{ScopeDriveFile},
			ResourceIdentity: creates,
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileMarker, Check: c.checkDriveMarker},
			ResultIDs:        createdFileResultIDs,
			Bounds:           c.singleBounds(),
		},
		{
			App: AppDrive, Name: ToolUploadNewVersion, Kind: connectors.KindWrite,
			Description: fmt.Sprintf("Replace the content of an existing Drive file (not a Google Doc, Sheet or Slides) with a new version, at "+
				"most %d MiB: content (text, or bytes in base64 with content_encoding base64), mime_type. The file keeps its id, name, "+
				"sharing and older revisions. Returns the file's id and url.", MaxDownloadBytes>>20),
			InputSchema: objectSchema([]property{
				fileIDProperty,
				{"content", "string", "The new content: text, or base64 when content_encoding is base64.", nil},
				{"content_encoding", "string", "text (default) or base64.", []string{EncodingText, EncodingBase64}},
				{"mime_type", "string", "MIME type of the new content (the file's current type when omitted).", nil},
			}, []string{"file_id", "content"}),
			RequiredScopes:   []string{ScopeDriveFile},
			ResourceIdentity: fileIdentity,
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileMarker, Check: c.checkFileMarker},
			ResultIDs:        createdFileResultIDs,
			Bounds:           c.singleBounds(),
		},
	}
}

func (c *Connector) driveFilesWriteHandlers() map[string]handler {
	return map[string]handler{
		ToolCopyFile: c.copyFile, ToolDriveTrash: c.setTrashed(true), ToolUntrash: c.setTrashed(false), ToolDeleteFile: c.deleteFile,
		ToolEmptyTrash: c.emptyTrash, ToolCreateShortcut: c.createShortcut, ToolUploadNewVersion: c.uploadNewVersion,
	}
}

// copyFile copies with the operation's marker in the copy's
// appProperties (files.copy takes the new file's metadata), so the copy
// and its marker exist together, like a create.
func (c *Connector) copyFile(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	fileID, err := idArg(call.Args, "file_id")
	if err != nil {
		return connectors.Result{}, err
	}
	name, err := optionalString(call.Args, "name")
	if err != nil {
		return connectors.Result{}, err
	}
	f, err := newDriveFile(call, strings.TrimSpace(name), "")
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.drive(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	created, err := svc.Files.Copy(fileID, f).Context(ctx).SupportsAllDrives(true).Fields(createdFileFields + ",name").Do()
	if err := classifyWrite("copy file", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: CreatedFile{ID: created.Id, Name: created.Name, MimeType: created.MimeType, URL: created.WebViewLink, Parents: created.Parents, DriveID: created.DriveId}}, nil
}

// setTrashed is trash (true) and untrash (false): files.update with
// trashed alone.
func (c *Connector) setTrashed(trashed bool) handler {
	return func(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
		fileID, err := idArg(call.Args, "file_id")
		if err != nil {
			return connectors.Result{}, err
		}
		svc, err := cl.drive(ctx)
		if err != nil {
			return connectors.Result{}, err
		}
		patch := &drive.File{Trashed: trashed, ForceSendFields: []string{"Trashed"}}
		updated, err := svc.Files.Update(fileID, patch).Context(ctx).SupportsAllDrives(true).Fields("id,name,trashed").Do()
		action := "trash file"
		if !trashed {
			action = "restore file"
		}
		if err := classifyWrite(action, err); err != nil {
			return connectors.Result{}, err
		}
		return connectors.Result{Content: TrashedFile{ID: fileID, Name: updated.Name, Trashed: updated.Trashed}}, nil
	}
}

func (c *Connector) deleteFile(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	fileID, err := idArg(call.Args, "file_id")
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.drive(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	if err := classifyWrite("delete file", svc.Files.Delete(fileID).Context(ctx).SupportsAllDrives(true).Do()); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: DeletedFile{ID: fileID, Deleted: true}}, nil
}

func (c *Connector) emptyTrash(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	driveID, err := idArgDefault(call.Args, "drive_id", "")
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.drive(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	req := svc.Files.EmptyTrash().Context(ctx)
	out := EmptiedTrash{Drive: DriveMy, Emptied: true}
	if driveID != "" {
		req, out.Drive = req.DriveId(driveID), driveID
	}
	if err := classifyWrite("empty trash", req.Do()); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: out}, nil
}

// createShortcut creates the shortcut with the operation's marker (one
// files.create); without a name it first reads the target's (a read: its
// failure is a known outcome and nothing is created).
func (c *Connector) createShortcut(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	targetID, err := idArg(call.Args, "file_id")
	if err != nil {
		return connectors.Result{}, err
	}
	name, err := optionalString(call.Args, "name")
	if err != nil {
		return connectors.Result{}, err
	}
	f, err := newDriveFile(call, strings.TrimSpace(name), MimeShortcut)
	if err != nil {
		return connectors.Result{}, err
	}
	f.ShortcutDetails = &drive.FileShortcutDetails{TargetId: targetID}
	svc, err := cl.drive(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	if f.Name == "" {
		target, err := svc.Files.Get(targetID).Context(ctx).Fields("id,name").SupportsAllDrives(true).Do()
		if err := classify("look up the shortcut's target", err); err != nil {
			return connectors.Result{}, err
		}
		f.Name = target.Name
	}
	created, err := svc.Files.Create(f).Context(ctx).SupportsAllDrives(true).Fields(createdFileFields + ",name").Do()
	if err := classifyWrite("create shortcut", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: CreatedFile{ID: created.Id, Name: created.Name, MimeType: created.MimeType, URL: created.WebViewLink, Parents: created.Parents, DriveID: created.DriveId}}, nil
}

// uploadNewVersion replaces the content (files.update with media) and
// sets the operation's marker in the same request, like update_file.
func (c *Connector) uploadNewVersion(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	fileID, err := idArg(call.Args, "file_id")
	if err != nil {
		return connectors.Result{}, err
	}
	raw, _, err := uploadContent(call.Args)
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
	svc, err := cl.drive(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	var opts []googleapi.MediaOption
	if mimeType != "" {
		opts = append(opts, googleapi.ContentType(mimeType))
	}
	patch := &drive.File{AppProperties: map[string]string{DriveMarkerKey: call.OperationID}}
	updated, err := svc.Files.Update(fileID, patch).Context(ctx).Media(bytes.NewReader(raw), opts...).SupportsAllDrives(true).Fields(createdFileFields + ",name").Do()
	if err := classifyWrite("upload new version", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: CreatedFile{ID: fileID, Name: updated.Name, MimeType: updated.MimeType, URL: updated.WebViewLink, Parents: updated.Parents, DriveID: updated.DriveId}}, nil
}

// --- reconciliation ---------------------------------------------------------------

// identityFile returns the identity's file_id, or ErrNotReconcilable.
func identityFile(in connectors.ReconcileInput) (string, error) {
	fileID := in.ResourceIdentity["file_id"]
	if fileID == "" || !idRE.MatchString(fileID) {
		return "", fmt.Errorf("%w: resource identity has no file", ErrNotReconcilable)
	}
	return fileID, nil
}

// checkFileTrashed is trash's and untrash's state check: the file's trashed
// flag equal to want is found, the other not_found; any error (a 404:
// the file may have been deleted since) is "cannot tell yet".
func (c *Connector) checkFileTrashed(want bool) func(context.Context, connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	return func(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
		tg, err := c.target(in)
		if err != nil {
			return connectors.ReconcileResult{}, err
		}
		fileID, err := identityFile(in)
		if err != nil {
			return connectors.ReconcileResult{}, err
		}
		ctx, cancel := context.WithTimeout(ctx, c.timeout)
		defer cancel()
		svc, err := tg.client.drive(ctx)
		if err != nil {
			return connectors.ReconcileResult{}, err
		}
		f, err := svc.Files.Get(fileID).Context(ctx).Fields("id,trashed").SupportsAllDrives(true).Do()
		if err := classify("reconcile: get file", err); err != nil {
			return connectors.ReconcileResult{}, err
		}
		if f.Trashed == want {
			return found(fileID), nil
		}
		return notFound, nil
	}
}

// checkFileDeleted is delete's check: the file answering 404 or 410 is
// found (deleted); a file still there (trashed or not) is not_found; any
// other error is "cannot tell yet".
func (c *Connector) checkFileDeleted(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	tg, err := c.target(in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	fileID, err := identityFile(in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	svc, err := tg.client.drive(ctx)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	_, err = svc.Files.Get(fileID).Context(ctx).Fields("id").SupportsAllDrives(true).Do()
	if err == nil {
		return notFound, nil
	}
	err = classify("reconcile: get file", err)
	if s := statusOf(err); s == http.StatusNotFound || s == http.StatusGone {
		return found(fileID), nil
	}
	return connectors.ReconcileResult{}, err
}
