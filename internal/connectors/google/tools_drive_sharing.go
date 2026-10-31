package google

import (
	"context"
	"fmt"
	"net/http"
	"net/mail"
	"slices"
	"strconv"
	"strings"
	"time"

	"google.golang.org/api/drive/v3"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Drive sharing, comment and revision tool names (increment 5).
const (
	ToolUpdatePermission  = "update_permission"
	ToolRemovePermission  = "remove_permission"
	ToolTransferOwnership = "transfer_ownership"
	ToolReplyComment      = "reply_comment"
	ToolResolveComment    = "resolve_comment"
	ToolDeleteComment     = "delete_comment"
	ToolListRevisions     = "list_revisions"
	ToolGetRevision       = "get_revision"
	ToolGetAbout          = "get_about"
)

// Ownership transfer modes: pending (the recipient accepts; the only way
// between consumer accounts) and direct (immediate; within one Google
// Workspace organization).
const (
	TransferPending = "pending"
	TransferDirect  = "direct"
)

// permissionRoles are the roles update_permission sets (owner goes
// through transfer_ownership; organizer and fileOrganizer exist on
// shared drives only).
var permissionRoles = []string{"reader", "commenter", "writer", "fileOrganizer", "organizer"}

// revisionFields are the metadata a revision is read with.
const revisionFields = "id,mimeType,modifiedTime,size,keepForever,published,originalFilename,lastModifyingUser(displayName,emailAddress)"

// UpdatedPermission is update_permission's and remove_permission's result.
type UpdatedPermission struct {
	FileID       string `json:"file_id"`
	PermissionID string `json:"permission_id"`
	Role         string `json:"role,omitempty"`
	Expires      string `json:"expires,omitempty"`
	Removed      bool   `json:"removed,omitempty"`
}

// OwnershipTransfer is transfer_ownership's result.
type OwnershipTransfer struct {
	FileID       string `json:"file_id"`
	PermissionID string `json:"permission_id"`
	Mode         string `json:"mode"`
	Role         string `json:"role"`
	Email        string `json:"email,omitempty"`
	PendingOwner bool   `json:"pending_owner,omitempty"`
}

// CreatedReply is reply_comment's and resolve_comment's result.
type CreatedReply struct {
	FileID    string `json:"file_id"`
	CommentID string `json:"comment_id"`
	ReplyID   string `json:"reply_id"`
	Action    string `json:"action,omitempty"`
	Created   string `json:"created,omitempty"`
}

// DeletedComment is delete_comment's result.
type DeletedComment struct {
	FileID    string `json:"file_id"`
	CommentID string `json:"comment_id"`
	Deleted   bool   `json:"deleted"`
}

// FileRevision is one revision's metadata (never its content).
type FileRevision struct {
	ID               string `json:"id"`
	MimeType         string `json:"mime_type,omitempty"`
	Modified         string `json:"modified,omitempty"`
	Size             int64  `json:"size,omitempty"`
	KeepForever      bool   `json:"keep_forever,omitempty"`
	Published        bool   `json:"published,omitempty"`
	OriginalFilename string `json:"original_filename,omitempty"`
	ModifiedBy       string `json:"modified_by,omitempty"`
	ModifiedByEmail  string `json:"modified_by_email,omitempty"`
}

// RevisionsPage is list_revisions' result.
type RevisionsPage struct {
	FileID        string         `json:"file_id"`
	MaxResults    int            `json:"max_results"`
	NextPageToken string         `json:"next_page_token,omitempty"`
	HasMore       bool           `json:"has_more"`
	Truncated     bool           `json:"truncated,omitempty"`
	Items         []FileRevision `json:"items"`
}

// DriveUser is the account get_about describes.
type DriveUser struct {
	DisplayName string `json:"display_name,omitempty"`
	Email       string `json:"email,omitempty"`
}

// DriveStorage is the account's storage quota in bytes (Limit 0: unlimited).
type DriveStorage struct {
	Limit        int64 `json:"limit"`
	Usage        int64 `json:"usage"`
	UsageInDrive int64 `json:"usage_in_drive"`
	UsageInTrash int64 `json:"usage_in_trash"`
}

// DriveAbout is get_about's result.
type DriveAbout struct {
	User          DriveUser    `json:"user"`
	Storage       DriveStorage `json:"storage"`
	MaxUploadSize int64        `json:"max_upload_size,omitempty"`
}

var (
	permissionIDProperty = property{"permission_id", "string", "The permission's id (from drive.list_permissions).", nil}
	commentIDProperty    = property{"comment_id", "string", "The comment's id (from drive.list_comments).", nil}
)

// identityOf copies the named, non-blank string arguments.
func identityOf(args map[string]any, names ...string) map[string]string {
	out := map[string]string{}
	for _, n := range names {
		if v, _ := args[n].(string); strings.TrimSpace(v) != "" {
			out[n] = strings.TrimSpace(v)
		}
	}
	return out
}

func (c *Connector) driveSharingReadTools() []connectors.Tool {
	return []connectors.Tool{
		{
			App: AppDrive, Name: ToolListRevisions, Kind: connectors.KindRead,
			Description: "List a Drive file's revisions (versions): id, modified, size, mime_type, keep_forever, who modified it. " +
				"Metadata only; read an old version's content with Drive's export or download in the Drive app.",
			InputSchema: objectSchema([]property{
				fileIDProperty,
				{"max_results", "integer", "Revisions per page (1-100; default 25); clamped to the tool's maximum.", nil},
				{"page_token", "string", "Token of the page to fetch (next_page_token of the previous result).", nil},
			}, []string{"file_id"}),
			RequiredScopes:   []string{ScopeDriveMetadataReadonly},
			ResourceIdentity: fileIdentity,
			Bounds:           c.pagedBounds(),
		},
		{
			App: AppDrive, Name: ToolGetRevision, Kind: connectors.KindRead,
			Description: "Get one revision's metadata of a Drive file: id, modified, size, mime_type, keep_forever, who modified it.",
			InputSchema: objectSchema([]property{
				fileIDProperty,
				{"revision_id", "string", "The revision's id (from list_revisions).", nil},
			}, []string{"file_id", "revision_id"}),
			RequiredScopes:   []string{ScopeDriveMetadataReadonly},
			ResourceIdentity: func(args map[string]any) map[string]string { return identityOf(args, "file_id", "revision_id") },
			Bounds:           c.singleBounds(),
		},
		{
			App: AppDrive, Name: ToolGetAbout, Kind: connectors.KindRead,
			Description: "Get the Drive account's user (name, email), storage quota in bytes (limit, usage, usage in Drive, usage in the " +
				"trash; limit 0 means unlimited) and the largest upload size.",
			InputSchema:      objectSchema(nil, nil),
			RequiredScopes:   []string{ScopeDriveMetadataReadonly},
			ResourceIdentity: func(map[string]any) map[string]string { return map[string]string{} },
			Bounds:           c.singleBounds(),
		},
	}
}

func (c *Connector) driveSharingReadHandlers() map[string]handler {
	return map[string]handler{ToolListRevisions: c.listRevisions, ToolGetRevision: c.getRevision, ToolGetAbout: c.getAbout}
}

func (c *Connector) driveSharingWriteTools() []connectors.Tool {
	permissionResult := func(res connectors.Result) map[string]string {
		if v, ok := res.Content.(UpdatedPermission); ok && v.PermissionID != "" {
			return map[string]string{"file_id": v.FileID, "permission_id": v.PermissionID}
		}
		return nil
	}
	replyResult := func(res connectors.Result) map[string]string {
		if v, ok := res.Content.(CreatedReply); ok && v.ReplyID != "" {
			return map[string]string{"file_id": v.FileID, "comment_id": v.CommentID, "reply_id": v.ReplyID}
		}
		return nil
	}
	return []connectors.Tool{
		{
			App: AppDrive, Name: ToolUpdatePermission, Kind: connectors.KindWrite,
			Description: "Change the role of someone a Drive file is shared with (a permission from list_permissions): reader, commenter, " +
				"writer, or on shared drives fileOrganizer or organizer; optionally an expiry (expires, RFC 3339). Ownership goes through transfer_ownership.",
			InputSchema: objectSchema([]property{
				fileIDProperty, permissionIDProperty,
				{"role", "string", "The new role.", permissionRoles},
				{"expires", "string", "When the access ends (RFC 3339; users and groups only).", nil},
			}, []string{"file_id", "permission_id", "role"}),
			RequiredScopes: []string{ScopeDriveFile},
			ResourceIdentity: func(args map[string]any) map[string]string {
				return identityOf(args, "file_id", "permission_id", "role")
			},
			Reconcile: connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: c.checkPermission(false)},
			ResultIDs: permissionResult,
			Bounds:    c.singleBounds(),
		},
		{
			App: AppDrive, Name: ToolRemovePermission, Kind: connectors.KindWrite,
			Description: "Stop sharing a Drive file with someone: remove a permission (from list_permissions); the user, group, domain or " +
				"link loses its access.",
			InputSchema:      objectSchema([]property{fileIDProperty, permissionIDProperty}, []string{"file_id", "permission_id"}),
			RequiredScopes:   []string{ScopeDriveFile},
			ResourceIdentity: func(args map[string]any) map[string]string { return identityOf(args, "file_id", "permission_id") },
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: c.checkPermission(true)},
			ResultIDs:        permissionResult,
			Bounds:           c.singleBounds(),
		},
		{
			App: AppDrive, Name: ToolTransferOwnership, Kind: connectors.KindWrite,
			Description: "Transfer ownership of a Drive file you own to another user (email). mode pending (default; the only way between " +
				"personal Google accounts) makes them a writer and pending owner: they become owner when they accept in Drive. mode direct " +
				"makes them owner at once (only within one Google Workspace organization); you keep writer access. Cannot be verified after " +
				"an unknown outcome: check the file's sharing.",
			InputSchema: objectSchema([]property{
				fileIDProperty,
				{"email", "string", "Address of the new owner.", nil},
				{"mode", "string", "pending (default) or direct.", []string{TransferPending, TransferDirect}},
			}, []string{"file_id", "email"}),
			RequiredScopes: []string{ScopeDriveFile},
			ResourceIdentity: func(args map[string]any) map[string]string {
				out := fileIdentity(args)
				out["mode"] = TransferPending
				if m, _ := args["mode"].(string); strings.TrimSpace(m) != "" {
					out["mode"] = strings.TrimSpace(m)
				}
				if email, _ := args["email"].(string); domainOf(email) != "" {
					out["grantee_domain"] = domainOf(email)
				}
				return out
			},
			Reconcile: connectors.Reconciliation{Kind: connectors.ReconcileNone},
			ResultIDs: func(res connectors.Result) map[string]string {
				if v, ok := res.Content.(OwnershipTransfer); ok && v.PermissionID != "" {
					return map[string]string{"file_id": v.FileID, "permission_id": v.PermissionID}
				}
				return nil
			},
			Bounds: c.singleBounds(),
		},
		{
			App: AppDrive, Name: ToolReplyComment, Kind: connectors.KindWrite,
			Description: "Reply to a comment on a Drive file (a Doc, Sheet, Slides or any file). Returns the reply's id. Cannot be verified " +
				"after an unknown outcome: check the comment.",
			InputSchema: objectSchema([]property{
				fileIDProperty, commentIDProperty,
				{"content", "string", "The reply's text.", nil},
			}, []string{"file_id", "comment_id", "content"}),
			RequiredScopes:   []string{ScopeDriveFile},
			ResourceIdentity: func(args map[string]any) map[string]string { return identityOf(args, "file_id", "comment_id") },
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileNone},
			ResultIDs:        replyResult,
			Bounds:           c.singleBounds(),
		},
		{
			App: AppDrive, Name: ToolResolveComment, Kind: connectors.KindWrite,
			Description: "Resolve a comment on a Drive file (or reopen it with reopen true), with an optional reply text.",
			InputSchema: objectSchema([]property{
				fileIDProperty, commentIDProperty,
				{"content", "string", "Optional reply text posted with the resolution.", nil},
				{"reopen", "boolean", "Reopen a resolved comment instead. Default false.", nil},
			}, []string{"file_id", "comment_id"}),
			RequiredScopes: []string{ScopeDriveFile},
			ResourceIdentity: func(args map[string]any) map[string]string {
				out := identityOf(args, "file_id", "comment_id")
				reopen, _ := args["reopen"].(bool)
				out["resolved"] = strconv.FormatBool(!reopen)
				return out
			},
			Reconcile: connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: c.checkCommentResolved},
			ResultIDs: replyResult,
			Bounds:    c.singleBounds(),
		},
		{
			App: AppDrive, Name: ToolDeleteComment, Kind: connectors.KindWrite,
			Description:      "Delete a comment (with its replies) from a Drive file.",
			InputSchema:      objectSchema([]property{fileIDProperty, commentIDProperty}, []string{"file_id", "comment_id"}),
			RequiredScopes:   []string{ScopeDriveFile},
			ResourceIdentity: func(args map[string]any) map[string]string { return identityOf(args, "file_id", "comment_id") },
			Reconcile:        connectors.Reconciliation{Kind: connectors.ReconcileStableID, Check: c.checkCommentDeleted},
			ResultIDs: func(res connectors.Result) map[string]string {
				if v, ok := res.Content.(DeletedComment); ok && v.CommentID != "" {
					return map[string]string{"file_id": v.FileID, "comment_id": v.CommentID}
				}
				return nil
			},
			Bounds: c.singleBounds(),
		},
	}
}

func (c *Connector) driveSharingWriteHandlers() map[string]handler {
	return map[string]handler{
		ToolUpdatePermission: c.updatePermission, ToolRemovePermission: c.removePermission, ToolTransferOwnership: c.transferOwnership,
		ToolReplyComment: c.replyComment(false), ToolResolveComment: c.replyComment(true), ToolDeleteComment: c.deleteComment,
	}
}

// --- reads ------------------------------------------------------------------------

func toFileRevision(r *drive.Revision) FileRevision {
	out := FileRevision{ID: r.Id, MimeType: r.MimeType, Modified: normalizeTimestamp(r.ModifiedTime), Size: r.Size, KeepForever: r.KeepForever,
		Published: r.Published, OriginalFilename: r.OriginalFilename}
	if r.LastModifyingUser != nil {
		out.ModifiedBy, out.ModifiedByEmail = r.LastModifyingUser.DisplayName, r.LastModifyingUser.EmailAddress
	}
	return out
}

func (c *Connector) listRevisions(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
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
	req := svc.Revisions.List(fileID).Context(ctx).PageSize(int64(maxResults)).Fields("nextPageToken,revisions(" + revisionFields + ")")
	if pageToken != "" {
		req = req.PageToken(pageToken)
	}
	list, err := req.Do()
	if err := classify("list revisions", err); err != nil {
		return connectors.Result{}, err
	}
	out := RevisionsPage{FileID: fileID, MaxResults: maxResults, NextPageToken: list.NextPageToken, HasMore: list.NextPageToken != "", Items: []FileRevision{}}
	for _, r := range list.Revisions {
		if r != nil {
			out.Items = append(out.Items, toFileRevision(r))
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

func (c *Connector) getRevision(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	fileID, err := idArg(call.Args, "file_id")
	if err != nil {
		return connectors.Result{}, err
	}
	revisionID, err := idArg(call.Args, "revision_id")
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.drive(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	r, err := svc.Revisions.Get(fileID, revisionID).Context(ctx).Fields(revisionFields).Do()
	if err := classify("get revision", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: toFileRevision(r)}, nil
}

func (c *Connector) getAbout(ctx context.Context, cl *client, _ connectors.Call) (connectors.Result, error) {
	svc, err := cl.drive(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	a, err := svc.About.Get().Context(ctx).Fields("user(displayName,emailAddress),storageQuota(limit,usage,usageInDrive,usageInDriveTrash),maxUploadSize").Do()
	if err := classify("get drive account", err); err != nil {
		return connectors.Result{}, err
	}
	out := DriveAbout{MaxUploadSize: a.MaxUploadSize}
	if a.User != nil {
		out.User = DriveUser{DisplayName: a.User.DisplayName, Email: a.User.EmailAddress}
	}
	if q := a.StorageQuota; q != nil {
		out.Storage = DriveStorage{Limit: q.Limit, Usage: q.Usage, UsageInDrive: q.UsageInDrive, UsageInTrash: q.UsageInDriveTrash}
	}
	return connectors.Result{Content: out}, nil
}

// --- writes -----------------------------------------------------------------------

func (c *Connector) updatePermission(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	fileID, err := idArg(call.Args, "file_id")
	if err != nil {
		return connectors.Result{}, err
	}
	permissionID, err := idArg(call.Args, "permission_id")
	if err != nil {
		return connectors.Result{}, err
	}
	role, err := requiredString(call.Args, "role")
	if err != nil {
		return connectors.Result{}, err
	}
	if !slices.Contains(permissionRoles, role) {
		return connectors.Result{}, invalid("role must be one of %s (ownership goes through transfer_ownership)", strings.Join(permissionRoles, ", "))
	}
	expires, err := optionalTime(call.Args, "expires")
	if err != nil {
		return connectors.Result{}, err
	}
	p := &drive.Permission{Role: role}
	if !expires.IsZero() {
		p.ExpirationTime = expires.UTC().Format(time.RFC3339)
	}
	svc, err := cl.drive(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	updated, err := svc.Permissions.Update(fileID, permissionID, p).Context(ctx).SupportsAllDrives(true).Fields("id,role,expirationTime").Do()
	if err := classifyWrite("update permission", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: UpdatedPermission{FileID: fileID, PermissionID: permissionID, Role: updated.Role, Expires: normalizeTimestamp(updated.ExpirationTime)}}, nil
}

func (c *Connector) removePermission(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	fileID, err := idArg(call.Args, "file_id")
	if err != nil {
		return connectors.Result{}, err
	}
	permissionID, err := idArg(call.Args, "permission_id")
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.drive(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	if err := classifyWrite("remove permission", svc.Permissions.Delete(fileID, permissionID).Context(ctx).SupportsAllDrives(true).Do()); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: UpdatedPermission{FileID: fileID, PermissionID: permissionID, Removed: true}}, nil
}

// transferOwnership creates the new owner's permission: pending (writer
// with pendingOwner; they accept in Drive) or direct (owner with
// transferOwnership).
func (c *Connector) transferOwnership(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	fileID, err := idArg(call.Args, "file_id")
	if err != nil {
		return connectors.Result{}, err
	}
	email, err := requiredString(call.Args, "email")
	if err != nil {
		return connectors.Result{}, err
	}
	addr, err := mail.ParseAddress(email)
	if err != nil {
		return connectors.Result{}, invalid("email must be an address")
	}
	mode, err := optionalString(call.Args, "mode")
	if err != nil {
		return connectors.Result{}, err
	}
	if mode = strings.TrimSpace(mode); mode == "" {
		mode = TransferPending
	}
	p := &drive.Permission{Type: "user", EmailAddress: addr.Address}
	switch mode {
	case TransferPending:
		p.Role, p.PendingOwner = "writer", true
	case TransferDirect:
		p.Role = "owner"
	default:
		return connectors.Result{}, invalid("mode must be pending or direct")
	}
	svc, err := cl.drive(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	req := svc.Permissions.Create(fileID, p).Context(ctx).SupportsAllDrives(true).Fields("id,role,emailAddress,pendingOwner")
	if mode == TransferDirect {
		req = req.TransferOwnership(true)
	}
	created, err := req.Do()
	if err := classifyWrite("transfer ownership", err); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: OwnershipTransfer{FileID: fileID, PermissionID: created.Id, Mode: mode, Role: created.Role, Email: created.EmailAddress, PendingOwner: created.PendingOwner}}, nil
}

// replyComment posts a reply (resolve false: content required) or a
// resolve / reopen action with an optional text (resolve true).
func (c *Connector) replyComment(resolve bool) handler {
	return func(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
		fileID, err := idArg(call.Args, "file_id")
		if err != nil {
			return connectors.Result{}, err
		}
		commentID, err := idArg(call.Args, "comment_id")
		if err != nil {
			return connectors.Result{}, err
		}
		content, err := textArg(call.Args, "content", !resolve)
		if err != nil {
			return connectors.Result{}, err
		}
		reply := &drive.Reply{Content: content}
		if resolve {
			reopen, err := optionalBool(call.Args, "reopen", false)
			if err != nil {
				return connectors.Result{}, err
			}
			reply.Action = "resolve"
			if reopen {
				reply.Action = "reopen"
			}
		}
		svc, err := cl.drive(ctx)
		if err != nil {
			return connectors.Result{}, err
		}
		created, err := svc.Replies.Create(fileID, commentID, reply).Context(ctx).Fields("id,createdTime,action").Do()
		if err := classifyWrite("reply to comment", err); err != nil {
			return connectors.Result{}, err
		}
		return connectors.Result{Content: CreatedReply{FileID: fileID, CommentID: commentID, ReplyID: created.Id, Action: created.Action, Created: normalizeTimestamp(created.CreatedTime)}}, nil
	}
}

func (c *Connector) deleteComment(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	fileID, err := idArg(call.Args, "file_id")
	if err != nil {
		return connectors.Result{}, err
	}
	commentID, err := idArg(call.Args, "comment_id")
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.drive(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	if err := classifyWrite("delete comment", svc.Comments.Delete(fileID, commentID).Context(ctx).Do()); err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{Content: DeletedComment{FileID: fileID, CommentID: commentID, Deleted: true}}, nil
}

// --- reconciliation ---------------------------------------------------------------

// identityIDs returns the named ids of the identity, or ErrNotReconcilable.
func identityIDs(in connectors.ReconcileInput, names ...string) ([]string, error) {
	out := make([]string, len(names))
	for i, n := range names {
		v := in.ResourceIdentity[n]
		if v == "" || !idRE.MatchString(v) {
			return nil, fmt.Errorf("%w: resource identity has no %s", ErrNotReconcilable, n)
		}
		out[i] = v
	}
	return out, nil
}

// isGone reports a classified 404 or 410.
func isGone(err error) bool {
	s := statusOf(err)
	return s == http.StatusNotFound || s == http.StatusGone
}

// checkPermission is update_permission's check (removed false: the
// permission's role equal to the identity's is found, another role
// not_found) and remove_permission's (removed true: a 404 is found, the
// permission still there not_found). Any other error is "cannot tell".
func (c *Connector) checkPermission(removed bool) func(context.Context, connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	return func(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
		tg, err := c.target(in)
		if err != nil {
			return connectors.ReconcileResult{}, err
		}
		ids, err := identityIDs(in, "file_id", "permission_id")
		if err != nil {
			return connectors.ReconcileResult{}, err
		}
		role := in.ResourceIdentity["role"]
		if !removed && role == "" {
			return connectors.ReconcileResult{}, fmt.Errorf("%w: resource identity has no role", ErrNotReconcilable)
		}
		ctx, cancel := context.WithTimeout(ctx, c.timeout)
		defer cancel()
		svc, err := tg.client.drive(ctx)
		if err != nil {
			return connectors.ReconcileResult{}, err
		}
		p, err := svc.Permissions.Get(ids[0], ids[1]).Context(ctx).SupportsAllDrives(true).Fields("id,role").Do()
		if err = classify("reconcile: get permission", err); err != nil {
			if removed && isGone(err) {
				return found(ids[1]), nil
			}
			return connectors.ReconcileResult{}, err
		}
		if !removed && p.Role == role {
			return found(ids[1]), nil
		}
		return notFound, nil
	}
}

// getComment reads the identity's comment (deleted ones included).
func (c *Connector) getComment(ctx context.Context, in connectors.ReconcileInput) (*drive.Comment, string, error) {
	tg, err := c.target(in)
	if err != nil {
		return nil, "", err
	}
	ids, err := identityIDs(in, "file_id", "comment_id")
	if err != nil {
		return nil, "", err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	svc, err := tg.client.drive(ctx)
	if err != nil {
		return nil, ids[1], err
	}
	cm, err := svc.Comments.Get(ids[0], ids[1]).Context(ctx).IncludeDeleted(true).Fields("id,resolved,deleted").Do()
	return cm, ids[1], classify("reconcile: get comment", err)
}

// checkCommentResolved is resolve_comment's check: the comment's
// resolved flag equal to the identity's is found, else not_found.
func (c *Connector) checkCommentResolved(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	cm, id, err := c.getComment(ctx, in)
	if err != nil {
		return connectors.ReconcileResult{}, err
	}
	if strconv.FormatBool(cm.Resolved) == in.ResourceIdentity["resolved"] {
		return found(id), nil
	}
	return notFound, nil
}

// checkCommentDeleted is delete_comment's check: a 404 or a deleted
// comment is found, one still there not_found.
func (c *Connector) checkCommentDeleted(ctx context.Context, in connectors.ReconcileInput) (connectors.ReconcileResult, error) {
	cm, id, err := c.getComment(ctx, in)
	if err != nil {
		if id != "" && isGone(err) {
			return found(id), nil
		}
		return connectors.ReconcileResult{}, err
	}
	if cm.Deleted {
		return found(id), nil
	}
	return notFound, nil
}
