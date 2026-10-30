package google

import (
	"context"
	"strings"

	"google.golang.org/api/drive/v3"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Shared drives (increment 4). drives.list accepts only the drive and
// drive.readonly scopes (Drive API reference, drives.list "Authorization
// scopes"): neither drive.metadata.readonly nor drive.file, so the tool
// requires drive.readonly and drive.file does not admit it per file
// (wholeDriveTools).

// ToolListSharedDrives is the shared-drive listing's name.
const ToolListSharedDrives = "list_shared_drives"

// defaultDrivesPerPage is list_shared_drives's page size when the
// harness gives none, capped by the bounds.
const defaultDrivesPerPage = 25

// sharedDriveFields is the small projection list_shared_drives asks for.
const sharedDriveFields = "nextPageToken,drives(id,name,createdTime,hidden,restrictions)"

// SharedDrive is one list_shared_drives item. Restrictions names the
// restrictions set on the drive (admin_managed, copy_requires_writer,
// domain_users_only, drive_members_only, sharing_folders_requires_organizer,
// download_restricted).
type SharedDrive struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Created      string   `json:"created,omitempty"`
	Hidden       bool     `json:"hidden,omitempty"`
	Restrictions []string `json:"restrictions,omitempty"`
}

// SharedDrivesPage is list_shared_drives's result.
type SharedDrivesPage struct {
	MaxResults    int           `json:"max_results"`
	NextPageToken string        `json:"next_page_token,omitempty"`
	HasMore       bool          `json:"has_more"`
	Truncated     bool          `json:"truncated,omitempty"`
	Items         []SharedDrive `json:"items"`
}

func (c *Connector) driveSharedReadTools() []connectors.Tool {
	return []connectors.Tool{{
		App: AppDrive, Name: ToolListSharedDrives, Kind: connectors.KindRead,
		Description: "List the shared drives the account is a member of: id, name, created, hidden and the restrictions set on each. " +
			"query filters with the Drive shared-drive search syntax (name contains 'Eng', hidden = true). " +
			"Use an id as drive_id of drive.search, create_folder or create_file. Shared drives exist for Google Workspace accounts; " +
			"a personal account has none. has_more and next_page_token say whether another page exists.",
		InputSchema: objectSchema([]property{
			{"query", "string", "Shared-drive search query (drives.list q syntax: name contains 'Eng', hidden = true). Omit for every shared drive.", nil},
			{"max_results", "integer", "Shared drives per page (1-100; default 25); clamped to the tool's maximum.", nil},
			{"page_token", "string", "Token of the page to fetch (next_page_token of the previous result).", nil},
		}, nil),
		RequiredScopes:   []string{ScopeDriveReadonly},
		ResourceIdentity: func(map[string]any) map[string]string { return map[string]string{} },
		Bounds:           c.pagedBounds(),
	}}
}

func (c *Connector) driveSharedReadHandlers() map[string]handler {
	return map[string]handler{ToolListSharedDrives: c.listSharedDrives}
}

// driveRestrictions names the restrictions set on a shared drive.
func driveRestrictions(r *drive.DriveRestrictions) []string {
	if r == nil {
		return nil
	}
	var out []string
	for _, f := range []struct {
		set  bool
		name string
	}{
		{r.AdminManagedRestrictions, "admin_managed"},
		{r.CopyRequiresWriterPermission, "copy_requires_writer"},
		{r.DomainUsersOnly, "domain_users_only"},
		{r.DriveMembersOnly, "drive_members_only"},
		{r.SharingFoldersRequiresOrganizerPermission, "sharing_folders_requires_organizer"},
		{r.DownloadRestriction != nil && (r.DownloadRestriction.RestrictedForReaders || r.DownloadRestriction.RestrictedForWriters), "download_restricted"},
	} {
		if f.set {
			out = append(out, f.name)
		}
	}
	return out
}

func (c *Connector) listSharedDrives(ctx context.Context, cl *client, call connectors.Call) (connectors.Result, error) {
	q, err := optionalString(call.Args, "query")
	if err != nil {
		return connectors.Result{}, err
	}
	maxResults, pageToken, clamped, err := c.pageArgs(call.Args, defaultDrivesPerPage)
	if err != nil {
		return connectors.Result{}, err
	}
	svc, err := cl.drive(ctx)
	if err != nil {
		return connectors.Result{}, err
	}
	req := svc.Drives.List().Context(ctx).PageSize(int64(maxResults)).UseDomainAdminAccess(false).Fields(sharedDriveFields)
	if q = strings.TrimSpace(q); q != "" {
		req = req.Q(q)
	}
	if pageToken != "" {
		req = req.PageToken(pageToken)
	}
	list, err := req.Do()
	if err := classify("list shared drives", err); err != nil {
		return connectors.Result{}, err
	}
	out := SharedDrivesPage{MaxResults: maxResults, NextPageToken: list.NextPageToken, HasMore: list.NextPageToken != "", Items: make([]SharedDrive, 0, len(list.Drives))}
	for _, d := range list.Drives {
		if d == nil {
			continue
		}
		out.Items = append(out.Items, SharedDrive{
			ID: d.Id, Name: d.Name, Created: normalizeTimestamp(d.CreatedTime), Hidden: d.Hidden, Restrictions: driveRestrictions(d.Restrictions),
		})
	}
	res := connectors.Result{Partial: clamped, Empty: len(out.Items) == 0}
	for encodedSize(out) > c.bounds.MaxResultBytes && len(out.Items) > 1 {
		out.Items = out.Items[:len(out.Items)-1]
		out.Truncated, res.Partial = true, true
	}
	res.Content = out
	return res, nil
}
