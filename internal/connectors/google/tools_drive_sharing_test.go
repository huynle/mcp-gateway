package google_test

import (
	"context"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/google"
)

// Increment 5: Drive permissions (update, remove, transfer ownership),
// comment replies, resolve and delete, revisions and about.

const (
	permID           = "perm9"
	permissionPath   = "/drive/v3/files/" + fileID + "/permissions/" + permID
	commentID        = "c9"
	commentPath      = "/drive/v3/files/" + fileID + "/comments/" + commentID
	repliesPath      = "POST " + commentPath + "/replies"
	revisionsPath    = "GET /drive/v3/files/" + fileID + "/revisions"
	revisionPath     = "GET /drive/v3/files/" + fileID + "/revisions/rev2"
	aboutPath        = "GET /drive/v3/about"
	writerPermBody   = `{"id":"` + permID + `","type":"user","role":"writer","emailAddress":"carol@other.test"}`
	readerPermBody   = `{"id":"` + permID + `","type":"user","role":"reader","emailAddress":"carol@other.test"}`
	pendingOwnerBody = `{"id":"perm7","type":"user","role":"writer","emailAddress":"dana@gmail.test","pendingOwner":true}`
	replyBody        = `{"id":"r1","content":"Done","createdTime":"2026-10-30T10:00:00Z","action":"resolve"}`
	resolvedBody     = `{"id":"` + commentID + `","resolved":true}`
	openBody         = `{"id":"` + commentID + `","resolved":false}`
	deletedBody      = `{"id":"` + commentID + `","deleted":true}`
	revisionsBody    = `{"nextPageToken":"p2","revisions":[{"id":"rev1","mimeType":"text/plain","modifiedTime":"2026-10-01T10:00:00.000Z","size":"12","keepForever":true,` +
		`"lastModifyingUser":{"displayName":"Bob","emailAddress":"bob@example.test"},"originalFilename":"notes.txt"},{"id":"rev2","mimeType":"text/plain","modifiedTime":"2026-10-02T10:00:00Z","size":"20"}]}`
	aboutBody = `{"user":{"displayName":"Alice","emailAddress":"alice@example.test"},"storageQuota":{"limit":"16106127360","usage":"1073741824",` +
		`"usageInDrive":"536870912","usageInDriveTrash":"1024"},"maxUploadSize":"5242880000000"}`
)

func TestDriveSharingDeclarations(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	r, w := connectors.KindRead, connectors.KindWrite
	declared(t, c, "drive.update_permission", w, []string{google.ScopeDriveFile}, connectors.ReconcileStableID)
	declared(t, c, "drive.remove_permission", w, []string{google.ScopeDriveFile}, connectors.ReconcileStableID)
	declared(t, c, "drive.transfer_ownership", w, []string{google.ScopeDriveFile}, connectors.ReconcileNone)
	declared(t, c, "drive.reply_comment", w, []string{google.ScopeDriveFile}, connectors.ReconcileNone)
	declared(t, c, "drive.resolve_comment", w, []string{google.ScopeDriveFile}, connectors.ReconcileStableID)
	declared(t, c, "drive.delete_comment", w, []string{google.ScopeDriveFile}, connectors.ReconcileStableID)
	declared(t, c, "drive.list_revisions", r, []string{google.ScopeDriveMetadataReadonly}, "")
	declared(t, c, "drive.get_revision", r, []string{google.ScopeDriveMetadataReadonly}, "")
	declared(t, c, "drive.get_about", r, []string{google.ScopeDriveMetadataReadonly}, "")
	for name, want := range map[string]map[string]string{
		"drive.update_permission":  {"file_id": fileID, "permission_id": permID, "role": "reader"},
		"drive.remove_permission":  {"file_id": fileID, "permission_id": permID},
		"drive.transfer_ownership": {"file_id": fileID, "mode": "pending", "grantee_domain": "gmail.test"},
		"drive.reply_comment":      {"file_id": fileID, "comment_id": commentID},
		"drive.resolve_comment":    {"file_id": fileID, "comment_id": commentID, "resolved": "true"},
		"drive.delete_comment":     {"file_id": fileID, "comment_id": commentID},
		"drive.get_revision":       {"file_id": fileID, "revision_id": "rev2"},
		"drive.get_about":          {},
	} {
		id := toolOf(t, c, name).ResourceIdentity(map[string]any{"file_id": fileID, "permission_id": permID, "role": "reader", "email": "Dana@Gmail.test",
			"comment_id": commentID, "content": "secret", "revision_id": "rev2"})
		if len(id) != len(want) {
			t.Errorf("%s identity = %v, want %v", name, id, want)
		}
		for k, v := range want {
			if id[k] != v {
				t.Errorf("%s identity = %v, want %v", name, id, want)
			}
		}
	}
	id := toolOf(t, c, "drive.resolve_comment").ResourceIdentity(map[string]any{"file_id": fileID, "comment_id": commentID, "reopen": true})
	if id["resolved"] != "false" {
		t.Errorf("reopen identity = %v", id)
	}
	id = toolOf(t, c, "drive.transfer_ownership").ResourceIdentity(map[string]any{"file_id": fileID, "email": "x@acme.test", "mode": "direct"})
	if id["mode"] != "direct" || id["grantee_domain"] != "acme.test" {
		t.Errorf("direct identity = %v", id)
	}
}

func TestDriveUpdatePermission(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"PATCH " + permissionPath: {status: 200, body: readerPermBody}})
	c, tk := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("drive.update_permission", map[string]any{"file_id": fileID, "permission_id": permID, "role": "reader", "expires": "2026-12-31T00:00:00Z"}))
	if err != nil {
		t.Fatal(err)
	}
	if ids := toolOf(t, c, "drive.update_permission").ResultIDs(res); ids["permission_id"] != permID || ids["file_id"] != fileID {
		t.Errorf("ResultIDs = %v", ids)
	}
	up := srv.Last(t, "PATCH "+permissionPath)
	if body := bodyOf(t, up); body["role"] != "reader" || body["expirationTime"] != "2026-12-31T00:00:00Z" || up.URL.Query().Get("supportsAllDrives") != "true" {
		t.Errorf("update = %v %v", body, up.URL.Query())
	}
	for _, args := range []map[string]any{
		{"file_id": fileID, "role": "reader"},
		{"file_id": fileID, "permission_id": permID},
		{"file_id": fileID, "permission_id": permID, "role": "owner"},
		{"file_id": fileID, "permission_id": permID, "role": "reader", "expires": "tomorrow"},
	} {
		_, err := run(t, c, write("drive.update_permission", args))
		wantClass(t, err, google.ClassInvalidArgument, 0)
	}
	if len(tk.calls) != 1 {
		t.Errorf("token calls = %d, want 1", len(tk.calls))
	}
	for _, tc := range writeErrorCases(readerPermBody) {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{"PATCH " + permissionPath: tc.rt})
			res, err := run(t, shortTimeout(t, srv), write("drive.update_permission", map[string]any{"file_id": fileID, "permission_id": permID, "role": "reader"}))
			checkWriteError(t, tc, res, err)
		})
	}
	for _, tc := range []struct {
		rt   route
		want string
	}{
		{route{status: 200, body: readerPermBody}, "found"},
		{route{status: 200, body: writerPermBody}, "not_found"},
		{route{status: 404, body: "error_not_found.json"}, "cannot_tell"},
	} {
		t.Run("check "+tc.want, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{"GET " + permissionPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			tool, in := reconcileInput(t, c, "drive.update_permission", map[string]any{"file_id": fileID, "permission_id": permID, "role": "reader"})
			out, err := tool.Reconcile.Check(context.Background(), in)
			wantOutcome(t, out, err, tc.want, permID)
		})
	}
}

func TestDriveRemovePermission(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"DELETE " + permissionPath: {status: 204, body: ""}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("drive.remove_permission", map[string]any{"file_id": fileID, "permission_id": permID}))
	if err != nil {
		t.Fatal(err)
	}
	if ids := toolOf(t, c, "drive.remove_permission").ResultIDs(res); ids["permission_id"] != permID {
		t.Errorf("ResultIDs = %v", ids)
	}
	_, err = run(t, c, write("drive.remove_permission", map[string]any{"file_id": fileID}))
	wantClass(t, err, google.ClassInvalidArgument, 0)
	for _, tc := range writeErrorCases("") {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{"DELETE " + permissionPath: tc.rt})
			res, err := run(t, shortTimeout(t, srv), write("drive.remove_permission", map[string]any{"file_id": fileID, "permission_id": permID}))
			checkWriteError(t, tc, res, err)
		})
	}
	for _, tc := range []struct {
		rt   route
		want string
	}{
		{route{status: 404, body: "error_not_found.json"}, "found"},
		{route{status: 200, body: writerPermBody}, "not_found"},
		{route{status: 500, body: "error_server.json"}, "cannot_tell"},
	} {
		t.Run("check "+tc.want, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{"GET " + permissionPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			tool, in := reconcileInput(t, c, "drive.remove_permission", map[string]any{"file_id": fileID, "permission_id": permID})
			out, err := tool.Reconcile.Check(context.Background(), in)
			wantOutcome(t, out, err, tc.want, permID)
		})
	}
}

func TestDriveTransferOwnership(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"POST " + permissionsPath: {status: 200, body: pendingOwnerBody}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("drive.transfer_ownership", map[string]any{"file_id": fileID, "email": "dana@gmail.test"}))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		PermissionID string `json:"permission_id"`
		Role         string `json:"role"`
		PendingOwner bool   `json:"pending_owner"`
	}
	decode(t, res, &out)
	if out.PermissionID != "perm7" || !out.PendingOwner {
		t.Errorf("out = %+v", out)
	}
	if ids := toolOf(t, c, "drive.transfer_ownership").ResultIDs(res); ids["permission_id"] != "perm7" {
		t.Errorf("ResultIDs = %v", ids)
	}
	p := srv.Last(t, "POST "+permissionsPath)
	if body := bodyOf(t, p); body["role"] != "writer" || body["pendingOwner"] != true || body["emailAddress"] != "dana@gmail.test" || body["type"] != "user" ||
		p.URL.Query().Get("transferOwnership") == "true" {
		t.Errorf("pending = %v %v", body, p.URL.Query())
	}
	if _, err := run(t, c, write("drive.transfer_ownership", map[string]any{"file_id": fileID, "email": "dana@acme.test", "mode": "direct"})); err != nil {
		t.Fatal(err)
	}
	p = srv.Last(t, "POST "+permissionsPath)
	if body := bodyOf(t, p); body["role"] != "owner" || body["pendingOwner"] != nil || p.URL.Query().Get("transferOwnership") != "true" {
		t.Errorf("direct = %v %v", body, p.URL.Query())
	}
	for _, args := range []map[string]any{
		{"file_id": fileID},
		{"file_id": fileID, "email": "nope"},
		{"file_id": fileID, "email": "a@b.test", "mode": "now"},
	} {
		_, err := run(t, c, write("drive.transfer_ownership", args))
		wantClass(t, err, google.ClassInvalidArgument, 0)
	}
	for _, tc := range writeErrorCases(pendingOwnerBody) {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{"POST " + permissionsPath: tc.rt})
			res, err := run(t, shortTimeout(t, srv), write("drive.transfer_ownership", map[string]any{"file_id": fileID, "email": "a@b.test"}))
			checkWriteError(t, tc, res, err)
		})
	}
}

func TestDriveCommentReplies(t *testing.T) {
	srv := newAPIServer(t, map[string]route{repliesPath: {status: 200, body: replyBody}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("drive.reply_comment", map[string]any{"file_id": fileID, "comment_id": commentID, "content": "Thanks"}))
	if err != nil {
		t.Fatal(err)
	}
	if ids := toolOf(t, c, "drive.reply_comment").ResultIDs(res); ids["reply_id"] != "r1" || ids["comment_id"] != commentID {
		t.Errorf("ResultIDs = %v", ids)
	}
	if body := bodyOf(t, srv.Last(t, repliesPath)); body["content"] != "Thanks" || body["action"] != nil {
		t.Errorf("reply body = %v", body)
	}
	if _, err := run(t, c, write("drive.resolve_comment", map[string]any{"file_id": fileID, "comment_id": commentID})); err != nil {
		t.Fatal(err)
	}
	if body := bodyOf(t, srv.Last(t, repliesPath)); body["action"] != "resolve" {
		t.Errorf("resolve body = %v", body)
	}
	if _, err := run(t, c, write("drive.resolve_comment", map[string]any{"file_id": fileID, "comment_id": commentID, "reopen": true, "content": "Not yet"})); err != nil {
		t.Fatal(err)
	}
	if body := bodyOf(t, srv.Last(t, repliesPath)); body["action"] != "reopen" || body["content"] != "Not yet" {
		t.Errorf("reopen body = %v", body)
	}
	for name, args := range map[string]map[string]any{
		"drive.reply_comment":   {"file_id": fileID, "comment_id": commentID},
		"drive.resolve_comment": {"file_id": fileID},
	} {
		_, err := run(t, c, write(name, args))
		wantClass(t, err, google.ClassInvalidArgument, 0)
	}
	for _, tc := range writeErrorCases(replyBody) {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{repliesPath: tc.rt})
			res, err := run(t, shortTimeout(t, srv), write("drive.reply_comment", map[string]any{"file_id": fileID, "comment_id": commentID, "content": "x"}))
			checkWriteError(t, tc, res, err)
		})
	}
	for _, tc := range []struct {
		reopen bool
		rt     route
		want   string
	}{
		{false, route{status: 200, body: resolvedBody}, "found"},
		{false, route{status: 200, body: openBody}, "not_found"},
		{true, route{status: 200, body: openBody}, "found"},
		{false, route{status: 500, body: "error_server.json"}, "cannot_tell"},
	} {
		t.Run("check resolve "+tc.want, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{"GET " + commentPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			tool, in := reconcileInput(t, c, "drive.resolve_comment", map[string]any{"file_id": fileID, "comment_id": commentID, "reopen": tc.reopen})
			out, err := tool.Reconcile.Check(context.Background(), in)
			wantOutcome(t, out, err, tc.want, commentID)
		})
	}
}

func TestDriveDeleteComment(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"DELETE " + commentPath: {status: 204, body: ""}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, write("drive.delete_comment", map[string]any{"file_id": fileID, "comment_id": commentID}))
	if err != nil {
		t.Fatal(err)
	}
	if ids := toolOf(t, c, "drive.delete_comment").ResultIDs(res); ids["comment_id"] != commentID {
		t.Errorf("ResultIDs = %v", ids)
	}
	for _, tc := range writeErrorCases("") {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{"DELETE " + commentPath: tc.rt})
			res, err := run(t, shortTimeout(t, srv), write("drive.delete_comment", map[string]any{"file_id": fileID, "comment_id": commentID}))
			checkWriteError(t, tc, res, err)
		})
	}
	for _, tc := range []struct {
		rt   route
		want string
	}{
		{route{status: 200, body: deletedBody}, "found"},
		{route{status: 404, body: "error_not_found.json"}, "found"},
		{route{status: 200, body: openBody}, "not_found"},
		{route{status: 500, body: "error_server.json"}, "cannot_tell"},
	} {
		t.Run("check "+tc.want, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{"GET " + commentPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			tool, in := reconcileInput(t, c, "drive.delete_comment", map[string]any{"file_id": fileID, "comment_id": commentID})
			out, err := tool.Reconcile.Check(context.Background(), in)
			wantOutcome(t, out, err, tc.want, commentID)
			if tc.rt.status == 200 {
				if q := query(t, srv, "/drive/v3/files/"+fileID+"/comments/"+commentID); q.Get("includeDeleted") != "true" {
					t.Errorf("query = %v", q)
				}
			}
		})
	}
}

func TestDriveRevisions(t *testing.T) {
	srv := newAPIServer(t, map[string]route{revisionsPath: {status: 200, body: revisionsBody}, revisionPath: {status: 200, body: `{"id":"rev2","mimeType":"text/plain","size":"20"}`}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("drive.list_revisions", map[string]any{"file_id": fileID}))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		FileID  string `json:"file_id"`
		HasMore bool   `json:"has_more"`
		Items   []struct {
			ID          string `json:"id"`
			Modified    string `json:"modified"`
			Size        int64  `json:"size"`
			KeepForever bool   `json:"keep_forever"`
			ModifiedBy  string `json:"modified_by"`
		} `json:"items"`
	}
	decode(t, res, &out)
	if out.FileID != fileID || !out.HasMore || len(out.Items) != 2 || out.Items[0].Size != 12 || !out.Items[0].KeepForever || out.Items[0].ModifiedBy != "Bob" ||
		out.Items[0].Modified != "2026-10-01T10:00:00Z" {
		t.Errorf("out = %+v", out)
	}
	if q := query(t, srv, "/drive/v3/files/"+fileID+"/revisions"); q.Get("fields") == "" {
		t.Error("revisions.list needs fields")
	}
	res, err = run(t, c, call("drive.get_revision", map[string]any{"file_id": fileID, "revision_id": "rev2"}))
	if err != nil {
		t.Fatal(err)
	}
	var rev struct {
		ID   string `json:"id"`
		Size int64  `json:"size"`
	}
	decode(t, res, &rev)
	if rev.ID != "rev2" || rev.Size != 20 {
		t.Errorf("rev = %+v", rev)
	}
	srv = newAPIServer(t, map[string]route{revisionsPath: {status: 200, body: `{"revisions":[]}`}})
	c, _ = newConnector(t, srv, connectors.Bounds{})
	if res, err := run(t, c, call("drive.list_revisions", map[string]any{"file_id": fileID})); err != nil || !res.Empty {
		t.Errorf("empty = %+v, %v", res, err)
	}
	_, err = run(t, c, call("drive.get_revision", map[string]any{"file_id": fileID}))
	wantClass(t, err, google.ClassInvalidArgument, 0)
	for _, tc := range readErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{revisionsPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			res, err := run(t, c, call("drive.list_revisions", map[string]any{"file_id": fileID}))
			checkReadError(t, tc, res, err)
		})
	}
}

func TestDriveGetAbout(t *testing.T) {
	srv := newAPIServer(t, map[string]route{aboutPath: {status: 200, body: aboutBody}})
	c, _ := newConnector(t, srv, connectors.Bounds{})
	res, err := run(t, c, call("drive.get_about", nil))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		User struct {
			DisplayName string `json:"display_name"`
			Email       string `json:"email"`
		} `json:"user"`
		Storage struct {
			Limit        int64 `json:"limit"`
			Usage        int64 `json:"usage"`
			UsageInDrive int64 `json:"usage_in_drive"`
			UsageInTrash int64 `json:"usage_in_trash"`
		} `json:"storage"`
		MaxUploadSize int64 `json:"max_upload_size"`
	}
	decode(t, res, &out)
	if out.User.Email != "alice@example.test" || out.Storage.Limit != 16106127360 || out.Storage.UsageInTrash != 1024 || out.MaxUploadSize == 0 {
		t.Errorf("out = %+v", out)
	}
	if q := query(t, srv, "/drive/v3/about"); !strings.Contains(q.Get("fields"), "storageQuota") {
		t.Errorf("fields = %q", q.Get("fields"))
	}
	for _, tc := range readErrorCases() {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{aboutPath: tc.rt})
			c, _ := newConnector(t, srv, connectors.Bounds{})
			res, err := run(t, c, call("drive.get_about", nil))
			checkReadError(t, tc, res, err)
		})
	}
}
