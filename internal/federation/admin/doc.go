// Package admin is the admins' pages for user-added MCP servers (Brain
// plan 0omkv2e1, task 1d9i8b07): every server with its owner, audience,
// credentials and review state; publishing to roles and back to private;
// shared credentials and static OAuth clients (write-only); disable,
// enable, delete; refresh and admin review of snapshots; every tunnel with
// revoke; and the netguard SSRF allow-list.
//
// Data access is admin-only (WithJobs, decision 17iv8p3b), so the pages
// are mounted with portal.MountAdmin and check the admin flag again
// themselves: anyone else gets the 404 page, POSTs need the CSRF token,
// responses are Cache-Control: no-store. Pages render the package's own
// embedded templates through the shared nav (internal/portal/nav);
// upstream text goes through the snapshot Display helpers before
// html/template escapes it. Every change is audited with the admin as the
// user and calls the connector's ServerChanged hook (or invalidates the
// allow list). See docs/plugins-admin.md.
package admin
