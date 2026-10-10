// Package portal owns the embedded web portal: server-rendered Go templates
// with htmx, CSRF on every form, HttpOnly/Secure/SameSite cookies. Users
// manage tokens, app connections, approvals and their activity; admins
// manage users, roles, vendor apps, audit and settings.
//
// This task ships the shell: sign-in, my account, admin users (list,
// enable/disable, assign role) and the error pages. Templates live in
// templates/ and the htmx build in static/, both embedded; the identity
// service's sign-in routes are mounted here so one middleware chain
// (session, then CSRF) covers everything.
//
// Design: Brain plan 36bakiw8 section 2; decision 7datr7x4.
package portal
