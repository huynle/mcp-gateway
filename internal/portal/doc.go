// Package portal owns the embedded web portal: server-rendered Go templates
// with htmx, CSRF on every form, HttpOnly/Secure/SameSite cookies. Users manage
// tokens, app connections, approvals and their activity; admins manage users,
// roles, vendor apps, audit and settings.
//
// Design: Brain plan 36bakiw8 section 2; decision 7datr7x4.
package portal
