// Package audit owns the append-only audit event stream: who, token, tool,
// account label, resource identity, decision, policy version, approval ID,
// operation ID, outcome and latency. Never full arguments, content or response
// bodies. Users see their own events, admins see metadata; retention defaults
// to one year.
//
// Design: Brain plan 36bakiw8 section 6; decision v6piaxdb.
package audit
