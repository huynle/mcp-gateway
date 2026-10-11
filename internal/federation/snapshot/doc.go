// Package snapshot pins what a reviewer approved of a user-added MCP server
// and refuses anything else (Brain plan 0omkv2e1, decision yhd5kcaz).
//
// Discover lists a server's tools, resources, resource templates and prompts
// through a federation client session into a Snapshot. Compare diffs a newly
// discovered snapshot against the approved one, BuildReview turns reviewer
// decisions into the per-tool Review stored with the approved snapshot, and
// Check (and Service.Allowed) admits a tool call only when the tool is
// enabled in the approved snapshot and its arguments validate against the
// pinned input schema.
//
// Review defaults (see docs/federation-snapshots.md):
//   - a tool's kind is read only when annotations.readOnlyHint is true;
//     missing annotations or a false hint mean write; a reviewer may override
//     the kind, which is recorded with who and when;
//   - nothing is enabled implicitly: every tool of a first snapshot, and every
//     new or changed tool of a refresh, stays disabled until a reviewer
//     enables it. ReviewDecisions.EnableReads is an explicit opt-in that
//     enables the read tools a reviewer did not decide on individually;
//   - approving a refresh keeps the review of unchanged tools and drops
//     removed ones.
//
// Names, titles and descriptions come from the upstream server: they are
// stored as is and never interpreted. Use Display / DisplayMultiline before
// rendering them.
package snapshot
