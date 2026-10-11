# Discovery snapshots and tool review (`internal/federation/snapshot`)

Pins what a reviewer approved of a user-added MCP server and refuses anything else. Built on the [federation client](federation-client.md) and the schema 14 snapshot store (`mcp_server_snapshots`). Design: Brain plan `0omkv2e1`, decisions `yhd5kcaz` (frozen snapshot, review on refresh, missing `readOnlyHint` = write), `17iv8p3b` (owner reviews only while private, admin via WithJobs), task `f3gvte62`.

## Model

A **snapshot** is a server's discovered capability set: tools (name, title, description, input schema, output schema, annotations), resources, resource templates and prompts. Each list is sorted by key. Each refresh that finds something new stores a new **version** (`pending`). Approving a version makes it the one **approved** snapshot (the previous one becomes `superseded`). Calls are only ever checked against the approved snapshot.

The **review** (`review` jsonb column) is a map from tool name to:

```json
{"search": {"enabled": true, "kind": "read",
            "kindOverride": {"kind": "write", "by": "<user id>", "at": "..."},
            "reviewedBy": "<user id>", "reviewedAt": "..."}}
```

`kind` is the effective kind. It is the override if there is one; otherwise it is `read` only when `annotations.readOnlyHint` is `true`. Missing annotations, or a `false` or absent hint, mean **write**. `destructiveHint`, `openWorldHint` and `idempotentHint` are kept in the snapshot for display only.

## Review defaults (chosen)

| Situation | Result |
|---|---|
| First snapshot approved with no decisions | every tool listed, **none enabled** |
| `ReviewDecisions.Tools[name].Enabled` | sets that tool's state, recorded with who/when |
| `ReviewDecisions.Tools[name].Kind` | `read`/`write` override (who/when recorded); `""` clears it |
| `ReviewDecisions.EnableReads` (explicit opt-in, e.g. an "enable all read tools" button) | enables read tools **no reviewer has decided on yet**. Tools a reviewer disabled stay disabled, and writes are never bulk-enabled |
| Refresh: unchanged tool | keeps its review (enabled state, override, reviewer) |
| Refresh: changed tool (title, description, input/output schema, annotations) | **disabled** until re-enabled; a `write` override is kept, a `read` override is dropped |
| Refresh: added tool | disabled, kind from its hint |
| Refresh: removed tool | dropped from the review, so calls get `ErrToolNotReviewed` |
| Decision for a tool not in the snapshot / bad kind | `ErrUnknownTool` / `ErrInvalidKind`, nothing stored |

Nothing is enabled implicitly, because `readOnlyHint` is the upstream's own claim. Enabling reads by default would let a hostile server label a write as read and have it enabled with no human looking at it.

Schemas are compared as **canonical JSON** (sorted keys, numbers kept as written). PostgreSQL `jsonb` reorders keys, so a byte comparison would see a change on every refresh.

## Service API

```go
svc := snapshot.NewService(st) // st: *store.Store (snapshot.Scoper)

owner := snapshot.Actor{UserID: userID}                // store user scope (RLS)
admin := snapshot.Actor{UserID: adminID, Admin: true}  // WithJobs; caller must have authorised the admin
sys   := snapshot.System()                             // WithJobs, no approver (jobs / connector)

rec, err        := svc.Create(ctx, owner, serverID, sess)  // discover + store pending (first or next version)
rec, diff, err  := svc.Refresh(ctx, owner, serverID, sess) // same, plus Diff vs approved; unchanged = no new version
diff, err       := svc.Diff(ctx, owner, serverID)          // latest vs approved
rec, err        := svc.Latest(ctx, owner, serverID)        // newest snapshot (review page)
rec, err        := svc.Approve(ctx, owner, serverID, version, snapshot.ReviewDecisions{...})
rec, err        := svc.Current(ctx, owner, serverID)       // approved snapshot + review
tool, kind, err := svc.Allowed(ctx, actor, serverID, toolName, args)
```

`sess` is any `snapshot.Session` (`*client.Session` satisfies it). Discovery lists only the capabilities the server advertises. It runs outside the database transaction. Empty or duplicate tool, prompt or resource keys are refused with `ErrInvalidSnapshot`.

`Approve(version)` accepts the **latest** version (approving a refresh) or the **approved** one (changing decisions). Anything else returns `ErrStaleVersion`. The review always starts from the approved snapshot's review.

**Who may do what** (enforced by row-level security, decision `17iv8p3b`):

| Actor | Create / Refresh | Approve | Current / Diff / Allowed |
|---|---|---|---|
| owner, private server | yes | yes | yes |
| owner, published server | yes (pending only) | **no** (`ErrReviewNotAllowed`) | yes |
| user the server is published to | no (`ErrReviewNotAllowed`) | no | yes |
| user who cannot see the server | no | no (`ErrNoSnapshot`) | `ErrNoSnapshot` / `ErrToolNotReviewed` |
| admin (`Admin: true`) | yes | yes | yes |

A refused approval changes nothing (the transaction rolls back).

## Enforcement: `Allowed` / `Check`

`Allowed` passes only if all of these hold:

1. the server has an approved snapshot visible to the actor, and the tool is in it. Otherwise `ErrToolNotReviewed`;
2. the review enables the tool. Otherwise `ErrToolDisabled`;
3. the arguments validate against the **pinned** input schema. Otherwise `ErrArgsInvalid`. This covers extra properties under `additionalProperties: false`, wrong types, missing required properties and every other schema keyword.

Validation uses `github.com/google/jsonschema-go` (the go-sdk's validator: drafts 2020-12 and 07):

- Arguments are round-tripped through JSON first, so the validator sees exactly what goes on the wire.
- `nil` arguments count as `{}`.
- A tool with no input schema accepts only `{}`.
- Remote `$ref`s are never fetched. A schema that needs one, or does not parse, is unusable, and the call gets `ErrArgsInvalid`.
- Error messages never contain argument values, argument names or upstream text. The validator's own message is dropped.

`Check(snapshot, review, tool, args)` is the same decision over in-memory values, for callers that cache the approved record.

## Untrusted text

Names, titles, descriptions, URIs and schemas come from the upstream server. They are stored as is and never interpreted. For display use:

- `Display(s, limit)`, `DisplayName` (128 runes), `DisplayTitle` (256): one line. Invalid UTF-8 becomes U+FFFD, whitespace controls become spaces, other C0/C1/DEL and Unicode format characters (bidi overrides, zero-width, BOM) are dropped, whitespace is collapsed and long text is capped with `…`.
- `DisplayMultiline(s, limit)`, `DisplayDescription` (4096): the same, but line breaks are kept, with at most one blank line in a row.

These helpers do **not** HTML-escape. Templates must still escape, and should show the server name next to the text as provenance.

## For the federation connector (task fybs78bs)

- Before every upstream `tools/call`, call `svc.Allowed(ctx, snapshot.Actor{UserID: caller}, serverID, tool, args)`. With a user actor this also checks visibility through RLS. If the connector has already checked visibility, it can use `snapshot.System()` instead. Use the returned `Kind` to route writes through the write path (confirmation / approval). Map `ErrToolNotReviewed` / `ErrToolDisabled` / `ErrArgsInvalid` to class-level errors. They are safe to show.
- `tools/list` should expose only tools that are enabled in `svc.Current(...)`, using the pinned schemas and descriptions, not the live upstream ones.
- Discovery (`Create` / `Refresh`) is triggered by the servers portal (owner) or an admin action, with a session from the federation client.

## Tests

- `go test ./internal/federation/snapshot/`: discovery mapping, `readOnlyHint` mapping, canonical JSON, diff, review rules, `Check` (unknown / disabled tools, schema violations, no echo of values), display sanitizing, codec.
- `make test-integration` (`GATEWAY_TEST_DATABASE_URL`): Service against PostgreSQL in its own database `gateway_snapshot_test`. Covers the owner lifecycle (first approval enables nothing, refresh with a changed schema disables the tool until re-enabled, added tool disabled, removed tool gone, stale version refused), the owner approving while private, the owner and a reader refused once published, the admin WithJobs path approving, and visibility for readers and non-readers.
