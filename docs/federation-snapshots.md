# Discovery snapshots and tool review (`internal/federation/snapshot`)

Pins what a reviewer approved of a user-added MCP server and refuses anything else. Built on the [federation client](federation-client.md) and the schema 14 snapshot store (`mcp_server_snapshots`). Design: Brain plan `0omkv2e1`, decisions `yhd5kcaz` (frozen snapshot, review on refresh, missing `readOnlyHint` = write), `17iv8p3b` (owner reviews only while private, admin via WithJobs), task `f3gvte62`.

## Model

A **snapshot** is a server's discovered capability set: tools (name, title, description, input schema, output schema, annotations), resources, resource templates and prompts. Each list is sorted by key. Each refresh that finds something new stores a new **version** (`pending`). Approving a version makes it the one **approved** snapshot (the previous one becomes `superseded`). Calls are only ever checked against the approved snapshot.

The **review** (`review` jsonb column) holds the tool review and the review of the resources, resource templates and prompts (task `bdb5zcud`):

```json
{"format": 2,
 "tools": {"search": {"enabled": true, "kind": "read",
                      "kindOverride": {"kind": "write", "by": "<user id>", "at": "..."},
                      "reviewedBy": "<user id>", "reviewedAt": "..."}},
 "content": {"resources":         {"docs://index":        {"enabled": true, "reviewedBy": "<user id>", "reviewedAt": "..."}},
             "resourceTemplates": {"docs://page/{slug}":  {"enabled": false}},
             "prompts":           {"summarize":           {"enabled": true}}}}
```

`tools` decodes to `snapshot.Review` (`Record.Review`), `content` to `*snapshot.ContentReview` (`Record.Content`). **Legacy layout**: rows approved before the content toggles hold only the flat tool map (`{"search": {...}}`). They decode with `Record.Content == nil`, which counts as **every resource, template and prompt enabled** (`ContentReview.ResourceEnabled` / `TemplateEnabled` / `PromptEnabled` answer true on nil), so servers approved earlier keep serving them without a new review. The layouts are told apart by `format` being a number (every legacy value is an object, even for a tool called `format`). Every approval writes the current layout. No migration: the column is jsonb.

`kind` is the effective kind. It is the override if there is one; otherwise it is `read` only when `annotations.readOnlyHint` is `true`. Missing annotations, or a `false` or absent hint, mean **write**. `destructiveHint`, `openWorldHint` and `idempotentHint` are kept in the snapshot for display only.

## Review defaults (chosen)

| Situation | Result |
|---|---|
| First snapshot approved with no decisions | every tool listed, **none enabled** |
| `ReviewDecisions.Tools[name].Enabled` | sets that tool's state, recorded with who/when |
| `ReviewDecisions.Tools[name].Kind` | `read`/`write` override (who/when recorded); `""` clears it |
| `ReviewDecisions.EnableReads` (explicit opt-in, e.g. an "enable all read tools" button) | enables read tools **no reviewer has decided on yet**. Tools a reviewer disabled stay disabled, and `EnableReads` never enables writes. (The review pages' "Approve with all tools enabled" sends an explicit `Enabled: true` per tool instead, writes included: decision `ome8yn5a`.) |
| Refresh: unchanged tool | keeps its review (enabled state, override, reviewer) |
| Refresh: changed tool (title, description, input/output schema, annotations) | **disabled** until re-enabled; a `write` override is kept, a `read` override is dropped |
| Refresh: added tool | disabled, kind from its hint |
| Refresh: removed tool | dropped from the review, so calls get `ErrToolNotReviewed` |
| Decision for a tool not in the snapshot / bad kind | `ErrUnknownTool` / `ErrInvalidKind`, nothing stored |
| Resources, templates, prompts (`BuildContentReview`) | the same rules: first snapshot **none enabled**; `ReviewDecisions.Resources` / `ResourceTemplates` / `Prompts` (key → enabled) set one item each with who/when; on a refresh an unchanged item keeps its state, a new or changed item (any field) starts **disabled**, a removed one is dropped. Against a legacy approved snapshot (no content review) unchanged items carry over as enabled. A decision for an item not in the snapshot: `ErrUnknownItem` |

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

`sess` is any `snapshot.Session` (`*client.Session` satisfies it). Discovery lists only the capabilities the server advertises. It runs outside the database transaction. Empty or duplicate tool, prompt or resource keys are refused with `ErrInvalidSnapshot`. Items the gateway cannot store or match are **skipped** (below); the record returned by `Create` / `Refresh` lists them in `Record.Skipped`, even when the refresh added no version.

## Skipped items and NUL (chosen policy)

PostgreSQL `jsonb` refuses U+0000, so one NUL anywhere in a server's answer used to make every refresh of that server fail ("unsupported Unicode escape sequence"): a hostile upstream could block its own re-review (Brain task `jsb8470s`, report `25175i87` finding 6). Discovery (`sanitize.go`) now applies this policy:

| Upstream text | Result |
|---|---|
| tool name, prompt name, resource URI or resource template with NUL or another control character (C0, DEL, C1) | item **skipped**, reason `invalid name`. Keys are matched against calls, so they are never rewritten. |
| prompt argument name with NUL or a control character | prompt **skipped**, reason `invalid argument` (dropping the argument would change the prompt's signature) |
| NUL in a **key** of a tool's input or output schema (any depth) | tool **skipped**, reason `invalid schema` |
| NUL in any other string: titles, descriptions, resource names and MIME types, annotation titles, prompt argument titles and descriptions, **string values** inside schemas | NUL **removed**, item kept |

Other text is still stored as discovered (display sanitizing below). Unpaired surrogates and invalid UTF-8 cannot reach the store: the JSON decoder and `encoding/json` already turn them into U+FFFD.

`snapshot.Skipped{Kind, Name, Reason}` names an item by its key passed through `DisplayName` (never raw upstream text); `Kind` is `tool`, `resource`, `resource template` or `prompt`. Skipped items are **not stored** (no column for them; no migration) and are not part of `Compare`. They are shown by the refresh that met them:

- servers portal and admin **Refresh**: when anything was skipped, the review page is rendered at once (instead of the redirect) with a notice listing each item as `<kind> <name>: skipped (<reason>)`;
- `gateway.refresh_server`: a `skipped` list (`[]` when none) and a sentence in `note`;
- the log (`federation.server_refreshed`, count only).

A later visit to the review page does not repeat the list; refresh again to see it.

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
- `tools/list` should expose only tools that are enabled in `svc.Current(...)`, using the pinned schemas and descriptions, not the live upstream ones. Resources, templates and prompts likewise: only those `Record.Content` enables (nil = all, legacy).
- Discovery (`Create` / `Refresh`) is triggered by the servers portal (owner) or an admin action, with a session from the federation client.

## Tests

- `go test ./internal/federation/snapshot/`: discovery mapping, `readOnlyHint` mapping, canonical JSON, diff, review rules, content review rules (first snapshot, decisions, carry-over, legacy base, both column layouts), `Check` (unknown / disabled tools, schema violations, no echo of values), display sanitizing, codec.
- `TestIntegrationSnapshotLegacyContentReview`: a snapshot approved with the legacy flat review serves all its resources, templates and prompts; approving its refresh keeps them enabled and starts a new resource disabled.
- `go test ./internal/federation/snapshot/`: `TestDiscoverSanitizesHostileText` (NUL in descriptions, titles, schema values, resource names and MIME types removed; NUL / C0 / C1 names, NUL schema keys, NUL resource URIs and templates, NUL prompt names and argument names skipped and listed; nothing stored carries a NUL).
- `make test-integration`: `TestIntegrationRefreshStoresSanitizedSnapshot` (a hostile upstream refreshes into PostgreSQL, the stored row has no NUL, skipped items reported, the clean tool approved and allowed; a second refresh adds no version and reports the skipped items again).
- `make test-security`: `TestSecurityFedNULInUpstreamTextSanitized` (portal Refresh of a hostile upstream answers 200 with the skipped list; clean items stored; the approved snapshot keeps serving).
- `make test-integration` (`GATEWAY_TEST_DATABASE_URL`): Service against PostgreSQL in its own database `gateway_snapshot_test`. Covers the owner lifecycle (first approval enables nothing, refresh with a changed schema disables the tool until re-enabled, added tool disabled, removed tool gone, stale version refused), the owner approving while private, the owner and a reader refused once published, the admin WithJobs path approving, and visibility for readers and non-readers.
