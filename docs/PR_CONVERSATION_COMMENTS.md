# Canonical pull-request conversations

An existing native PR has an independent, append-only conversation. Comments
are canonical forge events published with their outbox obligations through the
same exact-predecessor authority-head CAS as other metadata. They are available
on open, closed, and merged native PRs. Commenting changes neither the PR's
metadata version nor its review streams, branch tips, or policy epoch.

This implements append-only conversations and comments on exact original source
lines within `frankengit-root-doctrine-x2mv.4.20`. Editing, deletion, thread
resolution and source remapping remain outside this profile. Legacy-only and
merge-only records without native PR metadata do not acquire a fabricated
conversation subject. The canonical contract is
[`20.1 of the normative protocol](NORMATIVE_PROTOCOL_CONTRACTS.md#201-native-pr-conversation-streams).

## Read and append with `fg`

Read the discussion and its version:

```sh
fg pr comments "$STORAGE" "$TENANT" "$REPOSITORY" 7 --trusted-local --limit 20
```

An available PR with no comments returns `found: true` and
`discussion_version: "0"`. An absent or hidden PR returns `found: false` and a
null version. Storage, integrity, cancellation, and pagination failures are
errors; they are never represented as an empty conversation.

Append a comment using the returned **discussion** version:

```sh
fg pr comment "$STORAGE" "$TENANT" "$REPOSITORY" 7 --trusted-local \
  --principal "$PRINCIPAL" --idempotency-key 'pr-7-comment-1' \
  --expected-version 0 --body-file ./comment.md
```

Exactly one of `--body` and `--body-file` is required. The body is nonblank
UTF-8, at most 65,536 bytes, without NUL. Whitespace, line endings, Markdown,
and Unicode are preserved. Body files use the existing bounded, regular-file,
trusted-operator input path. The file is read before opening the repository.

The command's version is independent of the PR metadata version. Two writers
using the same discussion predecessor cannot both append at its successor:
one must receive a canonical stale-version refusal and deliberately submit a
new command if the author still wants to post it. A successful first append
creates comment version 1; each later append advances the discussion by one.

Add `--object-format sha256` for a SHA-256 repository. This metadata workflow
does not infer the repository format from a comment or invoke Git.

Pages are ordered by exact comment version. A positive `--after` requires the
original page's `--expected-head` token. The node can select that authenticated
retained head across ordinary later publications, subject to retained-history
availability and **current** disclosure policy. A page also reports the whole
discussion's version at its snapshot, even when `next_after` is present.
`complete` describes whether more comments remain after the returned page;
it is not an approval or permission to merge.

CLI identifiers, comment versions, and discussion versions use exact decimal
strings in JSON. Exit 0 means a committed append or completed page read; exit 3
means a canonical refusal; exit 4 means an absent/hidden PR; exit 2 means an
input, infrastructure, cleanup, or output failure. A known terminal decision
remains explicit even if node shutdown or stdout subsequently fails.

## Comment on exact original source lines

Inspect the PR's recorded comparison before constructing an anchor:

```sh
fg pr diff "$STORAGE" "$TENANT" "$REPOSITORY" 7 --trusted-local \
  --expected-version "$PR_VERSION" --comparison direct
```

The existing [PR diff](SOURCE_REVIEW_COMMAND.md) uses recorded source and target
tips from one authenticated head. A branch push does not silently refresh them.
`pull_request.version` is the **PR metadata version**; obtain the independent
**discussion version** through `fg pr comments` before appending.

The source profile is fixed as `frankengit.source-comment.myers-lines.v1`.
Choose a nonempty before- or after-side range of whole original lines from a
changed file. The service verifies the named commits, compared base, exact path,
blob, mode and original byte boundaries again during canonical admission.
Comments can select unchanged context within a file whose identity or mode
changed. An arbitrary blob or line number cannot become an accepted location.

All 15 anchor fields are required together. This table uses the names inside the
MCP `anchor` object and the returned `anchor` object:

| Field | Value to preserve from the inspected comparison |
|---|---|
| `pull_request_version` | Positive PR metadata version. |
| `source_ref_hex` | Exact source reference bytes, as lowercase hex; the diff's `after_reference_hex`. |
| `target_ref_hex` | Exact target reference bytes, as lowercase hex; the diff's `before_reference_hex`. |
| `source_tip` | Recorded source commit; the diff's `requested_after`. |
| `target_tip` | Recorded target commit; the diff's `requested_before`. |
| `compared_base` | Actual before-side commit; the diff's `compared_before`. |
| `comparison` | `direct` or `merge_base`. The diff's `merge-base` spelling becomes `merge_base` here. |
| `path_hex` | Exact repository-relative path bytes as lowercase hex. |
| `side` | `before` or `after`. |
| `blob` | Selected side's nonzero native blob ID. |
| `mode` | Selected side's canonical octal string: `100644`, `100755` or `120000`. |
| `byte_start` | Inclusive zero-based offset in that original blob. |
| `byte_end` | Exclusive offset in that original blob. |
| `line_start` | Zero-based original line index. |
| `line_count` | Positive number of complete original lines. |

References are distinct valid `refs/heads/*` names, at most 1,024 bytes each.
Paths are at most 4,096 raw bytes and 64 components, with no NUL, empty, `.` or
`..` component. All four OIDs use the repository's configured SHA-1 or SHA-256
format. Direct comparison requires `compared_base == target_tip`. Merge-base
comparison requires one unique best common ancestor; unrelated or ambiguous
ancestry refuses.

Each compared blob is at most 1 MiB and contains no NUL. A selected span is
nonempty, at most 64 KiB and contains 1–128 complete LF-delimited lines. LF
belongs to its line; CRLF, non-UTF-8 bytes and an unterminated last line are
preserved. A final LF adds no phantom line. The server checks that the line
coordinates reproduce the exact byte interval and reruns the bounded Myers
comparison. Additional object, traversal, work and deadline ceilings may refuse
a large comparison; no partial source validation succeeds. Symlink contents
are inert bytes. Directory and gitlink entries are not selectable anchors.

For CLI input, prefix each field with `--anchor-` and replace underscores with
hyphens. For example, after inspecting a regular `src/lib.rs` whose selected
after-side first line is exactly `reviewed\n` (nine original bytes):

```sh
fg pr comment "$STORAGE" "$TENANT" "$REPOSITORY" 7 --trusted-local \
  --principal "$PRINCIPAL" --idempotency-key 'pr-7-source-comment-1' \
  --expected-version "$DISCUSSION_VERSION" --body-file ./comment.md \
  --anchor-pull-request-version "$PR_VERSION" \
  --anchor-source-ref-hex "$SOURCE_REF_HEX" \
  --anchor-target-ref-hex "$TARGET_REF_HEX" \
  --anchor-source-tip "$SOURCE_TIP" --anchor-target-tip "$TARGET_TIP" \
  --anchor-compared-base "$TARGET_TIP" --anchor-comparison direct \
  --anchor-path-hex 7372632f6c69622e7273 --anchor-side after \
  --anchor-blob "$BLOB" --anchor-mode 100644 \
  --anchor-byte-start 0 --anchor-byte-end 9 \
  --anchor-line-start 0 --anchor-line-count 1
```

Use values from the inspected PR and blob for every variable; the example's
path and range apply only to those exact bytes. Add `--object-format sha256` to
both CLI commands for a SHA-256 repository. Omitting every anchor flag creates
an ordinary conversation comment. A partial anchor, duplicate field, unknown
field or caller-supplied profile is rejected.

An anchored row adds `anchor`, including the fixed output-only `profile`, and
`anchor_status`. CLI and MCP encode the PR version and all four coordinates as
canonical unsigned decimal strings; HTTP JSON emits integer values. Object IDs,
ref/path hex, comparison, side and octal mode remain strings on every surface.
Clients must preserve exact integers and bytes. Ordinary rows omit both anchor
fields, preserving their existing response shape.

`anchor_status: "exact"` compares the original anchor with PR metadata at the
comment page's selected `source_head`. It becomes `outdated` when that version,
either reference or either recorded tip differs. A title-only PR update can
therefore make a latest read outdated while an earlier pinned page remains
exact. Moving a branch without updating the recorded PR does not change the
status. Neither status is an approval or a claim about the current branch tips.
The original coordinates remain visible and are never heuristically moved.

## HTTP

Enable the existing PR HTTP profile. Reloadable repository credentials grant
`pulls-read` and `pulls-write` independently; comment appends require the latter.
The configured repository route and explicit Bearer token are checked before
body intake. A write grant does not imply reads, Git access, reviews, merges,
or outcome lookup. Existing cross-site request rejection and service ceilings
also apply.

```text
GET  /<repository-route>/api/v1/pulls/7/comments?limit=20
POST /<repository-route>/api/v1/pulls/7/comments
```

A POST requires `Content-Type: application/x-www-form-urlencoded`, a stable
`Idempotency-Key`, and `expected_version` plus `body`. For an anchored comment,
add every field in the table above with the prefix `anchor_`; for example,
`anchor_pull_request_version`, `anchor_source_ref_hex` and `anchor_byte_start`.
The decoded form values are strings; decimal values must be canonical, without
signs or leading zeros. The authenticated credential selects the actor.
Principal, approval, edit, status and profile overrides are rejected, as are
unknown, duplicate or incomplete anchor fields.

For the same inspected nine-byte line used in the CLI example, with `BASE_URL`
including the configured repository route:

```sh
curl "$BASE_URL/api/v1/pulls/7/comments" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Idempotency-Key: pr-7-source-comment-http-1' \
  --data-urlencode "expected_version=$DISCUSSION_VERSION" \
  --data-urlencode body@./comment.md \
  --data-urlencode "anchor_pull_request_version=$PR_VERSION" \
  --data-urlencode "anchor_source_ref_hex=$SOURCE_REF_HEX" \
  --data-urlencode "anchor_target_ref_hex=$TARGET_REF_HEX" \
  --data-urlencode "anchor_source_tip=$SOURCE_TIP" \
  --data-urlencode "anchor_target_tip=$TARGET_TIP" \
  --data-urlencode "anchor_compared_base=$TARGET_TIP" \
  --data-urlencode anchor_comparison=direct \
  --data-urlencode anchor_path_hex=7372632f6c69622e7273 \
  --data-urlencode anchor_side=after \
  --data-urlencode "anchor_blob=$BLOB" \
  --data-urlencode anchor_mode=100644 \
  --data-urlencode anchor_byte_start=0 --data-urlencode anchor_byte_end=9 \
  --data-urlencode anchor_line_start=0 --data-urlencode anchor_line_count=1
```

The recorded [PR diff HTTP route](PULL_REQUEST_DIFF_HTTP.md) provides source
coordinates under its own conjunctive source-read and PR-read grants.
Comment-write permission does not grant that source read.

The service returns the canonical committed/refused receipt, including
`comment_version` on commit and the supplied anchor when present. Receipts do
not include `anchor_status`: publication does not perform a later state read
that could obscure a completed outcome.

A GET accepts `after`, `limit` (1–100), `expected_head`, and the existing
`render=html_safe` presentation option. It rejects request bodies and
idempotency keys. Reply type `pull_request_comments` binds the tenant,
repository, incarnation, object format, PR number, exact `source_head`, and
round-trippable `snapshot_token`. HTTP numeric fields retain the existing
integer-preserving JSON contract; clients must reject unsafe coercion.

Both PR references and both references of every anchor in the selected conversation
must pass the caller's and current canonical hidden-ref policy before any comment
body, actor, anchor or count is returned, including for historical snapshots.
One undisclosed anchor hides the whole conversation rather than leaving a
version gap or leaking the count. An absent/hidden native PR is HTTP 404 with
null subject coordinates. An existing empty conversation is HTTP 200 with
version 0.

The request's native deadline starts before form intake. Existing framing and
wire limits apply; decoded comments retain the 64 KiB bound. HTTP output is
bounded to 1 MiB, including optional rendering. A response that would exceed
the limit fails as a whole; request a smaller page instead of accepting a
silently truncated timeline.

## MCP

The ordinary operator-sponsored MCP profile exposes:

| Tool | Required independent launch grant | Input |
|---|---|---|
| `frankengit_pull_comments` | `--allow-pulls` | `number`, optional `after`, `limit`, `expected_head` |
| `frankengit_pull_comment` | `--allow-pull-writes` | `number`, `expected_version`, `idempotency_key`, `body`, optional complete `anchor` |

Writes also require the existing launch-bound `--principal` and exact
`--expected-incarnation`. Clients cannot select a different author in tool
arguments. Reads do not require or imply write access. Original-key outcome
lookup remains independently granted through `--allow-outcomes`.

MCP numbers and versions are canonical unsigned decimal strings. Read page
limits are integer values 1–20, default 5. Appended bodies use the existing
MCP text ceiling of 16 KiB; previously published larger native comments can be
read subject to the protocol's response budget. Text is returned as data, not
an instruction or HTML authority.

```json
{
  "number": "7",
  "expected_version": "0",
  "idempotency_key": "pr-7-comment-1",
  "body": "Could we cover the cancellation path before merging?"
}
```

For a source comment, include a nested `anchor` object with all 15 fields from
the source-anchor table. The following is a SHA-1 wire-shape example; replace
the illustrative OIDs and coordinates with the exact inspected PR selection:

```json
{
  "number": "7",
  "expected_version": "0",
  "idempotency_key": "pr-7-source-comment-mcp-1",
  "body": "Could we cover the cancellation path on this line?",
  "anchor": {
    "pull_request_version": "2",
    "source_ref_hex": "726566732f68656164732f746f706963",
    "target_ref_hex": "726566732f68656164732f6d61696e",
    "source_tip": "1111111111111111111111111111111111111111",
    "target_tip": "2222222222222222222222222222222222222222",
    "compared_base": "2222222222222222222222222222222222222222",
    "comparison": "direct",
    "path_hex": "7372632f6c69622e7273",
    "side": "after",
    "blob": "3333333333333333333333333333333333333333",
    "mode": "100644",
    "byte_start": "0",
    "byte_end": "9",
    "line_start": "0",
    "line_count": "1"
  }
}
```

All anchor values are strings, including decimal coordinates and octal mode.
The optional field must be omitted for a plain comment; `anchor: null`, an
empty object, additional properties and a `profile` field are invalid.
The running tool's discovery schema lists the complete required nested fields
with `additionalProperties: false`. Anchored read rows return `anchor_status`;
publication receipts echo only the original anchor.

## Browser conversation

Open the repository's `/ui/pulls/` page, connect an explicitly scoped token,
and select a native PR. **Load latest conversation** reads a fresh conversation
snapshot independently of the selected PR metadata and review snapshot. Each
continuation keeps that conversation's exact head, discussion version, and page
size. Choose 1, 5, or 20 comments per page; a smaller page lets long comments fit
the HTTP response budget without silently truncating bodies.

The page displays each comment's version, authenticated author, and literal
body, with the existing source-bound safe Markdown presentation when available.
Missing or undisclosed conversations cannot be mistaken for an available empty
stream. A malformed or stale page clears the old conversation and writable
version, while preserving the unsent draft for an explicit reload. Credential
rejection or disconnect clears private views and drafts.

**Prepare comment** saves the original body and the loaded conversation version
locally. It does not publish. The existing explicit confirmation and send controls
submit that saved request; later form edits cannot change it. An uncertain result
retains the original request and key for retry, receipt export, and outcome
recovery. Terminal comment outcomes preserve independently inspected candidates,
PR metadata, and displayed review evidence. Reload the conversation explicitly to
observe the result. Open, closed, and merged native PRs use the same discussion
flow, subject to the server's independent read and write grants.

## Retry, history, and delivery

Retry an uncertain append using the **identical principal, original key, PR
number, expected discussion version, body bytes, and every optional anchor
coordinate**. Preserve whether an anchor was present. Do not increment either
version, refresh the PR tips, replace the key, trim the body or reread a modified
file to recover an old request. The native node resolves and revalidates a known
immutable terminal result before applying fresh-publication intake, quota or
source-basis checks. The original command can recover its committed outcome
after PR metadata changes or restart; a new command with the stale anchor must
be refused. A changed body or anchor cannot claim the old outcome by reusing
its key.

An append is one canonical event plus its delivery obligation. Delivery is
at least once unless the destination supplies stronger semantics; a receipt's
`delivery_acknowledged: null` does not claim a webhook was delivered.
Webhook subscription selector `pull_request_commented` admits both ordinary
kind-12 and anchored kind-15 comments. Exact selectors `kind:12` and `kind:15`
admit only their respective encoding. A review-only or PR-lifecycle-only
subscription does not receive anchored comments. A mixed committed batch
requires a family selector or a selection containing both exact kinds; filtering
out one event while retaining the original batch root is refused.

The canonical event remains in authenticated historical batches and raw
`fg events` output. `fg at` selects the correct historical forge-position root
but its compatibility summary does not render conversation bodies. Use a
pinned comments read for conversation text. The narrowly scoped issue/PR
event-feed API does not silently add this new family to existing grants.

## Canonical representation and compatibility

`AggregateId::PullRequestConversation(number)` uses the aggregate zero escape,
kind 8, and positive PR number; its position label is `conversation/N`.
`ForgeEventPayload::PullRequestCommentedNative` uses event kind 12 when
`anchor: None` and binds the exact 16-byte actor plus literal UTF-8 body.
Its complete existing encoding, event root and plain-command retry identity
remain unchanged: there is no added option marker or profile field. An anchored
comment uses required event kind 15 and appends the exact typed source anchor
after that actor and body. The fixed profile is implied by kind 15 and appears
as an output description, never as caller-selected input.

The aggregate's positive version identifies each append in the same
conversation. Its reference/transaction normal-form marker uses tag 9, binds
the conversation entity, and requests no reference effect.

Existing aggregate/event encodings are unchanged. Readers that do not support
the new required tags refuse the new records; they never reinterpret comments
as metadata or approvals. There is no second mutable comment store or side
publication step. Current canonical outbox/history capacity limits still
apply; this feature does not claim to remove those broader limits.

## Verification scope

Conversation regression suites cover codec/stream and reference transitions,
admission history/gaps/corruption, persisted restart, visibility, HTTP, CLI/MCP
grants, immutable retry and browser presentation. Source-anchor additions cover
kind-12 byte compatibility, kind-15 round trips, both native hash domains, exact
line and blob validation, malformed coordinates, work bounds, hidden historical
anchors, exact/outdated snapshot behavior and original-key recovery after
metadata changes. Webhook selector tests exercise both kinds and whole-batch
refusal. Browser tests use controlled HTTP responses and do not establish
execution of the Rust server.

Source formatting and review do not replace native gates. The source-anchor
node/CLI campaigns were added without executing native builds or tests in this
editing session; unchanged Asupersync compilation had exceeded the shared
runner's memory budget. Revision-bound execution evidence remains required, and
the broader PR-workflow bead remains open.
