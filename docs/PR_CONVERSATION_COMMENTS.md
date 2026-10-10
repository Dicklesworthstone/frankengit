# Canonical pull-request conversations

An existing native PR has an independent, append-only conversation. Comments
are canonical forge events published with their outbox obligations through the
same exact-predecessor authority-head CAS as other metadata. They are available
on open, closed, and merged native PRs. Commenting changes neither the PR's
metadata version nor its review streams, branch tips, or policy epoch.

This implements the conversation-comment part of
`frankengit-root-doctrine-x2mv.4.20`. Line anchors, editing, deletion, PR labels,
quorum, and changed approval-survival rules are separate unfinished features.
Legacy-only and merge-only records without native PR metadata do not acquire a
fabricated conversation subject.

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

## HTTP

Enable the existing PR HTTP profile. Reloadable repository credentials grant
`pull-read` and `pull-write` independently; comment appends require the latter.
The configured repository route and explicit Bearer token are checked before
body intake. A write grant does not imply reads, Git access, reviews, merges,
or outcome lookup. Existing cross-site request rejection and service ceilings
also apply.

```text
GET  /<repository-route>/api/v1/pulls/7/comments?limit=20
POST /<repository-route>/api/v1/pulls/7/comments
```

A POST requires `Content-Type: application/x-www-form-urlencoded`, a stable
`Idempotency-Key`, and exactly `expected_version` plus `body` form fields. The
authenticated credential selects the actor; no principal, branch, PR version,
approval, edit, or line-anchor field is accepted. The service returns the
canonical committed/refused receipt, including `comment_version` on commit,
without a later state read that could obscure a completed publication.

A GET accepts `after`, `limit` (1–100), `expected_head`, and the existing
`render=html_safe` presentation option. It rejects request bodies and
idempotency keys. Reply type `pull_request_comments` binds the tenant,
repository, incarnation, object format, PR number, exact `source_head`, and
round-trippable `snapshot_token`. HTTP numeric fields retain the existing
integer-preserving JSON contract; clients must reject unsafe coercion.

Both PR references must pass the caller's and current canonical hidden-ref
policy before any comment body, actor, or count is returned, including for
historical snapshots. An absent/hidden native PR is HTTP 404 with null subject
coordinates. An existing empty conversation is HTTP 200 with version 0.

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
| `frankengit_pull_comment` | `--allow-pull-writes` | `number`, `expected_version`, `idempotency_key`, `body` |

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
number, expected discussion version, and body bytes**. Do not increment the
version, replace the key, trim the body, or reread a modified file to recover an
old request. The native node resolves and revalidates a known immutable terminal
result before applying fresh-publication intake or quota gates. A changed
command cannot claim the old outcome by reusing its key.

An append is one canonical event plus its delivery obligation. Delivery is
at least once unless the destination supplies stronger semantics; a receipt's
`delivery_acknowledged: null` does not claim a webhook was delivered.
Webhook subscription selectors recognize `pull_request_commented` and the
exact `kind:12`. A review-only subscription does not receive comment bodies.

The canonical event remains in authenticated historical batches and raw
`fg events` output. `fg at` selects the correct historical forge-position root
but its compatibility summary does not render conversation bodies. Use a
pinned comments read for conversation text. The narrowly scoped issue/PR
event-feed API does not silently add this new family to existing grants.

## Canonical representation and compatibility

`AggregateId::PullRequestConversation(number)` uses the aggregate zero escape,
kind 8, and positive PR number; its position label is `conversation/N`.
`ForgeEventPayload::PullRequestCommentedNative` uses event kind 12 and binds
the exact 16-byte actor plus literal UTF-8 body. The aggregate's positive
version identifies each append. Its reference/transaction normal-form marker
uses tag 9, binds the conversation entity, and requests no reference effect.

Existing aggregate/event encodings are unchanged. Readers that do not support
the new required tags refuse the new records; they never reinterpret comments
as metadata or approvals. There is no second mutable comment store or side
publication step. Current canonical outbox/history capacity limits still
apply; this feature does not claim to remove those broader limits.

## Verification scope

The change includes codec/stream and reference-transition regressions,
admission history/gap/corruption tests, persisted-node restart and hidden-ref
tests, HTTP parser/output and real TCP campaigns, and CLI/MCP input,
independent-grant, exact-retry, and persisted-node tests. Each tests the
actual owning layer; a parser or protocol fixture is not native execution
evidence.

The pinned reference library suite passed all 61 tests on the canonical-comment
commit. The browser PR/transport suite passed all 309 tests, including the new
conversation client and real-template view regressions. Those browser tests use
controlled HTTP responses; they do not establish execution of the Rust server.

Full node/CLI compilation and native campaigns remain unexecuted in this
editing environment: unchanged Asupersync compilation exceeded the shared
runner's memory budget in the preceding session. Formatting and source review
do not replace those gates. The broader PR-workflow bead remains open.
