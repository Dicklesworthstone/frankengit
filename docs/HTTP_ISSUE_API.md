# Native issue HTTP API

This is the bounded, opt-in issue API served by `fg serve-http`. It composes the
existing durable issue commands and head-pinned issue/history readers. It does
not add an issue database, separate publication point, or another async runtime.
The source of accepted state remains the authenticated repository authority head
and its immutable forge/outbox history.

This document describes implementation interfaces, not a passing build, completed
FG-048 acceptance campaign, or production security certification. The API is not
the complete REST/OpenAPI or GitHub-compatibility surface.

## Enable the endpoint deliberately

Use an existing repository and operator-controlled credential file:

```sh
fg serve-http "$STORAGE" "$TENANT" "$REPOSITORY" 127.0.0.1:8080 \
  --trusted-local --credentials-file /secure/http-grants --allow-issues
```

Git pushes remain disabled unless `--allow-receive` is separately supplied.
Existing static-token and Git-only node APIs do not enable issue endpoints.
`--allow-issues` is rejected with `--token-file`: old tokens must not gain new
metadata authority implicitly.

Generate the exact repository-incarnation header without opening a listener:

```sh
fg serve-http "$STORAGE" "$TENANT" "$REPOSITORY" 127.0.0.1:0 \
  --trusted-local --print-credentials-header
```

The credential file starts with that header. Each following row is:

```text
<sha256-of-ASCII-bearer-token> <principal-id> <comma-separated-scopes>
```

Bearer tokens contain exactly 64 lowercase hexadecimal characters. Store the
SHA-256 of those **64 ASCII characters**, not the hash of their decoded 32 bytes.
The file contains digests, not plaintext bearer secrets. Files must be stable,
private regular files on Unix (0600 or stricter), not symlinks. Store credentials
outside repository content and never commit them or put them in URLs.

On Unix, the server opens credential files without following final-component
symlinks or waiting for a FIFO writer, then validates the opened descriptor's
type, permissions, size and identity. This also applies if the file is replaced
after its initial metadata check. The startup-only `--token-file` reader uses
the same protections. Parent directories remain operator-owned; this is not
filesystem containment or a deadline guarantee for an unavailable filesystem.
Atomic replacement leaves an already opened request snapshot intact, while
subsequent requests select the replacement file.

Scope names, when combined, appear once in this order:

```text
read,receive,issues-read,issues-write,outcomes-read
```

`read` means Git fetch, and `receive` means Git push. Neither grants issue access.
`issues-read` permits repository-wide issue lists and histories. `issues-write`
permits repository-wide issue mutation, including comments and lock/unlock. Write does not imply
read. A token with only issue scopes has no Git permission. Every endpoint also
requires the deployment's explicit `--allow-issues` ceiling. `outcomes-read` is
independent read-only transaction recovery, documented in [HTTP_OUTCOME_API.md](HTTP_OUTCOME_API.md).

The file is bounded to 256 grants / 64 KiB and bound to one tenant, repository,
and incarnation. Replace it atomically to rotate or revoke grants. Each new
request reloads it; unavailable, malformed, duplicate, or foreign-incarnation
configuration fails closed. A valid header without rows revokes every token.
Already authenticated in-flight requests retain their bounded grants.

For per-token code-reference write ceilings, the optional
[`frankengit-http-credentials-v2` format](HTTP_REF_WRITE_SCOPES.md) adds an explicit
exact-ref or slash-prefix field to each row. It covers Git and native source/merge
publication while keeping read and metadata grants independent. Existing v1 files
retain their current behavior.

The listener is loopback-only and does not terminate TLS. This profile is not an
account service, organization/team IAM, per-issue ACL model, or immediate
revocation of ongoing publication. A separately managed TLS gateway must forward
real bearer credentials; forwarded identity headers never authenticate.

## Requests and outcomes

Use the repository URL reported in the CLI's `smart_http_listening` JSON record
as `REPO_URL`. All requests require `Authorization: Bearer <token>`. No cookie
identity, query-string token, or body-supplied principal is accepted.

Mutation routes are:

```text
POST {REPO_URL}/api/v1/issues/{number}/open
POST {REPO_URL}/api/v1/issues/{number}/edit
POST {REPO_URL}/api/v1/issues/{number}/close
POST {REPO_URL}/api/v1/issues/{number}/reopen
POST {REPO_URL}/api/v1/issues/{number}/lock
POST {REPO_URL}/api/v1/issues/{number}/unlock
POST {REPO_URL}/api/v1/issues/{number}/comment
POST {REPO_URL}/api/v1/issues/{number}/append-comment
POST {REPO_URL}/api/v1/issues/{number}/add-assignees
POST {REPO_URL}/api/v1/issues/{number}/add-labels
POST {REPO_URL}/api/v1/issues/{number}/assign
POST {REPO_URL}/api/v1/issues/{number}/unassign
POST {REPO_URL}/api/v1/issues/{number}/set-milestone
POST {REPO_URL}/api/v1/issues/{number}/clear-milestone
```

The caller supplies a positive issue number; there is no implicit allocator.
Versioned commands never silently refresh their expected predecessor. Bodies use
`application/x-www-form-urlencoded`, optionally with `; charset=utf-8`. UTF-8 is decoded strictly, percent escapes are decoded
once, and `+` denotes a space. Fixed-length and chunked HTTP bodies are accepted;
trailers, incomplete framing, and buffered suffixes are refused before admission.

Every mutation requires an explicit `Idempotency-Key` header. Versioned actions
require the `expected_version` form field: open requires `0` (absent stream),
while edit, comment, close, reopen, lock, unlock, assign, unassign,
set-milestone and clear-milestone require the exact positive
predecessor. The separate `append-comment` action accepts only `body` and rejects
`expected_version`; it binds an immutable comment intent and appends against the
current canonical issue state. Independent appends can all commit while strict
edits or strict comments still refuse a stale predecessor.
The separate `add-assignees` action also rejects `expected_version`: it unions
the supplied principal IDs with assignments at the selected current predecessor.
Concurrent additions can all commit when the resulting set fits the existing
16-principal bound. This uses the same `issues-write` credential grant.

| Action | Additional form fields |
|---|---|
| `open` | Required `title` and `body`; optional repeated `label`. An empty opening body is explicit. |
| `edit` | At least one of `title`, `body`, repeated `label`, or `clear_labels=true`. Omitted fields are preserved. `body=` clears a body. |
| `comment` | Required nonblank `body`, with the exact `expected_version`. |
| `append-comment` | Required nonblank `body` only; `expected_version` is forbidden. |
| `add-assignees` | 1–16 distinct repeated `assignee` IDs; `expected_version` is forbidden. |
| `add-labels` | 1–32 distinct repeated `label` values; `expected_version` and `clear_labels` are forbidden. |
| `close`, `reopen`, `lock`, `unlock` | No fields besides `expected_version`. |
| `assign`, `unassign` | Required repeated `assignee`: 1–16 distinct 32-character lowercase hexadecimal principal IDs. |
| `set-milestone` | Required positive `milestone` and `expected_milestone_version`, in addition to the issue's exact `expected_version`. |
| `clear-milestone` | No fields besides the issue's exact `expected_version`. |

Milestone membership checks the selected open milestone at the same publication
basis as the issue. Milestone lifecycle routes, same-snapshot progress counts and
history use the existing independent issue grants. See
[native milestones](NATIVE_MILESTONES.md#authenticated-http-and-mcp) for the full
route and command contract. Closing a milestone preserves its members; clearing
membership remains available afterward and does not change issue lock/state.

Assignment adds or removes only the named principals, preserving all other
assignees. The resulting set is bounded to 16. Input IDs are sorted before
sealing, with duplicates rejected. Membership changes are idempotent, but each
accepted action still advances the exact issue version. Both open and closed
issues accept assignment deltas. These IDs are metadata, not an authentication
mechanism, account-existence assertion, access grant or notification endpoint.
`issues-write` remains required; naming an `issues-read` principal never widens
that principal's credentials. The wire and upgrade contract is
[normative §20.2](NORMATIVE_PROTOCOL_CONTRACTS.md#202-native-issue-assignment-deltas).

`POST .../issues/{number}/add-assignees` accepts the same repeated `assignee`
fields as `assign`. Its receipt has `action: "add-assignees"` and
`expected_version: null`; canonical history retains the versioned `assign`
event. An exact retry returns its original outcome, even after later assignment
removal, and never adds the removed principal again. A changed set or switching
between `assign` and `add-assignees` requires a new intent/key. The complete
[addition contract](NORMATIVE_PROTOCOL_CONTRACTS.md#2025-native-issue-assignee-addition-intents)
preserves the existing exact-version commands and request identities.

`POST .../issues/{number}/add-labels` unions the supplied labels with the current
set under the same `issues-write` grant. Each label is nonblank, at most 64 UTF-8
bytes, and contains no control characters; the complete union must fit 32 labels.
Its receipt identifies `action: "add-labels"`, `expected_version: null` and
`command_profile: "issue.add-labels.v1"`. Canonical history records the original
`{"name":"add-labels","labels":["bug"]}` delta. An identical original-key retry
recovers its terminal result without re-adding labels removed by a later edit.
`edit` with repeated `label` still replaces the whole set at an exact version;
`clear_labels=true` still clears it. See [native label additions](NATIVE_ISSUE_LABELS.md).

```sh
curl --fail-with-body --header @/secure/issue-writer.headers \
  --header 'Idempotency-Key: issue-41-labels-attempt-1' \
  --data-urlencode 'label=bug' --data-urlencode 'label=transport' \
  "$REPO_URL/api/v1/issues/41/add-labels"
```

Lock/unlock uses the same `issues-write` grant and explicit idempotency header.
It applies independently to open and closed issues. While locked, both strict
`comment` and `append-comment` refuse new publication; edits, assignments,
close and reopen preserve the lock and remain available. Repeating a lock state
with a new key and current version refuses `ProtectedRefTransitionDenied`;
a stale exact version refuses `EvidenceStale`. The server never refreshes it.
An identical original-key retry recovers its original terminal decision even
after the lock changes. In particular, unlocking cannot turn a previously
refused comment into success under the same key.

Repeated labels are sorted into the canonical set; duplicate labels are rejected.
`clear_labels=true` cannot be combined with labels. Unknown fields, duplicate
scalar fields, invalid UTF-8, NUL, and inapplicable fields are rejected instead of
ignored. Existing title/body/label validation remains owned by `fgit-forge`.

Example opening command (keep shell history and process visibility in mind when
handling bearer credentials; a private curl header file avoids literal secrets
in the command line):

```sh
curl --fail-with-body --header @/secure/issue-writer.headers \
  --header 'Idempotency-Key: issue-41-open-attempt-1' \
  --data-urlencode 'expected_version=0' \
  --data-urlencode 'title=Review the transport integration' \
  --data-urlencode 'body=Exercise a complete HTTP round trip.' \
  --data-urlencode 'label=transport' \
  "$REPO_URL/api/v1/issues/41/open"
```

The private header file contains `Authorization: Bearer ...` and is not the
server's hashed grant file. Curl selects the URL-encoded content type when
`--data-urlencode` is used. Inspect the JSON response even when the HTTP status
is non-successful.

For an additive comment, preserve the body and key without choosing a version:

```sh
curl --fail-with-body --header @/secure/issue-writer.headers \
  --header 'Idempotency-Key: issue-41-comment-attempt-1' \
  --data-urlencode 'body=The transport round trip succeeded.' \
  "$REPO_URL/api/v1/issues/41/append-comment"
```

Append receipts carry `action: "append-comment"` and `expected_version: null`.
Canonical history still records ordinary versioned `comment` events, so existing
history readers need no new event kind. An absent issue is a canonical refusal;
append does not create it. Changing the body or switching between `comment` and
`append-comment` under an existing key is an idempotency conflict. This profile
uses the same principal, issue-write scope, policy, quota and recovery boundary
as versioned commands.

A committed operation returns HTTP 200 and `type: "issue_publication"`, with
`outcome: "committed"`, the canonical `tx_id`, decision sequence, and repository
commit ID. A canonical refusal returns HTTP 409 with the same receipt type and
`outcome: "refused"`, its refusal code and refusal-record ID. Issue events and
outbox obligations use the existing canonical publication; a receipt's
`delivery_acknowledged: null` does not claim an external notification was sent.

A pre-decision idempotency conflict also returns HTTP 409, but its type is
`issue_error` and its code is `idempotency_key_reuse`. It does not fabricate a new
canonical refusal. Syntax errors are 400; missing credentials are 401;
insufficient scope/disabled service is 403; resource ceilings are 413; unsupported
media types are 415; throttling is 429. Infrastructure failures return 503.

**Retry the identical action, body and key after a lost reply; retain the exact
expected version for versioned actions.**
Do not refresh the expected version or replace the key while resolving an
ambiguous attempt. A token rotation for the same principal preserves identity;
a different principal is a different caller. The API returns the existing
terminal outcome on an identical retry. Mutation errors with
`outcome_unknown: true`, disconnects, timeouts, and cleanup errors never prove
non-commit. Once a terminal response has started, the gateway never appends a
second HTTP response.

## Read state and exact comment/action history

```text
GET {REPO_URL}/api/v1/issues?limit=50
GET {REPO_URL}/api/v1/issues/{number}?limit=50
```

List responses are `issue_page` JSON with ordered issue snapshots and an optional
`next_after`. Individual reads are `issue_history` JSON with the issue snapshot
at the selected head and versioned action/comment events, plus optional
`next_after_version`. A missing issue returns HTTP 404 with `found: false`, not
an empty fabricated issue. An issue created after a pinned head remains absent
when read through that earlier token.

Each issue snapshot includes a sorted `assignees` array of canonical principal
IDs, empty for unassigned or historical pre-assignment state. Assignment history
actions are `{"name":"assign","assignees":["<principal-id>"]}` or
`{"name":"unassign","assignees":["<principal-id>"]}`. They retain the original
delta rather than replacing it with the current assignment set.
Snapshots also contain boolean `locked`, including `false` for histories with
no lock action. Lock history actions are `{"name":"lock"}` and
`{"name":"unlock"}` with no content payload. The current lock belongs to the
selected snapshot, independently of the last event on a partial history page.

Every page includes an algorithm-qualified `snapshot_token` and the exact
`source_head`. Continue using that token and the returned cursor:

```sh
curl --get --header @/secure/issue-reader.headers \
  --data-urlencode 'limit=50' \
  --data-urlencode "after_version=$NEXT_VERSION" \
  --data-urlencode "expected_head=$SNAPSHOT_TOKEN" \
  "$REPO_URL/api/v1/issues/41"
```

For list continuation use `after`, not `after_version`. A nonzero cursor without
a token is rejected. Without a token, a first page selects the authenticated
current head. With a token, the reader selects that exact retained ancestor.
Ordinary intervening publications, including unrelated issues, comments, edits,
ref updates, and canonical refusals, no longer force the walk to restart.
The response still names the original head: newer issues do not enter the list,
and later comments or edits do not change the pinned history or its issue state.
An identical retained page can be read after the listener or node restarts.

### Retained snapshot bounds and authorization

A snapshot token is not a credential or a mutable cursor session. Every HTTP
request still authenticates current credential grants before reading metadata.
Revoked credentials cannot reuse old tokens; a rotated credential for the same
principal with the required read grant can continue normally.

The node starts from its current authenticated materialization and follows only
its committed predecessor chain, verifying every transition with the existing
chronicle verifier. It never directly trusts a client-named stored head. The
bounded profile permits at most 256 ancestor transitions and 65,536 traversed
decisions, within one repository/configuration/policy/registry/checkpoint epoch.
It refuses to cross compaction-generation links. The selected immutable forge
and outbox roots still pass their existing commitment and replay checks.

An unknown token, exceeded ancestry window, or unsupported epoch boundary
returns HTTP 409 with `code: "snapshot_moved"`; no different head is silently
substituted. Required evidence that is missing, corrupt, unavailable, or cancelled
remains an error, not a fabricated empty page. This profile creates no retention
lease and promises no indefinite availability of historical bodies. Restart a
walk explicitly when its old snapshot is unavailable.

The same retained-basis selector serves the local node PR-list and review-page
APIs. PRs and reviews continue to apply CURRENT canonical hidden-ref policy and
caller visibility before disclosure. Review freshness uses the historical ref
root matching the selected page, never a current ref map mixed into an old PR
view. Such a displayed historical approval is not merge authority: merge
admission still checks current votes, branch tips, and policy at its CAS.
This does not add HTTP PR/review endpoints or change mutation preconditions.

Issue text is JSON data. Control and bidi-formatting characters are escaped
without changing their decoded content. No returned text is executable HTML,
an authorization instruction, or a principal override.

### Derived Markdown rendering

Issue reads (`GET /api/v1/issues` and `GET /api/v1/issues/<number>`) accept
`render=html_safe`. The response is unchanged except that every
Markdown-bearing body (the issue snapshot's `body`, and each `open`, `edit`
and `comment` action's `body`) gains a sibling `body_rendered` object:

```json
{"renderer":"fgit-doc","profile":"html_safe",
 "parse_profile_sha256":"<64 hex>","source_sha256":"<64 hex>","html":"..."}
```

- The raw `body` stays canonical and is returned byte-for-byte; the rendering
  is a derived artifact keyed by `(source_sha256, parse_profile_sha256)`, so a
  renderer profile bump changes the key.
- `fgit-doc`'s `html_safe` profile escapes raw markup instead of passing it
  through and neutralises disallowed link schemes (`javascript:`, `data:` and
  similar). Neutralised parts stay visible, marked with
  `data-fgit-doc-rejected`. Links carry `rel="nofollow noopener noreferrer"`.
- Rendering is a pure function of the source bytes and the profile, so the
  same body renders byte-identically on every request.
- A renderer ceiling returns `"html":null` with a typed `refusal` tag. It never
  fails the canonical read.
- Any other `render` value is refused with HTTP 400 `unsupported_rendering`.
  Search responses are not rendered.

The rendering inherits the read's snapshot pin, authorization and paging.
It is not yet exposed through MCP or the browser shell.

## Bounds and verification entry points

Headers use the shared Git HTTP envelope parser. Forms have a separate 256 KiB
encoded ceiling, a 64 KiB per-value decoded ceiling, and bounded field/chunk
counts. Native issue limits include 256-byte titles, 64 KiB bodies, and 32 labels
of at most 64 bytes each. Pages contain 1–100 records, with a response ceiling of
48 MiB further narrowed by the server's configured response envelope. The existing
canonical issue reader also retains its replay/work bounds. Exceeding those
bounds returns an error, not a silently partial successful page.

```sh
cargo test -p fgit-wire --lib smart_http
cargo test -p fgit-node --lib treefs_workspace::issues
cargo test -p fgit-node --lib treefs_workspace::pull_request
cargo test -p fgit-node --lib smart_http::server
cargo test -p fgit-cli --bin fg smart_http_server::tests
cargo test -p fgit-node --test issue_http --test issue_http_race
```

The tests exercise actual node admission, TCP serving, exact-version conflicts,
retries, credential scope separation and rotation, bounded framing, retained
pagination through intervening publications, and reopened authority state.
Review tests distinguish retained display evidence from current merge admission.
Their presence is not a claim they have passed at a particular revision; record
actual execution separately.
