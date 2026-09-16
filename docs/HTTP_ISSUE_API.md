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

Scope names, when combined, appear once in this order:

```text
read,receive,issues-read,issues-write,outcomes-read
```

`read` means Git fetch, and `receive` means Git push. Neither grants issue access.
`issues-read` permits repository-wide issue lists and histories. `issues-write`
permits repository-wide issue mutation, including comments. Write does not imply
read. A token with only issue scopes has no Git permission. Every endpoint also
requires the deployment's explicit `--allow-issues` ceiling. `outcomes-read` is
independent read-only transaction recovery, documented in [HTTP_OUTCOME_API.md](HTTP_OUTCOME_API.md).

The file is bounded to 256 grants / 64 KiB and bound to one tenant, repository,
and incarnation. Replace it atomically to rotate or revoke grants. Each new
request reloads it; unavailable, malformed, duplicate, or foreign-incarnation
configuration fails closed. A valid header without rows revokes every token.
Already authenticated in-flight requests retain their bounded grants.

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
POST {REPO_URL}/api/v1/issues/{number}/comment
```

The caller supplies a positive issue number. There is no implicit allocator or
latest-version refresh. Bodies use `application/x-www-form-urlencoded`, optionally
with `; charset=utf-8`. UTF-8 is decoded strictly, percent escapes are decoded
once, and `+` denotes a space. Fixed-length and chunked HTTP bodies are accepted;
trailers, incomplete framing, and buffered suffixes are refused before admission.

Every mutation requires an explicit `Idempotency-Key` header and
`expected_version` form field. Open requires version `0` (absent stream); all
other actions require the exact positive predecessor version.

| Action | Additional form fields |
|---|---|
| `open` | Required `title` and `body`; optional repeated `label`. An empty opening body is explicit. |
| `edit` | At least one of `title`, `body`, repeated `label`, or `clear_labels=true`. Omitted fields are preserved. `body=` clears a body. |
| `comment` | Required nonblank `body`. |
| `close`, `reopen` | No fields besides `expected_version`. |

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

**Retry the identical command, expected version, and key after a lost reply.**
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
