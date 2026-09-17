# Native pull-request HTTP API

The bounded repository gateway exposes same-repository native pull requests
through `fg serve-http`. It composes the existing durable node PR admission and
retained metadata readers. It does not introduce a PR database, a second
publication point, or another runtime. PR events and their outbox obligations
are admitted together by the existing sealed transaction and authority-head CAS.
These metadata commands do not move Git refs or import candidate objects.

This describes implementation interfaces, not a passing build, live-client
acceptance result, completed FG-048 REST/OpenAPI surface, or production security
certification. The settled fastapi_rust/schema/projection integration remains a
separate product boundary; this is the existing bounded loopback gateway profile.

## Explicit opt-in and independent permissions

```sh
fg serve-http "$STORAGE" "$TENANT" "$REPOSITORY" 127.0.0.1:8080 \
  --trusted-local --credentials-file /secure/http-grants --allow-pulls
```

This requires an existing repository. It does not enable Git pushes, issue
endpoints, or outcome recovery. Those retain their separate switches. Use
`--allow-outcomes` as well to make read-only lost-response recovery available.
The `smart_http_listening` record includes `pulls_enabled` and the repository URL.

`--allow-pulls` requires a reloadable credential file, not a static token file.
Existing static tokens and old Git/issue/outcome serving entry points leave PR
access disabled. The new node entry point is
`OneNode::serve_repository_http_with_pull_requests_bounded`.

Credential provisioning is unchanged: `--print-credentials-header` reads the
existing repository's exact tenant/repository/incarnation binding without opening
a listener. Every following row contains the SHA-256 of the 64 ASCII characters
of a lowercase-hex bearer token, a principal ID, and explicit scopes. It does
not contain a plaintext bearer secret. Combined scopes appear once in this order:

```text
read,receive,issues-read,issues-write,outcomes-read,pulls-read,pulls-write
```

`pulls-read` permits PR list and individual reads. `pulls-write` permits open,
update and close. Write does not imply read. Neither PR scope grants Git fetch,
Git push, issue access, recovery, reviews, or merge publication. Conversely, no
existing scope implicitly grants PR access. The deployment ceiling and the
credential's grant must both permit an operation.

The private regular credential file is bound to the exact repository incarnation
and reloaded for every authentication. Rotation with the same principal retains
retry identity. Removing a token revokes subsequent authentications; already
authenticated bounded requests retain their grant. This is operator-managed,
repository-wide PR access, not organization/team IAM or per-PR/author ACLs.
In particular, a PR writer can update or close another author's PR when its
explicit preconditions and repository policy permit it. Forwarded identity,
query parameters, and PR text never supply an authenticated principal.

The listener is loopback-only and does not terminate TLS. A separately managed
TLS gateway must forward real credentials, not convert arbitrary forwarded-user
headers into authority. Keep credentials outside repository content and URLs.

## Routes and exact mutation commands

Use the repository URL from the readiness record as `REPO_URL`. All requests
require `Authorization: Bearer <token>`.

```text
GET  {REPO_URL}/api/v1/pulls
GET  {REPO_URL}/api/v1/pulls/{number}
POST {REPO_URL}/api/v1/pulls/{number}/open
POST {REPO_URL}/api/v1/pulls/{number}/update
POST {REPO_URL}/api/v1/pulls/{number}/close
```

The number is a caller-selected positive canonical decimal. This API does not
allocate numbers, create cross-repository/fork PRs, reopen closed PRs, submit
reviews, prepare merge candidates, or merge code. Unsupported actions are refused;
there is no fallback that turns a metadata command into a ref update.

Every POST requires an explicit `Idempotency-Key` header and a complete
`application/x-www-form-urlencoded` body, optionally declaring `charset=utf-8`.
Fixed-length and chunked framing are accepted. The full HTTP body must finish
before admission; trailers, truncation and buffered trailing bytes are refused.
Credentials, service scopes, declared size ceilings and intake quota are checked
before `100 Continue` is sent or the body is read.

Every command contains all eight fields:

| Field | Meaning |
|---|---|
| `expected_version` | `0` for open; exact positive predecessor aggregate version for update/close. |
| `object_format` | Exactly `sha1` or `sha256`, matching the repository. |
| `source_ref` | Full source branch name, such as `refs/heads/topic`. |
| `target_ref` | Full target branch name, such as `refs/heads/main`; distinct from source. |
| `source_tip` | Exact nonzero source commit OID, lowercase hex in the declared hash domain. |
| `target_tip` | Exact nonzero target commit OID in the same domain. |
| `title` | Nonblank title, at most 256 UTF-8 bytes, without control characters. |
| `body` | Explicit body, at most 64 KiB; `body=` is an empty body. |

Open and update compare both submitted tips with the current branches during
admission. A well-formed stale tip becomes the existing canonical ref-precondition
refusal; the gateway does not silently refresh it. The node independently checks
admitted native commit/tree dependencies rather than accepting a caller's object
proof. Canonical hidden-ref policy also applies during admission.

Updates replace the complete PR data and cannot change its branch identities.
Close requires the exact existing data as well as its expected version; it does
not refresh or clear title, body or tips. The core closing path remains possible
after a branch was deleted, subject to its existing evidence/policy checks. No
HTTP command silently reads latest state to fill omitted fields or change a retry.

Example opening command, with the bearer header held in a private file:

```sh
curl --fail-with-body --header @/secure/pr-writer.headers \
  --header 'Idempotency-Key: pr-41-open-attempt-1' \
  --data-urlencode 'expected_version=0' \
  --data-urlencode "object_format=$OBJECT_FORMAT" \
  --data-urlencode 'source_ref=refs/heads/topic' \
  --data-urlencode 'target_ref=refs/heads/main' \
  --data-urlencode "source_tip=$SOURCE_TIP" \
  --data-urlencode "target_tip=$TARGET_TIP" \
  --data-urlencode 'title=Review the transport change' \
  --data-urlencode 'body=Compare these exact branch tips.' \
  "$REPO_URL/api/v1/pulls/41/open"
```

The header file contains `Authorization: Bearer ...`, not the server's digest
table. Form decoding is strict UTF-8 and decodes percent escapes once. Unknown
fields, duplicate fields, NUL, invalid escapes and inapplicable envelopes are
refused, not ignored. Principal IDs, force flags or merge directives in the body
cannot expand this grammar. The encoded form is capped at 256 KiB and eight
fields; field-count overflow is a resource refusal, including excess duplicates.

## Canonical receipts and ambiguous outcomes

A committed command returns HTTP 200 with `type: "pull_request_publication"`.
A canonical refusal returns HTTP 409 with the same type. Receipts include the
repository/incarnation/hash domain, authenticated principal, PR number, expected
version, action, stable `tx_id`, decision sequence, and either repository commit
ID or refusal-record ID and code. `delivery_acknowledged: null` means the receipt
does not claim an external notification was delivered.

A key reused with different semantics returns a `pull_request_error` conflict
with `code: "idempotency_key_reuse"`, not an invented new canonical refusal.
Other request errors retain the existing bounded HTTP vocabulary: authentication
401, permission/disabled endpoint 403, malformed fields 400, resource ceilings
413, unsupported media 415 and throttling 429. Missing PRs return 404. Required
infrastructure/evidence failure returns 503 rather than an empty success.

**After a lost response, preserve the original principal, complete command,
expected version, and key.** An identical retry returns the existing canonical
outcome. Do not refresh tips/version or replace the key while resolving ambiguity.
A disconnect, timeout, `outcome_unknown: true`, or cleanup error never proves
non-commit. Once a final response has started, no second HTTP response is appended.

Read-only recovery is available through the existing independent outcome API:

```text
POST {REPO_URL}/api/v1/outcomes
Authorization: Bearer <token-for-original-principal-with-outcomes-read>
Idempotency-Key: <original-PR-command-key>
Content-Length: 0
```

That lookup needs no PR body, pack, or transaction ID and does not reexecute the
command. It can be granted after PR write access is revoked. Another principal
using the same textual key sees only its own namespace. See
[HTTP_OUTCOME_API.md](HTTP_OUTCOME_API.md) for nonterminal observations and limits.

## Lists, individual reads and retained snapshots

```text
GET {REPO_URL}/api/v1/pulls?limit=50
GET {REPO_URL}/api/v1/pulls?limit=50&after=41&expected_head=TOKEN
GET {REPO_URL}/api/v1/pulls/41?expected_head=TOKEN
```

A list returns `pull_request_page`, ordered numerically, with `next_after` or
null. Each record includes number, aggregate version, open/closed/merged state,
complete PR data, opener and last metadata actor when known. Existing native
merge-only receipts remain explicitly `merge_only: true`; the API does not invent
a title, opener or historical PR lifecycle for them. Reading a merged record does
not grant permission to publish a merge.
PR data and merge records preserve reference bytes in authoritative lowercase
`source_ref_hex` and `target_ref_hex`. The existing `source_ref` and `target_ref`
fields retain UTF-8 text and are null only when those bytes are not UTF-8.

An individual read returns `pull_request` with `found` and `pull_request` fields.
A missing or undisclosed number returns 404 and null, never the next visible PR.
Both branch names must pass current canonical hidden-ref policy. Issue and Git
permissions remain independent from this metadata disclosure.

Each page carries `source_head` and an algorithm-qualified `snapshot_token`.
Retain the first page's token for the entire walk. A nonzero list cursor without
a token is refused. Ordinary later publications do not mix newly created PRs,
edits, or closes into the pinned view. Current credentials and hidden-ref policy
still gate every request; a token is not authorization.

The existing retained-basis selector verifies ancestry from current authenticated
state, bounded to 256 head transitions and 65,536 decisions, without crossing
configuration/policy/registry/checkpoint or compaction boundaries. Unsupported
or unavailable snapshots return 409 `snapshot_moved`, never an automatic switch
to current state. No indefinite retention lease is created. Missing or corrupt
required evidence remains an error. See [HTTP_ISSUE_API.md](HTTP_ISSUE_API.md) for
the shared retained-snapshot boundary.

PR pages contain at most 100 records. Replies are completely built and bounded
before emitting success, capped at 48 MiB and the configured server ceiling.
The existing canonical readers retain their separate replay and work limits.
Text is escaped JSON data, not executable HTML or authorization instructions.
Mutation intake shares the existing per-principal quota and bounded connection
pool; read-only outcome recovery has its separate quota. Every accepted child
is owned and drained by the node's existing Asupersync serving profile.

## Verification entry points

```sh
cargo test -p fgit-node --lib smart_http::server
cargo test -p fgit-node --test pull_request_http --test issue_http --test outcome_http
cargo test -p fgit-cli --bin fg smart_http_server::tests
```

Tests exercise native object import, actual TCP handlers and the embedded
authority, exact-version conflicts, retained pages, authentication/refusal before
body intake, lost responses, restart and recovery after write revocation. Test
presence does not establish a passing execution. Record actual toolchain,
revision and results before making a build, compatibility or deployment claim.
