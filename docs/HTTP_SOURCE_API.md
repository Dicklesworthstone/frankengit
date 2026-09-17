# Repository source browsing and literal search over HTTP

The bounded repository gateway exposes tree listing, file byte ranges and
literal-byte code search through the existing native source readers. A client
can search a repository, open a matching path and continue file/directory reads
with explicit source coordinates, without opening local node storage.

These are read-only operations. They do not import objects, bind retry keys,
seal transactions, move refs, change forge metadata or publish outbox work.
The implementation uses the native TreeFS/object-fabric readers and source
search engine, not a checkout, another Git engine, index or database.

This describes implementation interfaces, not a passing Rust build, completed
compatibility campaign or production release. The full fastapi_rust/OpenAPI,
projection, search-index and browser integration remain separate boundaries.

## Enable source access deliberately

```sh
fg serve-http "$STORAGE" "$TENANT" "$REPOSITORY" 127.0.0.1:8080 \
  --trusted-local --credentials-file /secure/http-grants --allow-source
```

The repository must already exist. The readiness record includes `source_enabled`
and its canonical repository URL. Use that URL as `REPO_URL` below.

The credential must explicitly grant `read`, the existing repository Git-fetch
permission. This is a repository-wide source-read grant, not a path-scoped agent
capability. `receive`, issue, PR, review, merge and outcome grants do not imply
`read`. The source deployment switch does not enable any mutation or another
native API. Other APIs retain their own switches and grants. Static-token and
older node serving entry points leave source endpoints disabled.

Provision the existing private, incarnation-bound credential file using
`--print-credentials-header`. Source access introduces no new scope spelling.
The private file is reloaded for each authentication; token rotation can retain
the same principal, while removal revokes later authentications. Existing
in-flight requests retain their bounded grant. A file that is missing, malformed
or bound to another incarnation does not fall back to cached permissions.

Every request carries `Authorization: Bearer <token>`. Forwarded-user headers,
request paths, OIDs and search text never supply an authenticated identity.
Current canonical hidden-ref rules still apply. These endpoints do not provide
TLS, hosted account management, team IAM or per-path authorization. The listener
remains loopback-only; any nonlocal deployment needs a separately managed secure
gateway that preserves real authentication rather than trusting client headers.

## Common read envelope and source selection

```text
POST {REPO_URL}/api/v1/source/tree
POST {REPO_URL}/api/v1/source/blob
POST {REPO_URL}/api/v1/source/search
```

All three are body-bearing reads, not mutations. POST keeps paths and search
needles out of the URL. Send a complete `application/x-www-form-urlencoded`
body, optionally declaring `charset=utf-8`. Fixed-length and chunked framing
are supported. Query parameters and `Git-Protocol` are not accepted.

Do not send `Idempotency-Key`: the endpoint rejects it rather than pretending
that a read creates a mutation or durable search session. Repeating a query
repeats a read and cannot reexecute a previous publication.

Every request requires:

| Field | Meaning |
|---|---|
| `ref` | Full current repository ref, such as `refs/heads/main`. It must select a native commit. |
| `object_format` | Exactly `sha1` or `sha256`, matching the repository. |
| `expected_head` | Optional exact `snapshot_token` from an earlier source response; required for directory/file continuation. |
| `expected_commit` | Optional nonzero lowercase commit OID in the declared native hash domain. |

An OID is a precondition on the selected ref, not an arbitrary-object lookup.
There is no `object_id` request field. Annotated tags are not silently peeled;
a ref that does not select a commit returns a typed error. Use a commit-valued
branch or lightweight tag under the supported native reader profile.

A successful response includes tenant, repository, incarnation, object format,
ref, exact `source_head`, algorithm-qualified `snapshot_token`, `source_rcr`,
`source_commit`, root-tree OID and explicit read-only/non-publication flags.
Search's snapshot token is taken from the same native materialization that
supplies the scan, not a separate preliminary head read.

**Source pins are strict current-head comparisons, not retained pagination.**
An intervening publication, even an unrelated issue edit, makes an old
`expected_head` fail with HTTP 409 `source_snapshot_moved`. Nothing silently
mixes old and new pages or substitutes the latest head. The same token works
after reopening only while that head is still current. `expected_commit` can
separately require the same ref tip, but does not replace the head requirement
for nonzero cursors. Restart a walk explicitly after a moved-snapshot error.

## Tree listing

Optional fields are `path_hex`, `limit` and `after_hex`. Omit `path_hex` to list
the root; an empty string is not a synthetic root path. `path_hex` names the
exact raw Git path bytes. `after_hex` is one immediate child name, not a full
path. Results are ordered by raw child-name bytes, including directory names.

`limit` defaults to 100 and must be 1 through 1000. A `source_tree` response
contains `object_id`, `path_hex`, `after_hex`, `limit`, `next_after_hex` and an
`entries` array. Each entry has `name_hex`, `object_id` and a native kind:
`file`, `executable`, `directory`, `symlink` or `gitlink`.

```sh
curl --fail-with-body --header @/secure/source-reader.headers \
  --data-urlencode 'object_format=sha256' \
  --data-urlencode 'ref=refs/heads/main' \
  --data-urlencode 'limit=100' \
  "$REPO_URL/api/v1/source/tree"
```

Continue with the returned `next_after_hex` and the original `snapshot_token`
as `expected_head`, retaining the same ref, path and limit. A null next cursor
means that selected directory has no further disclosed entries in this page
walk. It does not assert anything about other directories or hidden refs.

## Byte-exact file reads

`path_hex` is required. `offset` defaults to zero; `limit` defaults to 65,536
bytes and is bounded to 1 through 1,048,576 bytes. A nonzero offset requires
`expected_head`. These are JSON-level byte ranges, not HTTP Range semantics.

A `source_blob` response contains the selected `object_id`, path, kind,
`total_bytes`, `offset`, `returned_bytes`, `next_offset` and `content_hex`.
No UTF-8 decoding, newline conversion, terminal rendering or HTML execution is
performed. Binary files and non-UTF-8 paths retain their exact bytes. At exact
EOF the returned content is empty; an offset beyond EOF is an error.

The following reads `README.md`, whose UTF-8/ASCII path bytes are shown in hex:

```sh
curl --fail-with-body --header @/secure/source-reader.headers \
  --data-urlencode 'object_format=sha256' \
  --data-urlencode 'ref=refs/heads/main' \
  --data-urlencode 'path_hex=524541444d452e6d64' \
  --data-urlencode 'limit=65536' \
  "$REPO_URL/api/v1/source/blob"
```

To continue, supply `offset=NEXT_OFFSET` and the original `expected_head`.
`content_hex` is the returned slice, not necessarily the entire object; native
object identity cannot be checked by hashing one partial slice alone.

Symlink payloads are link-text data, never followed into the repository or host
filesystem. Traversing through a symlink is refused. Gitlinks remain opaque
identities and cannot be read as files. Returned source text is not safe to
insert into HTML or terminals without the consumer's proper data rendering.

## Literal-byte code search

`needle_hex` is required: 1 through 256 bytes with no LF. NUL and non-UTF-8 bytes
are supported. `case` is `exact` by default, or `ascii-insensitive`; this is not
Unicode folding, regex, semantic ranking or an indexed search language.

Repeated `path_prefix_hex` fields narrow the scan by slash-delimited path
components. For example `src` includes `src/file.rs`, not `src2/file.rs`.
At most 128 prefixes and 32 KiB total decoded prefix bytes are accepted.
No prefix means all visible regular files in this selected source tree.
Symlinks and gitlinks are counted as non-regular entries but never searched.
Binary regular files are searched, without an implicit binary exclusion.

```sh
curl --fail-with-body --header @/secure/source-reader.headers \
  --data-urlencode 'object_format=sha256' \
  --data-urlencode 'ref=refs/heads/main' \
  --data-urlencode 'needle_hex=706f6c696379' \
  --data-urlencode 'case=ascii-insensitive' \
  --data-urlencode 'max_matches=200' \
  "$REPO_URL/api/v1/source/search"
```

This example searches for the bytes `policy`. Optional `max_matches` is bounded
to 1 through 4096. Optional `max_bytes` and `max_file_bytes` can narrow, not
increase, the native 64 MiB total searched-file read envelope and 8 MiB per-file
ceiling. Native tree/object, depth, work and capability bounds still apply.

`source_search` reports `completion`, `complete`, returned match count and
selected/read/searched-byte counters. `completion: complete` covers all selected
regular files. `completion: match_limit` means at least one additional match
was observed beyond the returned prefix; `complete` is false. Exactly filling
the limit does not automatically imply truncation: the engine uses lookahead.
There is no invented total-hit count or resumable search cursor. Narrow the
query or deliberately increase the limit within the supported envelope.

Matches are ordered by raw path bytes and byte offset. Each carries `path_hex`,
blob OID, zero-based `byte_offset`, one-based `line` and `byte_column`, match
length, `excerpt_offset` and `excerpt_hex`. Overlapping matches are retained.
Line boundaries use LF; excerpts stop before the following LF while preserving
any preceding CR. Excerpts are at most 416 original bytes and do not normalize
binary data or Unicode. Use the source token and commit as preconditions on a
subsequent blob read to inspect a matching file at consistent coordinates.

## Errors, ownership and resource bounds

Unknown/inapplicable or duplicate scalar fields, invalid hex, unsafe structural
paths, wrong object domains, invalid limits and incomplete HTTP bodies are
refused. Authentication, deployment/grant checks, declared body limits and the
source-specific principal quota precede `100 Continue` and body intake.

Errors use `source_error` with `outcome_unknown: false`, because these endpoints
attempt no mutation. Missing refs or user paths are 404. Missing or corrupt
required native objects are errors, not empty directories or no-match answers.
Snapshot/commit movement and non-file/non-directory operations are 409; invalid
requests/ranges are 400, permissions 401/403, resource ceilings 413, unsupported
media 415, throttling 429 and unavailable evidence/infrastructure 503. A bounded
native source read can surface an unavailable-object error rather than a size
classification; callers must not interpret either as a complete search.

Forms are at most 256 KiB. JSON replies are completely constructed before
success and capped at 8 MiB plus the configured server ceiling, whichever is
smaller. File slices are bounded but the native reader may verify/decompress the
whole object under its separate 16 MiB object and 64 MiB aggregate browse-read
limits. This is not unbounded random-access or disk-spooled streaming. Source
queries use an independent quota from mutation intake and outcome recovery,
while sharing the existing bounded connection pool and owned child shutdown.
No detached search, persistent cursor or alternate executor is introduced.

## Verification entry points

```sh
cargo test -p fgit-node --lib smart_http::server::source
cargo test -p fgit-node --lib treefs_workspace::source_search
cargo test -p fgit-node --test source_http --test smart_http_server \
  --test smart_http_credentials --test issue_http --test outcome_http
cargo test -p fgit-cli --bin fg smart_http_server::tests
```

The TCP tests import real native objects, exercise the listener and reopen the
embedded node. They cover both native hash formats, exact directory/range
continuations, binary/overlapping search, real match-limit lookahead, intervening
publication, rotation/revocation, isolated scopes, denial before body intake,
truncated framing, symlink refusal and unchanged authority after reads. Tests
being present is not evidence that they ran at this revision. Browser UI,
retained historical browsing, indexed/global search, archives and richer query
languages remain separate work.
