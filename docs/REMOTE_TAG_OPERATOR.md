# Native tag publication from a terminal

`scripts/forge_tags.mjs` exposes the existing native lightweight/annotated tag
publication, exact deletion, inspection and outcome recovery APIs without a
checkout, Git subprocess or local node-storage access. It uses the shipped
`TagClient`; the server's sealed admission and authority-head decision remain
the publication mechanism. This is a Git tag workflow, not a release-asset,
package, signing or hosted release service.

See [HTTP_TAG_API.md](HTTP_TAG_API.md) for the native operation semantics and
[HTTP_OUTCOME_API.md](HTTP_OUTCOME_API.md) for authoritative outcome lookup.
The command is a Node operator adapter. It adds no production Rust dependency
or runtime and does not change the native tag policy or transaction identity.

## Connection and credentials

Use the repository's exact `/ui/tags/` URL, tenant ID and repository ID:

```sh
node scripts/forge_tags.mjs list \
  --url https://forge.example/REPOSITORY_ROUTE/ui/tags/ \
  --tenant-id "$TENANT_ID" --repository-id "$REPOSITORY_ID" \
  --token-file /secure/forge/tag-token --object-format sha256
```

The command requires HTTPS except on loopback. Its token file contains one
ordinary 64-character lowercase hexadecimal credential, with an optional final
LF. Sponsored agent tokens are not accepted by this tag client. Credentials
travel in the Authorization header, never a URL or command-line token flag.
Requests reject redirects and identify this operator with the
`frankengit-agent` User-Agent.

| Operation | Required independent native grants |
|---|---|
| `list`, `show` | `read` |
| Fresh `lightweight`, `annotated`, `delete` | `read` for exact source selection; `receive` for publication |
| `status` | `outcomes-read` |
| `retry` | `outcomes-read`; `receive` if the original request must be resubmitted |

The server's existing source/receive/outcome deployment switches still apply.
A write grant does not imply a read grant. The explicit tenant/repository must
match the first response before any request is prepared or custody is saved.
Subsequent reads retain the same repository incarnation and snapshot.

Token, annotation-message and recovery files must be regular, single-link,
owned by the current Unix user and inaccessible to group/other users. Symlink
files, hard links, unstable reads, oversized files and public file permissions
are refused. The recovery directory must already exist and be owner-private,
typically mode 0700. Use private custody outside a checkout. This Unix filesystem
profile is not a defense against a malicious process with the same UID.

## Create an absent lightweight tag

```sh
node scripts/forge_tags.mjs lightweight \
  --url "$TAG_URL" --tenant-id "$TENANT_ID" --repository-id "$REPOSITORY_ID" \
  --token-file /secure/forge/tag-token --record /secure/forge/v1-lightweight.json \
  --object-format sha256 --ref refs/tags/v1 \
  --source-ref refs/heads/main --target "$EXACT_COMMIT_OID"
```

The source is an exact visible direct ref selected from the native inventory.
Its observed object ID must equal the caller's `--target`; a moved branch fails
before a recovery record or mutation. No current-tip substitution occurs. The
sealed request retains that exact target even if the source moves later.

Native creation requires the destination tag to be absent. There is no implicit
overwrite, replacement or force operation. The operator refuses destinations
already seen in the selected snapshot; native admission enforces absence
atomically, including unseen destinations and races after preflight. A conflict
is a canonical terminal refusal, not permission to choose another request key.

The target may be a commit, tree, blob or existing annotated tag according to
the native API's visibility/reachability policy. A lightweight tag simply points
to that exact existing object; the operator never synthesizes an annotation.

## Publish exact annotation bytes

```sh
node scripts/forge_tags.mjs annotated \
  --url "$TAG_URL" --tenant-id "$TENANT_ID" --repository-id "$REPOSITORY_ID" \
  --token-file /secure/forge/tag-token --record /secure/forge/v1-annotated.json \
  --object-format sha256 --ref refs/tags/v1-annotated \
  --source-ref refs/heads/main --target "$EXACT_COMMIT_OID" \
  --target-kind commit --tagger 'Release Author <release@example.invalid>' \
  --timestamp 1790000000 --message-file /secure/forge/v1-message
```

`--message-file` preserves every original message byte, including CRLF, invalid
UTF-8 and a missing final newline. Empty files are valid. The limit is 65,536
bytes; NUL is refused by native tag creation. The operator zeroes its temporary
input buffer and serializes the original bytes as the client's `message_hex`.
It does not trim, decode, re-encode or append a newline. The token file cannot
also be selected as the message file.

Tagger, native target kind and UTC Unix timestamp must be explicit. The browser
client supports exactly representable integer timestamps from 0 through
9,007,199,254,740,991; the underlying HTTP API's larger i64 range is not claimed
by this command. No wall clock or ambient Git identity is consulted.

The existing client constructs the exact native annotated-tag bytes, hashes them
with the selected native object format and validates the returned tag object ID.
The native server independently validates target kind, original object bytes and
publication policy. The annotation's tagger is Git content, not the authenticated
principal. Signature-looking message bytes remain opaque: this workflow neither
signs nor cryptographically verifies tags, and never reports them as trusted.

## Exact ref names and exact deletion

Each ref accepts exactly one encoding: `--ref` for a complete UTF-8 tag name or
`--ref-hex` for the lowercase hexadecimal bytes of the complete name. Creation
likewise accepts `--source-ref` or `--source-ref-hex`. Do not include quotes or
escape notation inside the hex value. Non-UTF-8 names need the hex form. Native
ref names are bounded to 1,024 bytes; write targets must begin with `refs/tags/`.

```sh
node scripts/forge_tags.mjs delete \
  --url "$TAG_URL" --tenant-id "$TENANT_ID" --repository-id "$REPOSITORY_ID" \
  --token-file /secure/forge/tag-token --record /secure/forge/v1-delete.json \
  --object-format sha256 --ref refs/tags/v1-annotated \
  --expected-object "$EXACT_OUTER_TAG_OID"
```

For annotated tags, the expected object is the outer tag OID, not the peeled
commit. The operator compares the exact current direct ref before preparing the
request. Native admission retains the same exact-old lease across races and
retries. Deletion removes the named ref; it does not erase annotation objects
still reachable through other tags or fabricate a forge release event.

## Inventory and inspection

`list` emits only tag rows from the native all-ref inventory. It requests hex
cursors so a byte-only ref in an intermediate page never prevents continuation.
`ref_hex` is authoritative; `ref` is a display string or null for non-UTF-8 names.
Branches traversed to reach tag rows are counted in `source_refs_scanned` but are
not returned as tag results.

```sh
node scripts/forge_tags.mjs list \
  --url "$TAG_URL" --tenant-id "$TENANT_ID" --repository-id "$REPOSITORY_ID" \
  --token-file /secure/forge/tag-token --object-format sha256 \
  --limit 100 --max-pages 20

node scripts/forge_tags.mjs show \
  --url "$TAG_URL" --tenant-id "$TENANT_ID" --repository-id "$REPOSITORY_ID" \
  --token-file /secure/forge/tag-token --object-format sha256 \
  --ref refs/tags/v1-annotated
```

`show` selects the exact direct tag ref, pins its outer object and inventory
snapshot, and returns its bounded outer-to-inner annotation chain. The client
hashes every supplied original tag body and validates each edge. Reports retain
`signature_verified: false` and `tagger_is_authenticated_principal: false`.
They contain no terminal commit/tree/blob body. A missing tag is reported only
after the relevant inventory has been exhausted; an incomplete selection scan
is an error.

Both reads check repository/hash identity, exact ordering, advancing byte
cursors, snapshot token and source-head consistency. An invalid later page,
changed authority head or corrupt annotation fails the whole read; the command
does not return its earlier prefix as successful. Unknown response extensions
and rendered HTML are omitted. JSON output escapes terminal control characters.

| Bound | Behavior |
|---|---|
| `--limit 1..100` | Native page size; default 100 |
| `--max-pages 1..100` | Default 1 for list, 20 for show and fresh mutation selection |
| Client reference session | At most 2,048 cached refs, counting branches and tags |
| `--max-output-bytes 1..8388608` | Read output limit, including its final JSON envelope; default 8 MiB |
| `--timeout-ms 1..300000` | Whole invocation deadline, including input/output; default 30 seconds |

The next fixed-size page must fit the remaining client session capacity. With
the default page size of 100, the maximum is 20 pages / 2,000 rows. A page size
of 64 can reach the exact 2,048-row cap. The command never enlarges the client
cache or restarts a scan automatically after a moved snapshot.

A bounded `list` prefix has `complete: false`, a `stop_reason`, and exit status
4. Its `next_after_hex` is an observation, not a supported cross-invocation
resume token: `cross_invocation_resume_supported` is false. Restart with an
explicitly larger budget if possible. No `--after` flag is accepted. `show`
and mutations fail if their chosen ref cannot be selected within the budget.
Creation may stop as soon as its exact source is selected; destination absence
continues to be enforced by native admission.

## Durable custody, status and retry

A fresh mutation checks the caller's exact source/deletion expectation, asks
the shipped client to prepare the request, then saves a private wrapper around
the client's original retry receipt. New-file-only creation prevents accidental
record replacement. File synchronization, exact readback, parent directory
synchronization and close must finish before submission. Every sender, including
a separate retry process, establishes its own file/parent synchronization
barrier. An incomplete or changed record is retained and refused.

The record binds URL, tenant/repository, incarnation, hash domain, original
credential fingerprint, operation, exact fields, nonce and original idempotency
key. It contains private tag metadata but not the token. Keep it even after
success; do not edit it, reuse its filename for a new operation or infer an
outcome from its presence.

```sh
node scripts/forge_tags.mjs status \
  --url "$TAG_URL" --tenant-id "$TENANT_ID" --repository-id "$REPOSITORY_ID" \
  --token-file /secure/forge/tag-token --record /secure/forge/v1-annotated.json

node scripts/forge_tags.mjs retry \
  --url "$TAG_URL" --tenant-id "$TENANT_ID" --repository-id "$REPOSITORY_ID" \
  --token-file /secure/forge/tag-token --record /secure/forge/v1-annotated.json
```

`status` only observes the original outcome. `retry` observes first and, only if
the result remains nonterminal, may send the same original body/key once. It
does not re-list refs, refresh a source OID, change tag bytes or select a new key.
An already terminal result is returned without another mutation, even if the
tag was subsequently deleted. This is evidence about the original operation,
not an assertion that the current ref still has that value.

The current `TagClient` requires the original credential fingerprint. A rotated
token is refused even if it identifies the same principal; native HTTP outcome
lookup has broader rotation support, but this operator does not claim it.
Mutation fields, object format and read-pagination flags are inapplicable to
`status`/`retry`; all semantics come from the original saved receipt.

Cancellation, lost acknowledgement, a 503 or an unobserved key never proves
non-commit. Errors after a possible submission retain `submitted_unknown` and
the record location/digest. Once a validated terminal decision is received, it
is reported even if a later cancellation arrives. Failed terminal output does
not discard the recovery record or change the canonical result.

| Exit | Meaning |
|---|---|
| 0 | Committed terminal outcome or complete read |
| 3 | Native terminal refusal |
| 4 | Valid bounded inventory prefix; more refs remain |
| 2 | Error, cancellation or unresolved original outcome |

## Verification scope

```sh
TMPDIR=/tmp node --test tests/operator/forge-tags.test.mjs \
  tests/browser/tags.test.mjs tests/browser/tags-view.test.mjs
```

The operator tests use real HTTP sockets, private files, process restarts and
CLI subprocesses against an explicitly simulated response-schema peer. They
exercise both hash formats, raw names, annotation byte preservation, exact
leases, lost acknowledgements, original-key retry, custody rejection, bounded
reads and cancellation. Browser tests cover the shared client/protocol and
preserve its default UTF-8 cursor behavior alongside opt-in hexadecimal cursors.
These tests do not establish Rust compilation, native authority durability,
cryptographic signature trust or live tag compatibility; native validation
belongs to the existing HTTP/tag suites documented in `HTTP_TAG_API.md`.
