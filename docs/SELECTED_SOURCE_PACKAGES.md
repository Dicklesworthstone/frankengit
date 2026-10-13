# Portable selected-source packages

A membership proof alone omits blob bodies. A local byte-check summary cannot
be independently replayed. The selected-source package combines the original
commit, complete needed parent trees, exact selected path/mode/blob inventory,
and complete file bodies in one bounded, credential-free artifact.

This is a selected-source consumer for FG-032 and plan section 27, not a complete
Context Packet, repository backup, forge export or authorization mechanism.

## Offline verification

Run the checked-in verifier without contacting a server:

```sh
node scripts/fg_verify_source_package.mjs \
  --package selected-source.json \
  --expect independently-retained-selection.json
```

The separate expected selection has this shape:

```json
{
  "format": "sha1",
  "commit": "<independently obtained commit digest>",
  "files": [
    { "pathHex": "<exact lowercase path bytes>", "blob": "<expected blob digest>" }
  ]
}
```

Use real native digests, not these placeholders. The files are in increasing
raw-byte path order. Neither the package nor the verifier supplies the independent
commit or expected selection. Deriving those pins from the same untrusted package
would discard their independence. The command accepts no token, endpoint or
extraction option. It bounds and checks regular input files, performs local
verification, and emits a JSON result; it never writes source files. `--timeout-ms`
sets a 1–300,000 ms verification deadline (30,000 ms by default). Successful
verification exits 0; malformed inputs, changed bytes, mismatched pins, cancellation
or failed output exit 1. File-I/O deadlines are checked before and after each
bounded read, not a promise to interrupt a stalled kernel/filesystem operation.

## Producer and verifier APIs

The browser-compatible module is
`crates/fgit-node/src/smart_http/server/browser/search-context-package.mjs`.

`acquireContextPackage(result, reference, independentCommit, request, crypto,
check, limits)` consumes an already validated Initial context. It preflights the
entire selected body set before networking, uses the existing membership reader
to verify the original commit and every needed complete parent tree, then reads
all selected regular files through the existing pinned `source/blob` route.
Every returned mode must also match the committed tree mode. Each complete blob
is checked with native Git framing before any package is returned.

The caller owns one operation deadline/cancellation lifetime and the existing
credentialed request host. All reads keep the original reference, commit,
authority snapshot and repository incarnation. No retry, refresh, unrelated
subtree traversal or successful-prefix return is permitted. The original context,
query, source pins and generation checkpoints are unchanged. Search terms,
rankings, annotations and claimed query-completeness flags are not copied into
the artifact: the package contains source, not a claim that a search was complete.

`readSourcePackage(bytes, expected, crypto, check, limits)` is the bounded UTF-8
JSON reader and offline verifier. It returns the owned checked package and a
fresh verification result. `verifySourcePackage` validates an object;
`encodeSourcePackage` takes an owned snapshot, verifies it again, and serializes
that exact snapshot. No saved success flag can replace verification. Caller
mutation while asynchronous hashing yields cannot change the checked input.

## Format, limits and disclosure

The closed `frankengit-selected-source-package-v1` format contains only:

- `membership`: the existing `frankengit-context-membership-proof-v1` evidence;
- `blobs`: one complete lowercase hexadecimal body per distinct native blob ID,
  in increasing bare-digest order.

Every needed blob is required and extras/duplicates are rejected. Bodies shared
by multiple selected paths are serialized once, but each occurrence still counts
toward the logical source-byte limit and is freshly read at its selected path.
This is not cross-repository reuse or an authorization shortcut.

The package admits 1–32 selected regular files, at most 8 MiB of logical complete
file bytes, at most 160 blob-page requests, and at most 32 MiB of serialized JSON.
Membership has separately configurable limits up to 512 metadata requests, 128
parent trees, 16,384 entries and 4 MiB of tree bytes. Source and blob-request limits
can be reduced, not enlarged. These limits bound a buffered implementation; they
do not claim minimal memory, a total wire-byte cap or server-work accounting.
Cancellation/deadline checkpoints also cover large body encoding and decoding.
An empty file still requires one page read and its native empty-blob hash.

The package retains private full file bodies, commit messages, and sibling names
and identities in needed parent trees. No ambient credential, local path, endpoint,
source-head claim or execution authority is included. Source text remains untrusted.
Byte equality and membership are conditional on the independently selected commit
and native hash algorithm. They do not establish current branch/repository authority,
freshness, signatures, permissions, search completeness or declaration semantics.
Unrelated tree/blob bodies and forge state are not included. Nothing is extracted
or executed by the verifier.

## Focused verification

```sh
node --test tests/browser/search-context-package*.test.mjs
```

The initial tests use complete package/membership/source validation modules, the
actual shared Transport, Fetch, WebCrypto, HTTP sockets, and real offline CLI
processes/files. Native-schema peers independently construct commit/tree/blob
bytes; they are not Rust `fg` servers or evidence of native authorization.
The normalized input context in these focused acquisition tests is an explicit
fixture. No Cargo, real-browser, whole-workspace or bead-closure claim follows.
