# Native compressed patches through source preparation

The existing `OneNode::prepare_workspace_patch_in` and trusted-owner adapter
now compose `fgit-diff` binary framing with the `fgit-pack` native
base85/zlib/delta decoder. Existing `source/prepare` HTTP patch uploads reach
this same code. No extra route, permission, database, external dependency,
Git subprocess, or alternate publication mechanism is introduced. This contract
supersedes older source-authoring descriptions that predate compressed-upload
integration; their other editor and recovery boundaries remain unchanged.

## Supported operation

An existing commit-valued branch can receive a mixed patch containing ordinary
literal edits, explicit regular-file renames, and non-renaming `GIT binary patch`
records. Compressed records support regular-file creation, replacement,
executable-mode changes, deletion, and replacement by a present empty blob.
Both literal and delta members are decoded; a delta header names the inflated
program size, not the final file size. Paths retain their original bytes.

Compressed rename records remain refused by the explicit parser profile. A move
with compressed content can instead use separate deletion and absent-destination
creation records. Swaps, chains, overlapping paths, symlinks, gitlinks, copies,
fuzzy application and external merge/filter drivers remain unsupported. The
separate initial-history preparation profile is not widened by this change.

The existing source editor's patch uploader accepts these inputs within its
1 MiB upload limit. The browser does not decompress them or accept a patch as
publication authority. Native preparation returns the candidate bundle and path
manifest; the existing browser submits the actual bundle for native inspection
before enabling separately confirmed publication. Binary bodies are not silently
presented as text diffs. Queued text/hex edits retain their existing literal-byte
encoder and original-request recovery behavior.

## Original identities and atomic effects

Every compressed record requires equal-width full old/new index identities in
the repository's SHA-1 or SHA-256 domain. All-zero names are absent-side sentinels,
not empty-blob IDs. Creation requires absence; other operations require the
original selected source. Claimed index prefixes from another domain cannot
select an object or satisfy a source expectation.

Both write targets of a rename, and every other target, retain the existing
capability checks before source disclosure. Hidden-ref, expected-commit and
complete-directory export checks are unchanged. File bodies are loaded through
the same bounded, verified immutable source and charged to its capability.

The decoder independently verifies the original source blob, reconstructs the
forward image, and verifies its full new native identity. Any supplied reverse
member is also fully decoded and must reproduce the original bytes exactly.
Malformed compression, base85 overflow, incorrect delta sizes/copies, trailing
records, wrong identities and corrupt reverse images refuse the whole attempt.
The existence of a correct forward image is insufficient.

Successful bytes become ordinary in-memory TreeFS intents. Every file must
validate, then the existing exporter constructs one exact tree and single-parent
bundle. A failed later file returns no partial candidate and performs no ref or
forge publication. The complete changed-path manifest still reports old/new blob
identities and modes; binary member counts are reported as hunks, not text lines.

Native quarantine and exact-predecessor admission remain the only publication
path. Retrying an uncertain publication uses its original bundle and idempotency
key, not a new decode against refreshed branch contents. A preparation error is a
read refusal, not a canonical transaction-abort or rollback receipt.

## Shared bounded decoding

`BinaryPatchBatch` owns one known set of at most 1,024 compressed files. Input
bytes, physical lines and expanded bytes are charged across all files rather
than renewed for every record. Expanded bytes include sources, both inflated
members, and each reconstructed delta result. Successful usage is derived from
the decoder's actual counters, not inferred from untrusted headers.

At the node boundary these shared ceilings narrow to the supplied `PatchLimits`:
16 MiB encoded input, 8 MiB per source/result/program, 262,144 physical lines and
32 MiB expanded bytes at the default ceiling. The existing whole-patch output
sum is still checked independently, including literal edits. Operator/API limits
can narrow these further. Parser file, path, hunk and declared-inflation limits,
source capability budgets and exporter ceilings remain additional constraints.

One 64-Mi-unit inflate allowance and one 64-Mi-unit delta allowance are divided
into equal, nontransferable per-file ceilings before decoding. The decoder's
existing per-forward/reverse split is retained. These are reserved upper bounds,
not measured instruction counts or performance claims. An asymmetric batch may
therefore refuse even when its total file bytes fit; unused shares do not renew
another file's budget. Fixed parser/hash/setup work retains its independent byte,
file-count and request-deadline bounds.

Every failure, including cancellation, poisons the batch. A caller cannot retry
failed decoding inside the same allowance or continue using tentative forward
output. Successfully decoded earlier files remain tentative until the entire
workspace preparation succeeds. No checksum or usage counter grants authority.

## Verification and limits of evidence

```sh
cargo test --locked -p fgit-pack --lib binary_patch
cargo test --locked -p fgit-node --lib treefs_workspace::patch::binary
cargo test --locked -p fgit-node --test workspace_binary_patch --test workspace_patch
python3 scripts/verify_compressed_patch_corpus.py /absolute/pinned/git \
  'git version 2.47.3' <sha256-of-that-executable>
```

This increment adds nine decoder-batch tests, two node adapter tests, and seven
native node integration tests. The integration tests consume the existing real
Git 2.47.3 literal/create/delete/delta goldens in both hash domains and exercise
actual TreeFS preparation, unchanged authority before publication, deterministic
bundles, exact final trees, sibling preservation, reopened original-key retries,
mixed literal/rename/binary effects, corruption, shared limits, capabilities,
hidden refs and cancellation. These tests do not invoke Git.

**Rust/Cargo was unavailable in the implementation environment; none of these
18 new Rust tests or native compilation was executed there.** The source was
reconstructed against exact upstream file hashes and inspected, but that is not
compiler or runtime evidence. Native HTTP/browser interoperability, full workspace,
Clippy, durable runtime acceptance and release gates remain unverified.

The pinned non-production corpus command executed 16 Git generation/application
scenarios across SHA-1/SHA-256, checking exact resulting trees, native blob bytes,
file modes and untouched siblings. It requires the exact executable hash before
running Git and records patch/tree identities. That checks interoperable input
fixtures, **not execution or differential validation of the native Rust decoder**.
There is no Git invocation in the production preparation or decoder modules.
