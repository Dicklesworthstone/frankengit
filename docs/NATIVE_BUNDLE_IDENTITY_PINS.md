# Match a native-verified bundle to independently known backup identities

`fg bundle verify` can verify a complete but unintended backup. Identity pins
add caller-owned constraints to the existing native Rust content verifier.
They do not replace pack reconstruction, object identity, graph connectivity,
required target kinds, cancellation, or the operator's resource limits.

```sh
fg bundle verify /backups/repository.bundle \
  --expect-sha256 "$TRUSTED_BUNDLE_SHA256"

fg bundle verify /backups/repository.bundle \
  --expect-format sha256 \
  --expect-ref "refs/heads/main=$TRUSTED_MAIN_COMMIT" \
  --expect-ref "refs/tags/release=$TRUSTED_TAG_OBJECT"
```

Use `--expect-format sha1` for native SHA-1. The format is never inferred from
an object ID's width. Native IDs must be complete canonical lowercase hex; a
matching `sha1:` or `sha256:` prefix is accepted. An annotated tag pin names
the tag object, not its peeled commit. The whole-artifact SHA-256 always uses
64 lowercase hexadecimal characters, regardless of the native hash domain.

The identities must come from a separately trusted record. A filename, an
unsigned adjacent manifest, or a value just read from the same untrusted
bundle does not establish provenance. A format alone is not an identity pin.

## Reference selection and raw-byte names

Without `--exact-refs`, every supplied pin must match but additional direct
refs are allowed. They and every included object's local dependencies still
undergo the existing full native graph verification. Add `--exact-refs` to
require precisely the supplied direct-ref set. Omitted refs, extra refs, and
changed tips refuse; exactness requires a nonempty pin set.

```sh
fg bundle verify /backups/repository.bundle \
  --expect-format sha1 \
  --expect-ref "refs/heads/main=$TRUSTED_MAIN_COMMIT" \
  --expect-ref-hex "726566732f746167732fff=$TRUSTED_RAW_TAG_OBJECT" \
  --exact-refs
```

`--expect-ref-hex HEX=OID` is the lossless alternative for non-UTF-8 names.
Neither names nor object data become filesystem paths. Names containing an
`=` are allowed: the final `=` separates the name from the ID. Repeated names
are errors, even across text and hexadecimal options or with identical IDs.
`HEAD` is an optional advertisement rather than a direct ref: pin its exact
presence/value with a whole-artifact hash, not a `HEAD=...` reference pin.

A native ref pin survives legitimate repacking and reordered header records;
a whole-artifact hash binds exact transport bytes and will reject either
change. Both forms may be combined, in which case all constraints must match.
The literal-path `--` separator retains its existing behavior.

## Failure and result boundary

The complete pin grammar and final resource options are validated before
opening the file, independent of argument order. Expected references are
bounded to 4,096, a 4 KiB name each, and 1 MiB aggregate name bytes, also
respecting narrower caller header/ref limits. The CLI additionally bounds
aggregate argument bytes to 2 MiB. Invalid pins never trigger an implicit
unpinned retry or a weaker verification profile.

After the existing bounded bundle-envelope parse, format and ref mismatches
refuse before pack decompression. When requested, the artifact hash is checked
using the native SHA-256 implementation with 64 KiB cancellation checkpoints.
Its result is reused in the final report rather than hashing again. All work
shares the existing sticky cancellation callback and cooperative deadline.

A matching header/hash is not a successful result. The native decoder and
whole included-object graph verification must still complete. A genuine pin
for a checksum-corrupt pack or a checksum-valid bundle missing a reachable
blob therefore fails. This path opens no node, requests no credential, runs
no external Git/JavaScript implementation, and publishes no repository state.

Unpinned invocation keeps the existing JSON report shape. Pinned success adds
`caller_expectations_matched: true` and an `expectations` object containing
`artifact_sha256`, `object_format`, `ref_set` (`contains`, `exact`, or null),
and a sorted `references` list of `ref_hex`/`object_id` pairs. Unspecified hash
or format fields are null. Existing `origin_authenticated`,
`signatures_verified`, and `current_branch_verified` remain false. A match is
relative to the caller's pins, not signature, freshness or authority proof.

The library exports `BundleExpectations`, `BundleExpectationError`,
`MatchedGitBundle`, and `verify_git_bundle_against` from
`fgit_node::source_retrieval::integrity::bundle_verify`.
`BundleExpectations::new` validates and owns typed values; its fields cannot
be mutated. The matched result borrows those immutable expectations and has
no public constructor. It exists only after the same native verifier used by
`verify_git_bundle` succeeds. The old entry point remains unchanged.

This does not add signed native capsule recovery, streaming Git decoding,
forge-state restore, or retirement of the JavaScript tools. It extends the
current upstream native verifier, not the earlier unmerged replacement.

## Verification commands and evidence boundary

```sh
cargo test -p fgit-node --lib source_retrieval::integrity::bundle_verify
cargo test -p fgit-cli --bin fg bundle::verify
cargo build -p fgit-cli --bin fg
python3 scripts/e2e/native_bundle_pins_smoke.py --fg target/debug/fg
```

The authored tests use native verification plus independently generated
SHA-1/SHA-256 fixtures, including both delta encodings, raw ref names, and
checksum-valid missing-blob cases. The command smoke driver uses the actual
binary and JSON receipts, with Git absent from the product process's PATH.
It covers expected hash/domain/ref mismatch, exact/subset sets, invalid
pre-I/O options, repacking, corruption, and missing object dependencies.

`--fixtures-only` is a separate mode that runs installed Git bundle/fetch/fsck
checks on the test data. It reports `native_fg_executed: false` and zero native
cases. It is not a substitute for executing Rust tests or the native command.
This change was authored without an available Rust toolchain: compilation,
Rust tests, rustfmt, and native binary execution have not been performed in
that environment. Test-data preflight and patch applicability are the only
executed evidence; no production-readiness or bead closure is claimed.
