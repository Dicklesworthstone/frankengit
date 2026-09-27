# Independently verify a portable Git backup

Run from the FrankenGit checkout with Node.js 22 or newer:

```sh
node scripts/verify_git_bundle.mjs /backups/repository.bundle
```

This read-only command does not require a running FrankenGit node, an installed
Git executable, a worktree, or a network connection. It opens one bounded local
regular file and never modifies the bundle or a repository. It prints a JSON
report to stdout only after verification succeeds. Exit status 0 means the
reported checks completed; failures exit nonzero with a diagnostic JSON record
on stderr. Interrupting a run discards the incomplete result.

## What success establishes

The verifier checks the full bundle header and native pack checksum, decompresses
every packed object with its own bounded DEFLATE decoder, resolves both offset
and object-ID deltas, and hashes the reconstructed Git-framed bytes. It then
walks the complete typed object graph from every advertised direct reference:
commit parents and root trees, nested trees and file/symlink blobs, and annotated
tag targets. A checksummed bundle missing a reachable file or ancestor fails.

A successful report has `objects_verified: true` and
`object_closure_verified: true`. It includes the artifact SHA-256, native hash
domain, exact byte-name reference inventory, packed and reachable object counts,
delta depth, resource accounting, and the number of external gitlink entries.
Missing-object and wrong-type errors identify the referring and target objects.

Extra transport-only objects are counted as `unreachable_objects`; their bytes
and metadata structure are checked, but their own unreachable history is not
included in the advertised-ref closure claim. The lower-level library function
`verifyGitBundleObjects` remains available for explicitly object-only checking.
The command always runs the stronger closure check.

## Check that it is the intended backup

Internal consistency alone does not establish provenance or freshness. Supply a
hash or native reference identity recorded through a separately trusted channel.
Do not treat an unsigned manifest supplied alongside an untrusted bundle as an
independent trust anchor.

To require an exact previously recorded artifact:

```sh
node scripts/verify_git_bundle.mjs /backups/repository.bundle \
  --expect-sha256 "$TRUSTED_BUNDLE_SHA256"
```

To require known native branch/tag identities, independently of pack encoding:

```sh
node scripts/verify_git_bundle.mjs /backups/repository.bundle \
  --expect-format sha1 \
  --expect-ref "refs/heads/main=$TRUSTED_MAIN_COMMIT" \
  --expect-ref "refs/tags/release=$TRUSTED_TAG_OBJECT"
```

Use `--expect-format sha256` for a native SHA-256 repository. Native object IDs
must be complete, not abbreviated; a matching `sha1:` or `sha256:` prefix is
accepted. Annotated tags must name the tag object's ID, not its peeled commit.
Ref names must be complete native names. `--expect-ref-hex HEX=OID` handles
non-UTF-8 names without replacement characters or filesystem interpretation.

Without `--exact-refs`, every supplied pin must match, but additional advertised
refs are permitted and still undergo full closure verification. Add
`--exact-refs` to require precisely the supplied direct-ref set. `HEAD` is a
separate optional advertisement, not a direct-ref pin; an artifact hash binds
its presence and value too. Hash and ref constraints may be combined.

Malformed expectations fail before opening the file. Wrong format, missing or
changed reference pins, unexpected additional refs in exact-set mode, and wrong
artifact hashes fail before object decompression. Matching pins never skip the
pack, object or closure checks. A successful pinned result adds
`caller_expectations_matched: true` and echoes the normalized expectations.
This statement is relative to the supplied pins, not a new identity authority.

`--` permits a literal filename that starts with a dash. `--help` prints all
options without opening a file.

## Supported profile and bounds

The profile accepts full Git bundle v2/v3 with native SHA-1 or SHA-256 and pack
version 2. Stored, fixed-Huffman and dynamic-Huffman DEFLATE, REF_DELTA (including
forward bases), OFS_DELTA and chained deltas are supported. Thin/prerequisite,
filtered, unknown-capability and unsupported-version bundles refuse explicitly.
No external base object is fetched and there is no fallback to another engine.

Defaults and hard ceilings are 16 MiB input, 256 KiB bundle header, 1,024 ref
records, 32,768 packed objects, 16 MiB per object or delta program, 128 MiB total
inflated-plus-reconstructed bytes, delta depth 64, 32 MiB metadata, 262,144 links,
256 Mi work units, and a 30-second verifier deadline. These are a bounded offline
profile, not the native node's acceptance limits. Library callers may lower the
limits. The decoder yields during long operations so cancellation can run.

Only native tree mode values 040000, 100644, 100755, 120000 and 160000 are accepted.
Original leading-zero spellings are hashed unchanged. Unsupported legacy modes,
ambiguous reference headers, invalid/duplicate/native-misordered tree entries,
reserved `.git` names, truncated objects, and missing/wrong-type reachable
objects refuse instead of being normalized into a stronger claim.

## What success does not establish

This verifies portable Git source, **not a full FrankenGit repository capsule**.
It does not recover or authenticate PRs, issues, policy, authority-head decisions,
retention state, permissions, workflows, or delivery acknowledgements. It does
not verify author identity or signatures, independently authenticate an origin,
prove a ref is current, or implement every upstream `git fsck` policy. Submodule
gitlinks name other repositories: they are counted but not followed or verified.
Symlink target bytes are verified, but links are never created or traversed.

The report keeps those non-claims explicit. Never equate successful verification
with native admission, a completed restore, or production readiness.

## Run the focused checks

```sh
node --test tests/browser/bundle-*.test.mjs
```

The unit/adversarial tests execute the actual verifier and command. The
`bundle-verify-git.test.mjs` matrix additionally uses the installed Git executable
to generate both native hash formats and delta encodings, compare object
inventories, and demonstrate a real restore failure for a checksum-valid bundle
missing a reachable blob. These are bounded installed-Git interoperability
observations, not the repository's pinned Git-oracle lane, native `fg` server
end-to-end tests, or repository-wide gates. Native zlib is a test encoder only;
the verifier itself imports no inflater or external Git engine.
