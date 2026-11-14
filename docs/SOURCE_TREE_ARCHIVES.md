# Source tree archives

`fg tree --output` exports a complete, authority-selected source directory as a
new POSIX ustar or stored-ZIP file. The authenticated HTTP source archive
endpoint exports the same selected source using ustar. These implement the
bounded source-archive slice of the archive
creation target in [the compatibility matrix](GIT_COMPATIBILITY_MATRIX.md), not
a Git bundle, repository capsule, backup, or canonical repository mutation.

```sh
fg tree ./fgit-data TENANT_ID REPOSITORY_ID --trusted-local \
  --ref refs/heads/main --output ./source.tar

# ZIP is an explicit CLI format choice; extensions never select a format.
fg tree ./fgit-data TENANT_ID REPOSITORY_ID --trusted-local \
  --ref refs/heads/main --archive-format zip --output ./source.zip

# Export only this directory, with independently reviewed native identity.
fg tree ./fgit-data TENANT_ID REPOSITORY_ID --trusted-local \
  --ref refs/heads/main --path crates --expected-commit NATIVE_OID \
  --object-format sha256 --output ./crates.tar
```

The CLI output path must not exist. The default format remains tar; explicit
`--archive-format tar|zip` is accepted only with `tree --output`, never on
`fg show` or a paged listing. Unknown and duplicate format options refuse
before source I/O. Directory pagination follows `--limit` (1–1000,
100 by default); changing that limit does not change the resulting archive.
`--after-hex` is not accepted with an archive because it would silently omit part
of a directory. Existing tree-page and `fg show --output` behavior remains
available. All reference and path hex forms remain available for raw Git names.

## Authenticated HTTP downloads

Enable the existing source profile with `fg serve-http --allow-source` and use
the repository URL from its readiness record. An ordinary repository-read
credential or a canonical sponsored `source-read` credential can request:

```text
POST {REPO_URL}/api/v1/source/archive
```

Send `application/x-www-form-urlencoded` with required `ref` and
`object_format` (`sha1` or `sha256`). Optional `path_hex` selects a directory
using its raw bytes. Optional `expected_head` carries a previous source response's
`snapshot_token`; `expected_commit` is its lowercase native commit OID without
the `sha1:` or `sha256:` display prefix. These compare the current visible ref;
they do not select an arbitrary object or historical snapshot.

```sh
curl --fail-with-body --header @/secure/source-reader.headers \
  --data-urlencode 'object_format=sha256' \
  --data-urlencode 'ref=refs/heads/main' \
  --data-urlencode "expected_head=$SNAPSHOT_TOKEN" \
  --data-urlencode "expected_commit=$NATIVE_COMMIT_HEX" \
  --output source.tar.part \
  "$REPO_URL/api/v1/source/archive"
```

Only publish a downloaded file after a successful status and complete body.
Check failures before treating an output path as an archive: command-line HTTP
clients can leave a partial file or an error body at that path.

The closed read envelope rejects URL query parameters, `Git-Protocol`,
`Idempotency-Key`, pagination, ranges, caller-selected limits and unknown fields.
It inherits the existing route, incarnation, hidden-ref and credential checks.
Source access creates no transaction and grants no repository write capability.

A successful response uses `application/x-tar`,
`Content-Disposition: attachment; filename="source.tar"`, an exact
`Content-Length`, `Cache-Control: no-store` and the following metadata:

| Header | Meaning |
|---|---|
| `X-FrankenGit-Archive-Profile` | `ustar-source-v1` |
| `X-FrankenGit-Snapshot-Token` | Algorithm-qualified current-head comparison token |
| `X-FrankenGit-Source-Head` / `X-FrankenGit-Source-Rcr` | Exact authority head and RCR |
| `X-FrankenGit-Source-Commit` | Typed native commit identity |
| `X-FrankenGit-Root-Tree` / `X-FrankenGit-Selected-Tree` | Repository root and selected subtree identities |
| `X-FrankenGit-Archive-Entries` | Header count including `source/` and gitlink directories |
| `X-FrankenGit-Archive-Gitlinks` / `X-FrankenGit-Archive-Reads` | Opaque gitlinks and native source-read count |

The source browser's **Download directory** action exports the full selected
directory, including entries beyond the visible page. It validates response
metadata, the retained snapshot and directory identity, and the complete bounded
body before creating a download link. Cancelled, truncated or superseded
responses never become downloads. Metadata is not an independent cryptographic
authority proof; the separate verified-read surface retains that boundary.

## Source and publication boundaries

The first verified source read fixes the repository authority head, RCR, native
commit, and repository root tree. Every subsequent directory page and file range
must match those pins, and every child read must match the native object identity
and entry kind supplied by its parent. Exporting a subdirectory retains both the
repository root tree and the separately selected subtree identity.

A source movement, hidden reference, missing object, inconsistent continuation,
cancellation or exhausted read budget refuses the entire export. No alternate
ref, ambient object lookup, local checkout or external Git engine is used. The
complete walk shares one request context, including its timeout. HTTP archives
retain the original request deadline through intake, assembly and delivery;
sponsored credentials retain their independent lifetime and byte reservation.

For CLI output, only after every read and explicit node shutdown succeeds does
the existing no-overwrite file publisher expose the finished archive. Failures before that
barrier expose no archive. An output-publication error may require checking the
named path; a failure to print the completion receipt after publication does not
undo the complete file. No successful receipt is printed for partial output.

HTTP success headers are withheld until bounded collection and encoding finish.
A subsequent socket failure can still truncate the transfer, so clients must
require the complete declared response length. Source movement returns 409;
unsupported archive names or links return 409 `source_archive_profile_refused`;
resource ceilings return 413. Native source-read failures retain their existing
typed mappings rather than becoming a successful empty archive.

The CLI JSON receipt is `source_tree_export`, schema 1. Tar retains profile
`ustar-source-v1`; ZIP selects `zip-store-source-v1`.
It includes source pins, selected subtree, original path bytes, counts and the
archive size. `repository_changed:false` distinguishes creating the operator's
local output file from publishing repository authority.

## Byte and extraction profile

Every archive has one `source/` prefix. Directories precede their children in
raw-name depth-first order. Regular files retain exact bytes, including binary
and empty payloads. Git executables use mode 0755; other regular files use 0644,
directories 0755, and symlinks 0777. There is no dependence on the exporting
host's clock, ownership, locale or filesystem ordering.

Tar retains zero UID, GID and modification time, empty owner names, and its two
zero end blocks. ZIP uses the existing TreeFS `ZipStoreV1` byte encoder:
uncompressed entries, per-member CRC-32, Unix type/mode bits, explicit UTF-8
names, and the fixed DOS epoch 1980-01-01 00:00:00. It carries no extra fields,
comments, encryption or ZIP64 records. Its local records, central directory and
end record all count against the complete output budget.

Symlinks are encoded as links and are never followed by the exporter. This
closed profile accepts only nonempty relative link targets of at most 100 bytes
in tar or 4096 bytes in ZIP, without NUL, backslash, colon or any `..` component. Parent traversal is refused
even when lexical normalization appears contained: preceding symlinks could
change its meaning. Unsupported links refuse the whole archive rather than
being silently dereferenced, rewritten or omitted. Treat extraction of untrusted
archives as a separate operation and use an empty, appropriately isolated target.

Gitlinks become empty directories. Their contents belong to a different
repository and are never fetched. The receipt reports `gitlink_directories` and
`submodules_materialized:false`; the source commit remains the reference for the
original gitlink OIDs. There is no `.git` metadata, Git history, forge state,
credential delegation, or submodule working tree in this source archive.

Tar names retain raw bytes, including non-UTF-8 bytes, within the exact ustar
100-byte name / 155-byte prefix fields. ZIP names must already be valid UTF-8;
there is no lossy recoding, normalization or false UTF-8 flag. ZIP permits up to
255 bytes per component and 4096 bytes per complete archive path, including
`source/`, and rejects ASCII control bytes below 0x20 through TreeFS path
validation. This supports names that exceed ustar's split fields.

Directory names include a trailing slash in both formats. Paths that cannot be
represented exactly refuse. Empty, dot, parent, `.git` (case-insensitive), NUL,
backslash, colon and slash-containing individual components refuse. No GNU
long-name, PAX, encoding or ZIP64 fallback silently changes the profile.

This is an exact source-tree export, **not full `git archive` compatibility**.
`export-ignore`, `export-subst`, pathspec rewriting, timestamps from commit
metadata, compression and the Git `upload-archive` protocol are not implemented
by these profiles. ZIP is currently selected through the CLI and shared collector;
the authenticated HTTP endpoint and browser retain their ustar response profile.
Git attributes are included as ordinary source bytes, not executed.

## Bounds and tests

The whole artifact, including all format framing, is limited to 128 MiB. HTTP
further intersects this with its configured response ceiling. The shared
collector's `collect_with_format_and_limit` applies the same complete-response
ceiling to either encoding; its existing `collect` and `collect_with_limit`
entrypoints retain ustar. Empty source directories require 1,536 bytes in tar
or 112 bytes in ZIP. Smaller ceilings refuse before source reads. Tar
admits 100,000 entries and ZIP admits 65,535, including the prefix. Both walks
are limited to 64 relative levels, 16 MiB of cumulative traversal-path bytes,
and 200,000 source reads. File reads use at most 1 MiB ranges, narrowed by the
remaining complete-output budget, with the existing per-file range bound.
Node object-read and command-time
limits also apply; archive limits do not override them. A declared file size is
checked against the remaining output allowance before assembling that file.
The shared ZIP builder reserves both copies of each name, the entire central
directory and the end record before accepting payload bytes. Duplicate names,
directory payloads and unrepresentable fields refuse before appending that
member. Finishing returns only a complete stream; the low-level builder grants
no source authority or host-write permission. The CLI rechecks its original
request lifetime after encoding, before the shutdown/publication barrier.

Focused native selectors are:

```sh
cargo test -p fgit-treefs --test archive
cargo test -p fgit-forge source_archive
cargo test -p fgit-cli --bin fg source_browse
cargo test -p fgit-cli --test native_source_browse_smoke
cargo test -p fgit-node --lib smart_http::server::source::archive
cargo test -p fgit-node --test source_archive_http
```

Shared archive assembly tests cover both native hash domains, subtree selection,
page-size-independent bytes, parent-selected object identities, file ranges,
non-UTF-8 names, executable modes, safe links, opaque gitlinks, malformed pages,
source movement, cancellation, resource refusal and the shutdown barrier. These
are report-level tests, not node-authentication evidence. The ustar encoder is
also compared with an independent 3,072-byte Python `tarfile` reference fixture
containing executable bytes, a directory and a symlink.

The native HTTP tests exercise actual node imports and TCP requests in both hash
domains, fixed and chunked framing, source authentication, restart determinism,
safe-subtree export beside an unsupported link, stale snapshots, byte ceilings,
cancellation and no authority mutation. The HTTP tar parser independently checks
checksums, entry modes, duplicate names, padding and the final zero blocks;
shared collector tests check raw-name traversal order across page boundaries.

Browser tests under `tests/browser/source-archive*.test.mjs` cover bounded binary
collection, metadata/pin mismatches, aborts, truncation and stale-response
suppression. Their DOM and fetch doubles are not live-browser evidence.

ZIP assembly tests exercise both object formats, exact Unicode/binary payloads,
executable and symlink modes, gitlink directories, deterministic pagination,
subtree pins, unsafe/non-UTF-8 names, longer representable paths and links,
source movement, cancellation, byte bounds and the shutdown barrier. TreeFS
builder tests cover exact whole-stream limits, entry limits, empty ZIPs and
refused appends without corrupting accepted members.

The existing fresh-process native source-browse campaign additionally imports
real SHA-1/SHA-256 objects, exports ZIPs through `fg`, and checks them with
Python's independent `zipfile` reader, including CRCs, payloads, modes, fixed
timestamps, repeatability, no-overwrite behavior and stale-source refusal. Its
tar twin checks that an output extension does not change the default format.

At source revision
[`71c994b`](https://github.com/Dicklesworthstone/frankengit/commit/71c994b9abfb74addd8056636890519dbbca6efe),
the actual TreeFS archive integration target passed **10 tests**, including all
three new builder cases. An isolated production-source harness passed **22 archive
component tests**, including all five new ZIP collector cases and the existing
ustar fixture, source-pin, range and typed-error checks. Both runs had no failures.

The archive harness used the original source-browse types, collector, encoders,
checked-in tests and fixture in their normal module layout, without replacement
DTOs or rewritten logic. Its 36 registry dependencies matched the repository
lockfile's versions and checksums. The toolchain was the pinned
`nightly-2026-08-31`; first-party and external optimization settings matched the
workspace. This is component evidence, not a full forge-crate test result.

The native CLI campaign, CLI argument tests and OneNode/HTTP/browser campaigns
were not executed in this session. A production CLI check was interrupted and
reaped with exit 130 after progress stalled under host memory pressure, before
any source compiler diagnostic arrived. Full node/CLI compilation and native
interoperability therefore remain unqualified. The component results establish
neither full Git archive compatibility nor roadmap closure.
