# Source tree archives

`fg tree --output` and the authenticated HTTP source archive endpoint export a
complete, authority-selected source directory as a POSIX ustar file. It is the bounded source-archive slice of the archive
creation target in [the compatibility matrix](GIT_COMPATIBILITY_MATRIX.md), not
a Git bundle, repository capsule, backup, or canonical repository mutation.

```sh
fg tree ./fgit-data TENANT_ID REPOSITORY_ID --trusted-local \
  --ref refs/heads/main --output ./source.tar

# Export only this directory, with independently reviewed native identity.
fg tree ./fgit-data TENANT_ID REPOSITORY_ID --trusted-local \
  --ref refs/heads/main --path crates --expected-commit NATIVE_OID \
  --object-format sha256 --output ./crates.tar
```

The output path must not exist. Directory pagination follows `--limit` (1–1000,
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

The CLI JSON receipt is `source_tree_export`, schema 1, profile `ustar-source-v1`.
It includes source pins, selected subtree, original path bytes, counts and the
archive size. `repository_changed:false` distinguishes creating the operator's
local output file from publishing repository authority.

## Byte and extraction profile

Every archive has one `source/` prefix. Directories precede their children in
raw-name depth-first order. Regular files retain exact bytes, including binary
and empty payloads. Git executables use mode 0755; other regular files use 0644,
directories 0755, and symlinks 0777. UID, GID and timestamps are zero, owner names
are empty, and the archive ends with two zero blocks. There is no dependence on
the exporting host's clock, ownership, locale or filesystem ordering.

Symlinks are encoded as links and are never followed by the exporter. This
closed profile accepts only nonempty relative link targets of at most 100 bytes,
without NUL, backslash, colon or any `..` component. Parent traversal is refused
even when lexical normalization appears contained: preceding symlinks could
change its meaning. Unsupported links refuse the whole archive rather than
being silently dereferenced, rewritten or omitted. Treat extraction of untrusted
archives as a separate operation and use an empty, appropriately isolated target.

Gitlinks become empty directories. Their contents belong to a different
repository and are never fetched. The receipt reports `gitlink_directories` and
`submodules_materialized:false`; the source commit remains the reference for the
original gitlink OIDs. There is no `.git` metadata, Git history, forge state,
credential delegation, or submodule working tree in this source archive.

Names retain raw bytes, including non-UTF-8 bytes, within the exact ustar
100-byte name / 155-byte prefix fields. Directory headers include a trailing
slash. Paths that cannot be represented without truncation refuse. Empty, dot,
parent, `.git` (case-insensitive), NUL, backslash, colon and slash-containing
individual components refuse. No GNU long-name or PAX fallback changes encoding.

This is an exact source-tree export, **not full `git archive` compatibility**.
`export-ignore`, `export-subst`, pathspec rewriting, timestamps from commit
metadata, compression, ZIP and the Git `upload-archive` protocol are not
implemented by this profile. Git attributes are included as ordinary source bytes, not executed.

## Bounds and tests

The whole artifact, including tar framing, is limited to 128 MiB. HTTP further
intersects this with the configured response ceiling before collecting file
contents. Even an empty directory requires 1,536 bytes; smaller response ceilings
refuse before source reads. The walk is
limited to 100,000 entries including the prefix, 64 relative levels, 16 MiB of
cumulative traversal-path bytes, and 200,000 source reads. File reads use 1 MiB
ranges and the existing per-file range bound. Node object-read and command-time
limits also apply; archive limits do not override them. A declared file size is
checked against the remaining output allowance before assembling that file.

Focused native selectors are:

```sh
cargo test -p fgit-forge source_archive
cargo test -p fgit-cli --bin fg source_browse
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

The implementation's pinned native build was interrupted by an unavailable
execution host before a test result could be observed. Central Rust verification
and live-browser interoperability remain pending. Included tests, source review
and an independently parseable fixture do not establish a passing runtime gate,
full Git archive compatibility or roadmap closure.
