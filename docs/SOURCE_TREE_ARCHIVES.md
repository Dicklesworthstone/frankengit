# Source tree archives

`fg tree --output` exports a complete, authority-selected source directory as a
new POSIX ustar file. It is the bounded source-archive slice of the archive
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

## Source and publication boundaries

The first verified source read fixes the repository authority head, RCR, native
commit, and repository root tree. Every subsequent directory page and file range
must match those pins, and every child read must match the native object identity
and entry kind supplied by its parent. Exporting a subdirectory retains both the
repository root tree and the separately selected subtree identity.

A source movement, hidden reference, missing object, inconsistent continuation,
cancellation or exhausted read budget refuses the entire export. No alternate
ref, ambient object lookup, local checkout or external Git engine is used. The
complete walk shares one command request context, including its timeout.

Only after every read and explicit node shutdown succeeds does the existing
no-overwrite file publisher expose the finished archive. Failures before that
barrier expose no archive. An output-publication error may require checking the
named path; a failure to print the completion receipt after publication does not
undo the complete file. No successful receipt is printed for partial output.

The JSON receipt is `source_tree_export`, schema 1, profile `ustar-source-v1`.
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
metadata, compression, ZIP and remote archive transport are not implemented by
this command. Git attributes are included as ordinary source bytes, not executed.

## Bounds and tests

The whole artifact, including tar framing, is limited to 128 MiB; the walk is
limited to 100,000 entries including the prefix, 64 relative levels, 16 MiB of
cumulative traversal-path bytes, and 200,000 source reads. File reads use 1 MiB
ranges and the existing per-file range bound. Node object-read and command-time
limits also apply; archive limits do not override them. A declared file size is
checked against the remaining output allowance before assembling that file.

The focused native test selector is:

```sh
cargo test -p fgit-cli --bin fg source_browse
```

Archive assembly tests cover both native hash domains, subtree selection,
page-size-independent bytes, parent-selected object identities, file ranges,
non-UTF-8 names, executable modes, safe links, opaque gitlinks, malformed pages,
source movement, cancellation, resource refusal and the shutdown barrier. These
are report-level tests, not node-authentication evidence. The ustar encoder is
also compared with an independent 3,072-byte Python `tarfile` reference fixture
containing executable bytes, a directory and a symlink.

The implementation session generated and parsed that fixture with Python, but
had no Cargo or Rust compiler. Native compilation and test execution are pending;
source inspection and an independently parseable fixture are not a passing
native test result or an end-to-end compatibility claim.
