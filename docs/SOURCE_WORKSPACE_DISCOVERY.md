# Discover local workspace changes by explicit directory scope

The external operator command `scripts/fg_source_workspace_scan.mjs` discovers
ordinary editor changes beneath explicitly selected directories in an existing
selected-source workspace. It reports modified files, mode changes, deletions
(including removed directories), unchanged files, and previously unselected local
files. Paths remain exact bytes. This is not the native Rust TreeFS runtime,
a full Git checkout, ignore-rule engine, authorization service or new authority.
It extends the host-editing workflow in `SOURCE_EDITING_WORKSPACES.md`; that
workflow's existing explicit-file capture command is unchanged.

## Scan and review

Use Node 22.16 or later on POSIX and retain the workspace hash returned by the
existing `fg_source_workspace.mjs create` or `expand` command independently.
Create an owner-private scope file; its parent must be a real `0700` directory:

```json
{"roots_hex":["737263"],"exclude_hex":["7372632f746172676574"],"include_unselected":false}
```

This selects `src/` and explicitly excludes `src/target/`. Roots name directories
below the workspace's `files/`, not host directories. The empty string explicitly
selects all of `files/`. Roots cannot overlap; exclusions must be strict
subtrees of a selected root. No `.gitignore`, workflow, repository text or filename
extension can broaden or narrow the scope. No directory is selected by default.

```sh
umask 077
node scripts/fg_source_workspace_scan.mjs scan \
  --workspace /srv/work --sha256 "$WORKSPACE_SHA256" \
  --scope /srv/review/scope.json > /srv/review/scan.json
```

The result contains `scan` and `scan_sha256`. The hash covers the exact canonical
JSON encoding of `scan` (one trailing newline), including the workspace directory,
original workspace hash, native source coordinates, scope and sorted entries.
Each entry records the baseline and observed raw-byte SHA-256, size and executable
mode, or explicit absence. File contents are not disclosed in the report. File
mtime/inode are stability checks, not identity: an identical atomic editor save
produces the same review hash. A byte, mode, path-set, baseline or scope change
does not. Different enumeration orders produce identical reports.

Unselected files are reported even when `include_unselected` is false, but they
are not selected for capture. Set it to true explicitly to include them. An
unselected local filename is **not** proof of absence in the native repository:
sparse source may omit an existing file. The existing capture/admission path must
still prove absence before constructing a creation. Nothing is inferred deleted
outside the selected, nonexcluded scope, and no rename is inferred.

## Safety and resource boundaries

The scanner verifies the independently retained workspace-manifest hash and the
source/expectation bytes committed by that manifest. It deliberately does not
implement a second Git object or membership decoder. Its report explicitly says
`native_membership_reverified: false`, `absence_verified: false`,
`complete_repository: false`, and `repository_changed: false`. Local custody
verification is not repository authority or permission to publish.

Directories must be owned by the current user and `0700`. Files must be regular,
owner-owned, singly linked and `0600` or `0700`. Symlinks, hardlinks, special files,
reserved/escaping paths and aliases refuse; symlinks are never traversed. Reads
use no-follow/nonblocking opens, bounded allocation, descriptor/named-file checks
and a final stability sweep. Parent directories must remain stable and trusted.
This catches observed concurrent changes, but is not an atomic filesystem snapshot
or protection from a hostile same-UID process manipulating ancestors.

Hard bounds: 4,096 enumerated entries (including excluded names), 256 directories,
256 local files, 1 MiB per local file, 16 MiB of local contents, 256 KiB of
accumulated discovered paths and a 256 KiB report. Existing baseline limits remain:
32 selected source files, 8 MiB logical source, 32 MiB encoded package, and bounded
128 KiB manifest/expectation inputs. The whole operation has one 30-second default
deadline, configurable through `--timeout-ms` up to 300 seconds. Every exhausted
bound refuses the whole scan instead of reporting a complete prefix. No history
is deleted and no file or repository state is changed.

## Executable evidence

```sh
node --test tests/operator/source_workspace_scan.test.mjs
```

The tests execute the production scanner, actual private POSIX files and the real
scan CLI. Inputs contain independently constructed SHA-1/SHA-256 native object
bytes in the existing workspace/package formats. Coverage includes raw byte
names, scoped omissions, removed parents, mode changes, binary contents, custody
corruption, unsafe links/permissions/FIFOs, deterministic ordering, every resource
bound, cancellation, changes during observation and independently pinned review.
These tests do not execute Rust `fg`, its authority/CAS, the native membership
verifier, a hostile runner or a hardware power-loss campaign. Related workspace
architecture: comprehensive plan section 17 and `GIT_TREE_FS.md`. No broader
workspace/TreeFS bead is closed by this host-adapter slice.
