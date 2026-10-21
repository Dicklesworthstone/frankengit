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
On macOS, invalid UTF-8 scope paths refuse with
`source_workspace_scan_host_path_unrepresentable` before filesystem I/O. Such a
name cannot be reported as absent merely because the host returns `ENOENT`.
Linux retains the arbitrary-byte profile, and no path is normalized or decoded
to make it representable.
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

## Capture exactly the reviewed changes

After reviewing `scan.json`, supply its independently retained `scan_sha256`.
There is no automatic refresh of scope, content, modes, or the path population:

```sh
node scripts/fg_source_workspace_scan.mjs capture \
  --workspace /srv/work --sha256 "$WORKSPACE_SHA256" \
  --scan /srv/review/scan.json --approve-scan-sha256 "$SCAN_SHA256" \
  --patch-profile bounded-line-hunks-v1 --output /srv/review/capture
```

Add `--byte-profile binary-safe-v1` explicitly for arbitrary file bytes. The
existing default remains NUL-free. These profile choices are retained by the
ordinary source-change request and draft, whose hash must still be reviewed
before native preparation. A scan hash does not approve a commit or a candidate.

The command first re-scans the **original scope** and requires the complete scan
to match. It then calls the existing `captureWorkspaceChanges` implementation,
which independently re-verifies the original source package, proves source-path
absence for creations, enforces all native-authoring limits, and writes its
normal root-last local draft. No new Git decoder, patch algorithm, repository
transaction, or publication key is introduced.

The selection includes exact post-edit `observations`: raw-byte SHA-256, size and
executable mode, or explicit absence, for every selected changed path. The
collector checks these against its own owned file reads **before** constructing
a draft. A file saved after preflight therefore cannot slip into a successful
capture. The ordinary offline capture inspector also reconstructs the selected
post-edit images from verified retained source and changes, then checks these
observations. Changing local checksums cannot excuse mismatching observation
bytes. Original explicit path selections omit this new optional field entirely;
their previous payloads, hashes, defaults and behavior remain unchanged.

The result has type `source_workspace_scan_capture` and contains the existing
capture receipt under `capture`, plus the reviewed scan hash and discovery scope.
The nested `capture` receipt's `selected_files_only` and
`unselected_paths_examined` fields describe the **capture**, not the preceding
explicit directory scan. Its `capture_sha256` and `draft_sha256` remain the
ordinary hashes consumed by existing capture inspection and authoring commands.

The scan can report more changes than a single capture permits. Capture still
requires 1–32 selected changes and retains the existing 1 MiB file, 4 MiB
before/after, 1 MiB patch and selection/payload bounds. It never quietly takes the
first 32 changes. A new file not covered by an authenticated absence proof refuses,
even though the scanner discovered it. Later additions are not silently appended
to the approved path list. This is exact selected-byte capture, not a globally
atomic filesystem snapshot.

For a separate review/capture process, `select` emits the compatible guarded path
selection, without writing a capture:

```sh
node scripts/fg_source_workspace_scan.mjs select \
  --workspace /srv/work --sha256 "$WORKSPACE_SHA256" \
  --scan /srv/review/scan.json --approve-scan-sha256 "$SCAN_SHA256" \
  --patch-profile bounded-line-hunks-v1 > /srv/review/paths.json
node scripts/fg_source_workspace.mjs capture \
  --workspace /srv/work --sha256 "$WORKSPACE_SHA256" \
  --paths /srv/review/paths.json --output /srv/review/capture
```

Both new commands use one shared operation deadline. Cancellation stops new work;
the existing writer drains an already-started root publication. Exit 4 means a
local capture may exist or its completed receipt could not be printed. Retain
that output slot and reported pin; inspect it rather than deleting it to force
a retry. No command submits a repository mutation or grants merge permission.

Run the complete focused lane:

```sh
bash scripts/verify_source_workspace_scan.sh
```

In addition to the real filesystem and scan/select CLI tests, the capture suite
executes the actual production collector/writer/offline inspector with explicit
fixtures for their pre-existing workspace and native authoring service boundaries.
It checks retained observation bytes, unchanged legacy selections, no output or
build after a post-review change, proof-before-read ordering for new paths,
offline inspection without the original workspace, and tampered observation
rejection even after local checksums are recalculated. The service-boundary
fixtures do **not** establish native membership verification, Git tree derivation,
native `fg` server publication, or full-workspace correctness.
