# Trusted local workspace command

`fg workspace run` connects authenticated local repository reads, sparse TreeFS
materialization, one ordinary tool invocation, declared output import, native
Git object construction, and an incremental Git bundle. It is a candidate
preparation command: **it does not update repository refs, admit a merge, or
claim a successful repository transaction**.

The implementation is in `fgit-node/src/treefs_workspace/` and the CLI dispatch
is in `fgit-cli/src/workspace.rs`. This is the Linux local-operator profile. The
operator must already be authorized to read the whole repository, and the tool
must be trusted to run with the operator's host-user privileges. It is not an
untrusted agent endpoint or a hostile CI sandbox.

## Run a tool against selected inputs

Assume the local node at `./fgit-data` already contains a nonempty
`refs/heads/main` and that the tenant/repository IDs below identify that node.
The example materializes only `README.md`, appends a line, and emits a candidate
bundle without moving `main`:

```bash
workspace_parent=$(mktemp -d)

fg workspace run ./fgit-data \
  11111111111111111111111111111111 \
  22222222222222222222222222222222 \
  refs/heads/main \
  "$workspace_parent" \
  33333333333333333333333333333333 \
  candidate.bundle \
  --trusted-local \
  --read README.md \
  --write README.md \
  --author 'Operator <operator@example.invalid>' \
  --timestamp 1788883200 \
  --message 'Update README through TreeFS' \
  --timeout-secs 60 \
  -- /usr/bin/python3 -c \
  'from pathlib import Path; p = Path("README.md"); p.write_bytes(p.read_bytes() + b"\nUpdated through TreeFS.\n")'
```

Replace the author, timestamp, and message with the intended commit metadata.
The committer equals the supplied author, both dates use UTC, and no ambient
Git configuration or identity is consulted. The executable must be an absolute
path; argv after `--` is passed unchanged, not reparsed through a shell.

The parent must be an existing private directory accepted by the host adapter
(mode `0700`, caller-owned). The bundle name is a single new filename inside
that parent. An existing destination, including a symlink, is never replaced.
Each simultaneously active workspace needs a distinct 16-byte identity, written
as 32 lowercase hexadecimal characters. A retained workspace prevents reuse of
its slot until its containment state is resolved.

Read selections are **top-level files or directory prefixes**, not globs. For
example, `--read src` makes the selected `src` subtree available, while
`--write src/lib.rs --write src/generated.rs` admits only those exact output
files. A new root-level output requires both `--read new.txt` and
`--write new.txt`. Declared new directories are represented by a selected
prefix, with exact output file paths underneath it.

The tool's environment is cleared except for `PATH=/usr/bin:/bin`; stdin is
closed. Tool stdout and stderr go to the command's stderr so that stdout can
carry one JSON result. Unselected inputs are not materialized. This is a sparse
working directory, not an OS access boundary: a trusted tool still has ordinary
host-user filesystem/network privileges.

## Candidate output and review

Successful stdout is one JSON object with:

- `type: "workspace_candidate"` and `published_to_repository: false`;
- `object_format`, `source_commit`, and `source_rcr`;
- `candidate_commit`, `root_tree`, and the exact pack object count;
- `changed_paths_hex` in canonical path order and the bundle path.

Paths in the change list are hexadecimal raw repository-path bytes rather than
lossy Unicode conversions. Commit identity depends on the exact source commit,
result tree, and explicit commit metadata, not on the temporary workspace ID.

The output is a standard **Git bundle v3** with an explicit SHA-1 or SHA-256
object-format capability and the original source commit as a prerequisite. It
contains the candidate commit, changed blobs, and rebuilt trees. Unchanged
objects are reused from the prerequisite repository; this is not a standalone
clone of the repository.

A reviewer with a normal Git checkout containing that source history can
explicitly import the candidate into a separate review branch:

```bash
git bundle verify "$workspace_parent/candidate.bundle"
git fetch "$workspace_parent/candidate.bundle" \
  refs/heads/main:refs/heads/treefs-review
git diff main...treefs-review
```

These are reviewer commands, **not** programs invoked by FrankenGit. The
production path constructs all native objects and packs in Rust. The source
branch remains unchanged; merging or pushing the review branch is a separate
explicit operation.

## Preservation, failure, and cleanup

The exporter retains the exact original immutable base throughout the tool
operation. A concurrently moved source ref does not silently change the
candidate's parent. Later publication must independently revalidate authority
and policy; a candidate bundle is never publication authority.

Sparse listing must not cause data loss. The local operator retains full tree
scope for export while the tool receives only selected materialized inputs. The
lower-level `export_workspace_edits_in` API independently checks that every
rebuilt directory is fully disclosable to its caller; incomplete scope produces
`IncompleteWorkspaceExportScope`, without naming undisclosed siblings, rather
than dropping those siblings from the result tree.

Successful output import checks the actual declared files and read-only inputs
at quiescence. Writes, deletions, and owner-executable mode changes become typed
file intents. Modifying a materialized read-only input refuses the entire
candidate. Newly created undeclared files do not enter the candidate; they are
subject to the host adapter's bounded cleanup. Symlink/gitlink editing and
non-regular outputs are not supported by this command profile.

The tool must be a **foreground program that joins its own descendants before
exiting**. A normal successful exit permits output import. A normal nonzero exit
returns failure and reaps the workspace under that trusted-program contract.
On timeout, cancellation while the child is live, or signal death, the command
kills/waits for the direct child where applicable but cannot prove descendant
quiescence. It therefore reports containment and **retains the workspace**, not
a false clean shutdown. Do not remove a retained directory until its possible
users have been reconciled. There is no background job or automatic timeout
retry.

On ordinary completed paths, the descriptor-relative workspace lease and node
are explicitly closed before bundle publication. The file is written and
synced under a private temporary name, atomically linked to the previously
absent destination, and the directory is synced. A post-link failure reports
that output is already visible; failure to write stdout similarly reports that
the bundle exists rather than suggesting that rerunning can overwrite it.

## Current bounded profile

The command admits at most 1,024 input prefixes, 10,000 output paths, 128 argv
elements of at most 16 KiB each, and a positive wall budget no larger than one
hour (60 seconds by default). Sparse materialization is limited to 10,000
entries, 16 MiB per file, and 64 MiB retained payload. Source reads share a
256 MiB / 100,000-object fetch allowance; candidate construction and pack
emission have independent bounded envelopes. These are implemented ceilings,
not throughput or isolation guarantees.

The full agent capability broker, hostile-process isolation, configurable
service resource profiles, durable merge/outbox publication, and automatic
candidate admission remain outside this command.

## Verification commands and evidence boundary

The checked-in tests target the production node and CLI paths:

```bash
RCH_CARGO_WRAPPER_BYPASS=1 \
CARGO_TARGET_DIR=/data/frankengit-targets/workspace-command \
cargo test --locked -p fgit-node --test workspace_edit_export

RCH_CARGO_WRAPPER_BYPASS=1 \
CARGO_TARGET_DIR=/data/frankengit-targets/workspace-command \
cargo test --locked -p fgit-cli --bin fg

RCH_CARGO_WRAPPER_BYPASS=1 \
CARGO_TARGET_DIR=/data/frankengit-targets/workspace-command \
cargo build --locked -p fgit-cli

python3 scripts/e2e/workspace_tool_smoke.py \
  --fg /data/frankengit-targets/workspace-command/debug/fg
```

The Python smoke command invokes the actual supplied binary, imports nonempty
SHA-1 and SHA-256 repositories, runs a real tool, independently parses and
hashes every emitted pack object, checks unchanged-file preservation and exact
commit identity, repeats for deterministic output, reopens the node to compare
refs, and exercises trust/overwrite/undeclared-change refusals. It does not
invoke another Git engine and cannot pass by substituting prebuilt candidate
fixtures for the binary's output.

**At implementation time these Rust build/test commands and the full binary
smoke run were not executed: the editing environment had no Rust toolchain.**
Python syntax and the independent pack inspector were checked. A separate
Python-created bundle-envelope experiment passed installed Git 2.47.3's
verify/fetch operations for both object formats, but did not execute this Rust
implementation and is not pinned-client conformance evidence. Native execution,
formatting, Clippy, and independent batch verification remain required before
assigning verified capability credit.
