# Local source import size profiles

`fg import` uses bounded disk-backed quarantine for reachable native object
bodies. The complete required-kind graph validates before the first fabric
placement. Exact spool bytes are re-identified before immutable placement;
mutable source paths are never reread after validation. Ref publication still
uses the original sealed admission and authority-head compare-and-swap path.

The default reachable-body ceiling remains **512 MiB**. A trusted local operator
may explicitly choose a ceiling from 1 to 16,384 MiB:

```sh
fg import ./fgit-data \
  11111111111111111111111111111111 \
  22222222222222222222222222222222 \
  33333333333333333333333333333333 \
  migration-20261016 ./source.git --max-expanded-mib 1024 --json
```

The principal and idempotency key have their existing trusted-local semantics.
The byte limit does not become part of transaction identity: equivalent source
refs retried under another sufficient profile resolve the same terminal result.
A smaller limit can refuse before publication and leaves canonical refs unchanged.
An interruption during publication remains ambiguous; recover using `fg outcome`
or the original source and key, rather than assuming rollback.

The profile reserves one finite deadline/poll/cost allowance before source I/O,
using the existing receive work-scaling policy. `--timeout-secs` is a strict
wall-clock ceiling, not a base that the larger profile extends. No phase mints a
replacement context. The library exposes `import_request_context_with_byte_limit`
and `import_loose_git_directory_with_byte_limit_durable_in`; callers pass the same
byte ceiling to both, and smaller or cancelled caller contexts are still honored.

Packed sources use private disk custody too, and each pack is **streamed**
(frankengit-855v): it is never read whole into memory. One pass inflates each
member in turn and binds it to its idx row, by offset and CRC. A base member
is verified against its idx identity and spooled at once. A delta whose base is
already reconstructed is resolved at once, from the spooled and re-identified
base. Any other delta program, such as a REF_DELTA written before its base,
waits in a separate unverified spool. It is resolved after the trailer is
authenticated against the idx, in bounded passes that never fetch an outside
base. Resident memory is one inflated member, or one delta base, program and
result, whatever the pack size. Each verified pack retains offsets and native
types, never a map of resident bodies. A pack installs nothing unless all of
it verifies.

Cumulative inflated and retained native bytes are bounded by the selected
import profile. One reconstruction-work witness spans every pack, so opening
another pack never renews its delta-work allowance. That allowance follows the
profile too (frankengit-kxew): twice its bytes plus one unit per object. Each
member is reconstructed once and charged its base and result bytes. The former
fixed 256 MiB refused ordinary histories whose deltas fit the profile. Every decoded member
counts, including members not reachable from the selected refs. Compressed pack
input, per pack and in total, is bounded by **twice the selected profile, never
less than 128 MiB**: 1 GiB under the default 512 MiB profile. A pack whose
objects fit the profile exceeds it only through framing and DEFLATE expansion
of incompressible members. Independent limits remain: 64 MiB per `.idx` file,
64 MiB of indexes in total, the existing per-object limit, and finite object,
ref and graph-edge counts. The 16 GiB ceiling is an operator bound, not a
tested repository-size guarantee.

Quarantine uses one reachable-closure file plus at most one private file per
loaded pack (the existing maximum is 128 packs), never one file per object.
A pack with deltas that must wait for their base also holds one transient
program file while it loads.
Packed custody closes before placement starts. On Unix each exclusive 0600 file
is unlinked before payload writes; the owned descriptor survives until cleanup.
An interruption between creation and unlink can leave an empty name. Other
platforms remove exclusive filenames on normal cleanup without claiming crash
cleanup or isolation from a malicious local host. Scratch custody is not a
backup, resumable import or durability receipt. Disk exhaustion, damaged retained
bytes and failed cleanup refuse rather than publishing partially verified data.

## HEAD and the default branch

As on a Git server, a repository's HEAD is fixed when it is created.
`fg init` stages an unborn HEAD naming `refs/heads/main`.
`fg init ... --initial-branch <name>` names `refs/heads/<name>` instead, as
`git init -b` does. Import and push publish refs only and never change HEAD. A
source whose default branch is not `main` should therefore be imported into a
repository initialized with that branch, or clones of it check nothing out:

```sh
fg init ./fgit-data 11111111111111111111111111111111 22222222222222222222222222222222 \
  --initial-branch trunk
```

The name is a short branch name. It is checked more strictly than
`git init -b` checks it: `HEAD` and a leading `-` are refused, as `git branch`
refuses them, and a `refs/` prefix is refused rather than nested under
`refs/heads/`.

`--initial-branch` is refused together with `--creation-idempotency-key`. The
creation record does not seal the branch, so a retry could not detect a changed
one. A HEAD that names a branch which does not exist yet is served as upstream
serves it: no HEAD line in protocol v0, and `unborn HEAD symref-target:` in v2.

## Executable coverage

```sh
cargo test -p fgit-node --lib loose_import:: -- --test-threads=2
cargo test -p fgit-cli --bin fg import_command:: -- --test-threads=2
cargo test -p fgit-node --test large_loose_import -- --test-threads=1
FG_BIN=/path/to/fg bash scripts/e2e/suites/admission/import_profiles.sh
FG_BIN=/path/to/fg bash scripts/e2e/suites/admission/import_recovery.sh
```

The large integration target contains a 288 MiB default-profile round trip and
an explicit-profile 576 MiB round trip. Both use real durable admission, remove
the source directory, reopen the node, and re-verify exact native objects and refs.
The binary suite pairs a 1 MiB refusal with a 4 MiB admission for the same 2 MiB
source in SHA-1 and SHA-256, then checks larger-profile and default-profile replay
and source-free outcome recovery. Test presence is not a completed batch gate;
executed results remain revision-bound.

## Packed-source regression campaign

```sh
FG_BIN=/path/to/fg bash scripts/e2e/suites/admission/packed_import_profiles.sh
FG_BIN=/path/to/fg FG_PACKED_LARGE=1 bash scripts/e2e/suites/admission/packed_import_profiles.sh
```

The default campaign constructs three native packs in each hash format and tests
an insufficient limit, admitted refs, source removal, cold integrity and original
key recovery. The opt-in cases contain 144 MiB of blob payload in three compressed
packs, and 72 MiB of incompressible blobs in ONE git-written pack over the former
64 MiB per-pack wall (frankengit-855v). An optional `FG_PACKED_BASELINE_BIN`
records the pre-custody implementation's 128 MiB refusal of the first, and
`FG_PACKED_SINGLE_BASELINE_BIN` the pre-streaming 64 MiB refusal of the second,
using the identical sources. This script's presence is not evidence
that it has run. The module tests independently exercise disk-custody reuse after
source deletion, complete-pack charging, per-pack bounds, a corrupt later pack,
and preservation of operation-wide reconstruction work.
