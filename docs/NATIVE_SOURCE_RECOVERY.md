# Native bare Git source recovery

Related: `frankengit-root-doctrine-x2mv.4.21` and `.4.44`, comprehensive plan
sections 21 and 23. This materializes Git source, not FrankenGit authority,
forge events, credentials, a complete capsule, or a currentness assertion.

## Recover directly with `fg`

```sh
fg bundle recover backup.bundle recovered.git \
  --trusted-local --head-ref refs/heads/main \
  --expect-sha256 "$INDEPENDENT_BUNDLE_SHA256"

# After interruption or a lost result, keep the same input and destination.
fg bundle recover backup.bundle recovered.git \
  --trusted-local --head-ref refs/heads/main \
  --expect-sha256 "$INDEPENDENT_BUNDLE_SHA256" --resume
```

`fg bundle recover` invokes the existing Rust verifier and recovery planner
directly. It does not need a Git executable, JavaScript engine, running node,
network, tenant, principal, or canonical authority. The result is an ordinary
bare Git repository. The source bundle and destination parent must be quiescent
and operator controlled. The filesystem profile currently requires Unix
regular-file identity, file/directory synchronization and create-only hard links;
other platforms refuse before destination creation. Path-based standard-library
I/O is not a sandbox against an adversarial same-user namespace.

An explicit advertised `refs/heads/...` branch selects HEAD. Use
`--head-ref-hex` for raw-byte names, including names that are not UTF-8. Ref
names become packed-refs and HEAD contents, never host filesystem paths. The
parser accepts the verifier's independent hash/reference pins, exact reference
set constraints, input/expanded/object/reference limits, and one cooperative
read/verification/publication deadline. `--` introduces the two literal paths.
An explicitly selected global `fg --timeout-secs` policy also applies; the
shorter of that policy and the command's local limit bounds the whole operation,
including resume. Without a global override, the local 1..3600-second selection
applies directly (300 seconds by default).
The native 128 MiB input and expanded-payload ceilings remain in force; this is
not a streaming large-repository restore.

### Publication and resume

All bundle bytes, object dependencies, reference targets and derived index
bytes are verified before creating the destination. Fresh recovery requires a
nonexistent destination and creates it with owner-only permissions. An existing
file, symlink, or even empty directory is never reused without explicit resume.
Destination components must not be `.` or `..`; supply its direct relative or
absolute path. The check uses the original path spelling before normalization.

The retained `.frankengit-native-source-recovery` record binds the exact
artifact SHA-256, object format, selected raw HEAD name, pack checksum and
materialization profile. It identifies local work; it is unsigned and grants no
source authenticity. Resume first recomputes the complete native plan from the
same verified input and compares the recovery record and every existing body.
Removing independently trusted command-line pins does not make this local
record an independent trust anchor.

The writer has a closed set of generated paths: the record, one pack and idx
under `objects/pack/`, packed-refs, config, HEAD, and their fixed private staging
names. It creates the empty `refs/` directory required by an ordinary bare Git
repository. Existing final files must match byte-for-byte. A staging file may
contain only an exact prefix of its freshly verified expected body; the writer
appends the remainder, synchronizes it and reads it back. It never truncates,
replaces or reinterprets an existing body. Symlinks, unexpected entries,
permissive modes, namespace substitutions, and unowned hard links refuse.

Each complete body is installed by a create-only hard link. The pack, index,
packed refs, config and their directories are synchronized before HEAD is
linked. The writer then synchronizes the publication directory and its parent.
Only that completed sequence produces a success report with `state: durable`.
This is acknowledgement of the selected local filesystem calls, not evidence
for an untested power-loss or remote-filesystem durability profile.

Errors distinguish `unchanged`, `staged`, `publication_uncertain`, `published`
and `durable`. Resume starts with publication uncertainty until the destination
can be inspected: input verification failures, an early cancellation, or a
changed private-directory mode cannot rule out a previous publication. Input
read and verification refusals also report that this attempt made no destination
writes. The destination is still inspected only after verifying the input.
An existing HEAD is observed before inspecting resume records or unrelated
entries: corruption cannot hide the fact that a publication root is already
visible. A HEAD with missing dependencies refuses
without filling them in around a live repository. A failure after linking HEAD
never means rollback. Explicit resume verifies and synchronizes all complete
bodies before acknowledging a repeated result; `already_published` identifies
that case. Output failure after successful materialization reports the durable
state so the caller can recover the result through resume.

Keep interrupted directories. There is no recursive cleanup, automatic
overwrite, or stale-lock breaking. Only an exactly identified staging hard
link is removed after its final body is installed. A crash before the complete
recovery record is installed leaves an unidentified directory, which resume
refuses; the original bundle remains usable with a different new destination.
After completed recovery, its identity record stays available for exact retry.
Ordinary Git mutations subsequently made in the recovered repository can cause
this strict recovery resume profile to refuse, preserving the user's work.

Success emits `git_bundle_recovery`, schema version 1, with profile
`native-bare-source-recovery-v1`. It reports the artifact, pack, exact references,
selected HEAD, record hash, publication state and resume status. Forge state,
authority, signatures, origin authentication, branch currentness and external
gitlink targets remain explicit non-claims. This is a source materialization
and does not complete the signed capsule/authority backup obligation in `.4.21`.

## Read-only native preparation

`fg bundle verify INPUT.bundle --recovery-head-hex HEX` adds an explicitly
requested `recovery` object to the existing verification JSON. HEX is the
lowercase hexadecimal spelling of a full advertised `refs/heads/...` name.
Existing verification without that flag keeps its original report shape.

The native engine validates the full bundle, every reconstructed object and
all typed local graph dependencies once. The same resolver supplies the exact
pack offsets and native IDs used to construct idx-v2. A forward REF_DELTA does
not borrow a base from another repository. The original pack is preserved,
not repacked. The derived index includes exact encoded-entry CRCs and native
pack/index trailers. `fgit-pack` owns its encoding; the existing native idx
reader checks its structure and checksum before return.

The additional object uses profile `native-bare-source-layout-v1`, a
`pack_offset` into the verified input, and `head_ref_hex`, `index_hex`,
`packed_refs_hex`, `config_hex`, `head_hex`. No arbitrary output path or
configuration directive is accepted from the bundle. All refs remain raw
bytes inside packed-refs; HEAD names the explicitly selected advertised branch.
Prefix-overlapping namespaces refuse instead of producing an unmaintainable
repository. Native SHA-1/SHA-256 identities remain separate domains.

Preparation is read-only. A filesystem owner must reserve a new or exactly
identified recovery directory, stage/sync/read back the index, pack and metadata,
then publish HEAD last. A content-verification report alone never authorizes
writing over an existing repository or resolving a publication uncertainty.

Input/expanded/object/reference limits and cancellation retain the existing
native verifier boundaries. Index output also obeys the selected pack byte and
index-entry ceilings. The CLI bounds the complete layout report to 16 MiB and
checks cancellation while hex-encoding metadata. There is no streaming claim;
input and index/metadata consume separately bounded memory.

## Evidence boundary

The production filesystem module has a dependency-free integration harness:

```sh
rustc --edition=2024 --test crates/fgit-cli/tests/bundle_recovery_filesystem.rs \
  -o /your/private/target/bundle-recovery-filesystem-tests
/your/private/target/bundle-recovery-filesystem-tests
```

Use the dated compiler pinned in `rust-toolchain.toml`. This compiles the actual
writer, without a mock Git parser or alternative runtime. Its synthetic bodies
test filesystem ownership, every cooperative interruption point, prefix resume,
publication ordering, hard-link/namespace checks and preservation on refusal.
These component tests do not establish native Git compatibility. The separate
`bundle_recovery` integration target runs the real `fg` binary with Git and
JavaScript absent from PATH, verifies SHA-1/SHA-256 original packs and independent
index goldens, and exercises fresh-process exact retry and interrupted resume.
Those commands describe the available tests; their execution must be bound to
the tested revision before making a verification claim.

The fixed fixtures in `tests/fixtures/native_bundle_recovery/` were independently
encoded and checked with Git 2.47.3: bundle verification, fetch, strict fsck and
reading the recovered file succeeded for SHA-1 and SHA-256. Their idx goldens
are the bytes emitted by that Git's `index-pack --index-version=2`. Both packs
contain a REF_DELTA before its base and an annotated tag.

The native plan tests cover those exact bytes, coordinate/domain/duplicate
refusals, index limits, cancellation, raw ref names, namespace conflicts and
matched-pin/graph checks. Fixture-oracle success alone is not native Rust
execution, power-loss durability, a full-workspace gate or a bead closure.
Full command acceptance still requires a built `fg` at the tested SHA.
