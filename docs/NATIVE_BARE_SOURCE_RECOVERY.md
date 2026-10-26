# Native bare-source recovery

Related: `frankengit-root-doctrine-x2mv.4.21` and `.4.44`, comprehensive plan
sections 21 and 23. This materializes portable Git source, not forge state or a
FrankenGit authority capsule. Native object/pack semantics remain in Rust.

The existing filesystem recovery owner now accepts an explicit native backend:

```js
import { recoverGitBundle } from './scripts/lib/source-recovery.mjs';

const result = await recoverGitBundle(bundleBytes, newDirectory, {
  head_ref_hex: Buffer.from('refs/heads/main').toString('hex'),
  expectations: { sha256: independentlyKnownBundleHash },
}, {
  nativeFg: '/absolute/path/to/trusted/fg',
  timeoutMs: 300000,
  resume: false,
});
```

`nativeFg` must name an operator-trusted absolute-path executable. An explicitly
supplied invalid value refuses; it does not choose another backend. The native
path never imports the JavaScript Git decoder and never falls back after a
missing executable, cancelled process, invalid report or content refusal.
Without `nativeFg`, existing callers retain the legacy preparation backend.
Legacy `verificationLimits` are not silently accepted as native limits.

## Verification and publication

The adapter copies input and constraints before yielding. It invokes the existing
`fg bundle verify --recovery-head-hex` command on a private snapshot with an exact
SHA-256 input pin and all supplied independent constraints. Rust validates the
bundle, resolves objects and the typed graph, and derives an idx-v2 plus bare
metadata from that same verification pass. No installed Git or shell is invoked
in production. The executable's authenticity is the operator's responsibility.

The adapter checks the native report, pack/index checksum binding, exact selected
HEAD, fixed safe config and packed-ref bytes against the reported references.
All output paths are fixed or derived solely from a validated hexadecimal pack
checksum; native reference bytes occur only inside metadata files. There is no
second JavaScript index, object or delta decoder. A deterministic plan binds the
source hash, hash domain, selected branch, caller constraints and every file's
bytes. A new native-specific plan schema prevents cross-backend resume.

The existing recovery owner exclusively reserves a private destination, stages
and synchronizes pack, idx, packed-refs and config, independently reads back the
files, and installs HEAD last without replacement. Cancellation before publication
retains the stage. Cancellation after HEAD cannot roll it back. Progress callback
or I/O errors report the current publication state, not a fabricated rollback.

`resume: true` re-verifies input, regenerates the exact plan, checks every retained
byte and acquires the existing append-only ownership lease. Active or unknown
owners refuse. Completed bytes are synchronized again; partial matching files
may be appended but never truncated or replaced. Changed source, constraints,
metadata or unexpected files refuse. Resuming a completed recovery does not
replace HEAD. Same host/PID namespace and an operator-controlled quiescent local
filesystem are required; this is not a hostile same-user namespace sandbox.

The owned-byte profile accepts at most 16 MiB input, 128 MiB expanded native payload,
100,000 objects, 4,096 refs and a 16 MiB native layout report. It retains input and
layout bytes in memory. Filesystem operations and synchronous work remain
cooperative; cancellation of a native child terminates, escalates and reaps it.
No current-branch, Git-signature, external-gitlink, forge/authority restoration or
power-loss guarantee is inferred from source-content verification.

## File-backed recovery with the same filesystem owner

The file API streams a larger native-verified pack through the existing recovery
writer, including its ownership leases and HEAD-last publication:

```js
import { recoverGitBundleFile } from './scripts/lib/source-recovery.mjs';

const result = await recoverGitBundleFile('./backup.bundle', './restored.git', {
  head_ref_hex: Buffer.from('refs/heads/main').toString('hex'),
  expectations: { sha256: independentlyKnownBundleHash },
}, {
  nativeFg: '/absolute/path/to/trusted/fg',
  nativeLimits: { maxInputMiB: 4096, maxExpandedMiB: 8192, maxBlobMiB: 512 },
  timeoutMs: 1800000,
  resume: false,
});
```

Input, expansion and streamed-blob allowances can be selected independently
from 1 through 16,384 MiB. Defaults remain 16 MiB input, 128 MiB expanded payload,
32 MiB per streamed blob and 60 seconds; the file API permits up to one hour.
The blob allowance does not raise total expansion, object/reference counts,
metadata or native work limits. Metadata objects and delta programs retain the
32 MiB buffered-object bound. Larger blob delta bases/results use authenticated
scratch chunks and one bounded base-block index; actual random reads consume
the shared work budget. The owned-byte API keeps its previous limits.

The adapter copies a stable local file into an exclusive private snapshot in
64 KiB chunks and verifies that snapshot with the existing Rust file-backed
verifier and recovery planner. Native scratch must be gone before the filesystem
owner is invoked. Only the pack is streamed during materialization; the bounded
index and bare metadata remain in memory. The original source path is never
reopened for writing or readback.

Each complete pack replay checks length, SHA-256, the native pack checksum and
snapshot identity. Comparing an existing partial pack drains the verified source
through EOF before the owner can append. Every destination readback compares
exact bytes; mismatch never truncates or replaces retained work. For a new recovery, an observed source change during capture, mutation of the
retained snapshot, resource exhaustion or cancellation before publication leaves
any created stage inspectable with HEAD absent. Once HEAD is visible, the same owner finishes its
synchronization and lease cleanup even when cancellation has been requested.

The canonical v1 plan, marker and expectation/approval binding are unchanged.
For input admitted by both profiles, the same source, HEAD, caller constraints
and approval produce the same plan identity. An explicit resume may therefore
continue a matching memory-backed operation in file mode or vice versa. A saved
marker never substitutes for fresh input verification or external approval.

Library callers composing authentication can pass `nativeArtifact: { sha256,
bytes }` and the existing `nativeApprovalBinding`. The artifact constraints must
match before any destination writes. They are integrity constraints, not a
signature verifier; the caller remains responsible for authenticating its
approval and enforcing freshness through the existing prepublication callbacks.

Preparation needs the private input snapshot plus native scratch of up to twice
the selected expanded allowance. During publication, the snapshot remains open
alongside the destination pack until the writer finishes. Cleanup removes only
the identified snapshot and empty owned directories. Unexpected residue is
retained. A cleanup error after publication preserves the recovery state and
reports `snapshot_cleanup_error` and `snapshot_directory`; it never reports a
rollback or removes the recovered repository.

## Executable evidence

```sh
node --test tests/operator/native-source-layout.test.mjs \
  tests/operator/native-source-recovery.test.mjs \
  tests/operator/native-file-source-recovery.test.mjs
FG_NATIVE_BIN="$PWD/target/release/fg" \
  node --test tests/operator/native-source-recovery.test.mjs \
    tests/operator/native-file-source-recovery.test.mjs
```

Default tests use an explicitly fake native process returning repository fixtures.
They execute the actual adapter and filesystem owner, including process kills
before and after HEAD publication, competing writers, exact resume, corruption
refusal and cancellation. When `/usr/bin/git` is exactly version 2.47.3, the oracle reads the resulting
SHA-1 and SHA-256 materializations, runs strict fsck and checks contents and tag
peeling; otherwise those oracle cases explicitly skip.
The SHA-256 index fixture matches the pre-existing metadata.json SHA-256 golden.
This demonstrates fixture interoperability, not Rust execution. The separate
actual-fg test is explicitly skipped unless a built `FG_NATIVE_BIN` is supplied.

## Operator command, including signed recovery

```sh
node scripts/recover_git_bundle.mjs backup.bundle ./restored.git \
  --native-fg "$PWD/target/release/fg" --head refs/heads/main \
  --native-timeout-secs 300 \
  --attestation backup.dsse.json --trust-key trusted-ed25519.pem \
  --repository owner/project --minimum-sequence 42
```

For a larger source backup, select file-backed recovery and explicit allowances:

```sh
node scripts/recover_git_bundle.mjs backup.bundle ./restored.git \
  --native-fg "$PWD/target/release/fg" --native-file-backed \
  --native-max-input-mib 4096 --native-max-expanded-mib 8192 \
  --native-max-blob-mib 512 --native-timeout-secs 1800 --head refs/heads/main \
  --attestation backup.dsse.json --trust-key trusted-ed25519.pem \
  --repository owner/project --minimum-sequence 42
```

All three byte-limit flags require both `--native-fg` and `--native-file-backed`.
They can precede or follow the mode flag; all options are validated before
opening command files. Values must be canonical positive decimal integers.
Defaults remain 16 MiB input, 128 MiB expanded data and 32 MiB per streamed blob.
Each selected ceiling can be at most 16,384 MiB. `--native-max-blob-mib` permits
larger blobs and blob delta bases/results without whole-body allocations.
Metadata and delta programs retain their 32 MiB memory bound; input, expansion
and reconstruction work remain separate allowances. No approval raises a ceiling.

The four approval arguments remain an all-or-nothing group. The unchanged
Ed25519/DSSE verifier checks the independently trusted key, source repository,
full-width sequence floor, lifetime, length and artifact hash before any native
process or destination write. The native engine receives only an owned snapshot
of those authenticated bytes, never the original input or approval/key paths.
Independent `--expect-*` pins still apply. To recover unsigned source, omit the
entire approval group; the content checks are identical but do not authenticate
an origin. Without `--native-fg`, legacy preparation remains the default.

One deadline covers authentication, reads, native preparation and filesystem
publication: 1..300 seconds for the owned-byte native path, or 1..3600 seconds
for file-backed recovery, with a 60-second default for both. Expired or cancelled
work does not gain a fresh budget at a stage boundary. Native child cancellation
terminates, escalates and waits for closure; filesystem work is cooperative.
Approval is checked again
after native verification and at the last prepublication notification, after
readback and immediately before the final liveness check and HEAD link. There is
no claim of atomic wall-clock expiry enforcement across a blocking kernel call.

Signed file-backed recovery authenticates captured, bounded approval/key bytes
before opening the source. The signed length is checked before source allocation
or native execution, and the signed digest binds the one private snapshot used
for verification and every pack replay. A conflicting independent digest refuses
before opening the source. Reauthentication uses the original captured controls;
replacing approval or key paths during a run cannot change its permission.

Add `--resume` with the **same source, branch, pins and approval arguments** to
continue an interrupted operation. Native signed plans additionally bind the
verified approval statement, trusted-key identity and exact repository/sequence
policy into the saved plan. An omitted approval, different signer, changed
statement or lowered floor cannot regenerate that plan. A marker supplies no
trust: every signed invocation reauthenticates against the explicitly supplied
key and policy. Library callers can provide `nativeApprovalBinding` (a SHA-256
hex digest) for this identity binding, but the digest itself is not verification
or permission; only the signed command composes it with authentication checks.

Native plans made by the earlier unsigned library entry retain the same bytes.
Signed native plans cannot be resumed as unsigned or as legacy plans. No automatic
backend migration or retry exists. A failure before inspecting a resume target
reports `existing_unknown`; it never claims the existing HEAD was rolled back.
A failed or expired signature cannot undo a prior published HEAD.

After HEAD becomes visible, expiry, cancellation or a throwing progress observer
cannot skip the owner's remaining directory synchronization and staging/lease
cleanup. Observer errors are reported after finalization; the published directory
is retained. A failed output pipe reports failure, not non-publication.

```sh
node --test tests/operator/native-recovery-command.test.mjs \
  tests/operator/native-source-layout.test.mjs \
  tests/operator/native-source-recovery.test.mjs \
  tests/operator/native-file-source-recovery.test.mjs
```

Command tests run the actual CLI, filesystem owner and real Ed25519 operations,
with a deliberately fake native-report process. A throwing import sentinel
establishes that explicit native selection never loads the legacy decoder. The
legacy-dispatch sentinel tests selection only, not Git semantics. These checks
are not Rust build/execution, power-loss or full repository verification evidence.
The file-backed command cases include a genuine fixture pack containing a
17 MiB blob, both native hash domains, exact signed resume across storage
profiles, refusal after prepublication approval expiry, and completion after
postpublication expiry. The native child remains explicitly fake in those
operator tests; optional `FG_NATIVE_BIN` tests exercise a supplied real build.
