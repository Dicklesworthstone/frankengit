# Native bundle verification from operator tools

Related work: `frankengit-root-doctrine-x2mv.4.21` and `.4.44`; plan sections
21 and 23. This is an offline source-content boundary, not capsule recovery.

```sh
node scripts/verify_git_bundle_native.mjs ./backup.bundle \
  --fg "$PWD/target/release/fg" \
  --expect-sha256 "$KNOWN_BUNDLE_SHA256" \
  --expect-format sha256 \
  --expect-ref "refs/heads/main=$KNOWN_COMMIT" --exact-refs
```

The operator explicitly selects an absolute path to a trusted native `fg` build.
The adapter invokes its existing `bundle verify` command without a shell or
PATH lookup. The Rust verifier owns bundle, pack, DEFLATE, delta, object and
closure semantics. Failure never invokes the JavaScript decoder or another Git
engine. The executable's authenticity is an operator responsibility; an output
profile string is not a build signature or proof against a malicious executable.

The source must be one nonempty, quiescent regular non-symlink file. An exclusive
private snapshot supplies the checked bytes to the child. The default profile
first reads the source into owned memory; the explicit file-backed profile below
copies and hashes it incrementally. The child always receives the snapshot's
SHA-256 as an input pin.
Independently supplied pins must additionally match. The parent validates the
native report's profile, object format, snapshot hash and length, verification
flags, reference pins, echoed expectations and explicit non-claims. It rejects
malformed, duplicate-key, extra-document, lossy-number and oversized reports.

Defaults are 128 MiB input, 128 MiB expanded native payload, 32 MiB per blob, 100,000 objects,
4,096 references, a two-MiB report and one 300-second deadline. The public adapter
can lower the report budget or select up to eight MiB. The default profile holds
input in memory and retains its 128 MiB input and expansion ceilings. Parent and
child memory both count when provisioning the host.

## File-backed verification

Select file-backed processing explicitly to verify larger portable bundles:

```sh
node scripts/verify_git_bundle_native.mjs ./large.bundle \
  --fg "$PWD/target/release/fg" --file-backed \
  --max-input-mib 4096 --max-expanded-mib 8192 --max-blob-mib 1024 \
  --timeout-secs 1800 \
  --expect-sha256 "$KNOWN_BUNDLE_SHA256"
```

This permits input, expanded-payload and streamed-blob limits up to 16,384
MiB each. Selecting the mode alone leaves the input/expanded defaults at 128 MiB
and the blob default at 32 MiB; each larger allowance must be requested explicitly.
The blob allowance is independent: increasing it never increases total expansion,
buffered metadata, delta-program, object-count, reference or report budgets.
Blob delta bases/results above the ordinary memory cap use authenticated scratch
chunks and a bounded block-hash index. Every physical random read is charged to
the shared work budget. A blob must fit its own allowance and the aggregate budget.

The public `verifyNativeGitBundleFile` adapter accepts `fileBacked: true` and
`maxBlobMiB`. The byte-array API retains its original limits and refuses the
file-backed profile. Native `fg bundle verify` and `fg bundle recover` share the
same `--max-blob-mib` setting, which requires `--file-backed --scratch-dir DIR`.

The parent reads at most 64 KiB at a time into one reusable data buffer, hashes
each chunk and writes it into its exclusive private snapshot. It checks source
length, EOF, descriptor and pathname identity, link count, permissions, owner,
and nanosecond modification/change times before invoking the child. The original
source path never reaches `fg`. The child uses the existing native file-backed
verifier and creates its own scratch file in the same owned private temporary
directory. Temporary paths passed to the native verifier are canonical paths.

The report must include `storage_profile: file-backed-native-full-bundle-v1`,
`scratch_bytes`, `scratch_removed: true`, and `pack_sha256` in addition to the
existing content checks. These fields are required only for the selected
file-backed profile. Temporary disk capacity must cover the complete snapshot
plus native scratch of up to twice the selected expanded ceiling, while the
original source remains in place. Native inflation now delivers ordinary blobs
to private scratch in bounded chunks, computes their native identities while
writing, and re-reads them with bounded buffers for scratch-integrity and graph
verification. Exact length, EOF, pack trailer and native identity checks remain
mandatory before a successful report or recovery layout. Large blob deltas use
a verified block index and bounded scratch chunks. Metadata and delta programs
retain separate memory bounds. Limits do not reserve or promise available space.

Cancellation/deadline covers source reads, snapshot staging and child execution.
The adapter uses the shared native-process owner: a private POSIX process group,
TERM followed by KILL after 500 milliseconds, and a separate two-second bound
for process/pipe quiescence. Windows owns only the direct child. A successful
leader that leaves workers cannot produce an accepted report. Unknown group
quiescence returns `native_verifier_containment_failed`; the parent closes its
descriptor but retains the exact snapshot and reports `directory`,
`snapshot_retained` and `descriptor_closed`. It does not unlink an input that
may still belong to unresolved native work. These boundaries own a trusted
local executable; they do not contain hostile children that escape the group.
Filesystem calls cannot be forcibly interrupted. Only the identified snapshot
and empty owned directories are removed. Native scratch leftovers, unexpected
children or observed substitutions refuse cleanup; there is no recursive
deletion. A same-user adversarial namespace is
outside this trusted-local profile. Process death may leave a private temporary
snapshot; it is not automatically recovered or garbage-collected.

`caller_expectations_matched` includes the adapter's snapshot pin and must not
be read as independent provenance. `caller_identity_pins_supplied` is false
without an externally supplied artifact digest or reference pin. A format alone
is not an identity pin. Origin/signature/currentness, gitlink targets, forge
state, complete capsules, repository mutation and change authorization remain
explicitly outside this content-verification result.

## Verification

```sh
node --test tests/operator/native-bundle-verifier.test.mjs
FG_NATIVE_BIN="$PWD/target/release/fg" \
  node --test tests/operator/native-bundle-verifier.test.mjs
```

Adapter tests run real child processes and filesystem operations with a clearly
identified fake verifier. They establish orchestration, constraints, cleanup and
failure handling, not native Git verification. The test-only SHA-1/SHA-256 bundle
fixtures are checked using exactly Git 2.47.3 when present, with file-only
protocol access and private bare repositories. Native Rust execution is a separate
test, explicitly skipped unless `FG_NATIVE_BIN` names an available built binary.
No repository-wide, native-build, durability or bead-closure claim follows from
adapter-test success.

The process regressions include a normally joined worker beside a cancelled
worker holding inherited output pipes. A denied group observation must retain
the exact snapshot, close the parent's descriptor and refuse the scoped read
consumer. At `bacec6472e1f7e8c765666d28d167fd9bbfbf553`, the focused seven-file
adapter/process-owner/import/recovery corpus records 246 tests: 242 pass,
zero failures and four explicit skips because Git 2.47.3 is unavailable. The
supplied native executable is older `a9d65885`, SHA-256
`95d06ddd1e10f696f4212df08c0c6d0e11b3e3e0a495cd435afb05f44633f2d1`.
TAP: `/data/tmp/frankengit-gap-work-20261030/native-verifier-corpus-bacec647.stdout`,
SHA-256 `01d378218157c3b5c21f41ba164d60827ba4d574689c66a7e9a37946bb1af7d0`.
Synthetic adapter/process tests remain distinct from the enabled native cells;
neither qualifies a current-source Rust build.

The existing `scripts/e2e/suites/operator/source_workspace.sh` campaign separately
invokes the actual `verify_git_bundle_native.mjs` CLI on native-exported source
in SHA-1 and SHA-256. Independent object framing and pinned sandboxed Git check
the exported objects and refs. Wrong reference pins and a lower object-count
budget refuse; buffered and file-backed verification must return the same
content identities, with finalized file-backed scratch. The same exact bundle
then enters the actual source-import and native bare-recovery CLIs with separate
canonical Rust readback. This is selected unsigned-source integration evidence,
not signed approval, every-entrypoint completeness, independent verification or
full/release qualification. The receipt binds the selected native digest; a
standalone run does not establish a new Rust build.

For each listed entrypoint, the workspace receipt derives its counts from actual
recorded CLI calls. Each row carries the client-file hash, selected native digest
and success/expected-nonzero counts. The suite rejects a listed path without both.
Expected nonzero exits can include unresolved outcomes; the counter never proves
canonical refusal or non-commit. Specific refusal semantics are checked by the
campaign's cases and canonical readback.
This also exercises the offline package verifier's plain-text wrong-blob refusal;
it does not turn an inventory of this source group into a whole-project census.

The discovered live suite exercises the signed operator command with a prebuilt
Rust verifier, including valid bundles larger than 16 MiB in both hash domains:

```sh
FG_BIN="$qualified_fg" \
FG_SIGNED_BUNDLE_SOURCE_CUT="$qualified_fg_source_commit" \
FGE_NODE="$pinned_node" \
  scripts/e2e/run_all.sh scripts/e2e/suites/recovery/native_signed_bundle.sh
```

`FGE_NODE` must match `tests/node-version`. The binary source cut is required
provenance supplied by the caller; the suite cannot authenticate a build from
its filename or infer it from the JavaScript checkout. It records that source
cut, the executable digest and the actual client-module hashes separately.
No compilation occurs in the suite.

Its 20 checks cover default-budget refusal and explicit file-backed success,
a direct Rust content read, wrong trust/ref pins, separate aggregate-expansion
and streamed-blob exhaustion, correctly signed invalid native content, artifact
tampering and expired approvals. All
native processes use the selected executable; child PATH is empty. Process
owners wait for group quiescence, and successful cases require snapshot/scratch
cleanup. Raw command streams and a summary remain under the E2E artifact root.

The aggregate case keeps the default 32 MiB streamed-blob allowance and requires
the exact `TotalExpandedLimit` for 17 MiB against a 1 MiB total. The separate blob
case keeps an 18 MiB total and requires the exact `ObjectSizeLimit` for a 1 MiB
blob allowance. Neither refusal substitutes for the successful 18 MiB allowance
and direct Rust readback.

This establishes one signed-bundle entrypoint, not the complete `.4.59` operator
lane. Generated packs are test inputs; no upstream-Git differential, signature
key-management, memory benchmark or forge-recovery claim follows.

That live lane remains failing with the supplied older debug binary: both
`42d4c28f` and the unchanged predecessor `cd3bc4e7` reach the existing 30-second
deadline in the first explicit SHA-1 file-backed verification. Both record four
passing and eighteen failing assertions out of 22. The timeout and assertions
are unchanged. Retained receipts are
`/data/frankengit-targets/noble_signed_bundle_42d4c28f_20261102/receipt.ndjson`
(SHA-256 `f4c82054b514f6c54d48ee6e9ffe1bbda2d56152a115820c12d13612d74f0dd0`)
and `/data/frankengit-targets/noble_signed_bundle_control_cd3bc4e7_20261102/receipt.ndjson`
(SHA-256 `79ea355a8afed883a9ef09d0b8f76fabe5069b3cb088209bffffe20b79409fb1`).
The process repair does not turn this native gate, the whole operator matrix or
release qualification green.

## Signed backup verification through the existing command

The existing operator entry point now offers an explicit native selection:

```sh
node scripts/verify_git_bundle.mjs ./backup.bundle \
  --native-fg "$PWD/target/release/fg" \
  --attestation ./backup.dsse.json --trust-key ./trusted-ed25519.pem \
  --repository Dicklesworthstone/frankengit --minimum-sequence 42 \
  --expect-format sha256 --expect-ref "refs/heads/main=$KNOWN_COMMIT"
```

The four attestation arguments are still an all-or-nothing group. The existing
Ed25519/DSSE verifier authenticates the captured small envelope, external key,
repository, full-width sequence floor, lifetime and signed length against the
selected input allowance before opening the artifact. A contradictory independent
artifact-hash pin refuses at this boundary too. The native adapter then binds its
single private snapshot to the mandatory signed SHA-256. Its validated byte count
must equal the signed length. Signature files and trust-key paths are not passed
to the child. Every native content check and independent format/reference pin
still applies when the signature is valid.

After the child and its temporary files have been finalized, the command
reauthenticates the original captured envelope, key and policy, including approval
lifetime, before output. It does not reread adjacent control files or accept a
replacement approval. An expired approval cannot ride through on a successful
native content-verification report.

Signed and unsigned invocations default to a 16 MiB input allowance and 128 MiB
expanded-payload allowance. `--native-max-input-mib` and
`--native-max-expanded-mib` select explicit limits up to 128 MiB in memory, or
up to 16,384 MiB with `--native-file-backed`. The mode alone does not raise the
defaults. For a large signed portable bundle:

```sh
node scripts/verify_git_bundle.mjs ./large.bundle \
  --native-fg "$PWD/target/release/fg" --native-file-backed \
  --native-max-input-mib 4096 --native-max-expanded-mib 8192 --native-max-blob-mib 1024 \
  --native-timeout-secs 1800 \
  --attestation ./large.dsse.json --trust-key ./trusted-ed25519.pem \
  --repository Dicklesworthstone/frankengit --minimum-sequence 42
```

The signature cannot enlarge the operator's allowance. Native-only options
require `--native-fg`; invalid combinations refuse before file access or legacy
decoder loading. `--native-max-blob-mib` requires the file-backed mode and selects
the same independently bounded streamed-blob allowance described above, including
blob delta bases/results. It never widens metadata, delta programs or total expansion. Object,
reference and report limits stay in force. The separate `verify_git_bundle_native.mjs` command defaults to 128 MiB
input and does not consume detached approvals itself.

`--native-timeout-secs` selects one 1..3600-second native operation deadline,
including authentication, snapshot staging and child processing. Authentication
time is subtracted from the child's allowance; it does not earn a fresh budget.
Final approval checks share the same deadline. This remains cooperative for
operating-system filesystem calls.

The returned `source_attestation` is independent of the native report: its
signature covers portable source bytes, not Git commit signatures, forge state,
current authority, branch freshness or a complete capsule. A report's native
`signatures_verified` and `origin_authenticated` fields remain false. This does
not turn an unsigned artifact hash into signer authentication.

Native selection does not load the JavaScript Git decoder, even to parse native
pins, and a missing/refusing native executable never triggers legacy fallback.
Without `--native-fg`, the command keeps its existing legacy backend, input
profile and report shape. Source recovery keeps its existing owned-byte profile;
this verification option does not select a different recovery/resume format.
No browser route or decoder is modified.

Additional integration tests:

```sh
node --test tests/operator/native-bundle-verifier.test.mjs \
  tests/operator/native-source-backup.test.mjs
```

The signed tests use real Ed25519 keys and the unchanged production attestation
module, while a deliberately fake `fg` exercises process/report composition.
They include a real 17 MiB input, its streamed signature, default-limit refusal,
and explicit file-backed acceptance with exact digest/length binding. The
artifact is deliberately opaque: this case tests bounded orchestration, not Git
content validity. Other cases cover trust-before-input ordering, signed length
disagreement, profile limits, expiry, cancellation and owned cleanup.
An import sentinel proves native selection never loads the legacy decoder;
a separate sentinel verifies default dispatch, not legacy Git semantics.
Neither constitutes a native Rust execution or full compatibility gate.
