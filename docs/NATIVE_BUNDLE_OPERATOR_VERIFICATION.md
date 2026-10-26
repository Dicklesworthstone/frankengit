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

Defaults are 128 MiB input, 128 MiB expanded native payload, 100,000 objects,
4,096 references, a two-MiB report and one 300-second deadline. The public adapter
can lower the report budget or select up to eight MiB. The default profile holds
input in memory and retains its 128 MiB input and expansion ceilings. Parent and
child memory both count when provisioning the host.

## File-backed verification

Select file-backed processing explicitly to verify larger portable bundles:

```sh
node scripts/verify_git_bundle_native.mjs ./large.bundle \
  --fg "$PWD/target/release/fg" --file-backed \
  --max-input-mib 4096 --max-expanded-mib 8192 --timeout-secs 1800 \
  --expect-sha256 "$KNOWN_BUNDLE_SHA256"
```

This permits input and expanded-payload limits up to 16,384 MiB each. Selecting
the mode alone leaves both defaults at 128 MiB; a larger allowance must be
requested separately. Object, reference, report, metadata and per-object bounds
are not widened. The public `verifyNativeGitBundleFile` adapter accepts the same
explicit `fileBacked: true` option. The byte-array API refuses that profile.

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
original source remains in place. The native engine still retains bounded
individual objects and metadata in memory. These limits are allowances, not
reservations or promises of available space.

Cancellation/deadline covers source reads, snapshot staging and child execution.
The adapter requests termination and escalates to a kill after 500 milliseconds,
then waits for process/pipe closure before cleanup. This is ownership of the
trusted `fg` process, not isolation or containment of arbitrary hostile programs.
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
  --native-max-input-mib 4096 --native-max-expanded-mib 8192 \
  --native-timeout-secs 1800 \
  --attestation ./large.dsse.json --trust-key ./trusted-ed25519.pem \
  --repository Dicklesworthstone/frankengit --minimum-sequence 42
```

The signature cannot enlarge the operator's allowance. Native-only options
require `--native-fg`; invalid combinations refuse before file access or legacy
decoder loading. Object, reference, report, metadata and per-object limits stay
in force. The separate `verify_git_bundle_native.mjs` command defaults to 128 MiB
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
