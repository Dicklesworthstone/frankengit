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

The source must be one nonempty, quiescent regular non-symlink file. One bounded
read produces owned bytes; an exclusive private snapshot supplies those exact
bytes to the child. The child always receives their SHA-256 as an input pin.
Independently supplied pins must additionally match. The parent validates the
native report's profile, object format, snapshot hash and length, verification
flags, reference pins, echoed expectations and explicit non-claims. It rejects
malformed, duplicate-key, extra-document, lossy-number and oversized reports.

Defaults are 128 MiB input, 128 MiB expanded native payload, 100,000 objects,
4,096 references, a two-MiB report and one 300-second deadline. The public byte
adapter can lower the report budget or select up to eight MiB. Input is held in
memory; the native engine is not a streaming large-repository verifier. The
parent uses bounded read/write chunks, but parent and child memory both count
when provisioning the host. CLI limits can be reduced, never raised beyond the
native profile's documented ceilings.

Cancellation/deadline covers source reads, snapshot staging and child execution.
The adapter requests termination and escalates to a kill after 500 milliseconds,
then waits for process/pipe closure before cleanup. This is ownership of the
trusted `fg` process, not isolation or containment of arbitrary hostile programs.
Filesystem calls cannot be forcibly interrupted. Only the identified temporary
file and empty private directory are removed. Observed substitutions refuse
cleanup; there is no recursive deletion. A same-user adversarial namespace is
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
