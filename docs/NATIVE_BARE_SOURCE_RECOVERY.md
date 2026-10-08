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

The bounded profile accepts at most 16 MiB input, 128 MiB expanded native payload,
100,000 objects, 4,096 refs and a 16 MiB native layout report. It retains input and
layout bytes in memory. Filesystem operations and synchronous work remain
cooperative; cancellation of a native child terminates, escalates and reaps it.
No current-branch, Git-signature, external-gitlink, forge/authority restoration or
power-loss guarantee is inferred from source-content verification.

## Executable evidence

```sh
node --test tests/operator/native-source-layout.test.mjs \
  tests/operator/native-source-recovery.test.mjs
FG_NATIVE_BIN="$PWD/target/release/fg" \
  node --test tests/operator/native-source-recovery.test.mjs
```

Default tests use an explicitly fake native process returning repository fixtures.
They execute the actual adapter and filesystem owner, including process kills
before and after HEAD publication, competing writers, exact resume, corruption
refusal and cancellation. The pinned Git 2.47.3 oracle reads the resulting SHA-1
and SHA-256 materializations, runs strict fsck and checks contents and tag peeling.
The SHA-256 index fixture matches the pre-existing metadata.json SHA-256 golden.
This demonstrates fixture interoperability, not Rust execution. The separate
actual-fg test is explicitly skipped unless a built `FG_NATIVE_BIN` is supplied.
