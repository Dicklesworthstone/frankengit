# Native source-backup import and lost-response recovery

Related: `frankengit-root-doctrine-x2mv.4.21` and `.4.44`; comprehensive plan
sections 21 and 23. This is portable **Git source** restoration, not recovery
of a repository capsule, forge history, policy, issues, reviews or credentials.

```sh
node scripts/import_git_bundle_native.mjs import ./backup.bundle \
  --trusted-local --fg "$PWD/target/release/fg" \
  --storage /absolute/existing-node \
  --tenant 11111111111111111111111111111111 \
  --repository-id 22222222222222222222222222222222 \
  --principal 33333333333333333333333333333333 \
  --object-format sha256 \
  --recovery-directory /absolute/private-parent/new-import \
  --expect-sha256 "$KNOWN_BUNDLE_SHA256"
```

Initialize the destination node separately using `fg init`. Import delegates
all Git semantics to the explicitly selected native `fg`: first `bundle verify`,
then `bundle import`. The existing native admission path creates all advertised
direct refs atomically, requiring their absence; it does not overwrite existing
refs or force a merge. Pack quarantine, current policy, stable sealed identity
and authority-head publication remain native responsibilities. No production
upstream Git, JavaScript Git decoder, shell or failure fallback is introduced.

The executable is operator-trusted. These tools do not authenticate its build,
sandbox it, grant a principal, or convert a local self-asserted principal into
remote authentication. External artifact/reference pins are checked when supplied;
an automatically computed snapshot hash is integrity, not provenance. A format
alone is not an independent identity pin. The byte ceiling is 16 MiB, the direct
reference ceiling is 64, and native expansion retains the existing bounded
128 MiB profile. Parent and child allocations both matter for provisioning.

## Responsibility before publication

Before calling native import, the operator tool verifies owned source bytes,
preflights the original key's outcome, exclusively creates a private recovery
directory, and writes an immutable `intent.json` plus `source.bundle`. Both are
synchronized and read back; directory synchronization completes before submission.
The intent retains the exact target, tenant/repository/principal, native format,
random 256-bit retry key, native key digest, bundle hash/size, and caller expectations.
A transaction ID is learned from the native seal/decision, never synthesized from
the key before the native request exists. Keys reach native commands through
byte-exact stdin, not process arguments.
The recovery directory never becomes an alternative repository authority.

The original input path is never reopened after verification. An occupied or
partially prepared recovery directory is never overwritten, recursively deleted,
or treated as permission to generate another identity. A failed preparation may
leave partial material that needs operator diagnosis. Process death leaves that
material in place. Keep it until the original canonical outcome is resolved.

```sh
node scripts/import_git_bundle_native.mjs status /absolute/private-parent/new-import \
  --trusted-local --fg "$PWD/target/release/fg" \
  --intent-sha256 "$RECORDED_INTENT_SHA256"

node scripts/import_git_bundle_native.mjs retry /absolute/private-parent/new-import \
  --trusted-local --fg "$PWD/target/release/fg" \
  --intent-sha256 "$RECORDED_INTENT_SHA256"
```

The optional intent hash pins the exact retained JSON bytes. The directory and
files must still have their required private ownership/permissions without it.

`status` performs only `fg outcome` under the original key. There is no
`fg bundle outcome` command. It never imports, verifies the source again, initializes a node, writes an
acknowledgement, or generates a new key. It can resolve committed/refused outcomes
even when the original source and retained snapshot have disappeared. Native
`key_not_observed`, `seal_not_observed`, and `undecided` states exit 4 and remain
nonterminal. They are reported as `unknown_pending`, never committed
or rolled back. The native recovery receipt binds the original principal and
key digest as well as tenant, repository and object format.

`retry` is explicitly requested, never automatic. It first resolves historical
terminal outcomes without requiring source bytes. For an unresolved request it
reads and verifies the exact retained snapshot, re-establishes persistence and
resubmits the same native arguments and key. Source mutation, missing evidence,
foreign receipt identities and corrupt/torn intent data refuse. After a normal
import receipt, a separate read-only outcome lookup must confirm that same
transaction and decision under the original key. Native u64 decision sequences
are preserved as decimal strings, including values beyond JavaScript safe
integers. Concurrent explicit retries rely on the same native idempotency contract; no local lock or
second outcome database supplies publication authority.

A timeout, signal, child failure, invalid report or lost stdout after submission
is an **unknown outcome**, not rollback. Error receipts retain the recovery path
and intent pin. A native canonical refusal is terminal, not a retry instruction.
Reports are bounded and reject duplicate JSON fields, contradictory exit/status
pairs and mismatched namespace/transaction/count fields.

## Host and lifetime boundary

This is a quiescent, current-user-owned **local POSIX** filesystem profile.
Recovery directories are mode 0700, files mode 0600, and private files must be
single-link regular files. The target and recovery parents must not be writable
by another user/group. Final symlinks refuse. Target device/inode identity is
bound, and observed target replacement refuses. Recovery and target paths may
not overlap. Directory identity is not a native repository-incarnation proof:
**do not replace or reinitialize the target in place while recovery is pending.**
Same-user malicious namespace mutation and hostile executables are outside this
profile; pathname checks are not a descriptor-relative sandbox.

One cooperative deadline (default 300 seconds, selectable 1..3600) covers input,
verification, persistence and native commands. Cancellation requests SIGTERM,
escalates after 500 milliseconds, and waits for child/pipe closure. It owns the
trusted native process, not an arbitrary hostile descendant tree. Filesystem
calls are not preemptible. Source snapshots are deliberately retained, not
removed during cancellation. Exit codes are 0 committed, 3 canonical refusal,
4 unresolved observation, and 2 error; an error can still follow a commit. A native
receipt explicitly reporting a terminal decision with a cleanup failure retains
that decision and reports `node_closed:false`; its command exit remains an error.

## Executable evidence

```sh
node --test tests/operator/native-import-receipt.test.mjs \
  tests/operator/native-source-import.test.mjs
FG_NATIVE_BIN="$PWD/target/release/fg" \
  node --test tests/operator/native-source-import.test.mjs
```

The default tests execute real files and child processes with an explicitly
**fake** native adapter. They test orchestration, identity retention, bounded
reports, cancellation, read-only lookup, explicit retry and refusal, not Git
parsing, native CAS, power-loss durability or native recovery correctness.
The actual `fg` test is separate and explicitly skipped without `FG_NATIVE_BIN`.
No full-workspace, production-readiness, full-capsule or bead-closure claim follows.

## Signed source approval and explicit retry

Add all four options to the initial `import` command:

```sh
--attestation ./backup.dsse.json --trust-key ./trusted-ed25519.pem \
  --source-repository Dicklesworthstone/frankengit --minimum-sequence 42
```

`--source-repository` is the signed source's human-readable identity;
`--repository-id` is the opaque hexadecimal destination identity. Neither is inferred from
a filename or silently substituted for the other. Partial approval groups refuse.
The existing DSSE/Ed25519 module verifies the caller-selected key, source name,
full-width positive-u64 sequence floor, validity period, and exact bytes before
any native verifier/admission is invoked. A valid signature never skips native
Git content checks or independently supplied artifact/reference constraints.

Signed intents use version 2 and retain immutable copies of the exact approval
and public key plus their SHA-256 digests and original trust policy. Unsigned
version-1 intents remain readable without migration. An unresolved signed retry
must reauthenticate those retained bytes under that same policy; it cannot select
another key, lower the floor, use replacement source paths, or fall back to
unsigned mode. Missing, changed, invalid or expired approval blocks a new send.
No private signing key is read or retained.

Approval is checked again immediately before invoking native import. This is
permission to attempt source restoration, not an expiry predicate injected into
the native canonical transaction. Expiry while import is in flight cannot undo
publication. Historical terminal lookup therefore remains available after expiry
or loss of approval/snapshot files, and never reports current approval validity.
Reports distinguish `checked_before_this_submission` from a currentness claim.
The source approval does not grant destination principal permissions or restore
forge policy. The same shared operation deadline bounds all composition steps.

The signature tests use real Ed25519 keys and the unchanged production approval
module. Native process/admission behavior remains explicitly fake in default
tests. The original provisional adapter, which used an incorrect CLI contract,
was a negative control: both current invocation tests rejected it. Dedicated
receipt cases exercise literal forms from `bundle.rs::finish_import` and
`transaction_outcome.rs::render` at `6f20ee29`, including cleanup failures and
full-width decision sequences. These tests were executed with Node 22.16.0. No native execution
or repository-wide gate is claimed by that control.
