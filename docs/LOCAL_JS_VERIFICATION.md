# Native JavaScript verification

The test runtime identity is pinned once in `tests/node-version`. This is a
verification profile for the existing JavaScript modules; it does not resolve
owner decision D10 or admit JavaScript as a production implementation platform.
The live-`fg` operator lane in `x2mv.4.59` must reuse this identity rather than
introducing another Node pin. Rust verification remains separate.

On macOS or Linux, with that exact Node executable on PATH:

```sh
node scripts/verify_js.mjs browser
node scripts/verify_js.mjs operator
node scripts/verify_js.mjs scripts
```

An unsupported runtime exits **3** with one JSON `js_verification_refusal` on
stderr: code `js_runtime_version_mismatch`, expected/actual Node versions, scope,
and `corpus_started: false`. It acquires no Git metadata or test-process
responsibility. `node scripts/verify_js.mjs runtime` checks that same pin and
returns an explicit `js_runtime_identity` without running tests; live native
campaigns use this command rather than maintaining another runtime policy.
That identity-only command earns no test coverage credit.

The live [operator campaign launcher](../scripts/e2e/operator_issue_smoke.py)
requests TERM on interruption or its unchanged 40-second execution deadline,
then gives the Node owner four seconds to drain its native children. Repeated
TERM/INT requests during this drain do not preempt it. Forced owner termination
has a separate two-second reap bound and fails as
`operator_owner_containment_failed`; it does not establish native quiescence.
Both streams and a command-journal row survive, and interrupted native effects
remain explicitly unknown. This closes the observed Python `subprocess.run`
failure that killed Node before it could request shutdown of a detached child.
It does not cover Python SIGKILL, interruption inside process creation, escaped
hostile children or every other campaign's direct subprocess calls.

The existing operator contract suite invokes
[`selftests/test_operator_command.py`](../scripts/e2e/selftests/test_operator_command.py)
with the same pinned Node. At `859da441da270a2aebf0f9d7bcd5441281940f1a`, its nine
real-process cases complete with zero failures/skips: normal success/refusal,
unexpected exit, malformed JSON, TERM, repeated signals, timeout, uncooperative
owner and spawn failure. The cooperative executable is synthetic; these are
process-ownership regressions, not native mutation evidence. At that same
source, the existing backup lane completes 19 assertions, zero failures/skips,
against the explicitly older `a9d65885` native binary identified below. Receipt:
`/data/frankengit-targets/noble_operator_drain_backup_859da441_20261102/receipt.ndjson`,
SHA-256 `0de21b1bcd9760e5b6fc35d132ec95ffe18d7d4c363f47e576659ff74ab20133`.
The full operator matrix and current-source native qualification remain open.

The shared GitHub pull peer and issue operator fixture allocate listeners through
`tests/fetch-peer.mjs`. Hosts may assign ephemeral ports that Fetch refuses
before any TCP request. The helper retires those selections before exposing a
URL, preserves an already usable listener, and fails after sixteen forbidden
selections. Tests exercise a real blocked listener, its permitted Fetch twin and
bounded exhaustion. This changes fixture allocation, with no production request
retry or relaxed redirect assertion. Older failures without a retained selected
port remain unexplained; the port hazard alone does not establish their cause.

The discovered live suite
[`scripts/e2e/suites/operator/remote_issue.sh`](../scripts/e2e/suites/operator/remote_issue.sh)
drives the actual remote issue CLI against `fg serve-http` in SHA-1 and SHA-256.
It checks all eight actions through canonical Rust issue/event reads, stale-version
refusal beside its current-version twin, original-key recovery, independent
outcome grants and complete owned service drain. Complete command streams and
private failure artifacts are retained. This covers one operator entrypoint;
the complete entrypoint matrix and same-revision binary qualification remain
separate acceptance conditions in `x2mv.4.59`.

The discovered [signed-backup operator lane](../scripts/e2e/suites/operator/backup.sh)
drives seven shipped entrypoints: attest, witness, select, replicate, scrub,
direct native verification and integrated recovery. It imports independently
framed Git objects checked by pinned sandboxed Git, creates two native forge
checkpoints, signs actual native exports, checks healthy/corrupt replicas and
retained-generation refusals, then restores from local media with every original
source/export pathname unavailable. Canonical Rust reads compare binary Git
bytes, executable kinds, commit/tree/blob identities, issue data and history.
Cache-only exact resume preserves the approval record and authority head;
changed approval bytes refuse. Original sources remain retained elsewhere:
this is not destructive power loss or independent-failure-domain evidence.

At source `61842fdb41f3c729b040bed1100b350f500645c8`, the lane completes 19
assertions across SHA-1/SHA-256, zero failures/skips, with pinned Node 26.8.1 and
Git 2.54.0. The supplied native binary is explicitly older
`a9d65885fde8a996c229827b3a86e136b2583bba`, SHA-256
`95d06ddd1e10f696f4212df08c0c6d0e11b3e3e0a495cd435afb05f44633f2d1`.
Receipt: `/data/frankengit-targets/noble_backup_join_61842fdb_20261102/receipt.ndjson`,
SHA-256 `39f52dffaa4d8df900ec8fbb026b7d956529ea47e174a3038fa1c96029586a28`.
A separate test-only adapter that delegates every operation except native
restore causes a non-pass at `recover_repository_backup.mjs`; the cache/record
survive and no restored root exists. Its retained `restore_attempted_unknown`
state is not rewritten as a rollback. Neither result qualifies a current-source
native build, the remaining operator matrix, HTTPS/cloud storage, hostile-code
isolation, forced-driver cleanup, full capsules, deployment or release.

The discovered suite
[`scripts/e2e/suites/operator/contract_tests.sh`](../scripts/e2e/suites/operator/contract_tests.sh)
calls the existing `operator` and `scripts` profiles. `./scripts/verify.sh e2e`
selects it alongside the browser module suite and supplies its once-built `fg`.
The suite forwards that binary as `FG_NATIVE_BIN`, enabling the existing native
bundle/import/backup/recovery tests that otherwise skip. An absent Node or `fg`
is a non-pass disposition. Each scope retains complete TAP and the shared
profile's source/runtime/containment header; empty, incomplete or failing TAP
cannot pass. Optional oracle skips remain visible and earn no coverage credit.
Most cases still use explicit module or HTTP-schema peers. This wiring does
not complete `x2mv.4.59`'s required live-server coverage of every production
operator entrypoint, or replace its original acceptance conditions.

Each invocation discovers all `.test.mjs` files in the selected directory. The
`scripts` scope includes both `scripts/tests/` and the root `scripts/` directory,
where the workflow-supervisor entrypoint tests live. Each invocation
runs TAP with two concurrent files, a five-minute per-test bound, and a ten-minute
campaign bound. The 101-publication bootstrap test performs hundreds of durable
filesystem operations. An exploratory 30-second bound timed it out on macOS;
the unchanged test subsequently passed all five lifecycle cases in 172 seconds
under an external 180-second campaign bound. The per-test limit matches the
operator's existing five-minute operation budget, rather than that exploratory
short limit. The earlier draft 120-second profile is not a passing result.
The profile does not remove any test or relax any product assertion. A timeout
fails. A skip remains a skip in TAP and provides no coverage credit.
The scripts scope also supplies the existing binary-edit test's required
`--experimental-vm-modules` flag; the header records whether it is enabled.

The runner creates its own private temporary root under the canonical host temp
directory and supplies it to fixture processes. On macOS, `/var` commonly aliases
`/private/var`. Only fixture-owned paths are canonicalized; production custody
checks still reject an explicitly aliased, replaced, public or unowned parent.
The root is removed on success and retained on failure. Cancellation terminates
the owned process group and escalates after five seconds. Descendants that
deliberately detach from this group are outside this test-runner boundary; this
is not hostile-code isolation. A successful leader that leaves descendants fails
the profile. Cleanup kills those descendants and waits at most five seconds for
group quiescence; failure to establish it remains a containment failure. The
campaign deadline is also checked against a monotonic clock at child closure.
Initialization installs cancellation handling before acquiring subprocess or
temporary-directory responsibility. Source metadata uses `/usr/bin/git` through
the existing native-process owner, with a five-second execution bound and its
separate drain bound. Git configuration and environment are isolated for those
read-only calls; cancellation stays latched across the test-process handoff.
Each test process starts a fresh Node test-runner context. An inherited internal
`NODE_TEST_CONTEXT` is removed so invoking the profile from a test cannot turn
the inner corpus into Node's recursive-run warning and an empty success.
The behavior is defined by Node 26.8.1's
[recursive-run check](https://github.com/nodejs/node/blob/v26.8.1/lib/internal/test_runner/runner.js#L1057).

Patch encoder tests retain ordinary worktree application, byte/mode assertions,
and reverse application. Arbitrary non-UTF-8 filename cases use independently
constructed Git objects and indexes on every host, apply the actual browser
patch, compare complete native tree IDs, reverse the patch and check wrong-base
refusal. These cases never pass raw names through the host filesystem, decode
or normalize them, or skip them on APFS. Git is a test-only oracle here; these
observations are not pinned-upstream compatibility or native Rust proof.

The header records the source revision and dirty flag (using bounded, test-only
Git metadata commands). For revision-bound results, require `dirty=false`,
retain the complete TAP and profile header, and record the exit status.
Module tests using DOM/fetch doubles or HTTP schema peers remain module/peer
tests, even when all pass. A browser suite pass does not prove real-browser or
live-node operation; full/release gates and D10 remain separate obligations.

At the 2026-10-20 qualification snapshot, `x2mv.4.71` remains in progress: the
whole macOS operator campaign exceeded its ten-minute bound, and the broader
scripts corpus retained failures. A browser lane pass does not complete those
obligations. The authoritative bead records the exact tested revisions and
remaining work; later peer source additions require their own qualification.

The macOS sparse-directory workspace profile refuses invalid UTF-8 repository
path bytes with `source_workspace_host_path_unrepresentable` before acquiring
a materialization destination. Its scanner refuses such requested scope bytes
with `source_workspace_scan_host_path_unrepresentable` before filesystem I/O;
an OS `ENOENT` must not become a complete empty scan. These checks use the
original bytes and do not decode or normalize Git names. They are platform
refusals, not evidence that macOS materialized or scanned those names. Linux
retains the original arbitrary-byte conflict/resolution/scan cases; both hosts
execute the near-identical UTF-8 emoji/newline byte-path twins. Native package
membership/authority verification is separate from the source-service fixtures.

The custody regressions execute both default and canonical temporary parents
in SHA-1 and SHA-256, a real replaced-inode negative with stable-identity twins,
and the owner-check axis with explicit identity-reader fault injection over
real `lstat` data. That last cell is a guard unit test, not OS UID switching.
The witness descriptor closure assertion reads `/dev/fd` on macOS and
`/proc/self/fd` on Linux; its before/after equality remains unchanged.

Workflow execution remains the explicit trusted-local Linux profile. A macOS
operator aggregate that reaches that guard remains a failed qualification;
none of those tests is suppressed by the portable fixture repairs above.

The same macOS path refusal applies to workspace file reads, including requests
against an absent local root; representable missing paths retain their ordinary
local-absence result. A process-group observation or signal failure is classified
as `js_profile_containment_failed` (exit 1), even during deadline or signal
cancellation. It is never downgraded to an ordinary timeout/interruption. Stop
escalates after five seconds and allows at most another five seconds for leader
closure; inability to establish closure retires the local child handle and
reports containment failure, without claiming the child was reaped.
