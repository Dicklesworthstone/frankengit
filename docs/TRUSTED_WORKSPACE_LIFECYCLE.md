# Trusted workspace execution: source pins and owned process cleanup

`fg workspace run` is an explicit local-owner tool, not a remote agent endpoint
or hostile-code sandbox. Its executable retains host-user privileges. Inputs
and declared output paths limit the sparse copy and candidate export, not all
possible external effects of the executable.

## Exact source before execution

Optional `--expected-head alg:<algorithm>:<digest>` and `--expected-commit <oid>`
flags fence execution to the source the caller reviewed. Both checks run inside
the same authenticated source-selection operation, before creating a workspace
or starting a process. An unrelated canonical event can change the head without
changing the commit: the head fence intentionally refuses that change too. The
commit fence alone permits such a head change while still requiring the exact
native source commit. SHA-1 and SHA-256 identities remain distinct.

The node API `run_trusted_workspace_tool_at_in` exposes the same optional pair;
the existing `run_trusted_workspace_tool_in` remains its unpinned compatibility
wrapper. Source expectations are not approvals, credentials or publication
capabilities. A matching candidate is still only a bundle; publishing it uses
ordinary admission via `fg workspace apply`.

## Completion belongs to the process group

The runner's `run_trusted_command` executes the literal argv without inserting a
shell. It reuses the existing Linux process-group owner used by workflow steps.
The direct child stays waitable until group inspection and signalling finish,
so its numeric PID/PGID cannot be recycled underneath cleanup. The owner never
signals a group after reaping its leader.

A successful leader that leaves group members behind is not a successful tool
execution. Its group is drained, the workspace is retained, and no candidate is
exported. Properly joined children and ordinary nonzero exits preserve their
real exit statuses. Timeouts, signals, and cancellation after spawn also retain
the workspace. Known group members stopping is not proof that every possible
escaped descendant was contained or reaped.

SIGTERM and SIGINT sent to `fg workspace run` request cooperative cancellation.
An owned Asupersync blocking-pool child relays signals into a derived request
while synchronous tool work executes. The shared native context remains usable
for workspace settlement and node shutdown. Repeated signals do not interrupt
that drain. Observer and node cleanup are both attempted and both failures are
retained; a candidate bundle is not written unless execution and cleanup finish.
Signals arriving after completed execution do not imply rollback of effects.
SIGKILL and machine failure remain abrupt failures.

## Durable invocation custody and recovery

The CLI reserves a permanent invocation identity before tool execution. The key
binds tenant, repository incarnation and workspace ID; the request binds the
selected authority head and native commit, executable path and literal argv,
source/output paths, author/message/timestamp, clean environment profile and
command/tool time budgets. Source pins are checked before reservation, and the
native execution boundary requires the same selected source again. The ID cannot
be reused with changed inputs, after successful workspace cleanup, or after a
missing result. An empty or torn claim is unresolved, not a free execution slot.

Records live under `<node-root>/workspace-invocations/<scope>-<workspace-id>`.
The original request digest and directory are printed before the tool can run.
The directory is private (0700); request and result files are private (0600).
Only one caller can create the directory, and its creation and request bytes are
synced before execution. Cancellation and failures never delete this reservation.

After the tool, workspace, signal observer and node cleanup all succeed, the CLI
saves the exact candidate bundle and candidate receipt, syncs those bodies, then
writes the sole terminal record and syncs its directory. Only afterward does it
publish the requested destination bundle. A destination collision or lost response
can therefore be recovered without running the tool again. Failed operations
retain bounded UTF-8 diagnostics; a failure does not prove absence of external
effects. Missing or incomplete terminal evidence stays unresolved.

Inspect a saved candidate without opening the repository database or executing
any source or tool:

```bash
fg workspace recover /absolute/invocation-directory --trusted-local \
  --request-id <original-request-sha256>
```

To export its exact saved bytes, add `--output /private/new-candidate.bundle`.
The output must be absent and its parent private; recovery never overwrites an
existing output. An optional `--terminal-id <retained-terminal-sha256>` pins the
complete original result. Successful recovery returns the verified saved receipt
as the escaped `receipt_json` field, together with separate request/terminal IDs
and the actual export path. The receipt's original `bundle` field is the requested
destination, not evidence that an earlier publication succeeded. Export remains
candidate-only; applying the bundle still uses ordinary `fg workspace apply`
authority and expected-source checks. Repeated inspection is byte-stable and
never acknowledges, erases, or reexecutes the original invocation.

The `FGWIR001` request and `FGWIT001` terminal formats use exact bounded
length-prefixed fields and SHA-256 framing checks. A ready terminal binds both
result lengths/digests to its original request. Recovery refuses wrong pins,
unknown versions/states, trailing/truncated/oversized data, substituted payloads,
symlinks, nonregular files, hard-linked files and public permissions. Legacy
request-only records remain unresolved; no migration interprets them as unused.

This is trusted local execution custody, not canonical repository state or a
complete IntentRun/effect broker. It applies to `fg workspace run`; the embedded
raw node tool API has no new persistent invocation guarantee. The operator must
retain these directories along with the node, including across backup/restore,
and keep filesystem parents stable. Deleting records, rolling back the node or
choosing a different workspace ID can admit another execution. Digests detect
corruption; they are not signatures or protection against a malicious local owner.
Keep the original request and result identities independently. No automatic
pruning, force-retry or reset is provided. Stored argv/metadata can be sensitive.

A crash before the terminal is durable may leave an unrecoverable candidate and
an unresolved invocation. That deliberately sacrifices automatic retry rather
than duplicate an uncertain external effect. SIGKILL cannot perform cooperative
process cleanup; retained workspaces and any external effects still require
reconciliation. This is not an exactly-once external-effect or physical power-loss
claim. Broader agent identity, capability, broker and durable obligation work
remains separate.

## Executed-path regression coverage

`tests/trusted_command.rs` in fgit-runner exercises real argv/status, envelope
refusals, failed spawn, pre-cancel, joined and orphaned children, signal exit,
timeout and cancellation. The node workspace tests reproduce the original
orphan-on-success defect and pair it with proper child joining and source-pin
refusal/success twins.

`scripts/e2e/suites/workspace/lifecycle.sh` drives a prebuilt `FG_BIN` in both
native hash formats. It verifies exact candidate bundle bytes, stale-pin refusal
before host effects, SIGTERM/SIGINT against live nested descendants, repeated
signals, timeout and orphan rejection, retained-slot and bundle-destination
replay refusal, and unchanged canonical refs. Descendant liveness is checked
before test-fixture cleanup. This is Linux trusted-host evidence, not a full
workspace release gate or proof of hostile isolation.

`scripts/e2e/suites/workspace/invocation_guard.sh` reproduces a completed tool
followed by failed bundle publication, then verifies retry does not repeat its
external-effect counter. The same campaign's explicitly labelled baseline mode
reproduces duplicate effects on the earlier implementation.

`scripts/e2e/suites/workspace/recovery.sh` tests ready-result inspection, exact-byte
export, ordinary admitted publication, independent pin failures, corruption of
every saved file, failed results, and recovery with the original node path absent,
in both native hash domains. It also kills a real execution owner during a tool
and verifies unresolved recovery plus replay refusal. The test cleans its planted
child after SIGKILL; that is not evidence of product-side containment. The Rust
storage/codec tests cover each truncation and corruption boundary, finite limits,
concurrent reservations and failure-before-terminal behavior.
