# Recovering native workflow watches

Native watchers recover two distinct durable boundaries. PR and merge-queue
candidate watches can finish an uncertain CI publication and begin the original
candidate's first execution when retained custody proves execution never
started. Ref, PR and queue watchers can also finish a missing settlement for an
already completed execution **without executing the workflow again**. Neither
path invents a passing canonical check or authorizes a target merge.

## Before the first candidate execution

New merge-candidate events retain a versioned intent before CI publication. It
binds the original event and execution IDs, source authority head, native
candidate, bundle commitments, CI principal, publication key and exact old-tip
lease. The execution configuration is also retained: input prefixes, workflow
limits and artifact configuration must agree with the restarting controller.
Restart the same foreground watch or owned HTTP service with its original
private run parent and configuration. No reset option or replacement identity
is required.

Recovery validates the intent, candidate artifacts, scope and configuration
while holding the existing exclusive watch owner. It can defer an event only
when the durable execution-start fence and every dispatch directory are absent.
The original protocol writes and syncs that fence before entering dispatch;
therefore even a crash between the fence and the first script remains blocked.
An old event without the versioned intent cannot establish this new boundary.

The next native poll processes retained eligible work before selecting a new
PR or queue head. It uses the original publication key, CI old-tip lease,
candidate bytes and prepared authority head. A known terminal CI outcome can
be recovered before current subject validation. A new publication still needs
its original head and normal native admission. The watcher then validates the
same PR/queue subject and candidate before beginning its first dispatch under
the original run identity. It never refreshes a lease, regenerates a candidate
or runs an already-started script again.

The retained-check publisher only counts and defers these intents as
`pending_execution`. It neither retries their CI publication nor manufactures
`check-sources`, `settled`, `reported` or successful job evidence. Its receipt
continues to report `execution_retried: false` and `refs_changed: false`.
Completed events in the same scope retain their existing check publication
semantics.

`pending_execution` describes verified local custody, not permission to publish
or execute. A retained refusal receipt blocks this classification. If a refusal
receipt was lost, or the canonical PR/queue changed after preparation, the
post-readiness poll discovers that outcome through the original transaction
replay and subject checks. It then retains the blocked event without starting a
script or manufacturing settlement.

Owned HTTP startup verifies eligible intent custody and the complete execution
configuration before readiness. Pending intents may survive that check, with
their count retained in the service receipt. **CI publication retry and first
script execution wait for successful HTTP listener readiness.** A failed or
stopped readiness callback cannot start either operation. The startup check
reporter may still recover original completed checks under its independent
publisher authority. A stopped or failed scan cannot clear a previously
observed pending execution count.

Stale subjects, refused CI publications, corrupt intents or artifacts, changed
configuration and any started dispatch remain blocked. They are not retired as
empty executions or relabeled as green checks. A queue reorder or removed head
cannot discard an earlier unresolved intent. Retain its original custody for
reconciliation.

## After completed execution

After a native dispatch returns, the watcher checks that its processes and
workspaces have closed. It then writes and syncs `check-sources`, retaining the
original event, executed commit, child run IDs, journal identities and exact
journal pins. Finally it writes and syncs `settled`.

A crash between those last two writes used to leave the entire watch scope
blocked despite a completed execution. The watcher now verifies the completion
handoff and writes the original missing settlement acknowledgement. Existing
v1 handoffs retain their exact bytes and interpretation. Event identities,
execution receipts and check publication keys are unchanged.

Recovery runs automatically while the original exclusive watch owner is held:

- Before a native poll can admit later events.
- Before the retained-check publisher prepares the original check sets.
- During owned HTTP workflow-controller startup, before listener readiness.

Restart the same watch or service with its original private run parent and
scope/configuration. The existing publisher continues to use its separately
bound principal. No reset switch or new recovery identity is needed. In HTTP
service mode, recovery and pending check publication can finish before readiness;
new CI candidate publication and script execution still wait for successful
listener readiness.

## Cooperative cancellation after proved closure

A cooperative stop can now settle an interrupted dispatch after the native
owners have proved that its processes, workspaces and shared input cache are
closed. The completed execution keeps its original non-green observations.
The watcher finishes its already-owned terminal handoff under one separate
30-second allowance, shared across every child journal and the final settlement
write. Cancellation of execution does not discard that finalization duty.

Stopped dispatches use the local `FGWCS002` handoff profile. It retains the
original selected workflow count, a closed terminal stop reason and the SHA-256
of the exact original `dispatch.json`, in addition to the unchanged event,
commit, executed-child identities and journal pins. This profile is local
operational custody; it is not canonical check evidence or permission to run
anything. Ordinary completions continue to use `FGWCS001`.

The next live owner can publish the exact retained **cancelled** checks through
normal native admission, once, and then process later source events. It does not
rerun the original scripts. Completed failed or successful jobs retain their
own original conclusions; unstarted later workflow definitions receive no
invented checks. A late stop after a completed durable handoff remains an
interrupted service result without an unresolved-execution fence.

A stop after the exact dispatch plan was persisted but before its first child
may also settle, using the explicit v2 terminal record. Recovery requires the
original selected count and plan digest to match, the terminal reason to be
`request_stopped`, and no child directories. An empty directory or an old v1
zero-child handoff cannot establish this boundary when the plan selected work.
Cancellation during earlier source discovery, an error without a returned
terminal dispatch, an unfinished `Started` owner, abrupt termination and
unproved descendant containment remain unresolved.

## What is verified

The completion handoff must name the exact scope and event. Its original
`event.json`, `dispatch.json` and child `attempt.json` records must agree on the
repository incarnation, refs, commit, workflow paths, object identities, graph,
authority head and execution inputs. Retained path strings are compared with
paths derived by the owner; they are not followed as authority to read arbitrary
host files.

Every recorded child must exist, and an extra or missing child refuses recovery.
The child IDs and coordinator run/attempt IDs are independently derived with the
existing identity functions. Each `execution.owner` must contain a complete
receipt without outstanding containment, and its exact journal pin must equal
the completion handoff. The complete original job observations must match the
terminal job evidence in the locked journal. Every original job must be terminal.
A selected prefix that stopped after a closed failure or v2 cooperative stop
remains that same prefix. V2 recovery also compares the exact dispatch-plan
digest and selected count. Unstarted later definitions are never represented as
executed. The legacy v1 cancellation and nonempty-selection/empty-prefix
refusals remain unchanged.

Private files and directories retain their permission, inode and bounded-length
checks. The handoff and directory identities are rechecked before the
creation-only settlement write. Cancellation stops verification before that
write; once the write starts, its directory sync completes. Existing partial or
invalid settlement records are never replaced.

Optional final `report.json` files are not completion authority and are not
required for recovery. A process exit, successful CI-ref publication, candidate
bundle or partial job journal alone is insufficient.

## Outcomes and remaining custody

A closed failed build can settle and publish its original **failure** checks.
Settlement suppresses repeated execution; it does not claim the build passed.
A genuine dispatch that selected no workflows can settle without inventing any
check. Ordinary canonical check admission still decides whether original
evidence can be published, using the unchanged original keys and identities.

Missing or corrupt handoffs, unfinished owners, changed journal pins, foreign
bindings and unresolved process containment remain blocked. Cancellation of a
read-only recovery pass defers its remaining verification to a later live owner;
it does not complete or erase custody.
An uncertain CI candidate publication is eligible for the separate pre-execution
recovery path above only when its versioned intent proves the first dispatch
never started. A crash during execution cannot use that path. Keep the original
publication key, lease, candidate artifacts and execution custody; absence of a
response never proves rollback or that a script did not run.

An unresolved event still fences the whole watch scope. For merge queues this
includes later heads after reorder, dequeue, landing or queue removal. Deleting,
moving or replacing custody records is not a recovery protocol.

## Finite recovery profile

The existing scope limit remains 1,024 retained events. Within one recovered
event, verification has these aggregate ceilings:

| Resource | Maximum |
|---|---:|
| Workflow children | 32 |
| Original jobs | 128 |
| Completed owner receipt frames | 16 MiB |
| Terminal job evidence | 16 MiB |
| Journal bytes at retained pins | 32 MiB |
| JSON and history metadata | 8 MiB |
| History batches | 1,024 |

Terminal handoff creation likewise checks a cumulative 32 MiB of private journal
files before opening them, with at most 32 children and the single 30-second
finalization allowance. It compares each verified final journal pin with the
prechecked byte length. The handoff frame itself is bounded to 4 KiB. A failed
or expired finalization retains the original custody; a complete handoff whose
last settlement write was interrupted can be recovered normally.

These limits are checked before bounded reads and allocations, with cancellation
checkpoints throughout verification. The owned service uses its finite attempt
deadline during startup reconciliation. Oversized retained executions remain
unresolved rather than producing a truncated proof. Encoded receipts include
captured output, so a large otherwise completed run can exceed this recovery
profile even when its execution output limit was valid.

## Validation entrypoints

The focused native test sources cover both Git hash formats, ref/PR/queue modes,
original check identity, closed failures, empty selections, service readiness,
cancellation, corrupt custody and no script replay:

```sh
cargo test --locked -p fgit-runner --lib coordinator::delivery::journal::attempt::tests -- --test-threads=1
cargo test --locked -p fgit-node --test trusted_watch_settlement_recovery -- --test-threads=1
cargo test --locked -p fgit-node --test trusted_merge_watch_recovery -- --test-threads=1
```

The runner's real-process tests require a host where its supervisor can observe
the complete child process group. A restricted process view correctly produces
a containment refusal, not a passing execution.

The merge-watch recovery test sources exercise original CI identity and leases,
first execution after uncertain publication, deferred check reporting, immutable
configuration, readiness failure/stop and corrupt or already-started custody.
These entrypoints describe validation to run at the selected revision; they are
not a claim that an unexecuted revision has passed.
