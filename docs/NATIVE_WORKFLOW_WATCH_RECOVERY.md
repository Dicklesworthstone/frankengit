# Recovering completed native workflow watches

Native ref, PR and merge-queue watchers can finish a missing local settlement
after a crash **without executing the workflow again**. Recovery uses the
original durable completion handoff and independently verifies its retained
execution records. It does not turn local execution into a passing canonical
check or authorize a target merge.

## The recoverable boundary

After a native dispatch returns, the watcher checks that its processes and
workspaces have closed. It then writes and syncs `check-sources`, retaining the
original event, executed commit, child run IDs, journal identities and exact
journal pins. Finally it writes and syncs `settled`.

A crash between those last two writes used to leave the entire watch scope
blocked despite a completed execution. The watcher now verifies the completion
handoff and writes the original missing settlement acknowledgement. This applies
to existing compatible handoffs as well as new executions; event identities,
handoff bytes, execution receipts and check publication keys are unchanged.

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
A selected prefix that stopped after a closed failure remains that same prefix;
unstarted later definitions are never represented as executed.

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
bindings, cancellation and unresolved process containment remain blocked. In
particular, a crash during CI candidate publication or script execution happens
before the completed-dispatch handoff and is not resumed by this feature. Keep
the original publication key, lease, candidate artifacts and execution custody;
absence of a response never proves rollback or that a script did not run.

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
```

The runner's real-process tests require a host where its supervisor can observe
the complete child process group. A restricted process view correctly produces
a containment refusal, not a passing execution.
