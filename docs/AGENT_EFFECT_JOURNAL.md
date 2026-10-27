# Durable agent effect responsibility

The native agent host can retain the existing effect broker's accepted requests,
obligation bindings, lifecycle transitions, output commitments and reconciliation
observations across process death. This implements the journal prerequisite of
`frankengit-audit-agent-execution-p7sa`. It does not complete that bead's action
executor, task persistence, runner, ECC assembly or publication requirements.

## Native entry points

`OneNode::create_restorable_agent_broker_in` additionally stores the complete
original run in an immutable `<run-id>.fg-agent-run` checkpoint before exposing
the checked journal-backed broker. It accepts the original backend
`HeadReadReceipt`, reauthenticates it through this node's existing authority
store, and requires it to reproduce the run's exact authenticated receipt.
The checkpoint retains the original token, head key, head bytes, generation,
observation time, verifier profile, operation scope, every budget grade and
expiry. It creates no repository authority, task claim or new capability.

After process restart, `OneNode::recover_agent_journal_in` needs only the run
ID, an independently retained complete run commitment, and the independently
retained acknowledged journal tail. It loads the bounded checkpoint,
reauthenticates the original receipt against the real persisted issuance ledger,
reconstructs the exact original run, and reads the anchored journal. The caller
does not need to reconstruct an `IntentRun` from memory or fixture inputs.
The returned `RecoveredAgentJournal` provides the original run, inspected
history and `reconciliation_report`; it never returns an issuing broker.

The embedded authority provider retains issuance records across reopen and
authenticates superseded receipts by their exact opaque token, key, generation
and bytes. Recovery therefore remains possible after the current repository
head advances, without relabeling an old observation as current. An expired run
can still expose cleanup debt; restoration never refreshes expiry, increases
scope or resets spent-resource history. A wrong store, slot, token, body or
complete-run pin refuses before a recovered run is returned.

The existing lower-level entry points remain available when the caller already
has the original independently authenticated run:

`fgit_node::agent_journal::create_checked_broker_in` takes a runtime-owned
`asupersync::Cx`, an existing absolute operator-owned directory, the complete
authenticated `IntentRun`, a region and an agent instance. It creates a new
single-writer journal and returns the existing
`CurrentAuthorityRevocationCheckedEffectBroker`. All existing capability,
revocation and irreversible-start checks still apply. The host exposes no raw
high-value grant constructor.

The file name contains the numeric run identity. Creation uses `create_new`:
neither a retry nor another body using the same run ID can open a fresh issuing
broker in that directory. Existing files are never truncated, overwritten or
automatically repaired. `File::try_lock` retains process-bound exclusive custody
until the broker and every still-owned effect have released their journal
references. A second reader or writer refuses while that custody is live.

The host performs bounded synchronous I/O on its caller's owned blocking lane.
It spawns no detached work and creates no runtime. It checks the supplied context
before work and after synchronization; an OS sync already in progress is drained
before returning. This local filesystem profile therefore has finite byte/work
limits and cooperative cancellation, not a hard deadline for an unresponsive OS
filesystem operation. The directory and its ancestors belong to the operator;
hostile namespace replacement and filesystems without reliable local locking and
sync are outside this profile.

The run checkpoint is a separate immutable local recovery input, using profile
`frankengit-agent-run-checkpoint` version 1. Its total bound is 64 KiB, including
at most 32 KiB of original head bytes and a 256-byte head key; lengths are checked
before copying. Unknown versions, truncation and trailing bytes refuse. Both
checkpoint and journal creation use `create_new`, file synchronization and
directory synchronization. A crash or cancellation between their creation
steps may leave one or both files; no broker has escaped, and another creation
refuses instead of overwriting the uncertain setup. A checkpoint file is never
itself an independent run commitment or journal-tail anchor. Hostile replacement
of local files cannot supply those externally retained pins.

## Responsibility before successful return

The optional `EffectJournalSink` is attached beneath all checked broker facades.
An acceptance, binding or lifecycle transition must be appended and synchronized
before its API call can report success. A file's initial header and its directory
entry are synchronized before the host exposes its writer. Each later frame is
written and synchronized on the same locked descriptor.

An append can fail after writing bytes. Every append failure therefore stops new
issuance and prevents a stale acknowledged prefix from being returned as the
complete journal. In-memory records still retain the observed transition. A
grant whose acceptance was not acknowledged never escapes to the caller, and
its budget reservation is explicitly released.

A post-commit failure returns the existing deferred obligation. Reconciliation
checks journal health before calling a downstream, so recovering that value
cannot bypass a failed persistence boundary. A failure after terminal settlement
retains the observed terminal record and reports the persistence error. An
escalation is still live responsibility: `AfterEscalation` preserves the actual
named-owner obligation, including both authorization layers in checked facades.
Cleanup remains available after a journal failure, with further persistence
failures reported explicitly.

Acknowledgement, escalation and permanent-failure observations have zero new
resource cost. They preserve the actual cost already charged at commit rather
than overwriting it with zero. Independent journal replay reconstructs that same
consumed budget. Resource-region quiescence from `close()` is separate from
journal durability; the caller must also retain a successful `durable_position()`
result when it needs a complete acknowledged history.

## Format and finite bounds

The local derived format is `frankengit-agent-effect-journal-v1`; it is not a new
canonical repository body or authority root. Its immutable header commits the
numeric run, complete `IntentRunCommitment`, exact authenticated-read identity and
format version. It cannot be decoded as another run with the same numeric ID.

Every frame includes its length, dense sequence, predecessor digest, typed event
payload and SHA-256 frame digest. Recovery checks every byte, every tag and the
chain, then requires decode/re-encode equality and replays the ordinary broker
state machine. It reconstructs reconciliation observations through the existing
resource state machine. The historical record did not retain its retry ceiling;
the decoder checks the ceiling relation needed for each recorded transition and
does not manufacture a runnable retry plan.

The profile admits at most 16 MiB per journal, 256 KiB per frame, 32,768 events,
4,096 accepted effects, 1,024 output commitments per lifecycle event and 2,048
reconciliation transitions per event. Declared lengths and counts are checked
before allocation or copying. Unknown versions, impossible transitions,
over-limit payloads, changed sequences, corrupt frames and incomplete suffixes
refuse. Recovery never silently discards a damaged tail or replaces the file.
There is no v0 migration or permissive unknown-field interpretation.

## Recovery and the independent tail anchor

`fgit_node::agent_journal::recover_in` reopens the existing file after obtaining
exclusive custody. Its caller supplies the original independently authenticated
run; the journal cannot create an `AuthorityReadReceipt`, reauthenticate a head,
mint capability or widen scope. The run's original logical observation, expiry,
budget and operation set remain part of its commitment.

The returned `RecoveredEffectJournal` provides event and record inspection. It
never returns an issuing broker, live grant or downstream adapter. It never
dispatches, repeats a request, resets a budget or infers that an ambiguous effect
did not commit. Expired runs can still be inspected and reconciled for cleanup.

A digest chain detects damaged and reordered frames, but cannot by itself detect
replacement by an older valid complete prefix. The caller must independently
retain the exact acknowledged `EffectJournalPosition` (event count, byte length
and final digest), such as in the surrounding run controller's durable receipt.
`recover_in(..., Some(expected_tail))` requires exact equality, including refusal
of both a shorter prefix and an unacknowledged longer suffix. With no anchor,
inspection is permitted but `reconciliation_report` refuses. Only an anchored
history can produce the existing `RunReconciliationReport` consumed by handoff
and cancellation. Obtaining a position from the same untrusted file is not an
independent anchor.

An interrupted append can leave a valid longer suffix or an incomplete frame.
The API preserves this uncertainty instead of choosing a last-good prefix on
the operator's behalf. This profile does not yet implement an authority-rooted
run catalog, automatic tail-anchor publication, resumed issuance or automated
settlement of recovered external effects. Capability-chain and dispatch
authorization objects still require their own durable codecs; a retained
capability identity is not a reconstructed authorization proof.

## Concrete validation surfaces

`crates/fgit-agent/tests/effect_journal.rs` includes the exact native file module
and exercises real writes, syncs, lock contention, reopen and a child process
that exits without destructors while holding an unresolved outbox obligation.
The acknowledged tail crosses that process boundary separately; the receiving
process reconstructs the original-run debt without a downstream call.

Other cases cover checked-facade adoption, same-ID run substitution, duplicate
writer creation, corruption, truncation, complete-prefix rollback, unanchored
inspection, output bounds, cancellation, and injected ambiguous appends at
acceptance, commit, acknowledgement and escalation. The injected sink cases are
fault-model tests, not claims about real disk hardware failures. The authority
source in these focused tests is the repository's reference authority engine,
not a persisted-node or full agent-run execution test. Test source alone is not
a revision-bound execution result.

`crates/fgit-agent/tests/run_checkpoint.rs` executes the exact native checkpoint
and journal file modules with the reference authority provider. It covers
complete original-run restoration, changed current heads, expired-run cleanup,
wrong-store and forged receipt refusals, scope/budget/expiry substitution,
independent pins, every truncated prefix, version and size bounds, cancellation,
create-new refusal and nonempty journal recovery without the original run object.

`crates/fgit-node/tests/agent_journal_checkpoint.rs` exercises the actual embedded
provider: create a checked broker and nonempty journal, advance authority through
ordinary native merge admission, close the node, reopen storage, and recover the
original run and history in a fresh child process in both Git hash formats. The
independent run and tail pins cross that process boundary separately. It also checks exact retries,
wrong pins, cancellation and unchanged repository authority during recovery.
Execution of that integration test is a separate gate; its presence and successful
type checking alone do not establish an executed persisted-node result.
