# Durable admitted-object membership checkpoints

`fg checkpoint outcomes` publishes a capsule with
`DecisionHistoryWithAdmissionClosureV1` coverage. Besides the retained terminal
outcome index, it records the exact cumulative set of Git object IDs admitted at
that authenticated head. A cold admission reader can read that set and replay
only later decisions. Restart no longer forces this particular projection to
revisit every decision before an eligible checkpoint.

The canonical contract is [§7 and §23 of the normative protocol
contracts](NORMATIVE_PROTOCOL_CONTRACTS.md). This is a serving-membership
projection of canonical history. It does not change per-transaction object
closures, move refs, publish a transaction, or authorize disclosure of objects
outside the current visible-ref scope.

## Publication and compatibility

The new backup-profile byte is **4**. The three existing discriminants, capsule
layout and legacy bytes remain unchanged. Older readers reject the unknown
profile; upgrade readers before activating a new checkpoint. Existing capsules
continue to work through authenticated history replay, including capsules whose
object roots describe only the latest transaction, reachable objects or an
external closure representation.

Native maintenance derives the complete admitted set from its authenticated
materialization, stages the ordinary repository-scoped permitted-closure frame,
then reads it back and checks both its digest and exact set equality. The capsule
binds that root and the exact head. Only its successful exact-predecessor
activation makes the declaration selectable. The generic chronicle freeze API
accepts a trusted publisher's profile declaration; it verifies the head binding,
not the application's complete membership computation.

An existing outcome checkpoint at the same decision position is upgraded by
rebinding its already verified retained leaves into a new profile-4 capsule.
This does not repack the outcome archive or create a same-position outcome
predecessor link. Repeating maintenance after that upgrade verifies the retained
outcome evidence and rereads the selected membership frame before returning
`published=false`. Missing newest evidence cannot be repaired or overlooked by
that no-op path. CLI receipts report the selected capsule's canonical profile
name, `decision_history_with_admission_closure_v1`.

## Selection and failure behavior

The history reader retains the original capsule body that passed the complete
checkpoint-transition verifier. Closure selection stops only at the explicit
profile-4 declaration. It loads and canonicalizes that membership frame under
the existing decode limits, verifies its committed digest, and unions the
per-decision closure roots collected from the later authenticated suffix.

Deleting a branch or tag does not delete previously admitted membership.
Reusing an admitted object changes no membership; refusal-only decisions admit
no new objects. Genesis and refusal-only checkpoints have no latest committed
RCR and must name the canonical empty set. Their provenance preserves that
absence rather than inventing a committed record.

Missing, malformed, wrongly identified or foreign selected checkpoint evidence
refuses. Cancellation during a capsule or closure read cannot publish a partial
cache entry. An intervening legacy capsule still undergoes its complete
transition verification before a reader reaches an older eligible membership
checkpoint; corruption of the newer capsule never permits skipping that edge.
A verified in-memory prefix remains disposable and scoped to its authenticated
store, head and cache permit.

`ClosureSelectionSource::CapsuleCheckpoint` reports the exact capsule, optional
latest RCR and number of selected closure bodies united. That body count includes
one cumulative checkpoint body; it is not a count of original transaction roots
inside the retained prefix. Source browsing and indexing continue to require a
real latest RCR.

## Validation and limits

The native regression suite compares checkpoint-derived membership and its
canonical root with the independent full-history walker. Its read-accounting
fixtures isolate closure selection from other materializations and cover cold
reads, fresh-cache reopen, later additions/deletions/reuse/refusals, multiple
checkpoint profiles, damaged or cancelled evidence, cache preservation, and
source backup/restore followed by another native publication. Chronicle tests
cover profile-byte compatibility, capsule identity binding, and history-only
archive/repair classifications. Maintenance tests cover upgrading a legacy exact
outcome checkpoint without repacking and stable repeated-call no-ops.

This slice does not establish sustained-scale latency or remove every history
ceiling. Maintenance still bounds the cumulative retained outcome set at 65,536
terminal decisions and 16 MiB of retained leaf payload. Independent forge,
outbox, snapshot and other history consumers keep their existing replay bounds.
No automatic checkpoint cadence, history pruning, GC, repair or full-payload
backup profile is introduced. A checkpoint's cumulative membership frame still
uses the existing immutable-body/codec limits and requires memory proportional
to its selected object set.
