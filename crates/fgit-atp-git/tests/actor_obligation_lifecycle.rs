#![forbid(unsafe_code)]
//! The transfer actor's obligation lifecycle (`frankengit-78ra`).
//!
//! §3.2 states these rules and this module implements them as types:
//!
//! - *"Long-lived work owns children through regions and closes to
//!   quiescence."* — `close` refuses with `ActorNotQuiescent` while any effect
//!   is unsettled.
//! - *"Cancellation is request → drain → finalize; dropping a future is not a
//!   complete protocol."* — `cancel` walks exactly those three phases and hands
//!   back a receipt naming them.
//! - *"Effects that acquire responsibility use typed obligations: reserve /
//!   commit / abort as the two-phase boundary, plus explicit acknowledgement
//!   for externally observed effects."* — the reserve → commit → acknowledge
//!   chain, with `EffectNotReserved` guarding every step.
//!
//! Measured **per variant** against both existing actor suites rather than
//! trusting an enum-level count:
//!
//! ```text
//! InvalidActorPhase              untested   several sites
//! DuplicateEffectKey             untested
//! EffectNotReserved              untested   three reachable shapes
//! ActorNotQuiescent              untested
//! TooManyTransferEffects         untested
//! CommittedEffectRequiresOutcome ALREADY covered by path_swarm_actor.rs
//! EffectParametersTooLarge       ALREADY covered by path_swarm_actor.rs
//! ```
//!
//! The last two are exercised here only as neighbours of the probes that need
//! them; they are **not** claimed as new coverage.
//!
//! # One arm, three reachable shapes
//!
//! `EffectNotReserved` fires from `commit_effect` when the key is unknown and
//! when the key is present but not `Reserved`, and from `acknowledge_effect`
//! when the effect is `Reserved` rather than `Committed`. Each is a separate
//! way to be wrong about where in the two-phase boundary an effect sits, so
//! each gets its own probe.
//!
//! # An asymmetry that is benign, recorded so the next reader need not re-derive it
//!
//! `reserve_effect` and `commit_effect` both call `ensure_effect_phase`;
//! `acknowledge_effect` does **not**. That looks like an omission. It is
//! reachable only in `Closed` — every other phase either permits effect work or
//! is transient inside `cancel` — and in `Closed` the method's own precondition
//! cannot hold, because `close` only succeeds once every effect is terminal and
//! no terminal effect is `Committed`. So the missing gate admits nothing the
//! state machine does not already exclude. Documented rather than asserted: a
//! test pinning the current behaviour of a guard that does not exist would make
//! adding one a regression.
//!
//! # Non-claims
//!
//! Five of the 23 unnamed `AtpRefusal` variants. The swarm/piece family, the
//! cache family and the object-order family remain; `frankengit-0k6d` covered
//! the transfer-manifest cluster. LEAD count, not a remaining-work total.
//!
//! Nothing here modifies `crates/fgit-atp-git/src/**`.

use fgit_atp_git::{
    AtpRefusal, PathId, TransferAbortReason, TransferActor, TransferActorLimits,
    TransferActorPhase, TransferCancellationSource, TransferCapability, TransferEffectBroker,
    TransferEffectIntent, TransferEffectKey, TransferEffectKind, TransferEffectReceipt,
    TransferEffectState, TransferInputRoot,
};

/// A broker that accepts every operation and records what it was asked to do.
///
/// It never refuses, so every refusal in this file is the **actor's** and not
/// the broker's — which is what makes the probes attributable.
#[derive(Debug, Default)]
struct RecordingBroker {
    reserved: Vec<TransferEffectKey>,
    committed: Vec<TransferEffectKey>,
    aborted: Vec<(TransferEffectKey, TransferAbortReason)>,
    acknowledged: Vec<TransferEffectKey>,
}

impl TransferEffectBroker for RecordingBroker {
    fn reserve(&mut self, intent: &TransferEffectIntent) -> Result<(), AtpRefusal> {
        self.reserved.push(intent.key());
        Ok(())
    }

    fn commit(
        &mut self,
        key: TransferEffectKey,
        _receipt: TransferEffectReceipt,
    ) -> Result<(), AtpRefusal> {
        self.committed.push(key);
        Ok(())
    }

    fn abort(
        &mut self,
        key: TransferEffectKey,
        reason: TransferAbortReason,
    ) -> Result<(), AtpRefusal> {
        self.aborted.push((key, reason));
        Ok(())
    }

    fn acknowledge(
        &mut self,
        key: TransferEffectKey,
        _receipt: TransferEffectReceipt,
    ) -> Result<(), AtpRefusal> {
        self.acknowledged.push(key);
        Ok(())
    }
}

const fn key(tag: u8) -> TransferEffectKey {
    TransferEffectKey::from_bytes([tag; 32])
}

const fn receipt(tag: u8) -> TransferEffectReceipt {
    TransferEffectReceipt::from_bytes([tag; 32])
}

fn intent(tag: u8) -> TransferEffectIntent {
    TransferEffectIntent::new(
        key(tag),
        TransferEffectKind::PathAttempt,
        TransferCapability::Path(PathId::new(u32::from(tag))),
        TransferInputRoot::from_bytes([42; 32]),
        256,
        vec![tag; 4],
    )
}

/// An actor admitting `max_effects` effects with a generous parameter bound, so
/// the parameter arm never fires by accident in probes about other arms.
fn actor(max_effects: usize) -> TransferActor {
    TransferActor::new(TransferActorLimits::new(max_effects, 64).expect("bounded actor limits"))
}

// ---------------------------------------------------------------------------
// The permitted terminus: the whole §3.2 obligation lifecycle
// ---------------------------------------------------------------------------

/// reserve → commit → acknowledge → finalize → close.
///
/// Every refusal below is measured against this. Without it they would be
/// unattributable — an actor that refused everything would satisfy them all.
#[test]
fn the_full_obligation_lifecycle_settles_and_closes() {
    let mut broker = RecordingBroker::default();
    let mut actor = actor(2);

    actor
        .reserve_effect(&mut broker, intent(1))
        .expect("a first effect reserves");
    actor
        .commit_effect(&mut broker, key(1), receipt(1))
        .expect("a reserved effect commits");
    actor
        .acknowledge_effect(&mut broker, key(1), receipt(1))
        .expect("a committed effect is acknowledged");
    actor
        .begin_finalization()
        .expect("finalization opens from the prepared phase");

    let settled = actor.close().expect("an acknowledged effect is settled");
    assert_eq!(settled.settled_effects(), 1);
    assert_eq!(actor.phase(), TransferActorPhase::Closed);
    assert_eq!(broker.reserved, vec![key(1)]);
    assert_eq!(broker.committed, vec![key(1)]);
    assert_eq!(broker.acknowledged, vec![key(1)]);
    assert!(
        broker.aborted.is_empty(),
        "an acknowledged effect is never aborted"
    );
}

// ---------------------------------------------------------------------------
// ActorNotQuiescent — §3.2 "closes to quiescence"
// ---------------------------------------------------------------------------

/// A reserved effect is not settled, so `close` refuses and reports how many
/// obligations are still outstanding.
#[test]
fn closing_with_an_unsettled_effect_is_refused() {
    let mut broker = RecordingBroker::default();
    let mut actor = actor(4);
    actor
        .reserve_effect(&mut broker, intent(1))
        .expect("a first effect reserves");
    actor
        .reserve_effect(&mut broker, intent(2))
        .expect("a second effect reserves");
    actor.begin_finalization().expect("finalization opens");

    let refusal = actor
        .close()
        .expect_err("an actor with reservations outstanding is not quiescent");
    assert_eq!(
        refusal,
        AtpRefusal::ActorNotQuiescent { outstanding: 2 },
        "the refusal counts every unsettled obligation, not just the first"
    );
}

/// A **committed** effect is unsettled too, until acknowledgement.
///
/// This is the arm that makes the acknowledgement step load-bearing rather than
/// decorative: committing is not settling.
#[test]
fn closing_with_a_committed_but_unacknowledged_effect_is_refused() {
    let mut broker = RecordingBroker::default();
    let mut actor = actor(2);
    actor
        .reserve_effect(&mut broker, intent(1))
        .expect("a first effect reserves");
    actor
        .commit_effect(&mut broker, key(1), receipt(1))
        .expect("a reserved effect commits");
    actor.begin_finalization().expect("finalization opens");

    let refusal = actor
        .close()
        .expect_err("a committed effect is owed an acknowledgement before quiescence");
    assert_eq!(refusal, AtpRefusal::ActorNotQuiescent { outstanding: 1 });
}

// ---------------------------------------------------------------------------
// DuplicateEffectKey and TooManyTransferEffects
// ---------------------------------------------------------------------------

/// One idempotency key names one effect.
#[test]
fn reserving_one_key_twice_is_refused() {
    let mut broker = RecordingBroker::default();
    let mut actor = actor(4);
    actor
        .reserve_effect(&mut broker, intent(1))
        .expect("a first effect reserves");

    let refusal = actor
        .reserve_effect(&mut broker, intent(1))
        .expect_err("one idempotency key cannot name two effects");
    assert_eq!(refusal, AtpRefusal::DuplicateEffectKey { key: key(1) });
    assert_eq!(
        broker.reserved,
        vec![key(1)],
        "the refused reservation never reached the broker"
    );
}

/// The effect budget is a hard bound.
#[test]
fn reserving_past_the_effect_bound_is_refused() {
    let mut broker = RecordingBroker::default();
    let mut actor = actor(1);
    actor
        .reserve_effect(&mut broker, intent(1))
        .expect("the first effect fits the budget");

    let refusal = actor
        .reserve_effect(&mut broker, intent(2))
        .expect_err("a second effect exceeds a budget of one");
    assert_eq!(refusal, AtpRefusal::TooManyTransferEffects { maximum: 1 });
}

// ---------------------------------------------------------------------------
// EffectNotReserved — one arm, three reachable shapes
// ---------------------------------------------------------------------------

/// Shape 1: committing a key the actor never reserved.
#[test]
fn committing_an_unknown_effect_is_refused() {
    let mut broker = RecordingBroker::default();
    let mut actor = actor(2);
    let refusal = actor
        .commit_effect(&mut broker, key(9), receipt(9))
        .expect_err("an unreserved key has no obligation to commit");
    assert_eq!(refusal, AtpRefusal::EffectNotReserved { key: key(9) });
    assert!(
        broker.committed.is_empty(),
        "a refused commit never reaches the broker"
    );
}

/// Shape 2: committing a key that is already committed.
///
/// The guard tests for the `Reserved` state specifically, so an effect past
/// that state is as ineligible as one that never reached it.
#[test]
fn committing_an_already_committed_effect_is_refused() {
    let mut broker = RecordingBroker::default();
    let mut actor = actor(2);
    actor
        .reserve_effect(&mut broker, intent(1))
        .expect("a first effect reserves");
    actor
        .commit_effect(&mut broker, key(1), receipt(1))
        .expect("a reserved effect commits");

    let refusal = actor
        .commit_effect(&mut broker, key(1), receipt(1))
        .expect_err("an effect commits once");
    assert_eq!(refusal, AtpRefusal::EffectNotReserved { key: key(1) });
    assert_eq!(
        broker.committed,
        vec![key(1)],
        "the second commit never reached the broker"
    );
}

/// Shape 3: acknowledging an effect that is only reserved.
///
/// Acknowledgement follows commitment; an effect that never committed has
/// nothing externally observed to acknowledge.
#[test]
fn acknowledging_an_uncommitted_effect_is_refused() {
    let mut broker = RecordingBroker::default();
    let mut actor = actor(2);
    actor
        .reserve_effect(&mut broker, intent(1))
        .expect("a first effect reserves");

    let refusal = actor
        .acknowledge_effect(&mut broker, key(1), receipt(1))
        .expect_err("a reserved effect has committed nothing to acknowledge");
    assert_eq!(refusal, AtpRefusal::EffectNotReserved { key: key(1) });
    assert_eq!(broker.acknowledged, Vec::new());
}

// ---------------------------------------------------------------------------
// InvalidActorPhase — several sites, each naming the observed phase
// ---------------------------------------------------------------------------

/// Site 1: a transition whose expected predecessor phase does not hold.
#[test]
fn beginning_the_swarm_before_the_race_is_refused() {
    let mut actor = actor(2);
    let refusal = actor
        .begin_swarm()
        .expect_err("swarming follows racing, not preparation");
    assert_eq!(
        refusal,
        AtpRefusal::InvalidActorPhase {
            phase: TransferActorPhase::Prepared
        },
        "the refusal names the phase actually observed"
    );
}

/// Site 2: `close` has its own phase guard, distinct from the transitions.
#[test]
fn closing_before_finalization_is_refused() {
    let mut actor = actor(2);
    let refusal = actor
        .close()
        .expect_err("closure certifies quiescence only from finalization");
    assert_eq!(
        refusal,
        AtpRefusal::InvalidActorPhase {
            phase: TransferActorPhase::Prepared
        }
    );
}

/// Site 3: `ensure_effect_phase`, reached through `reserve_effect` once the
/// actor is closed.
///
/// A closed actor owns nothing, so it cannot acquire a new obligation.
#[test]
fn reserving_an_effect_after_close_is_refused() {
    let mut broker = RecordingBroker::default();
    let mut actor = actor(2);
    actor.begin_finalization().expect("finalization opens");
    actor
        .close()
        .expect("an actor with no effects is quiescent");

    let refusal = actor
        .reserve_effect(&mut broker, intent(1))
        .expect_err("a closed actor cannot acquire an obligation");
    assert_eq!(
        refusal,
        AtpRefusal::InvalidActorPhase {
            phase: TransferActorPhase::Closed
        }
    );
    assert_eq!(broker.reserved, Vec::new());
}

/// Site 4: the same guard reached through `commit_effect`.
///
/// Probed separately because a refusal reached through `reserve_effect` says
/// nothing about the commit path having the gate at all.
#[test]
fn committing_an_effect_after_close_is_refused() {
    let mut broker = RecordingBroker::default();
    let mut actor = actor(2);
    actor.begin_finalization().expect("finalization opens");
    actor
        .close()
        .expect("an actor with no effects is quiescent");

    let refusal = actor
        .commit_effect(&mut broker, key(1), receipt(1))
        .expect_err("a closed actor cannot commit an obligation");
    assert_eq!(
        refusal,
        AtpRefusal::InvalidActorPhase {
            phase: TransferActorPhase::Closed
        }
    );
}

// ---------------------------------------------------------------------------
// Cancellation as a sequence — §3.2 request → drain → finalize
// ---------------------------------------------------------------------------

/// Cancellation walks exactly the three phases, in order, and says so.
///
/// *"Dropping a future is not a complete protocol"* is precisely the claim that
/// these phases happened and in this sequence, so the receipt's phase list is
/// asserted rather than just the outcome. A reserved effect is aborted on the
/// way through; the broker records the reason.
#[test]
fn cancellation_walks_request_drain_finalize_and_aborts_reservations() {
    let mut broker = RecordingBroker::default();
    let mut actor = actor(2);
    actor
        .reserve_effect(&mut broker, intent(1))
        .expect("a first effect reserves");

    let cancellation = actor
        .cancel(&mut broker, TransferCancellationSource::RuntimeRequested)
        .expect("a reserved-only actor cancels cleanly");
    assert_eq!(
        cancellation.phases(),
        &[
            TransferActorPhase::CancelRequested,
            TransferActorPhase::Draining,
            TransferActorPhase::Finalizing,
        ],
        "cancellation is request, then drain, then finalize"
    );
    assert_eq!(cancellation.aborted(), [key(1)]);
    assert_eq!(
        broker.aborted,
        vec![(key(1), TransferAbortReason::Cancelled)],
        "the drain phase aborted the reservation through the broker"
    );
    assert_eq!(actor.phase(), TransferActorPhase::Finalizing);

    actor
        .close()
        .expect("an aborted reservation is settled, so the actor is quiescent");
}

/// A **committed** effect is not aborted by cancellation; it stays owed.
///
/// The refusal variant itself is already covered by `path_swarm_actor.rs`, so
/// this probe is about the surrounding behaviour rather than the variant: the
/// committed effect must survive the drain, the broker must not be told to
/// abort it, and acknowledging it afterwards must let `close` certify
/// quiescence. That is the whole two-phase boundary in one run.
#[test]
fn a_committed_effect_survives_cancellation_and_settles_by_acknowledgement() {
    let mut broker = RecordingBroker::default();
    let mut actor = actor(2);
    actor
        .reserve_effect(&mut broker, intent(1))
        .expect("a first effect reserves");
    actor
        .commit_effect(&mut broker, key(1), receipt(1))
        .expect("a reserved effect commits");

    actor
        .cancel(&mut broker, TransferCancellationSource::RuntimeRequested)
        .expect_err("a committed effect is owed an outcome before cancellation completes");
    assert!(
        broker.aborted.is_empty(),
        "a committed effect is never aborted"
    );
    assert!(matches!(
        actor.effect_state(key(1)),
        Some(TransferEffectState::Committed(_))
    ));

    actor
        .acknowledge_effect(&mut broker, key(1), receipt(1))
        .expect("the owed outcome can still be recorded after cancellation");
    actor
        .close()
        .expect("acknowledgement settles the obligation and the actor is quiescent");
}

// ---------------------------------------------------------------------------
// Ordering — calls that are wrong twice
// ---------------------------------------------------------------------------

/// The effect-budget check runs **before** the duplicate-key check.
///
/// This reservation is wrong twice: the actor is already at its budget of one
/// *and* the key duplicates the effect it already holds. It must report the
/// budget. Single-fault probes cannot see this: each violates one rule and
/// still reaches its own stage wherever that stage sits in the chain.
#[test]
fn the_effect_budget_outranks_a_duplicate_key() {
    let mut broker = RecordingBroker::default();
    let mut actor = actor(1);
    actor
        .reserve_effect(&mut broker, intent(1))
        .expect("the first effect fits the budget");

    let refusal = actor
        .reserve_effect(&mut broker, intent(1))
        .expect_err("a reservation wrong in two ways must still refuse");
    assert_eq!(
        refusal,
        AtpRefusal::TooManyTransferEffects { maximum: 1 },
        "the budget check runs before the duplicate scan"
    );
}

/// The phase gate outranks every bound in the reserve chain.
///
/// Wrong twice again: the actor is closed *and* the parameters exceed the
/// bound. It must report the phase, because `ensure_effect_phase` runs first —
/// the opposite end of the chain from the probe above, so the two together pin
/// the order rather than one adjacency of it.
#[test]
fn the_phase_gate_outranks_an_oversized_parameter_block() {
    let mut broker = RecordingBroker::default();
    let mut actor = actor(2);
    actor.begin_finalization().expect("finalization opens");
    actor
        .close()
        .expect("an actor with no effects is quiescent");

    let oversized = TransferEffectIntent::new(
        key(1),
        TransferEffectKind::PathAttempt,
        TransferCapability::Path(PathId::new(1)),
        TransferInputRoot::from_bytes([42; 32]),
        256,
        vec![7; 4096],
    );
    let refusal = actor
        .reserve_effect(&mut broker, oversized)
        .expect_err("a reservation wrong in two ways must still refuse");
    assert_eq!(
        refusal,
        AtpRefusal::InvalidActorPhase {
            phase: TransferActorPhase::Closed
        },
        "the phase gate runs before the parameter bound"
    );
}

/// Deterministic inspection: the actor exposes each effect's state, so a
/// receipt can be checked rather than inferred.
#[test]
fn effect_state_is_observable_at_each_step_of_the_boundary() {
    let mut broker = RecordingBroker::default();
    let mut actor = actor(2);
    assert!(actor.effect_state(key(1)).is_none());

    actor
        .reserve_effect(&mut broker, intent(1))
        .expect("a first effect reserves");
    assert_eq!(
        actor.effect_state(key(1)),
        Some(&TransferEffectState::Reserved)
    );

    actor
        .commit_effect(&mut broker, key(1), receipt(1))
        .expect("a reserved effect commits");
    assert!(matches!(
        actor.effect_state(key(1)),
        Some(TransferEffectState::Committed(_))
    ));

    actor
        .acknowledge_effect(&mut broker, key(1), receipt(1))
        .expect("a committed effect is acknowledged");
    assert!(matches!(
        actor.effect_state(key(1)),
        Some(TransferEffectState::Acknowledged(_))
    ));
}
