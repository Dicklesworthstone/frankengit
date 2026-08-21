//! The worked example: an outbox effect against a weakly idempotent downstream.
//!
//! The model below is a test double for an external receiver, not a stand-in
//! for anything in the crate: the reconciliation machine under test is the real
//! one. The double exists because the interesting behaviour is what happens
//! when an acknowledgement is lost, which no in-process call can produce.

use core::num::NonZeroU32;
use std::collections::VecDeque;

use fgit_resource::algebra::{Grade, ResourceVector};
use fgit_resource::custody::{
    LeakDisposition, ObligationLedger, ObligationState, RegionCloseOutcome,
};
use fgit_resource::ids::{IdempotencyKey, OpaqueHandle, RegionId};
use fgit_resource::kinds::{DownstreamAck, EffectDispatched, OutboxDispatch, OutboxEffectPermit};
use fgit_resource::settlement::{
    DeliveryVerdict, DownstreamChannel, DownstreamIdempotency, Observation, ProbeVerdict,
    ReconcileOutcome, ReconcilePlan, ReconcilePolicy, ReconcileState, reconcile,
};
use fgit_resource::twophase::{
    DeferralReason, EscalationReason, TerminalFailureReason, UnacknowledgedEffect,
};
use fgit_types::{
    CANONICAL_CODEC_VERSION, Digest, DigestAlgorithmId, DigestBytes, OPAQUE_ID_LEN, PrincipalId,
    RepositoryCommitId,
};

fn digest(tag: u8) -> Digest {
    Digest::new(
        DigestAlgorithmId::try_new(1).expect("code point one is a valid algorithm slot"),
        DigestBytes::try_new(&[tag; 32]).expect("thirty-two bytes is a valid digest body"),
    )
}

fn rcr(tag: u8) -> RepositoryCommitId {
    RepositoryCommitId::from_digest(
        DigestAlgorithmId::try_new(1).expect("valid algorithm slot"),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[tag; 32]).expect("valid digest body"),
    )
}

const fn principal(tag: u8) -> PrincipalId {
    PrincipalId::from_bytes([tag; OPAQUE_ID_LEN])
}

fn opaque(tag: u8) -> OpaqueHandle {
    OpaqueHandle::new(&[tag; 20]).expect("twenty bytes is a valid opaque handle")
}

fn budget() -> ResourceVector {
    ResourceVector::single(Grade::EgressBytes, 256)
}

const fn attempts(count: u32) -> ReconcilePolicy {
    ReconcilePolicy::new(match NonZeroU32::new(count) {
        Some(ceiling) => ceiling,
        None => NonZeroU32::MIN,
    })
}

/// A receiver whose duplicate suppression is bounded by a window.
///
/// `accepted` is the ground truth this test asserts against: the whole point of
/// the machine under test is that this vector never grows past one entry.
struct Receiver {
    idempotency: DownstreamIdempotency,
    window: VecDeque<IdempotencyKey>,
    window_capacity: usize,
    durable: Vec<IdempotencyKey>,
    accepted: Vec<IdempotencyKey>,
    lose_acknowledgements: u32,
    transient_failures: u32,
    permanent_rejection: bool,
    lies_on_probe: bool,
    probes: u32,
}

impl Receiver {
    fn weak(window_capacity: usize) -> Self {
        Self {
            idempotency: DownstreamIdempotency::Weak,
            window: VecDeque::new(),
            window_capacity,
            durable: Vec::new(),
            accepted: Vec::new(),
            lose_acknowledgements: 0,
            transient_failures: 0,
            permanent_rejection: false,
            lies_on_probe: false,
            probes: 0,
        }
    }

    fn strong() -> Self {
        Self {
            idempotency: DownstreamIdempotency::Strong,
            window: VecDeque::new(),
            window_capacity: usize::MAX,
            durable: Vec::new(),
            accepted: Vec::new(),
            lose_acknowledgements: 0,
            transient_failures: 0,
            permanent_rejection: false,
            lies_on_probe: false,
            probes: 0,
        }
    }

    fn losing_acknowledgements(mut self, count: u32) -> Self {
        self.lose_acknowledgements = count;
        self
    }

    fn failing_transiently(mut self, count: u32) -> Self {
        self.transient_failures = count;
        self
    }

    fn rejecting_permanently(mut self) -> Self {
        self.permanent_rejection = true;
        self
    }

    fn breaking_its_probe_contract(mut self) -> Self {
        self.lies_on_probe = true;
        self
    }

    /// Simulates the suppression window ageing out.
    fn expire_window(&mut self) {
        self.window.clear();
    }

    fn remember(&mut self, key: IdempotencyKey) {
        self.accepted.push(key);
        self.durable.push(key);
        self.window.push_back(key);
        while self.window.len() > self.window_capacity {
            self.window.pop_front();
        }
    }
}

impl DownstreamChannel for Receiver {
    fn deliver(&mut self, key: &IdempotencyKey, _attempt: u32) -> DeliveryVerdict {
        if self.permanent_rejection {
            return DeliveryVerdict::PermanentRejection;
        }
        if self.transient_failures > 0 {
            self.transient_failures -= 1;
            return DeliveryVerdict::TransientFailure;
        }
        if self.window.contains(key) {
            return DeliveryVerdict::DuplicateSuppressed;
        }
        self.remember(*key);
        if self.lose_acknowledgements > 0 {
            self.lose_acknowledgements -= 1;
            // The effect landed; only the acknowledgement was lost.
            return DeliveryVerdict::AmbiguousTimeout;
        }
        DeliveryVerdict::Accepted
    }

    fn probe(&mut self, key: &IdempotencyKey) -> ProbeVerdict {
        self.probes += 1;
        if self.lies_on_probe {
            return ProbeVerdict::Unknown;
        }
        if self.window.contains(key) {
            return ProbeVerdict::Delivered;
        }
        match self.idempotency {
            DownstreamIdempotency::Strong => {
                if self.durable.contains(key) {
                    ProbeVerdict::Delivered
                } else {
                    ProbeVerdict::NotDelivered
                }
            }
            DownstreamIdempotency::Weak => ProbeVerdict::Unknown,
        }
    }
}

/// Sets up one committed-but-unacknowledged outbox effect.
struct Scenario {
    ledger: ObligationLedger,
    effect: UnacknowledgedEffect<OutboxEffectPermit>,
    key: IdempotencyKey,
}

fn deferred_effect(region: u64, strength: DownstreamIdempotency) -> Scenario {
    let ledger = ObligationLedger::root(
        RegionId::new(region),
        LeakDisposition::RecordAndContinue,
        budget(),
    );
    let grant = ledger
        .grant(budget())
        .expect("capacity covers the dispatch");
    let key = IdempotencyKey::new(digest(0x7A));
    let obligation = ledger
        .reserve::<OutboxEffectPermit>(
            OutboxDispatch {
                idempotency: key,
                precondition_rcr: rcr(0x7B),
                endpoint: opaque(0x7C),
                idempotency_strength: strength,
            },
            grant,
        )
        .expect("egress is the required grade");
    let committed = obligation
        .commit(EffectDispatched { attempt: 1 }, &budget())
        .expect("the dispatch fits inside the reservation");
    let effect = committed.defer_acknowledgement(DeferralReason::AwaitingObservation);
    Scenario {
        ledger,
        effect,
        key,
    }
}

#[test]
fn a_lost_acknowledgement_inside_the_window_reconciles_without_duplicating() {
    let scenario = deferred_effect(401, DownstreamIdempotency::Weak);
    let mut receiver = Receiver::weak(4).losing_acknowledgements(1);
    let mut plan = ReconcilePlan::new(scenario.key, DownstreamIdempotency::Weak, attempts(3));

    let outcome = reconcile(
        scenario.effect,
        &mut plan,
        &mut receiver,
        principal(0x01),
        |attempt| DownstreamAck {
            receipt: opaque(0x02),
            attempt,
        },
    );

    match outcome {
        ReconcileOutcome::Acknowledged(settled) => {
            assert_eq!(settled.state(), ObligationState::Acknowledged);
        }
        other => panic!("a probe inside the window resolves the effect: {other:?}"),
    }
    assert_eq!(
        receiver.accepted.len(),
        1,
        "the receiver saw the effect exactly once"
    );
    assert_eq!(receiver.probes, 1, "one probe was enough");
    assert_eq!(
        plan.state(),
        ReconcileState::Delivered { attempt: 1 },
        "the plan ends delivered on the first attempt"
    );
    let trace: Vec<Observation> = plan
        .transitions()
        .iter()
        .map(|transition| transition.observation())
        .collect();
    assert_eq!(
        trace,
        vec![
            Observation::Delivery(DeliveryVerdict::AmbiguousTimeout),
            Observation::Probe(ProbeVerdict::Delivered),
        ],
        "the transition trace replays what the downstream reported"
    );
    let outcome = scenario.ledger.close();
    assert!(outcome.is_quiescent(), "{outcome:?}");
}

#[test]
fn a_weak_downstream_that_forgot_the_key_escalates_instead_of_resending() {
    let scenario = deferred_effect(402, DownstreamIdempotency::Weak);
    let mut receiver = Receiver::weak(1).losing_acknowledgements(1);
    let mut plan = ReconcilePlan::new(scenario.key, DownstreamIdempotency::Weak, attempts(3));

    // Attempt one lands but its acknowledgement is lost.
    assert_eq!(
        plan.step(&mut receiver),
        ReconcileState::Probing { attempt: 1 },
        "an ambiguous timeout moves to probing, never straight to a resend"
    );
    assert_eq!(receiver.accepted.len(), 1);

    // The suppression window ages out before the probe arrives.
    receiver.expire_window();
    assert_eq!(
        plan.step(&mut receiver),
        ReconcileState::Indeterminate {
            reason: EscalationReason::IndeterminateDelivery,
        },
        "an unknown probe against a weak downstream is undecidable"
    );

    let outcome = reconcile(
        scenario.effect,
        &mut plan,
        &mut receiver,
        principal(0x03),
        |attempt| DownstreamAck {
            receipt: opaque(0x04),
            attempt,
        },
    );
    match outcome {
        ReconcileOutcome::Escalated(receipt) => {
            assert_eq!(receipt.owner(), principal(0x03));
            assert_eq!(receipt.reason(), EscalationReason::IndeterminateDelivery);
            assert_eq!(receipt.commit_receipt().attempt, 1);
        }
        other => panic!("an undecidable outcome must escalate, not settle: {other:?}"),
    }
    assert_eq!(
        receiver.accepted.len(),
        1,
        "escalating never duplicates the canonical effect"
    );

    match scenario.ledger.close() {
        RegionCloseOutcome::ContainmentFailure(failure) => {
            let escalated = failure.escalated();
            assert_eq!(
                escalated.len(),
                1,
                "the region names what it could not settle"
            );
            let first = escalated.first().expect("checked length");
            assert_eq!(first.state(), ObligationState::Escalated);
            assert!(
                failure.leaks().is_empty(),
                "an escalation is an owned outcome, not a leak"
            );
        }
        RegionCloseOutcome::Quiescent(receipt) => {
            panic!("an escalated effect must block quiescence: {receipt:?}")
        }
    }
}

#[test]
fn the_same_sequence_against_a_strong_downstream_proceeds_without_a_human() {
    let scenario = deferred_effect(403, DownstreamIdempotency::Strong);
    let mut receiver = Receiver::strong().losing_acknowledgements(1);
    let mut plan = ReconcilePlan::new(scenario.key, DownstreamIdempotency::Strong, attempts(3));

    assert_eq!(
        plan.step(&mut receiver),
        ReconcileState::Probing { attempt: 1 },
        "the same ambiguous timeout as the weak case"
    );
    // The same window expiry as the weak case; a strong downstream still knows.
    receiver.expire_window();

    let outcome = reconcile(
        scenario.effect,
        &mut plan,
        &mut receiver,
        principal(0x05),
        |attempt| DownstreamAck {
            receipt: opaque(0x06),
            attempt,
        },
    );
    match outcome {
        ReconcileOutcome::Acknowledged(settled) => {
            assert_eq!(settled.state(), ObligationState::Acknowledged);
        }
        other => panic!("a durable downstream answers definitively: {other:?}"),
    }
    assert_eq!(receiver.accepted.len(), 1, "still exactly once");
    let outcome = scenario.ledger.close();
    assert!(outcome.is_quiescent(), "{outcome:?}");
}

#[test]
fn a_definite_non_delivery_is_retried_under_the_same_key() {
    let scenario = deferred_effect(404, DownstreamIdempotency::Strong);
    let mut receiver = Receiver::strong().failing_transiently(2);
    let mut plan = ReconcilePlan::new(scenario.key, DownstreamIdempotency::Strong, attempts(4));

    let outcome = reconcile(
        scenario.effect,
        &mut plan,
        &mut receiver,
        principal(0x07),
        |attempt| DownstreamAck {
            receipt: opaque(0x08),
            attempt,
        },
    );
    match outcome {
        ReconcileOutcome::Acknowledged(settled) => {
            assert_eq!(settled.state(), ObligationState::Acknowledged);
        }
        other => panic!("a transient failure is retried, not escalated: {other:?}"),
    }
    assert_eq!(
        plan.state(),
        ReconcileState::Delivered { attempt: 3 },
        "the third attempt landed"
    );
    assert_eq!(
        receiver.accepted.len(),
        1,
        "retrying under one key produces one effect"
    );
    let outcome = scenario.ledger.close();
    assert!(outcome.is_quiescent(), "{outcome:?}");
}

#[test]
fn a_permanent_rejection_fails_terminally_rather_than_retrying_forever() {
    let scenario = deferred_effect(405, DownstreamIdempotency::Weak);
    let mut receiver = Receiver::weak(4).rejecting_permanently();
    let mut plan = ReconcilePlan::new(scenario.key, DownstreamIdempotency::Weak, attempts(5));

    let outcome = reconcile(
        scenario.effect,
        &mut plan,
        &mut receiver,
        principal(0x09),
        |attempt| DownstreamAck {
            receipt: opaque(0x0A),
            attempt,
        },
    );
    match outcome {
        ReconcileOutcome::TerminallyFailed(settled) => {
            assert_eq!(settled.state(), ObligationState::TerminallyFailed);
        }
        other => panic!("a permanent rejection is terminal: {other:?}"),
    }
    assert_eq!(
        plan.state(),
        ReconcileState::Undeliverable {
            reason: TerminalFailureReason::PermanentDownstreamRejection,
        }
    );
    assert!(receiver.accepted.is_empty(), "nothing was delivered");
    let outcome = scenario.ledger.close();
    assert!(
        outcome.is_quiescent(),
        "a terminally failed effect is settled, so the region closes: {outcome:?}"
    );
}

#[test]
fn an_exhausted_retry_budget_escalates_instead_of_looping() {
    let scenario = deferred_effect(406, DownstreamIdempotency::Strong);
    let mut receiver = Receiver::strong().failing_transiently(10);
    let mut plan = ReconcilePlan::new(scenario.key, DownstreamIdempotency::Strong, attempts(2));

    let outcome = reconcile(
        scenario.effect,
        &mut plan,
        &mut receiver,
        principal(0x0B),
        |attempt| DownstreamAck {
            receipt: opaque(0x0C),
            attempt,
        },
    );
    match outcome {
        ReconcileOutcome::Escalated(receipt) => {
            assert_eq!(receipt.reason(), EscalationReason::RetryBudgetExhausted);
        }
        other => panic!("an exhausted budget escalates: {other:?}"),
    }
    assert!(
        plan.transitions().len() <= 6,
        "the loop is bounded by the policy, not by the downstream"
    );
    assert!(receiver.accepted.is_empty());
    let outcome = scenario.ledger.close();
    assert!(!outcome.is_quiescent(), "{outcome:?}");
}

#[test]
fn a_strong_downstream_that_answers_unknown_is_a_contract_violation() {
    let scenario = deferred_effect(407, DownstreamIdempotency::Strong);
    let mut receiver = Receiver::strong()
        .losing_acknowledgements(1)
        .breaking_its_probe_contract();
    let mut plan = ReconcilePlan::new(scenario.key, DownstreamIdempotency::Strong, attempts(3));

    let outcome = reconcile(
        scenario.effect,
        &mut plan,
        &mut receiver,
        principal(0x0D),
        |attempt| DownstreamAck {
            receipt: opaque(0x0E),
            attempt,
        },
    );
    match outcome {
        ReconcileOutcome::Escalated(receipt) => {
            assert_eq!(
                receipt.reason(),
                EscalationReason::ProbeContractViolation,
                "a broken idempotency promise is escalated as such, not resent"
            );
        }
        other => panic!("a contract violation escalates: {other:?}"),
    }
    assert_eq!(receiver.accepted.len(), 1, "still no duplicate");
    let outcome = scenario.ledger.close();
    assert!(!outcome.is_quiescent(), "{outcome:?}");
}

#[test]
fn a_plan_is_replayable_from_its_transition_list() {
    let scenario = deferred_effect(408, DownstreamIdempotency::Weak);
    let mut receiver = Receiver::weak(4).failing_transiently(1);
    let mut plan = ReconcilePlan::new(scenario.key, DownstreamIdempotency::Weak, attempts(3));
    let terminal = plan.run(&mut receiver);
    assert_eq!(terminal, ReconcileState::Delivered { attempt: 2 });

    let mut replayed = ReconcileState::Pending { attempt: 1 };
    for transition in plan.transitions() {
        assert_eq!(
            transition.from(),
            replayed,
            "each recorded step starts where the previous one ended"
        );
        replayed = transition.to();
    }
    assert_eq!(
        replayed, terminal,
        "replaying the trace reaches the same end"
    );
    assert_eq!(plan.key(), scenario.key);
    assert_eq!(plan.idempotency(), DownstreamIdempotency::Weak);

    let settled = scenario.effect.acknowledge(DownstreamAck {
        receipt: opaque(0x0F),
        attempt: 2,
    });
    assert_eq!(settled.state(), ObligationState::Acknowledged);
    let outcome = scenario.ledger.close();
    assert!(outcome.is_quiescent(), "{outcome:?}");
}
