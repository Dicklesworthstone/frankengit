#![forbid(unsafe_code)]
//! FG-023a acceptance tests for deterministic ATP-Git path and swarm ownership.
//!
//! The broker below is intentionally an in-process receipt recorder.  It proves
//! the SANS-I/O actor's ordering contract (reserve before effect; abort or
//! acknowledgement before close), not native socket reaping.  A runtime adapter
//! owns the latter when it binds this interface to its region and obligations.

use fgit_atp_git::{
    AtpRefusal, PathAdmission, PathAttributes, PathCandidate, PathId, PathProbeObservation,
    PathRaceLimits, PathRacer, PathTransport, PeerAvailability, PeerIdentity, PeerPenaltyLedger,
    PeerPenaltyPolicy, PieceId, SwarmLimits, SwarmPieceTracker, TransferAbortReason, TransferActor,
    TransferActorLimits, TransferActorPhase, TransferCancellationSource, TransferCapability,
    TransferEffectBroker, TransferEffectIntent, TransferEffectKey, TransferEffectKind,
    TransferEffectReceipt, TransferInputRoot,
};

fn peer(value: u8) -> PeerIdentity {
    PeerIdentity::from_bytes([value; 32])
}

const fn attributes(policy_rank: u16, rtt: u64, goodput: u64, cost: u64) -> PathAttributes {
    PathAttributes {
        policy_rank,
        estimated_rtt_micros: rtt,
        estimated_goodput_bytes_per_second: goodput,
        estimated_cost_microunits: cost,
        regime_epoch: 7,
    }
}

fn candidate(id: u32, admission: PathAdmission, attrs: PathAttributes) -> PathCandidate {
    PathCandidate::new(
        PathId::new(id),
        peer(u8::try_from(id).expect("small test path id")),
        PathTransport::DirectQuic,
        admission,
        attrs,
    )
}

#[test]
fn path_race_replays_the_same_winner_and_drains_the_same_losers() {
    let racer = PathRacer::new(PathRaceLimits::new(3, 2).expect("bounded race limits"));
    let candidates = vec![
        candidate(
            3,
            PathAdmission::PrivacyScopeDenied,
            attributes(0, 1, 99, 0),
        ),
        candidate(2, PathAdmission::Permitted, attributes(1, 10, 100, 2)),
        candidate(1, PathAdmission::Permitted, attributes(1, 10, 100, 2)),
    ];
    let observations = vec![
        PathProbeObservation {
            path: PathId::new(2),
            arrival_turn: 8,
            usable: true,
        },
        PathProbeObservation {
            path: PathId::new(1),
            arrival_turn: 8,
            usable: true,
        },
    ];

    let first = racer
        .race(candidates.clone(), &observations)
        .expect("admitted paths may race");
    let replay = racer
        .race(
            candidates.into_iter().rev().collect(),
            &observations.into_iter().rev().collect::<Vec<_>>(),
        )
        .expect("the same logical trace must replay");

    assert_eq!(first, replay);
    assert_eq!(first.started(), &[PathId::new(1), PathId::new(2)]);
    assert_eq!(first.policy_rejected(), &[PathId::new(3)]);
    assert_eq!(first.winner(), Some(PathId::new(1)));
    assert_eq!(first.drained_losers(), &[PathId::new(2)]);
}

#[test]
fn path_race_refuses_to_count_an_unarmed_path_as_a_result() {
    let racer = PathRacer::new(PathRaceLimits::new(2, 1).expect("bounded race limits"));
    let refusal = racer
        .race(
            vec![
                candidate(1, PathAdmission::Permitted, attributes(1, 1, 1, 1)),
                candidate(
                    2,
                    PathAdmission::BudgetDenied,
                    attributes(0, 0, u64::MAX, 0),
                ),
            ],
            &[PathProbeObservation {
                path: PathId::new(2),
                arrival_turn: 0,
                usable: true,
            }],
        )
        .expect_err("a denied path is never armed or eligible to win");

    assert_eq!(
        refusal,
        AtpRefusal::ObservationForUnstartedPath {
            path: PathId::new(2)
        }
    );
}

#[test]
fn path_race_refuses_reused_ids_even_when_attributes_sort_apart() {
    let racer = PathRacer::new(PathRaceLimits::new(2, 1).expect("bounded race limits"));

    assert_eq!(
        racer.race(
            vec![
                candidate(1, PathAdmission::Permitted, attributes(1, 1, 1, 1)),
                candidate(1, PathAdmission::Permitted, attributes(2, 2, 2, 2)),
            ],
            &[],
        ),
        Err(AtpRefusal::DuplicatePathCandidate {
            path: PathId::new(1),
        })
    );
}

#[test]
fn peer_penalties_have_a_declared_decay_and_verified_reset_regime() {
    let mut penalties =
        PeerPenaltyLedger::new(PeerPenaltyPolicy::new(3, 1).expect("nonzero exclusion threshold"));
    let source = peer(9);

    assert_eq!(penalties.record_bad_piece(source, 4), Ok(1));
    assert_eq!(penalties.record_bad_piece(source, 4), Ok(2));
    assert_eq!(penalties.penalty_at(source, 5), Ok(1));
    assert!(penalties.is_eligible(source, 5).expect("monotonic epoch"));
    penalties
        .record_verified_piece(source, 5)
        .expect("verification resets only this peer's evidence");
    assert_eq!(penalties.penalty_at(source, 5), Ok(0));
    assert_eq!(
        penalties.penalty_at(source, 4),
        Err(AtpRefusal::NonMonotonicRegimeEpoch {
            previous: 5,
            observed: 4,
        })
    );
}

#[test]
fn swarm_uses_rarest_first_then_bounded_endgame_duplicates() {
    let penalty = PeerPenaltyPolicy::new(3, 1).expect("valid penalty policy");
    let limits = SwarmLimits::new(2, 5, 3, 1, 2, penalty).expect("valid swarm limits");
    let mut tracker = SwarmPieceTracker::new(
        limits,
        vec![PieceId::new(1), PieceId::new(2)],
        vec![
            PeerAvailability::new(peer(1), vec![PieceId::new(1)]),
            PeerAvailability::new(peer(2), vec![PieceId::new(1), PieceId::new(2)]),
            PeerAvailability::new(peer(3), vec![PieceId::new(2)]),
            PeerAvailability::new(peer(4), vec![PieceId::new(2)]),
        ],
    )
    .expect("strictly sorted bounded swarm declaration");

    let rarest = tracker
        .next_assignment(0)
        .expect("valid regime")
        .expect("a rare piece is available");
    assert_eq!(rarest.piece, PieceId::new(1));
    assert_eq!(rarest.peer, peer(1));
    assert!(!rarest.duplicate);

    let common = tracker
        .next_assignment(0)
        .expect("valid regime")
        .expect("the remaining piece is available");
    assert_eq!(common.piece, PieceId::new(2));
    tracker
        .record_piece_result(common.piece, common.peer, true, 0)
        .expect("verified common piece settles its assignment");

    let duplicate = tracker
        .next_assignment(0)
        .expect("valid regime")
        .expect("endgame permits one bounded duplicate");
    assert_eq!(duplicate.piece, PieceId::new(1));
    assert_eq!(duplicate.peer, peer(2));
    assert!(duplicate.duplicate);
    assert_eq!(tracker.in_flight_assignments(), 2);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BrokerEvent {
    Reserved(TransferEffectKey),
    Committed(TransferEffectKey, TransferEffectReceipt),
    Aborted(TransferEffectKey, TransferAbortReason),
    Acknowledged(TransferEffectKey, TransferEffectReceipt),
}

#[derive(Default)]
struct RecordingBroker {
    events: Vec<BrokerEvent>,
}

impl TransferEffectBroker for RecordingBroker {
    fn reserve(&mut self, intent: &TransferEffectIntent) -> Result<(), AtpRefusal> {
        self.events.push(BrokerEvent::Reserved(intent.key()));
        Ok(())
    }

    fn commit(
        &mut self,
        key: TransferEffectKey,
        receipt: TransferEffectReceipt,
    ) -> Result<(), AtpRefusal> {
        self.events.push(BrokerEvent::Committed(key, receipt));
        Ok(())
    }

    fn abort(
        &mut self,
        key: TransferEffectKey,
        reason: TransferAbortReason,
    ) -> Result<(), AtpRefusal> {
        self.events.push(BrokerEvent::Aborted(key, reason));
        Ok(())
    }

    fn acknowledge(
        &mut self,
        key: TransferEffectKey,
        receipt: TransferEffectReceipt,
    ) -> Result<(), AtpRefusal> {
        self.events.push(BrokerEvent::Acknowledged(key, receipt));
        Ok(())
    }
}

fn effect(key: u8, parameter_bytes: usize) -> TransferEffectIntent {
    TransferEffectIntent::new(
        TransferEffectKey::from_bytes([key; 32]),
        TransferEffectKind::PathAttempt,
        TransferCapability::Path(PathId::new(u32::from(key))),
        TransferInputRoot::from_bytes([42; 32]),
        128,
        vec![key; parameter_bytes],
    )
}

fn enter_phase(actor: &mut TransferActor, phase: TransferActorPhase) {
    match phase {
        TransferActorPhase::Prepared => {}
        TransferActorPhase::Racing => actor.begin_race().expect("prepared to racing"),
        TransferActorPhase::Swarming => {
            actor.begin_race().expect("prepared to racing");
            actor.begin_swarm().expect("racing to swarming");
        }
        TransferActorPhase::Finalizing => {
            actor.begin_finalization().expect("prepared to finalizing")
        }
        TransferActorPhase::CancelRequested
        | TransferActorPhase::Draining
        | TransferActorPhase::Closed => {
            panic!("test only enters externally reachable active phases")
        }
    }
}

#[test]
fn lab_injected_cancellation_leaves_each_active_actor_phase_logically_quiescent() {
    for phase in [
        TransferActorPhase::Prepared,
        TransferActorPhase::Racing,
        TransferActorPhase::Swarming,
        TransferActorPhase::Finalizing,
    ] {
        let mut actor =
            TransferActor::new(TransferActorLimits::new(2, 16).expect("bounded actor limits"));
        let mut broker = RecordingBroker::default();
        enter_phase(&mut actor, phase);
        let intent = effect(phase as u8 + 1, 4);
        let key = intent.key();
        actor
            .reserve_effect(&mut broker, intent)
            .expect("reservation is owned before cancellation");

        let cancellation = actor
            .cancel(&mut broker, TransferCancellationSource::LabInjected)
            .expect("a reserved-only phase can drain to finalization");
        assert_eq!(cancellation.aborted(), &[key]);
        assert_eq!(
            cancellation.source(),
            TransferCancellationSource::LabInjected
        );
        assert_eq!(
            cancellation.phases(),
            &[
                TransferActorPhase::CancelRequested,
                TransferActorPhase::Draining,
                TransferActorPhase::Finalizing,
            ]
        );
        assert_eq!(actor.phase(), TransferActorPhase::Finalizing);
        assert_eq!(
            actor
                .close()
                .expect("terminal effects are quiescent")
                .settled_effects(),
            1
        );
        assert_eq!(actor.phase(), TransferActorPhase::Closed);
        assert_eq!(
            broker.events,
            vec![
                BrokerEvent::Reserved(key),
                BrokerEvent::Aborted(key, TransferAbortReason::Cancelled),
            ]
        );
    }
}

#[test]
fn cancellation_never_relabels_a_committed_effect_as_non_commit() {
    let mut actor =
        TransferActor::new(TransferActorLimits::new(2, 16).expect("bounded actor limits"));
    let mut broker = RecordingBroker::default();
    let intent = effect(7, 4);
    let key = intent.key();
    let receipt = TransferEffectReceipt::from_bytes([8; 32]);
    actor
        .reserve_effect(&mut broker, intent)
        .expect("reserve before external work");
    actor
        .commit_effect(&mut broker, key, receipt)
        .expect("record external commit");

    assert_eq!(
        actor.cancel(&mut broker, TransferCancellationSource::LabInjected),
        Err(AtpRefusal::CommittedEffectRequiresOutcome { key })
    );
    assert_eq!(actor.phase(), TransferActorPhase::Finalizing);
    actor
        .acknowledge_effect(&mut broker, key, receipt)
        .expect("an observed commit requires acknowledgement");
    assert_eq!(
        actor
            .close()
            .expect("acknowledged effect can settle")
            .settled_effects(),
        1
    );
    assert_eq!(
        broker.events,
        vec![
            BrokerEvent::Reserved(key),
            BrokerEvent::Committed(key, receipt),
            BrokerEvent::Acknowledged(key, receipt),
        ]
    );
}

#[test]
fn actor_refuses_oversized_effect_parameters_before_broker_reservation() {
    let mut actor =
        TransferActor::new(TransferActorLimits::new(1, 3).expect("bounded actor limits"));
    let mut broker = RecordingBroker::default();

    assert_eq!(
        actor.reserve_effect(&mut broker, effect(1, 4)),
        Err(AtpRefusal::EffectParametersTooLarge {
            offered: 4,
            maximum: 3,
        })
    );
    assert!(broker.events.is_empty());
}
