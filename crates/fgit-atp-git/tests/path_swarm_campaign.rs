#![forbid(unsafe_code)]
//! FG-023b bounded path/swarm campaign over the published SANS-I/O surface.
//!
//! This is a campaign over recorded logical observations, not an assertion
//! about a live socket runtime. `fgit-atp-git` deliberately has neither an
//! async runtime nor wall-clock deadline API: a path race receives a bounded
//! candidate vector and a bounded observation slice, then returns a receipt or
//! [`AtpRefusal`]. The companion e2e suite guards that construction boundary.
//!
//! In particular, availability is an untrusted scheduling declaration. A peer
//! that advertises a piece but yields an invalid result is penalized, and the
//! piece cannot become verified until a manifest-verified result arrives from
//! an eligible peer.

use fgit_atp_git::{
    AtpRefusal, PathAdmission, PathAttributes, PathCandidate, PathId, PathProbeObservation,
    PathRaceLimits, PathRacer, PathTransport, PeerAvailability, PeerIdentity, PeerPenaltyPolicy,
    PieceId, PieceStatus, SwarmLimits, SwarmPieceTracker, TransferAbortReason, TransferActor,
    TransferActorLimits, TransferCapability, TransferEffectBroker, TransferEffectIntent,
    TransferEffectKey, TransferEffectKind, TransferEffectReceipt, TransferEffectState,
    TransferInputRoot,
};

const fn peer(value: u8) -> PeerIdentity {
    PeerIdentity::from_bytes([value; 32])
}

const fn attributes(policy_rank: u16, regime_epoch: u64) -> PathAttributes {
    PathAttributes {
        policy_rank,
        estimated_rtt_micros: 100,
        estimated_goodput_bytes_per_second: 1_000,
        estimated_cost_microunits: 1,
        regime_epoch,
    }
}

fn candidate(
    id: u32,
    transport: PathTransport,
    admission: PathAdmission,
    policy_rank: u16,
    regime_epoch: u64,
) -> PathCandidate {
    PathCandidate::new(
        PathId::new(id),
        peer(u8::try_from(id).expect("campaign path identifiers fit in a byte")),
        transport,
        admission,
        attributes(policy_rank, regime_epoch),
    )
}

fn path_effect(path: u8) -> TransferEffectIntent {
    TransferEffectIntent::new(
        TransferEffectKey::from_bytes([path; 32]),
        TransferEffectKind::PathAttempt,
        TransferCapability::Path(PathId::new(u32::from(path))),
        TransferInputRoot::from_bytes([42; 32]),
        256,
        vec![path; 4],
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BrokerEvent {
    Reserved(TransferEffectKey),
    Committed(TransferEffectKey),
    Aborted(TransferEffectKey, TransferAbortReason),
    Acknowledged(TransferEffectKey),
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
        _receipt: TransferEffectReceipt,
    ) -> Result<(), AtpRefusal> {
        self.events.push(BrokerEvent::Committed(key));
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
        _receipt: TransferEffectReceipt,
    ) -> Result<(), AtpRefusal> {
        self.events.push(BrokerEvent::Acknowledged(key));
        Ok(())
    }
}

#[test]
fn partition_shapes_are_bounded_receipts_or_named_refusals() {
    let racer = PathRacer::new(PathRaceLimits::new(2, 2).expect("nonzero bounded race"));
    let permitted = vec![
        candidate(
            1,
            PathTransport::DirectQuic,
            PathAdmission::Permitted,
            0,
            19,
        ),
        candidate(2, PathTransport::Relay, PathAdmission::Permitted, 1, 19),
    ];

    let failover = racer
        .race(
            permitted.clone(),
            &[
                PathProbeObservation {
                    path: PathId::new(1),
                    arrival_turn: 4,
                    usable: false,
                },
                PathProbeObservation {
                    path: PathId::new(2),
                    arrival_turn: 5,
                    usable: true,
                },
            ],
        )
        .expect("a permitted alternate path yields a bounded receipt");
    assert_eq!(failover.started(), &[PathId::new(1), PathId::new(2)]);
    assert_eq!(failover.winner(), Some(PathId::new(2)));
    assert_eq!(failover.drained_losers(), &[PathId::new(1)]);

    let no_usable_path = racer
        .race(
            permitted.clone(),
            &[
                PathProbeObservation {
                    path: PathId::new(1),
                    arrival_turn: 0,
                    usable: false,
                },
                PathProbeObservation {
                    path: PathId::new(2),
                    arrival_turn: 1,
                    usable: false,
                },
            ],
        )
        .expect("all unusable observations remain a terminal receipt");
    assert_eq!(no_usable_path.winner(), None);
    assert_eq!(
        no_usable_path.drained_losers(),
        &[PathId::new(1), PathId::new(2)]
    );

    assert_eq!(
        racer.race(
            vec![candidate(
                3,
                PathTransport::Mailbox,
                PathAdmission::BudgetDenied,
                0,
                19,
            )],
            &[],
        ),
        Err(AtpRefusal::NoEligiblePath)
    );
    assert_eq!(
        racer.race(
            permitted,
            &[PathProbeObservation {
                path: PathId::new(99),
                arrival_turn: 0,
                usable: true,
            }],
        ),
        Err(AtpRefusal::ObservationForUnstartedPath {
            path: PathId::new(99),
        })
    );

    let bounded_to_one = PathRacer::new(PathRaceLimits::new(1, 1).expect("one bounded path"));
    assert_eq!(
        bounded_to_one.race(
            vec![
                candidate(
                    1,
                    PathTransport::DirectQuic,
                    PathAdmission::Permitted,
                    0,
                    19
                ),
                candidate(2, PathTransport::Relay, PathAdmission::Permitted, 1, 19),
            ],
            &[],
        ),
        Err(AtpRefusal::TooManyPathCandidates {
            offered: 2,
            maximum: 1,
        })
    );
}

#[test]
fn failover_aborts_the_loser_before_the_winner_has_a_visible_effect() {
    let racer = PathRacer::new(PathRaceLimits::new(2, 2).expect("nonzero bounded race"));
    let receipt = racer
        .race(
            vec![
                candidate(
                    1,
                    PathTransport::DirectQuic,
                    PathAdmission::Permitted,
                    0,
                    23,
                ),
                candidate(2, PathTransport::Relay, PathAdmission::Permitted, 1, 23),
            ],
            &[
                PathProbeObservation {
                    path: PathId::new(1),
                    arrival_turn: 0,
                    usable: false,
                },
                PathProbeObservation {
                    path: PathId::new(2),
                    arrival_turn: 1,
                    usable: true,
                },
            ],
        )
        .expect("the relay takes over from the failed direct path");
    assert_eq!(receipt.winner(), Some(PathId::new(2)));
    assert_eq!(receipt.drained_losers(), &[PathId::new(1)]);

    let mut actor = TransferActor::new(
        TransferActorLimits::new(2, 16).expect("two bounded path effects are permitted"),
    );
    let mut broker = RecordingBroker::default();
    actor
        .begin_race()
        .expect("prepared actor enters bounded race");

    let loser = path_effect(1);
    let loser_key = loser.key();
    let winner = path_effect(2);
    let winner_key = winner.key();
    let winner_receipt = TransferEffectReceipt::from_bytes([2; 32]);
    actor
        .reserve_effect(&mut broker, loser)
        .expect("the direct path reservation is owned before probing");
    actor
        .reserve_effect(&mut broker, winner)
        .expect("the relay reservation is owned before probing");
    actor
        .abort_effect(&mut broker, loser_key, TransferAbortReason::RaceLoser)
        .expect("the losing path drains before an external commit");
    actor
        .commit_effect(&mut broker, winner_key, winner_receipt)
        .expect("only the selected path can commit");
    actor
        .acknowledge_effect(&mut broker, winner_key, winner_receipt)
        .expect("the selected path remains owed until acknowledgement");
    actor
        .begin_finalization()
        .expect("a settled bounded race may enter finalization");
    assert_eq!(
        actor
            .close()
            .expect("every effect has a terminal outcome")
            .settled_effects(),
        2
    );

    assert_eq!(
        actor.effect_state(loser_key),
        Some(&TransferEffectState::Aborted(
            TransferAbortReason::RaceLoser
        ))
    );
    assert_eq!(
        actor.effect_state(winner_key),
        Some(&TransferEffectState::Acknowledged(winner_receipt))
    );
    assert_eq!(
        broker.events,
        vec![
            BrokerEvent::Reserved(loser_key),
            BrokerEvent::Reserved(winner_key),
            BrokerEvent::Aborted(loser_key, TransferAbortReason::RaceLoser),
            BrokerEvent::Committed(winner_key),
            BrokerEvent::Acknowledged(winner_key),
        ]
    );
}

#[test]
fn invalid_availability_claim_is_penalized_and_cannot_verify_the_piece() {
    let piece = PieceId::new(7);
    let penalty = PeerPenaltyPolicy::new(1, 0).expect("one bad result excludes a peer");
    let limits = SwarmLimits::new(1, 2, 1, 0, 1, penalty).expect("bounded swarm limits");
    let mut tracker = SwarmPieceTracker::new(
        limits,
        vec![piece],
        vec![
            PeerAvailability::new(peer(1), vec![piece]),
            PeerAvailability::new(peer(2), vec![piece]),
        ],
    )
    .expect("two canonical availability declarations are accepted");

    let liar_assignment = tracker
        .next_assignment(31)
        .expect("the bounded scheduler accepts the regime")
        .expect("an availability declaration offers the missing piece");
    assert_eq!(liar_assignment.peer, peer(1));
    tracker
        .record_piece_result(piece, liar_assignment.peer, false, 31)
        .expect("an invalid result records negative peer evidence");
    assert_eq!(tracker.status(piece), Some(PieceStatus::Rejected));
    assert_eq!(tracker.penalty_at(peer(1), 31), Ok(1));

    let honest_assignment = tracker
        .next_assignment(31)
        .expect("the bounded scheduler accepts the same regime")
        .expect("the unpenalized peer is still eligible");
    assert_eq!(honest_assignment.peer, peer(2));
    tracker
        .record_piece_result(piece, honest_assignment.peer, true, 31)
        .expect("only a verified result may settle the piece");
    assert_eq!(tracker.status(piece), Some(PieceStatus::Verified));
    assert_eq!(tracker.penalty_at(peer(2), 31), Ok(0));
}

#[test]
fn admitted_git_pack_transport_is_receipted_as_path_selection_not_controller_fallback() {
    let racer = PathRacer::new(PathRaceLimits::new(3, 1).expect("one bounded fallback path"));
    let receipt = racer
        .race(
            vec![
                candidate(
                    1,
                    PathTransport::DirectQuic,
                    PathAdmission::TrustScopeDenied,
                    0,
                    29,
                ),
                candidate(
                    2,
                    PathTransport::SwarmPeer,
                    PathAdmission::BudgetDenied,
                    1,
                    29,
                ),
                candidate(
                    3,
                    PathTransport::GitPackFallback,
                    PathAdmission::Permitted,
                    2,
                    29,
                ),
            ],
            &[PathProbeObservation {
                path: PathId::new(3),
                arrival_turn: 0,
                usable: true,
            }],
        )
        .expect("a permitted conservative fallback path remains selectable");

    assert_eq!(receipt.policy_rejected(), &[PathId::new(1), PathId::new(2)]);
    assert_eq!(receipt.started(), &[PathId::new(3)]);
    assert_eq!(receipt.winner(), Some(PathId::new(3)));
    assert_eq!(receipt.drained_losers(), &[]);
}
