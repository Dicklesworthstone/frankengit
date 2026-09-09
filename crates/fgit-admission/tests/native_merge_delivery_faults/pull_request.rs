//! Native merge admission against canonical, genesis-seeded PR frontiers.
//! The event bodies and selected head are real; the MemoryAuthorityStore is
//! deliberately non-durable. Open/Update/Close publication is absent at this
//! revision, so these fixtures do not claim that lifecycle admission exists.

use fgit_codec::{CanonicalForgePositionState, CanonicalOutboxState, ForgePositionStateEntry};
use fgit_forge::event::pull_request::{
    PullRequestAction, PullRequestCommand, PullRequestData, validate_transition,
};

use super::*;

#[derive(Clone, Copy, Debug)]
enum Prior {
    Open,
    Update,
    Close,
    OtherSourceRef,
    OtherTargetRef,
    OtherSourceTip,
    OtherTargetTip,
}

impl Prior {
    fn refusal(self) -> Option<RefusalCode> {
        match self {
            Self::Open | Self::Update => None,
            Self::Close | Self::OtherSourceRef | Self::OtherTargetRef => {
                Some(RefusalCode::ProtectedRefTransitionDenied)
            }
            Self::OtherSourceTip | Self::OtherTargetTip => Some(RefusalCode::EvidenceStale),
        }
    }
}

fn selected_pr_fixture(format: GitHashAlgorithm, prior: Prior) -> Fixture {
    let mut fixture = Fixture::new_for_format(format);
    let merge = fixture.intent.merge().unwrap().clone();
    let mut data = PullRequestData {
        source_ref: merge.source_ref.clone(),
        target_ref: merge.target_ref.clone(),
        source_tip: merge.source_tip,
        target_tip: merge.target_tip_before,
        title: "Reviewed native PR".into(),
        body: "Untrusted PR description".into(),
    };
    match prior {
        Prior::OtherSourceRef => data.source_ref = name(b"refs/heads/other-topic"),
        Prior::OtherTargetRef => data.target_ref = name(b"refs/heads/other-main"),
        Prior::OtherSourceTip => data.source_tip = merge.base_tip,
        Prior::OtherTargetTip => data.target_tip = merge.base_tip,
        Prior::Open | Prior::Update | Prior::Close => {}
    }
    let mismatches = [
        data.source_ref != merge.source_ref,
        data.target_ref != merge.target_ref,
        data.source_tip != merge.source_tip,
        data.target_tip != merge.target_tip_before,
    ]
    .into_iter()
    .filter(|different| *different)
    .count();
    assert_eq!(
        mismatches,
        usize::from(matches!(
            prior,
            Prior::OtherSourceRef
                | Prior::OtherTargetRef
                | Prior::OtherSourceTip
                | Prior::OtherTargetTip
        )),
        "each coordinate refusal isolates exactly one field"
    );
    let actions: &[PullRequestAction] = match prior {
        Prior::Open => &[PullRequestAction::Open],
        // Match the Update control's predecessor count; a version mismatch
        // must not substitute for the terminal-state guard.
        Prior::Close => &[PullRequestAction::Open, PullRequestAction::Close],
        _ => &[PullRequestAction::Open, PullRequestAction::Update],
    };
    let mut command = PullRequestCommand {
        number: PullRequestNumber::FIRST,
        expected_version: ExpectedVersion::NewStream,
        action: PullRequestAction::Open,
        data,
    };
    let mut events = Vec::new();
    for action in actions {
        command.action = *action;
        if *action == PullRequestAction::Update {
            command.data.body.push_str("\nUpdated description");
        }
        let event = command
            .proposed_event(fixture.context.principal_id, format)
            .unwrap();
        validate_transition(events.last(), &event).unwrap();
        command.expected_version = ExpectedVersion::Exactly(event.version);
        events.push(event);
    }
    fixture.intent =
        NativeMergeIntent::new(command.number, command.expected_version, merge.clone()).unwrap();
    let event_count = u32::try_from(events.len()).unwrap();
    let event_root = fixture
        .store
        .stage(
            fixture.context.repository_id,
            EVENT_NAMESPACE,
            &ForgeEventBatch { events },
        )
        .unwrap();
    let forge = CanonicalForgePositionState::try_new(
        fixture.context.repository_id,
        vec![
            ForgePositionStateEntry::try_new(
                AsciiSlug::from_static("pull-request/1"),
                0,
                event_count,
                event_root,
            )
            .unwrap(),
        ],
    )
    .unwrap();
    fixture.genesis.forge_position_root = fixture
        .store
        .stage(fixture.context.repository_id, POSITION_NAMESPACE, &forge)
        .unwrap();
    fixture.genesis.outbox_root = fixture
        .store
        .stage(
            fixture.context.repository_id,
            delivery::OUTBOX_NAMESPACE,
            &CanonicalOutboxState::try_new(fixture.context.repository_id, Vec::new()).unwrap(),
        )
        .unwrap();
    // Authenticate a separate selected starting state; do not overwrite the
    // first fixture head or invent a PR publication transaction.
    fixture.context.head_key = HeadKey::new(b"native-pr-frontier/head".to_vec()).unwrap();
    initialize_repository(
        &fixture.store.backend,
        &fixture.context.head_key,
        &fixture.genesis,
    )
    .unwrap();
    assert_eq!(fixture.intent.merge().unwrap(), &merge);
    fixture
}

fn selected_state(fixture: &Fixture) -> (CanonicalRefState, delivery::DeliveryState) {
    let head = fixture.head();
    let refs = fixture
        .store
        .read(fixture.context.repository_id, REF_NAMESPACE, head.ref_root)
        .unwrap();
    let basis = PublicationBasis::new(
        fgit_authority::authority_head_identity(&head).unwrap(),
        head,
    );
    let state = poll_ready(delivery::read_in(
        fixture.store.as_ref(),
        &(),
        &basis,
        &|| false,
    ))
    .expect("the selected canonical PR frontier must resolve through the production reader");
    (refs, state)
}

#[test]
fn native_pr_frontier_gates_both_drivers_and_original_sealed_adapters() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for driver in [NativeDriver::Sync, NativeDriver::Async] {
            for original_seal in [false, true] {
                for prior in [
                    Prior::Open,
                    Prior::Update,
                    Prior::Close,
                    Prior::OtherSourceRef,
                    Prior::OtherTargetRef,
                    Prior::OtherSourceTip,
                    Prior::OtherTargetTip,
                ] {
                    let fixture = selected_pr_fixture(format, prior);
                    let before = fixture.head();
                    let (before_refs, before_delivery) = selected_state(&fixture);
                    let merge = fixture.intent.merge().unwrap();
                    assert_eq!(
                        before_refs.refs().get(&merge.source_ref),
                        Some(&merge.source_tip)
                    );
                    assert_eq!(
                        before_refs.refs().get(&merge.target_ref),
                        Some(&merge.target_tip_before)
                    );
                    validate_merge_objects(
                        fixture.objects.as_ref(),
                        merge,
                        MergeObjectLimits::default(),
                        &mut || true,
                    )
                    .expect("PR refusal cases retain a valid native merge and live tips");
                    let package = original_seal.then(|| sealed_native_fixture(&fixture));
                    let attempt = match &package {
                        Some(package) => {
                            seal_attempt_for(&fixture.context, &package.borrowed()).unwrap()
                        }
                        None => fixture.intent.seal_attempt(&fixture.context).unwrap(),
                    };
                    let tx_id = attempt.derive().unwrap().0;
                    let run = |driver: NativeDriver| match &package {
                        Some(package) => driver.sealed(&fixture, package),
                        None => driver.run(&fixture, &fixture.context, &fixture.intent),
                    };
                    let terminal = run(driver).unwrap_or_else(|error| {
                        panic!("{format:?} {prior:?} original_seal={original_seal}: {error:?}")
                    });
                    assert_eq!(fixture.outcome(tx_id), OutcomeLookup::Decided(terminal));
                    let after = fixture.head();
                    let (after_refs, after_delivery) = selected_state(&fixture);
                    let batch = read_decision_batch_body(
                        &fixture.store.backend,
                        after
                            .decision_tail_id
                            .expect("the public driver must publish a decision"),
                    )
                    .unwrap();
                    if let Some(expected) = prior.refusal() {
                        assert!(
                            matches!(terminal.outcome, DecisionOutcome::Refused { code, .. }
                            if code == expected),
                            "{prior:?}: {terminal:?}"
                        );
                        assert_eq!(after.ref_root, before.ref_root);
                        assert_eq!(after.forge_position_root, before.forge_position_root);
                        assert_eq!(after.outbox_root, before.outbox_root);
                        assert_eq!(
                            after.latest_committed_rcr_id,
                            before.latest_committed_rcr_id
                        );
                        assert_eq!(after_refs, before_refs);
                        assert_eq!(after_delivery.forge, before_delivery.forge);
                        assert_eq!(after_delivery.outbox, before_delivery.outbox);
                        assert!(batch.committed_rcrs.is_empty());
                    } else {
                        assert!(
                            matches!(terminal.outcome, DecisionOutcome::Committed { .. }),
                            "{prior:?}: {terminal:?}"
                        );
                        assert_ne!(after.ref_root, before.ref_root);
                        assert_ne!(after.forge_position_root, before.forge_position_root);
                        assert_ne!(after.outbox_root, before.outbox_root);
                        let mut expected_refs = before_refs.refs().clone();
                        expected_refs.insert(merge.target_ref.clone(), merge.merge_commit);
                        assert_eq!(after_refs.refs(), &expected_refs);
                        assert_eq!(after_refs.head_target(), before_refs.head_target());
                        assert_eq!(after_delivery.forge.entries().len(), 1);
                        let position = &after_delivery.forge.entries()[0];
                        assert_eq!(
                            position.successor_position(),
                            fixture.intent.event().version.get()
                        );
                        assert_eq!(after_delivery.outbox.entries().len(), 1);
                        let effect = &after_delivery.outbox.entries()[0];
                        let event_root =
                            evidence_root(&ForgeEventBatch::of_one(fixture.intent.event().clone()))
                                .unwrap();
                        assert_eq!(effect.tx_id(), tx_id);
                        assert_eq!(effect.payload_root(), event_root);
                        assert_eq!(position.event_batch_root(), event_root);
                        assert_eq!(batch.committed_rcrs.len(), 1);
                        assert_eq!(batch.committed_rcrs[0].tx_id, tx_id);
                        assert_eq!(batch.committed_rcrs[0].forge_event_batch_root, event_root);
                    }
                    // Reuse the exact original identity after the terminal
                    // decision, including the now-stale successful ref tips.
                    assert_eq!(run(driver.other()).unwrap(), terminal);
                    assert_eq!(run(driver).unwrap(), terminal);
                    assert_eq!(fixture.head(), after);
                    assert_eq!(fixture.store.publications.lock().unwrap().len(), 1);
                }
            }
        }
    }
}
