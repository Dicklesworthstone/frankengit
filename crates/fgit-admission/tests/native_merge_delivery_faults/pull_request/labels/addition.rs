//! Real metadata publication and deterministic CAS losers for additive labels.
use super::*;
use fgit_forge::event::pull_request_labels::PullRequestLabelsIntent;

fn intent(values: &[&str]) -> PullRequestLabelsIntent {
    PullRequestLabelsIntent {
        number: PullRequestNumber::FIRST,
        labels: values.iter().map(|value| (*value).into()).collect(),
    }
}
fn add(
    case: &PrFixture,
    intent: &PullRequestLabelsIntent,
) -> Result<TerminalOutcome, AdmissionError> {
    poll_ready(labels::admit_addition_async(
        case.fixture.store.as_ref(),
        &(),
        &case.fixture.context,
        intent,
        AdmissionLimits::default(),
        &case.projection,
    ))
}

#[test]
fn additions_union_after_competing_addition_replacement_or_close_with_original_seal() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for competitor in 0..3 {
            let case =
                PrFixture::new(format, PullRequestAction::Update).with_key(b"add-labels-original");
            committed(
                submit(
                    &case.with_key(b"initial-labels"),
                    &command(0, &["base", "shared"]),
                )
                .unwrap(),
            );
            let initial = read(&case, &basis(&case));
            let original = intent(&["beta", "shared"]);
            let (_, seal) = labels::addition_proposal(&case.fixture.context, &original).unwrap();
            let (tx, sealed) = seal.derive().unwrap();
            let mut winner = case.with_key(b"add-labels-winner");
            winner.command.action = PullRequestAction::Close;
            winner.command.data = initial.data.clone().unwrap();
            case.fixture.store.publications.lock().unwrap().clear();
            *case.fixture.store.before_publish.lock().unwrap() = Some(Box::new(move || {
                committed(
                    match competitor {
                        0 => add(&winner, &intent(&["alpha", "shared"])),
                        1 => submit(&winner, &command(1, &["alpha"])),
                        _ => winner.run(),
                    }
                    .unwrap(),
                );
            }));
            let before = basis(&case);
            let outcome = add(&case, &original).unwrap();
            committed(outcome);
            let after = basis(&case);
            let selected = read(&case, &after);
            assert_eq!(
                selected.labels,
                match competitor {
                    0 => vec!["alpha", "base", "beta", "shared"],
                    1 => vec!["alpha", "beta", "shared"],
                    _ => vec!["base", "beta", "shared"],
                }
            );
            assert_eq!(
                selected.labels_version.unwrap().get(),
                if competitor == 2 { 2 } else { 3 }
            );
            assert_eq!(selected.data, initial.data);
            if competitor == 2 {
                assert!(matches!(&selected.event.payload,
                    ForgeEventPayload::PullRequestChangedNative(change)
                        if change.action == PullRequestAction::Close));
            } else {
                assert_eq!(selected.event, initial.event);
            }
            assert_eq!(after.body().ref_root, before.body().ref_root);
            assert_eq!(after.body().policy_epoch, before.body().policy_epoch);
            let publications = case.fixture.store.publications.lock().unwrap();
            assert_eq!(publications.len(), 3);
            assert!(matches!(publications[0].1, CasOutcome::Committed(_)));
            assert!(matches!(publications[1].1, CasOutcome::PredecessorMismatch));
            assert!(matches!(publications[2].1, CasOutcome::Committed(_)));
            drop(publications);
            let (_, state) = selected_state(&case.fixture);
            let entry = state
                .forge
                .entry(AsciiSlug::from_static("pull-request-labels/1"))
                .unwrap();
            let events: ForgeEventBatch = case
                .fixture
                .store
                .read(
                    case.fixture.context.repository_id,
                    EVENT_NAMESPACE,
                    entry.event_batch_root(),
                )
                .unwrap();
            assert!(matches!(&events.events[0].payload,
                ForgeEventPayload::PullRequestLabelsAddedNative(change)
                    if change.additions == original.labels && change.labels == selected.labels));
            assert_eq!(
                state
                    .outbox
                    .entries()
                    .iter()
                    .filter(|entry| entry.tx_id() == tx)
                    .count(),
                1
            );
            let batch = read_decision_batch_body(
                &case.fixture.store.backend,
                case.fixture.head().decision_tail_id.unwrap(),
            )
            .unwrap();
            assert_eq!(
                batch.committed_rcrs[0].canonical_request_digest,
                sealed.canonical_request_digest
            );
            assert_eq!(
                labels::addition_proposal(&case.fixture.context, &original)
                    .unwrap()
                    .1,
                seal
            );
            committed(
                submit(
                    &case.with_key(b"later-clear"),
                    &command(selected.labels_version.unwrap().get(), &[]),
                )
                .unwrap(),
            );
            let cleared = basis(&case);
            assert_eq!(add(&case, &original).unwrap(), outcome);
            assert!(add(&case, &intent(&["different"])).is_err());
            assert_eq!(basis(&case), cleared);
            assert!(read(&case, &cleared).labels.is_empty());
            assert_eq!(read(&case, &after).labels, selected.labels);
        }
    }
}

#[test]
fn strict_replacement_stays_stale_after_an_additive_cas_winner() {
    let case = PrFixture::new(GitHashAlgorithm::Sha256, PullRequestAction::Update)
        .with_key(b"strict-loses-to-addition");
    let winner = case.with_key(b"addition-beats-strict");
    *case.fixture.store.before_publish.lock().unwrap() = Some(Box::new(move || {
        committed(add(&winner, &intent(&["winner"])).unwrap());
    }));
    let result = submit(&case, &command(0, &["replacement"])).unwrap();
    assert!(matches!(
        result.outcome,
        DecisionOutcome::Refused {
            code: RefusalCode::EvidenceStale,
            ..
        }
    ));
    assert_eq!(read(&case, &basis(&case)).labels, vec!["winner"]);
}

#[test]
fn capacity_is_rechecked_after_cas_loss_and_overlapping_additions_still_commit() {
    let case = PrFixture::new(GitHashAlgorithm::Sha256, PullRequestAction::Update)
        .with_key(b"capacity-addition");
    let mut initial = command(0, &[]);
    initial.labels = (0..31).map(|n| format!("label-{n:02}")).collect();
    committed(submit(&case.with_key(b"capacity-initial"), &initial).unwrap());
    let winner = case.with_key(b"capacity-winner");
    *case.fixture.store.before_publish.lock().unwrap() = Some(Box::new(move || {
        committed(add(&winner, &intent(&["winner"])).unwrap());
    }));
    let original = intent(&["zz-original"]);
    let outcome = add(&case, &original).unwrap();
    assert!(matches!(
        outcome.outcome,
        DecisionOutcome::Refused {
            code: RefusalCode::ResourceBudgetExceeded,
            ..
        }
    ));
    let full = read(&case, &basis(&case));
    assert_eq!(full.labels.len(), 32);
    assert_eq!(full.labels_version.unwrap().get(), 2);
    committed(
        add(
            &case.with_key(b"overlap-at-capacity"),
            &intent(&["label-00", "winner"]),
        )
        .unwrap(),
    );
    let overlapping = read(&case, &basis(&case));
    assert_eq!(overlapping.labels, full.labels);
    assert_eq!(overlapping.labels_version.unwrap().get(), 3);
    committed(submit(&case.with_key(b"capacity-clear"), &command(3, &[])).unwrap());
    let cleared = basis(&case);
    assert_eq!(add(&case, &original).unwrap(), outcome);
    assert_eq!(basis(&case), cleared);
    committed(add(&case.with_key(b"new-capacity-attempt"), &original).unwrap());
}

#[test]
fn cancelled_additions_stay_undecided_and_missing_prs_refuse() {
    for cancellation in [CANCEL_BEFORE_SEAL, CANCEL_BEFORE_PUBLICATION] {
        let case = PrFixture::new(GitHashAlgorithm::Sha1, PullRequestAction::Update)
            .with_key(b"cancelled-addition");
        let original = intent(&["triage"]);
        let tx = labels::addition_proposal(&case.fixture.context, &original)
            .unwrap()
            .1
            .derive()
            .unwrap()
            .0;
        let before = basis(&case);
        case.projection
            .cancellation
            .store(cancellation, Ordering::SeqCst);
        assert!(add(&case, &original).is_err());
        assert_eq!(basis(&case), before);
        assert_eq!(case.fixture.outcome(tx), OutcomeLookup::Undecided);
        case.projection.cancellation.store(LIVE, Ordering::SeqCst);
        committed(add(&case, &original).unwrap());
    }
    let missing = PrFixture::new(GitHashAlgorithm::Sha1, PullRequestAction::Open)
        .with_key(b"missing-addition");
    assert!(matches!(
        add(&missing, &intent(&["triage"])).unwrap().outcome,
        DecisionOutcome::Refused {
            code: RefusalCode::EvidenceMissing,
            ..
        }
    ));
}
