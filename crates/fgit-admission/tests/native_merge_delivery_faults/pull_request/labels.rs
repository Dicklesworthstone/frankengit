//! Label replacement through production sealing/CAS with deterministic model faults.
use super::*;
use fgit_admission::merge::native::pull_request::{self as native, labels};
use fgit_forge::ForgeEventPayload;
use fgit_forge::event::pull_request_labels::PullRequestLabelsCommand;

#[path = "labels/addition.rs"]
mod addition;

fn command(previous: u64, values: &[&str]) -> PullRequestLabelsCommand {
    PullRequestLabelsCommand {
        number: PullRequestNumber::FIRST,
        expected_version: fgit_forge::AggregateVersion::try_new(previous)
            .map_or(ExpectedVersion::NewStream, ExpectedVersion::Exactly),
        labels: values.iter().map(|value| (*value).into()).collect(),
    }
}
fn submit(
    case: &PrFixture,
    command: &PullRequestLabelsCommand,
) -> Result<TerminalOutcome, AdmissionError> {
    poll_ready(labels::admit_async(
        case.fixture.store.as_ref(),
        &(),
        &case.fixture.context,
        command,
        AdmissionLimits::default(),
        &case.projection,
    ))
}
fn basis(case: &PrFixture) -> PublicationBasis {
    let head = case.fixture.head();
    PublicationBasis::new(
        fgit_authority::authority_head_identity(&head).unwrap(),
        head,
    )
}
fn read(case: &PrFixture, at: &PublicationBasis) -> native::PullRequestView {
    poll_ready(native::read_page_at(
        case.fixture.store.as_ref(),
        &(),
        at,
        0,
        1,
        &|_, _| true,
        &|| false,
    ))
    .unwrap()
    .pull_requests
    .remove(0)
}
fn committed(outcome: TerminalOutcome) {
    assert!(
        matches!(outcome.outcome, DecisionOutcome::Committed { .. }),
        "{outcome:?}"
    );
}

#[test]
fn labels_have_independent_versions_history_and_original_key_recovery() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let case = PrFixture::new(format, PullRequestAction::Update).with_key(b"label-original");
        let before = basis(&case);
        let original = read(&case, &before);
        let change = command(0, &["bug", "urgent"]);
        let (event, seal) = labels::proposal(&case.fixture.context, &change).unwrap();
        let (tx, _) = seal.derive().unwrap();
        let outcome = submit(&case, &change).unwrap();
        committed(outcome);
        let after = basis(&case);
        let selected = read(&case, &after);
        assert_eq!(selected.labels, change.labels);
        assert_eq!(selected.labels_version.unwrap().get(), 1);
        assert_eq!(
            selected.labels_actor,
            Some(case.fixture.context.principal_id)
        );
        assert_eq!(selected.event, original.event);
        assert_eq!(selected.data, original.data);
        assert_eq!(selected.opened_by, original.opened_by);
        assert_eq!(selected.last_metadata_actor, original.last_metadata_actor);
        assert_eq!(before.body().ref_root, after.body().ref_root);
        assert_eq!(before.body().policy_epoch, after.body().policy_epoch);
        assert_eq!(
            before.body().configuration_root,
            after.body().configuration_root
        );
        let (_, state) = selected_state(&case.fixture);
        assert_eq!(
            state
                .forge
                .entry(AsciiSlug::from_static("pull-request/1"))
                .unwrap()
                .successor_position(),
            1
        );
        let labels_entry = state
            .forge
            .entry(AsciiSlug::from_static("pull-request-labels/1"))
            .unwrap();
        let events: ForgeEventBatch = case
            .fixture
            .store
            .read(
                case.fixture.context.repository_id,
                EVENT_NAMESPACE,
                labels_entry.event_batch_root(),
            )
            .unwrap();
        assert_eq!(events.events, vec![event]);
        assert_eq!(
            state
                .outbox
                .entries()
                .iter()
                .filter(|entry| entry.tx_id() == tx)
                .count(),
            1
        );
        let clearer = case.with_key(b"label-clear");
        committed(submit(&clearer, &command(1, &[])).unwrap());
        let latest = basis(&case);
        assert!(read(&case, &latest).labels.is_empty());
        assert_eq!(read(&case, &latest).labels_version.unwrap().get(), 2);
        assert_eq!(submit(&case, &change).unwrap(), outcome);
        assert_eq!(basis(&case), latest);
        assert!(read(&case, &before).labels.is_empty());
        assert_eq!(read(&case, &after).labels, change.labels);
        assert!(submit(&case, &command(0, &["different"])).is_err());
        assert_eq!(
            labels::proposal(&case.fixture.context, &change).unwrap().1,
            seal
        );
    }
}

#[test]
fn label_cas_race_preserves_exact_predecessor_but_allows_independent_content_changes() {
    for competitor_labels in [true, false] {
        let case = PrFixture::new(GitHashAlgorithm::Sha256, PullRequestAction::Update)
            .with_key(b"label-race-loser");
        let mut winner = case.with_key(b"label-race-winner");
        let initial = read(&case, &basis(&case));
        winner.command.action = PullRequestAction::Close;
        winner.command.data = initial.data.clone().unwrap();
        *case.fixture.store.before_publish.lock().unwrap() = Some(Box::new(move || {
            let result = if competitor_labels {
                submit(&winner, &command(0, &["winner"]))
            } else {
                winner.run()
            };
            committed(result.unwrap());
        }));
        let result = submit(&case, &command(0, &["original"])).unwrap();
        let selected = read(&case, &basis(&case));
        if competitor_labels {
            assert!(matches!(
                result.outcome,
                DecisionOutcome::Refused {
                    code: RefusalCode::EvidenceStale,
                    ..
                }
            ));
            assert_eq!(selected.labels, vec!["winner"]);
            assert_eq!(selected.event, initial.event);
        } else {
            committed(result);
            assert_eq!(selected.labels, vec!["original"]);
            assert!(
                matches!(&selected.event.payload, ForgeEventPayload::PullRequestChangedNative(change)
                if change.action == PullRequestAction::Close)
            );
        }
        let current = basis(&case);
        assert_eq!(submit(&case, &command(0, &["original"])).unwrap(), result);
        assert_eq!(basis(&case), current);
    }
}

#[test]
fn label_cancellation_and_missing_subjects_never_become_empty_successes() {
    for cancellation in [CANCEL_BEFORE_SEAL, CANCEL_BEFORE_PUBLICATION] {
        let case = PrFixture::new(GitHashAlgorithm::Sha1, PullRequestAction::Update)
            .with_key(b"label-cancelled");
        let before = basis(&case);
        let change = command(0, &["triage"]);
        let tx = labels::proposal(&case.fixture.context, &change)
            .unwrap()
            .1
            .derive()
            .unwrap()
            .0;
        case.projection
            .cancellation
            .store(cancellation, Ordering::SeqCst);
        assert!(submit(&case, &change).is_err());
        assert_eq!(basis(&case), before);
        assert_eq!(case.fixture.outcome(tx), OutcomeLookup::Undecided);
        case.projection.cancellation.store(LIVE, Ordering::SeqCst);
        committed(submit(&case, &change).unwrap());
    }
    let absent =
        PrFixture::new(GitHashAlgorithm::Sha1, PullRequestAction::Open).with_key(b"label-missing");
    let result = submit(&absent, &command(0, &["triage"])).unwrap();
    assert!(matches!(
        result.outcome,
        DecisionOutcome::Refused {
            code: RefusalCode::EvidenceMissing,
            ..
        }
    ));
}
