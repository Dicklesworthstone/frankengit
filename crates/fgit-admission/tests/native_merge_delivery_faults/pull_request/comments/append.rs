//! Deterministic publication races and uncertain delivery through real admission.
//! The model store schedules faults; it does not establish filesystem durability.
use super::*;
use fgit_admission::merge::native::pull_request::{self as native_pr, PullRequestView};
use fgit_authority::SealAttempt;
use fgit_forge::event::pull_request_comment::PullRequestAppendCommentCommand;

fn append(body: &str) -> PullRequestAppendCommentCommand {
    PullRequestAppendCommentCommand {
        number: PullRequestNumber::FIRST,
        body: body.into(),
        anchor: None,
    }
}
fn submit(
    case: &PrFixture,
    command: &PullRequestAppendCommentCommand,
    limits: AdmissionLimits,
) -> Result<TerminalOutcome, AdmissionError> {
    poll_ready(conversation::admit_append_async(
        case.fixture.store.as_ref(),
        &(),
        &case.fixture.context,
        command,
        limits,
        &case.projection,
    ))
}
fn seal(case: &PrFixture, command: &PullRequestAppendCommentCommand) -> SealAttempt {
    conversation::append_proposal(&case.fixture.context, command)
        .unwrap()
        .1
}
fn current_pr(case: &PrFixture) -> PullRequestView {
    let page = poll_ready(native_pr::read_page_at(
        case.fixture.store.as_ref(),
        &(),
        &basis(case),
        PullRequestNumber::FIRST.get() - 1,
        1,
        &|_, _| true,
        &|| false,
    ))
    .unwrap();
    assert_eq!(page.pull_requests.len(), 1);
    page.pull_requests.into_iter().next().unwrap()
}
fn interleave(case: &PrFixture, close: bool) {
    let mut competitor = case.with_key(b"winner-before-append");
    if close {
        // The shared fixture carries an unsubmitted metadata update. Closing
        // must retain the authority-selected data, not accidentally submit that
        // edit and be refused before the append can lose its head CAS.
        let selected = current_pr(case);
        competitor.command.expected_version = ExpectedVersion::Exactly(selected.event.version);
        competitor.command.data = selected.data.unwrap();
        competitor.command.action = PullRequestAction::Close;
    }
    *case.fixture.store.before_publish.lock().unwrap() = Some(Box::new(move || {
        let terminal = if close {
            competitor.run().unwrap()
        } else {
            submit(
                &competitor,
                &append("Winning comment"),
                AdmissionLimits::default(),
            )
            .unwrap()
        };
        assert!(
            matches!(terminal.outcome, DecisionOutcome::Committed { .. }),
            "the competing publication must commit before the append: {terminal:?}"
        );
    }));
}
fn once(case: &PrFixture, command: &PullRequestAppendCommentCommand, count: usize) {
    let tx = seal(case, command).derive().unwrap().0;
    let (_, state) = selected_state(&case.fixture);
    assert_eq!(
        state
            .outbox
            .entries()
            .iter()
            .filter(|entry| entry.tx_id() == tx)
            .count(),
        1
    );
    let page = read(case, &basis(case), 0, 10);
    assert_eq!(page.comments.len(), count);
    assert_eq!(page.discussion_version.unwrap().get(), count as u64);
    assert_eq!(page.comments.last().unwrap().body, command.body);
    for (index, comment) in page.comments.iter().enumerate() {
        assert_eq!(comment.version.get(), index as u64 + 1);
    }
}

#[test]
fn append_replans_after_real_comment_or_close_cas_without_changing_original_seal() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for close in [false, true] {
            let case = opened(format);
            case.fixture.store.publications.lock().unwrap().clear();
            let before = case.fixture.head();
            let original_pr = current_pr(&case);
            let command = append("Original append survives contention é\r\n");
            let original = seal(&case, &command);
            let (tx, sealed) = original.derive().unwrap();
            interleave(&case, close);
            let terminal = submit(&case, &command, AdmissionLimits::default()).unwrap();
            assert!(matches!(
                terminal.outcome,
                DecisionOutcome::Committed { .. }
            ));
            assert_eq!(seal(&case, &command), original);
            assert_eq!(case.fixture.outcome(tx), OutcomeLookup::Decided(terminal));
            let publications = case.fixture.store.publications.lock().unwrap();
            assert_eq!(publications.len(), 3);
            assert!(matches!(publications[0].1, CasOutcome::Committed(_)));
            assert!(matches!(publications[1].1, CasOutcome::PredecessorMismatch));
            assert!(matches!(publications[2].1, CasOutcome::Committed(_)));
            assert_eq!(publications[0].0, publications[1].0);
            assert_ne!(publications[1].0, publications[2].0);
            drop(publications);
            let after = case.fixture.head();
            assert_eq!(after.ref_root, before.ref_root);
            assert_eq!(after.retention_root, before.retention_root);
            assert_eq!(after.policy_epoch, before.policy_epoch);
            let batch = read_decision_batch_body(
                &case.fixture.store.backend,
                after.decision_tail_id.unwrap(),
            )
            .unwrap();
            assert_eq!(batch.committed_rcrs.len(), 1);
            assert_eq!(batch.committed_rcrs[0].tx_id, tx);
            assert_eq!(
                batch.committed_rcrs[0].canonical_request_digest,
                sealed.canonical_request_digest
            );
            once(&case, &command, if close { 1 } else { 2 });
            let retained_pr = current_pr(&case);
            assert_eq!(retained_pr.data, original_pr.data);
            assert_eq!(retained_pr.opened_by, original_pr.opened_by);
            assert_eq!(
                retained_pr.last_metadata_actor,
                original_pr.last_metadata_actor
            );
            if close {
                assert!(
                    matches!(
                        &retained_pr.event.payload,
                        ForgeEventPayload::PullRequestChangedNative(change)
                            if change.action == PullRequestAction::Close
                    ),
                    "replanning a comment must not reopen the competing close"
                );
                assert_eq!(
                    retained_pr.event.version,
                    original_pr.event.version.next().unwrap()
                );
            } else {
                assert_eq!(retained_pr, original_pr);
            }
            let (_, state) = selected_state(&case.fixture);
            assert_eq!(
                state
                    .forge
                    .entry(AsciiSlug::from_static("pull-request/1"))
                    .unwrap()
                    .successor_position(),
                if close { 2 } else { 1 }
            );
            assert_eq!(
                submit(&case, &command, AdmissionLimits::default()).unwrap(),
                terminal
            );
            assert!(
                submit(
                    &case,
                    &append("Changed body under original key"),
                    AdmissionLimits::default()
                )
                .is_err()
            );
            assert_eq!(case.fixture.head(), after);
        }
    }
}

#[test]
fn a_strict_comment_still_refuses_when_an_append_wins_its_predecessor() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let case = opened(format);
        interleave(&case, false);
        let strict = command(0, "Exact old predecessor");
        let terminal = super::submit(&case, &strict).unwrap();
        assert!(matches!(
            terminal.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::EvidenceStale,
                ..
            }
        ));
        let page = read(&case, &basis(&case), 0, 10);
        assert_eq!(page.comments.len(), 1);
        assert_eq!(page.comments[0].body, "Winning comment");
        let after = case.fixture.head();
        assert_eq!(super::submit(&case, &strict).unwrap(), terminal);
        assert_eq!(case.fixture.head(), after);
    }
}

#[test]
fn exhausted_append_replan_budget_remains_undecided_and_retries_the_same_intent() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let case = opened(format);
        let command = append("Retry after bounded contention");
        let original = seal(&case, &command);
        let tx = original.derive().unwrap().0;
        interleave(&case, false);
        assert!(matches!(
            submit(
                &case,
                &command,
                AdmissionLimits {
                    max_cas_replans: 1,
                    ..AdmissionLimits::default()
                }
            ),
            Err(AdmissionError::CasReplanLimitExceeded { limit: 1 })
        ));
        assert_eq!(case.fixture.outcome(tx), OutcomeLookup::Undecided);
        assert_eq!(read(&case, &basis(&case), 0, 10).comments.len(), 1);
        let terminal = submit(&case, &command, AdmissionLimits::default()).unwrap();
        assert!(matches!(
            terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        assert_eq!(seal(&case, &command), original);
        once(&case, &command, 2);
        let after = case.fixture.head();
        assert_eq!(
            submit(&case, &command, AdmissionLimits::default()).unwrap(),
            terminal
        );
        assert_eq!(case.fixture.head(), after);
    }
}

#[test]
fn append_cancellation_and_lost_cas_responses_never_become_false_refusals_or_duplicates() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for cancellation in [CANCEL_BEFORE_SEAL, CANCEL_BEFORE_PUBLICATION] {
            let case = opened(format);
            let before = case.fixture.head();
            let command = append("Cancelled append remains retryable");
            let tx = seal(&case, &command).derive().unwrap().0;
            case.projection
                .cancellation
                .store(cancellation, Ordering::SeqCst);
            assert!(matches!(
                submit(&case, &command, AdmissionLimits::default()),
                Err(AdmissionError::AsyncProjectionUnavailable(
                    RefusalCode::CancellationInProgress
                ))
            ));
            assert_eq!(case.fixture.head(), before);
            assert_eq!(case.fixture.outcome(tx), OutcomeLookup::Undecided);
            case.projection.cancellation.store(LIVE, Ordering::SeqCst);
            let terminal = submit(&case, &command, AdmissionLimits::default()).unwrap();
            assert!(matches!(
                terminal.outcome,
                DecisionOutcome::Committed { .. }
            ));
            once(&case, &command, 1);
            let after = case.fixture.head();
            assert_eq!(
                submit(&case, &command, AdmissionLimits::default()).unwrap(),
                terminal
            );
            assert_eq!(case.fixture.head(), after);
        }
        for fault in [FaultKind::LoseRequest, FaultKind::LoseResponse] {
            let case = opened(format);
            let before = case.fixture.head();
            let command = append("An ambiguous response is not rollback");
            let tx = seal(&case, &command).derive().unwrap().0;
            case.fixture
                .store
                .backend
                .install_fault_plan(FaultPlan::explicit(vec![FaultDirective::nth_of_kind(
                    0,
                    AuthorityOpKind::CompareExchangeHead,
                    fault,
                )]));
            assert!(matches!(
                submit(&case, &command, AdmissionLimits::default()),
                Err(AdmissionError::Outcome(_))
            ));
            let observed = case.fixture.outcome(tx);
            assert_eq!(
                matches!(observed, OutcomeLookup::Decided(_)),
                fault == FaultKind::LoseResponse
            );
            if fault == FaultKind::LoseRequest {
                assert_eq!(case.fixture.head(), before);
            }
            case.fixture
                .store
                .backend
                .install_fault_plan(FaultPlan::none());
            let terminal = submit(&case, &command, AdmissionLimits::default()).unwrap();
            assert!(matches!(
                terminal.outcome,
                DecisionOutcome::Committed { .. }
            ));
            once(&case, &command, 1);
            let after = case.fixture.head();
            assert_eq!(
                submit(&case, &command, AdmissionLimits::default()).unwrap(),
                terminal
            );
            assert_eq!(case.fixture.head(), after);
        }
    }
}
