//! Real admission and head-CAS races through the faultable model store.
//! These tests establish transaction semantics, not filesystem crash durability.
use super::*;
use fgit_admission::merge::native::issues;
use fgit_forge::event::issue::{
    IssueAction, IssueCommand, IssueEdit, IssueLabelsIntent, IssueState, MAX_LABELS,
};
use fgit_forge::{AggregateVersion, ForgeEventPayload, IssueNumber};

#[derive(Clone)]
enum Mutation {
    Add(IssueLabelsIntent),
    Strict(IssueCommand),
}
fn addition(labels: &[&str]) -> Mutation {
    Mutation::Add(IssueLabelsIntent {
        number: IssueNumber::FIRST,
        labels: labels.iter().map(|label| (*label).into()).collect(),
    })
}
fn strict(action: IssueAction) -> Mutation {
    Mutation::Strict(IssueCommand {
        number: IssueNumber::FIRST,
        expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
        action,
    })
}
fn context(fixture: &Fixture, key: &[u8]) -> AdmissionContext {
    let mut context = fixture.context.clone();
    context.idempotency_key = IdempotencyKey::new(key.to_vec()).unwrap();
    context
}
fn submit(
    fixture: &Fixture,
    context: &AdmissionContext,
    mutation: &Mutation,
    limits: AdmissionLimits,
) -> Result<TerminalOutcome, AdmissionError> {
    let projection = fixture.projection(context);
    match mutation {
        Mutation::Add(intent) => poll_ready(issues::admit_issue_labels_async(
            fixture.store.as_ref(),
            &(),
            context,
            intent,
            limits,
            &projection,
        )),
        Mutation::Strict(command) => poll_ready(issues::admit_issue_async(
            fixture.store.as_ref(),
            &(),
            context,
            command,
            limits,
            &projection,
        )),
    }
}
fn seal(context: &AdmissionContext, mutation: &Mutation) -> fgit_authority::SealAttempt {
    match mutation {
        Mutation::Add(intent) => issues::labels_proposal(context, intent).unwrap().1,
        Mutation::Strict(command) => issues::proposal(context, command).unwrap().1,
    }
}
fn opened(format: GitHashAlgorithm, labels: Vec<String>) -> Arc<Fixture> {
    let fixture = Arc::new(Fixture::new_for_format(format));
    let opening = Mutation::Strict(IssueCommand {
        number: IssueNumber::FIRST,
        expected_version: ExpectedVersion::NewStream,
        action: IssueAction::Open {
            title: "Original title".into(),
            body: "Original body".into(),
            labels,
        },
    });
    let terminal = submit(
        &fixture,
        &context(&fixture, b"open-issue"),
        &opening,
        AdmissionLimits::default(),
    )
    .unwrap();
    assert!(matches!(
        terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
    fixture.store.publications.lock().unwrap().clear();
    fixture
}
fn basis(fixture: &Fixture) -> PublicationBasis {
    let head = fixture.head();
    PublicationBasis::new(
        fgit_authority::authority_head_identity(&head).unwrap(),
        head,
    )
}
fn history(fixture: &Fixture) -> issues::IssueHistoryPage {
    poll_ready(issues::read_history_at(
        fixture.store.as_ref(),
        &(),
        &basis(fixture),
        IssueNumber::FIRST,
        0,
        100,
        &|| false,
    ))
    .unwrap()
}
fn interleave(fixture: &Arc<Fixture>, mutation: Mutation) {
    let competitor = fixture.clone();
    *fixture.store.before_publish.lock().unwrap() = Some(Box::new(move || {
        let terminal = submit(
            &competitor,
            &context(&competitor, b"competing-label-writer"),
            &mutation,
            AdmissionLimits::default(),
        )
        .unwrap();
        assert!(
            matches!(terminal.outcome, DecisionOutcome::Committed { .. }),
            "{terminal:?}"
        );
    }));
}
fn assert_once(fixture: &Fixture, tx: TxId, events: usize) {
    let selected = basis(fixture);
    let delivery = poll_ready(delivery::read_in(
        fixture.store.as_ref(),
        &(),
        &selected,
        &|| false,
    ))
    .unwrap();
    assert_eq!(
        delivery
            .outbox
            .entries()
            .iter()
            .filter(|entry| entry.tx_id() == tx)
            .count(),
        1
    );
    let page = history(fixture);
    assert_eq!(page.events.len(), events);
    assert_eq!(page.issue.unwrap().version.get(), events as u64);
}

#[test]
fn label_addition_replans_after_real_addition_edit_replacement_or_close_without_changing_seal() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for competitor in 0..4 {
            let fixture = opened(format, vec!["keep".into()]);
            let before = fixture.head();
            let context = context(&fixture, b"original-label-addition");
            let mutation = addition(&["feature", "shared"]);
            let original = seal(&context, &mutation);
            let (tx, sealed) = original.derive().unwrap();
            let competing = match competitor {
                0 => addition(&["other", "shared"]),
                1 => strict(IssueAction::Edit(IssueEdit {
                    title: Some("Concurrent title".into()),
                    ..Default::default()
                })),
                2 => strict(IssueAction::Edit(IssueEdit {
                    labels: Some(vec!["replacement".into()]),
                    ..Default::default()
                })),
                _ => strict(IssueAction::Close),
            };
            interleave(&fixture, competing);
            let terminal =
                submit(&fixture, &context, &mutation, AdmissionLimits::default()).unwrap();
            assert!(
                matches!(terminal.outcome, DecisionOutcome::Committed { .. }),
                "{terminal:?}"
            );
            assert_eq!(seal(&context, &mutation), original);
            assert_eq!(fixture.outcome(tx), OutcomeLookup::Decided(terminal));
            let publications = fixture.store.publications.lock().unwrap();
            assert_eq!(publications.len(), 3);
            assert!(matches!(publications[0].1, CasOutcome::Committed(_)));
            assert!(matches!(publications[1].1, CasOutcome::PredecessorMismatch));
            assert!(matches!(publications[2].1, CasOutcome::Committed(_)));
            drop(publications);
            let after = fixture.head();
            assert_eq!(after.ref_root, before.ref_root);
            assert_eq!(after.retention_root, before.retention_root);
            assert_eq!(after.policy_epoch, before.policy_epoch);
            let batch =
                read_decision_batch_body(&fixture.store.backend, after.decision_tail_id.unwrap())
                    .unwrap();
            assert_eq!(batch.committed_rcrs.len(), 1);
            assert_eq!(batch.committed_rcrs[0].tx_id, tx);
            assert_eq!(
                batch.committed_rcrs[0].canonical_request_digest,
                sealed.canonical_request_digest
            );
            assert_once(&fixture, tx, 3);
            let page = history(&fixture);
            let issue = page.issue.unwrap();
            let expected = match competitor {
                0 => vec!["feature", "keep", "other", "shared"],
                2 => vec!["feature", "replacement", "shared"],
                _ => vec!["feature", "keep", "shared"],
            };
            assert_eq!(issue.labels, expected);
            assert_eq!(
                issue.title,
                if competitor == 1 {
                    "Concurrent title"
                } else {
                    "Original title"
                }
            );
            assert_eq!(
                issue.state,
                if competitor == 3 {
                    IssueState::Closed
                } else {
                    IssueState::Open
                }
            );
            assert_eq!(issue.body, "Original body");
            assert_eq!(issue.comments, 0);
            assert!(
                matches!(&page.events.last().unwrap().payload, ForgeEventPayload::IssueChangedNative(change)
                if change.action == IssueAction::AddLabels { labels: vec!["feature".into(), "shared".into()] })
            );
            assert_eq!(
                submit(&fixture, &context, &mutation, AdmissionLimits::default()).unwrap(),
                terminal
            );
            assert_eq!(fixture.head(), after);
            assert!(
                submit(
                    &fixture,
                    &context,
                    &addition(&["changed"]),
                    AdmissionLimits::default()
                )
                .is_err()
            );
            assert_eq!(fixture.head(), after);
        }
    }
}

#[test]
fn strict_label_replacement_loser_keeps_its_precondition_and_cannot_erase_a_winner() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = opened(format, vec!["keep".into()]);
        interleave(&fixture, addition(&["winner"]));
        let context = context(&fixture, b"exact-replacement");
        let mutation = strict(IssueAction::Edit(IssueEdit {
            labels: Some(vec!["replacement".into()]),
            ..Default::default()
        }));
        let terminal = submit(&fixture, &context, &mutation, AdmissionLimits::default()).unwrap();
        assert!(matches!(
            terminal.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::EvidenceStale,
                ..
            }
        ));
        let page = history(&fixture);
        assert_eq!(page.events.len(), 2);
        assert_eq!(page.issue.unwrap().labels, ["keep", "winner"]);
        let after = fixture.head();
        assert_eq!(
            submit(&fixture, &context, &mutation, AdmissionLimits::default()).unwrap(),
            terminal
        );
        assert_eq!(fixture.head(), after);
    }
}

#[test]
fn concurrent_union_capacity_is_revalidated_and_overlapping_addition_is_permitted() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for overlap in [false, true] {
            let labels = (0..MAX_LABELS - 1)
                .map(|n| format!("label-{n:02}"))
                .collect();
            let fixture = opened(format, labels);
            interleave(&fixture, addition(&["winner"]));
            let context = context(&fixture, b"capacity-contender");
            let mutation = addition(&[if overlap { "winner" } else { "overflow" }]);
            let terminal =
                submit(&fixture, &context, &mutation, AdmissionLimits::default()).unwrap();
            if overlap {
                assert!(matches!(
                    terminal.outcome,
                    DecisionOutcome::Committed { .. }
                ));
            } else {
                assert!(matches!(
                    terminal.outcome,
                    DecisionOutcome::Refused {
                        code: RefusalCode::ResourceBudgetExceeded,
                        ..
                    }
                ));
            }
            let page = history(&fixture);
            assert_eq!(page.events.len(), if overlap { 3 } else { 2 });
            let issue = page.issue.unwrap();
            assert_eq!(issue.labels.len(), MAX_LABELS);
            assert!(issue.labels.iter().any(|label| label == "winner"));
            assert!(!issue.labels.iter().any(|label| label == "overflow"));
            let after = fixture.head();
            assert_eq!(
                submit(&fixture, &context, &mutation, AdmissionLimits::default()).unwrap(),
                terminal
            );
            assert_eq!(fixture.head(), after);
        }
    }
}

#[test]
fn bounded_replan_exhaustion_leaves_original_label_intent_undecided_and_retryable() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = opened(format, vec![]);
        let context = context(&fixture, b"retry-bounded-addition");
        let mutation = addition(&["original"]);
        let original = seal(&context, &mutation);
        let tx = original.derive().unwrap().0;
        interleave(&fixture, addition(&["winner"]));
        assert!(matches!(
            submit(
                &fixture,
                &context,
                &mutation,
                AdmissionLimits {
                    max_cas_replans: 1,
                    ..AdmissionLimits::default()
                }
            ),
            Err(AdmissionError::CasReplanLimitExceeded { limit: 1 })
        ));
        assert_eq!(fixture.outcome(tx), OutcomeLookup::Undecided);
        assert_eq!(history(&fixture).issue.unwrap().labels, ["winner"]);
        let terminal = submit(&fixture, &context, &mutation, AdmissionLimits::default()).unwrap();
        assert!(matches!(
            terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        assert_eq!(seal(&context, &mutation), original);
        assert_once(&fixture, tx, 3);
        assert_eq!(
            history(&fixture).issue.unwrap().labels,
            ["original", "winner"]
        );
    }
}

#[test]
fn lost_request_or_response_recovers_one_original_label_effect_and_outbox_entry() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for fault in [FaultKind::LoseRequest, FaultKind::LoseResponse] {
            let fixture = opened(format, vec![]);
            let before = fixture.head();
            let context = context(&fixture, b"ambiguous-label-addition");
            let mutation = addition(&["original"]);
            let tx = seal(&context, &mutation).derive().unwrap().0;
            fixture
                .store
                .backend
                .install_fault_plan(FaultPlan::explicit(vec![FaultDirective::nth_of_kind(
                    0,
                    AuthorityOpKind::CompareExchangeHead,
                    fault,
                )]));
            assert!(matches!(
                submit(&fixture, &context, &mutation, AdmissionLimits::default()),
                Err(AdmissionError::Outcome(_))
            ));
            assert_eq!(
                matches!(fixture.outcome(tx), OutcomeLookup::Decided(_)),
                fault == FaultKind::LoseResponse
            );
            if fault == FaultKind::LoseRequest {
                assert_eq!(fixture.head(), before);
            }
            fixture.store.backend.install_fault_plan(FaultPlan::none());
            let terminal =
                submit(&fixture, &context, &mutation, AdmissionLimits::default()).unwrap();
            assert!(matches!(
                terminal.outcome,
                DecisionOutcome::Committed { .. }
            ));
            assert_once(&fixture, tx, 2);
            assert_eq!(history(&fixture).issue.unwrap().labels, ["original"]);
            let after = fixture.head();
            assert_eq!(
                submit(&fixture, &context, &mutation, AdmissionLimits::default()).unwrap(),
                terminal
            );
            assert_eq!(fixture.head(), after);
        }
    }
}
