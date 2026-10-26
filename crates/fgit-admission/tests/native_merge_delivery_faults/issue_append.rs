//! Actual append-comment admission through the existing faultable model store.
//! These tests prove canonical CAS/recovery behavior, not filesystem durability.
use super::*;
use fgit_admission::merge::native::issues;
use fgit_forge::event::issue::{IssueAction, IssueCommand, IssueCommentIntent, IssueEdit};
use fgit_forge::{AggregateVersion, ForgeEventPayload, IssueNumber};

#[derive(Clone)]
enum Mutation {
    Append(IssueCommentIntent),
    Strict(IssueCommand),
}
fn append(body: &str) -> Mutation {
    Mutation::Append(IssueCommentIntent {
        number: IssueNumber::FIRST,
        body: body.into(),
    })
}
fn edit(title: &str) -> Mutation {
    Mutation::Strict(IssueCommand {
        number: IssueNumber::FIRST,
        expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
        action: IssueAction::Edit(IssueEdit {
            title: Some(title.into()),
            ..Default::default()
        }),
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
        Mutation::Append(intent) => poll_ready(issues::admit_issue_comment_async(
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
        Mutation::Append(intent) => issues::append_proposal(context, intent).unwrap().1,
        Mutation::Strict(command) => issues::proposal(context, command).unwrap().1,
    }
}
fn opened(format: GitHashAlgorithm) -> Arc<Fixture> {
    let fixture = Arc::new(Fixture::new_for_format(format));
    let mutation = Mutation::Strict(IssueCommand {
        number: IssueNumber::FIRST,
        expected_version: ExpectedVersion::NewStream,
        action: IssueAction::Open {
            title: "Original title".into(),
            body: "Original body".into(),
            labels: vec!["keep".into()],
        },
    });
    let terminal = submit(
        &fixture,
        &context(&fixture, b"open-issue"),
        &mutation,
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
        10,
        &|| false,
    ))
    .unwrap()
}
fn interleave(
    fixture: &Arc<Fixture>,
    context: AdmissionContext,
    mutation: Mutation,
) -> Arc<Mutex<Option<TerminalOutcome>>> {
    let competitor = fixture.clone();
    let winner = Arc::new(Mutex::new(None));
    let captured = winner.clone();
    *fixture.store.before_publish.lock().unwrap() = Some(Box::new(move || {
        let outcome = submit(&competitor, &context, &mutation, AdmissionLimits::default()).unwrap();
        assert!(matches!(outcome.outcome, DecisionOutcome::Committed { .. }));
        *captured.lock().unwrap() = Some(outcome);
    }));
    winner
}
fn assert_once(fixture: &Fixture, tx: TxId, expected_comments: u64, events: usize) {
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
    let history = history(fixture);
    assert_eq!(history.events.len(), events);
    assert_eq!(history.issue.as_ref().unwrap().comments, expected_comments);
    assert_eq!(history.issue.unwrap().version.get(), events as u64);
}

#[test]
fn append_replans_after_a_real_competing_comment_or_title_cas_with_the_original_seal() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for title_edit in [false, true] {
            let fixture = opened(format);
            let before = fixture.head();
            let context = context(&fixture, b"append-after-cas-loss");
            let mutation = append("Original append survives contention");
            let original = seal(&context, &mutation);
            let (tx, sealed) = original.derive().unwrap();
            let competitor_context = self::context(&fixture, b"winner-before-append");
            let competitor_mutation = if title_edit {
                edit("Concurrent title retained")
            } else {
                append("Other comment retained")
            };
            let winner = interleave(
                &fixture,
                competitor_context.clone(),
                competitor_mutation.clone(),
            );
            let terminal =
                submit(&fixture, &context, &mutation, AdmissionLimits::default()).unwrap();
            assert!(matches!(
                terminal.outcome,
                DecisionOutcome::Committed { .. }
            ));
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
            let batch =
                read_decision_batch_body(&fixture.store.backend, after.decision_tail_id.unwrap())
                    .unwrap();
            assert_eq!(batch.committed_rcrs.len(), 1);
            assert_eq!(batch.committed_rcrs[0].tx_id, tx);
            assert_eq!(
                batch.committed_rcrs[0].canonical_request_digest,
                sealed.canonical_request_digest
            );
            assert_once(&fixture, tx, if title_edit { 1 } else { 2 }, 3);
            let page = history(&fixture);
            let issue = page.issue.unwrap();
            assert_eq!(
                issue.title,
                if title_edit {
                    "Concurrent title retained"
                } else {
                    "Original title"
                }
            );
            assert_eq!(issue.body, "Original body");
            assert_eq!(issue.labels, ["keep"]);
            let last = page.events.last().unwrap();
            assert_eq!(last.version.get(), 3);
            assert!(
                matches!(&last.payload, ForgeEventPayload::IssueChangedNative(change)
                if matches!(&change.action, IssueAction::Comment { body }
                    if body == "Original append survives contention"))
            );
            assert_eq!(
                submit(&fixture, &context, &mutation, AdmissionLimits::default()).unwrap(),
                terminal
            );
            assert_eq!(
                submit(
                    &fixture,
                    &competitor_context,
                    &competitor_mutation,
                    AdmissionLimits::default()
                )
                .unwrap(),
                winner.lock().unwrap().unwrap()
            );
            assert_eq!(fixture.head(), after);
            assert!(
                submit(
                    &fixture,
                    &context,
                    &append("Changed meaning under old key"),
                    AdmissionLimits::default()
                )
                .is_err()
            );
            assert_eq!(fixture.head(), after);
        }
    }
}

#[test]
fn exact_title_and_legacy_comment_losers_still_refuse_their_original_predecessor() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for legacy_comment in [false, true] {
            let fixture = opened(format);
            let context = context(&fixture, b"strict-loser");
            let mutation = if legacy_comment {
                Mutation::Strict(IssueCommand {
                    number: IssueNumber::FIRST,
                    expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
                    action: IssueAction::Comment {
                        body: "Strict comment cannot refresh".into(),
                    },
                })
            } else {
                edit("Losing title cannot overwrite")
            };
            let competitor = if legacy_comment {
                append("Winning append")
            } else {
                edit("Winning title")
            };
            interleave(
                &fixture,
                self::context(&fixture, b"strict-winner"),
                competitor,
            );
            let terminal =
                submit(&fixture, &context, &mutation, AdmissionLimits::default()).unwrap();
            assert!(matches!(
                terminal.outcome,
                DecisionOutcome::Refused {
                    code: RefusalCode::EvidenceStale,
                    ..
                }
            ));
            let after = fixture.head();
            assert_eq!(history(&fixture).events.len(), 2);
            let tx = seal(&context, &mutation).derive().unwrap().0;
            assert_eq!(fixture.outcome(tx), OutcomeLookup::Decided(terminal));
            assert_eq!(
                submit(&fixture, &context, &mutation, AdmissionLimits::default()).unwrap(),
                terminal
            );
            assert_eq!(fixture.head(), after);
        }
    }
}

#[test]
fn exhausted_replan_budget_leaves_append_undecided_and_the_same_seal_can_retry() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = opened(format);
        let context = context(&fixture, b"bounded-append-retry");
        let mutation = append("Retry after budget exhaustion");
        let original = seal(&context, &mutation);
        let tx = original.derive().unwrap().0;
        interleave(
            &fixture,
            self::context(&fixture, b"budget-competitor"),
            append("Won first"),
        );
        let result = submit(
            &fixture,
            &context,
            &mutation,
            AdmissionLimits {
                max_cas_replans: 1,
                ..AdmissionLimits::default()
            },
        );
        assert!(matches!(
            result,
            Err(AdmissionError::CasReplanLimitExceeded { limit: 1 })
        ));
        assert_eq!(fixture.outcome(tx), OutcomeLookup::Undecided);
        assert_eq!(history(&fixture).events.len(), 2);
        let terminal = submit(&fixture, &context, &mutation, AdmissionLimits::default()).unwrap();
        assert!(matches!(
            terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        assert_eq!(seal(&context, &mutation), original);
        assert_once(&fixture, tx, 2, 3);
        let after = fixture.head();
        assert_eq!(
            submit(&fixture, &context, &mutation, AdmissionLimits::default()).unwrap(),
            terminal
        );
        assert_eq!(fixture.head(), after);
    }
}

#[test]
fn unavailable_or_lost_cas_response_never_becomes_a_refusal_or_a_duplicate_comment() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for fault in [FaultKind::LoseRequest, FaultKind::LoseResponse] {
            let fixture = opened(format);
            let before = fixture.head();
            let context = context(&fixture, b"ambiguous-append");
            let mutation = append("Ambiguity preserves this exact intent");
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
            let observed = fixture.outcome(tx);
            assert_eq!(
                matches!(observed, OutcomeLookup::Decided(_)),
                fault == FaultKind::LoseResponse
            );
            if fault == FaultKind::LoseRequest {
                assert_eq!(fixture.head(), before);
            } else {
                let OutcomeLookup::Decided(terminal) = observed else {
                    unreachable!()
                };
                assert!(matches!(
                    terminal.outcome,
                    DecisionOutcome::Committed { .. }
                ));
            }
            fixture.store.backend.install_fault_plan(FaultPlan::none());
            let terminal =
                submit(&fixture, &context, &mutation, AdmissionLimits::default()).unwrap();
            assert!(matches!(
                terminal.outcome,
                DecisionOutcome::Committed { .. }
            ));
            assert_once(&fixture, tx, 1, 2);
            let after = fixture.head();
            assert_eq!(
                submit(&fixture, &context, &mutation, AdmissionLimits::default()).unwrap(),
                terminal
            );
            assert_eq!(fixture.head(), after);
        }
    }
}
