//! Lock and unlock races through the production discussion admission driver. The
//! faultable reference authority is non-durable; persisted reopen has a node test.
use super::*;

fn strict(version: u64, action: DiscussionAction) -> Mutation {
    Mutation::Strict(DiscussionCommand {
        number: DiscussionNumber::FIRST,
        expected_version: ExpectedVersion::Exactly(AggregateVersion::try_new(version).unwrap()),
        action,
    })
}
fn committed(fixture: &Fixture, key: &[u8], mutation: &Mutation) -> TerminalOutcome {
    let terminal = submit(
        fixture,
        &context(fixture, key),
        mutation,
        AdmissionLimits::default(),
    )
    .unwrap();
    assert!(
        matches!(terminal.outcome, DecisionOutcome::Committed { .. }),
        "{terminal:?}"
    );
    terminal
}
fn denied(fixture: &Fixture, key: &[u8], mutation: &Mutation) -> TerminalOutcome {
    let before = history(fixture);
    let context = context(fixture, key);
    let terminal = submit(fixture, &context, mutation, AdmissionLimits::default()).unwrap();
    assert!(
        matches!(
            terminal.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::ProtectedRefTransitionDenied,
                ..
            }
        ),
        "{terminal:?}"
    );
    let after = history(fixture);
    assert_eq!(after.discussion, before.discussion);
    assert_eq!(after.events, before.events);
    let tx = seal(&context, mutation).derive().unwrap().0;
    assert_eq!(fixture.outcome(tx), OutcomeLookup::Decided(terminal));
    let selected = basis(fixture);
    let delivery = poll_ready(delivery::read_in(
        fixture.store.as_ref(),
        &(),
        &selected,
        &|| false,
    ))
    .unwrap();
    assert!(
        delivery
            .outbox
            .entries()
            .iter()
            .all(|entry| entry.tx_id() != tx),
        "a refused comment or lock must not emit a forge delivery"
    );
    terminal
}

#[test]
fn locked_discussions_refuse_both_comment_profiles_and_prior_outcomes_survive_both_transitions() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = opened(format);
        let strict_before = strict(
            1,
            DiscussionAction::Comment {
                body: "Admitted strict comment".into(),
            },
        );
        let strict_terminal = committed(&fixture, b"strict-before-lock", &strict_before);
        let append_before = append("Admitted append intent");
        let append_terminal = committed(&fixture, b"append-before-lock", &append_before);
        let lock = strict(3, DiscussionAction::Lock);
        let lock_terminal = committed(&fixture, b"lock-comments", &lock);
        let selected = history(&fixture);
        let discussion = selected.discussion.unwrap();
        assert!(discussion.locked);
        assert_eq!(discussion.comments, 2);
        assert_eq!(discussion.version.get(), 4);
        let locked_head = fixture.head();
        for (key, mutation, expected) in [
            (
                b"strict-before-lock".as_slice(),
                &strict_before,
                strict_terminal,
            ),
            (
                b"append-before-lock".as_slice(),
                &append_before,
                append_terminal,
            ),
            (b"lock-comments".as_slice(), &lock, lock_terminal),
        ] {
            assert_eq!(
                submit(
                    &fixture,
                    &context(&fixture, key),
                    mutation,
                    AdmissionLimits::default()
                )
                .unwrap(),
                expected
            );
        }
        assert_eq!(
            fixture.head(),
            locked_head,
            "terminal recovery precedes the new lock gate"
        );

        let strict_blocked = strict(
            4,
            DiscussionAction::Comment {
                body: "Blocked strict comment".into(),
            },
        );
        let append_blocked = append("Blocked append intent");
        let refused_strict = denied(&fixture, b"strict-while-locked", &strict_blocked);
        let refused_append = denied(&fixture, b"append-while-locked", &append_blocked);
        denied(
            &fixture,
            b"duplicate-lock",
            &strict(4, DiscussionAction::Lock),
        );
        let unlock = strict(4, DiscussionAction::Unlock);
        committed(&fixture, b"unlock-comments", &unlock);
        assert!(!history(&fixture).discussion.unwrap().locked);
        let unlocked_head = fixture.head();
        for (key, mutation, expected) in [
            (
                b"strict-while-locked".as_slice(),
                &strict_blocked,
                refused_strict,
            ),
            (
                b"append-while-locked".as_slice(),
                &append_blocked,
                refused_append,
            ),
            (b"lock-comments".as_slice(), &lock, lock_terminal),
        ] {
            assert_eq!(
                submit(
                    &fixture,
                    &context(&fixture, key),
                    mutation,
                    AdmissionLimits::default()
                )
                .unwrap(),
                expected
            );
        }
        assert_eq!(
            fixture.head(),
            unlocked_head,
            "unlock cannot reinterpret an old outcome"
        );
        denied(
            &fixture,
            b"duplicate-unlock",
            &strict(5, DiscussionAction::Unlock),
        );

        committed(
            &fixture,
            b"strict-after-unlock",
            &strict(
                5,
                DiscussionAction::Comment {
                    body: "Resumed strict comment".into(),
                },
            ),
        );
        committed(
            &fixture,
            b"append-after-unlock",
            &append("Resumed append intent"),
        );
        let page = history(&fixture);
        let discussion = page.discussion.unwrap();
        assert_eq!(page.events.len(), 7);
        assert_eq!(discussion.version.get(), 7);
        assert_eq!(discussion.comments, 4);
        assert!(!discussion.locked);
        assert_eq!(discussion.title, "Original title");
        assert_eq!(discussion.body, "Original body");
    }
}

#[test]
fn a_competing_lock_or_unlock_revalidates_the_same_append_intent_after_a_real_cas_loss() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for unlock_wins in [false, true] {
            let fixture = opened(format);
            if unlock_wins {
                committed(
                    &fixture,
                    b"initial-lock",
                    &strict(1, DiscussionAction::Lock),
                );
            }
            let before = fixture.head();
            fixture.store.publications.lock().unwrap().clear();
            let submitted = append("Original intent must follow the current comment gate");
            let submitted_context = context(&fixture, b"racing-append");
            let original = seal(&submitted_context, &submitted);
            let tx = original.derive().unwrap().0;
            let winner_context = context(&fixture, b"winner-lock-state");
            let winner_mutation = if unlock_wins {
                strict(2, DiscussionAction::Unlock)
            } else {
                strict(1, DiscussionAction::Lock)
            };
            let winner = interleave(&fixture, winner_context.clone(), winner_mutation.clone());
            let terminal = submit(
                &fixture,
                &submitted_context,
                &submitted,
                AdmissionLimits::default(),
            )
            .unwrap();
            if unlock_wins {
                assert!(matches!(
                    terminal.outcome,
                    DecisionOutcome::Committed { .. }
                ));
            } else {
                assert!(matches!(
                    terminal.outcome,
                    DecisionOutcome::Refused {
                        code: RefusalCode::ProtectedRefTransitionDenied,
                        ..
                    }
                ));
            }
            assert_eq!(seal(&submitted_context, &submitted), original);
            assert_eq!(fixture.outcome(tx), OutcomeLookup::Decided(terminal));
            let publications = fixture.store.publications.lock().unwrap();
            assert_eq!(publications.len(), 3);
            assert!(matches!(publications[0].1, CasOutcome::Committed(_)));
            assert!(matches!(publications[1].1, CasOutcome::PredecessorMismatch));
            assert!(matches!(publications[2].1, CasOutcome::Committed(_)));
            drop(publications);
            let page = history(&fixture);
            let discussion = page.discussion.unwrap();
            assert_eq!(discussion.locked, !unlock_wins);
            assert_eq!(discussion.comments, u64::from(unlock_wins));
            assert_eq!(discussion.version.get(), if unlock_wins { 4 } else { 2 });
            assert_eq!(page.events.len(), if unlock_wins { 4 } else { 2 });
            assert_eq!(fixture.head().ref_root, before.ref_root);
            let after = fixture.head();
            assert_eq!(
                submit(
                    &fixture,
                    &submitted_context,
                    &submitted,
                    AdmissionLimits::default()
                )
                .unwrap(),
                terminal
            );
            assert_eq!(
                submit(
                    &fixture,
                    &winner_context,
                    &winner_mutation,
                    AdmissionLimits::default()
                )
                .unwrap(),
                winner.lock().unwrap().unwrap()
            );
            assert_eq!(fixture.head(), after);
        }
    }
}
