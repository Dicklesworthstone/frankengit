//! Real persisted additive assignment, concurrent union and exact recovery.
use super::*;
use fgit_forge::ForgeEventPayload;
use fgit_forge::event::issue::{IssueAssigneesIntent, MAX_ASSIGNEES};
use std::collections::BTreeSet;

fn principal(seed: u8) -> PrincipalId {
    PrincipalId::from_bytes([seed; 16])
}

fn intent(number: u64, assignees: &[u8]) -> IssueAssigneesIntent {
    IssueAssigneesIntent {
        number: IssueNumber::try_new(number).unwrap(),
        assignees: assignees.iter().copied().map(principal).collect(),
    }
}

fn add(
    node: &OneNode,
    intent: &IssueAssigneesIntent,
    key: &str,
) -> Result<(TxId, TerminalOutcome), NodeReceiveTransportRefusal> {
    let request = node.request_context();
    node.runtime()
        .block_on(node.admit_issue_assignees_durable_in(
            &request,
            &session(key),
            intent,
            AdmissionLimits::default(),
        ))
}

fn complete_history(node: &OneNode, number: u64) -> issues::IssueHistoryPage {
    let request = node.request_context();
    node.runtime()
        .block_on(node.read_issue_history_in(
            &request,
            IssueNumber::try_new(number).unwrap(),
            0,
            100,
            None,
        ))
        .unwrap()
}

#[test]
fn additions_preserve_intervening_edits_strict_predecessors_and_reopened_outcomes() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = node(&scratch, format);
        accepted(apply(&node, &open(7), "open"));
        let submitted = intent(7, &[1, 3]);
        accepted(apply(
            &node,
            &change(
                7,
                1,
                IssueAction::Edit(IssueEdit {
                    title: Some("concurrent title".into()),
                    ..Default::default()
                }),
            ),
            "edit",
        ));
        let before = snapshot(&node);
        let original = accepted(add(&node, &submitted, "add"));
        let second = accepted(add(&node, &intent(7, &[2, 3]), "add-independent"));
        assert_ne!(original.0, second.0);
        let page = complete_history(&node, 7);
        let issue = page.issue.as_ref().unwrap();
        assert_eq!(
            issue.assignees,
            vec![principal(1), principal(2), principal(3)]
        );
        assert_eq!(issue.version.get(), 4);
        assert_eq!(issue.title, "concurrent title");
        assert_eq!(issue.body, "text é\r\nwithout terminal newline");
        assert_eq!(issue.comments, 0);
        assert!(matches!(
            &page.events[2].payload,
            ForgeEventPayload::IssueChangedNative(change)
                if change.actor == actor()
                    && change.action == IssueAction::Assign { assignees: submitted.assignees.clone() }
        ));
        let after = snapshot(&node);
        no_code_changes(&before, &after);
        assert_eq!(
            after.snapshot().outbox.len(),
            before.snapshot().outbox.len() + 2
        );
        assert_eq!(add(&node, &submitted, "add").unwrap(), original);
        assert!(add(&node, &intent(7, &[4]), "add").is_err());
        assert_eq!(snapshot(&node).basis(), after.basis());

        let strict = change(
            7,
            1,
            IssueAction::Assign {
                assignees: submitted.assignees.clone(),
            },
        );
        let refused = apply(&node, &strict, "strict-stale").unwrap();
        assert!(matches!(
            refused.1.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::EvidenceStale,
                ..
            }
        ));
        assert!(apply(&node, &strict, "add").is_err());
        assert_eq!(complete_history(&node, 7).issue, page.issue);

        accepted(apply(
            &node,
            &change(
                7,
                4,
                IssueAction::Unassign {
                    assignees: vec![principal(3)],
                },
            ),
            "remove",
        ));
        let settled = snapshot(&node);
        let final_page = complete_history(&node, 7);
        assert_eq!(
            final_page.issue.as_ref().unwrap().assignees,
            vec![principal(1), principal(2)]
        );
        assert_eq!(add(&node, &submitted, "add").unwrap(), original);
        assert_eq!(snapshot(&node).basis(), settled.basis());
        node.shutdown().unwrap();

        let mut reopened = OneNode::open_existing(scratch.config(format)).unwrap();
        // Historical recovery precedes reopening intake and cannot resurrect
        // an assignee removed after this command's original publication.
        assert_eq!(add(&reopened, &submitted, "add").unwrap(), original);
        assert_eq!(apply(&reopened, &strict, "strict-stale").unwrap(), refused);
        reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
        assert_eq!(complete_history(&reopened, 7), final_page);
        assert_eq!(snapshot(&reopened).basis(), settled.basis());
        reopened.shutdown().unwrap();
    }
}

#[test]
fn overlapping_additions_merge_exact_sets_and_publish_each_request_once() {
    const COUNT: usize = 4;
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = node(&scratch, format);
        accepted(apply(&node, &open(1), "open"));
        let before = snapshot(&node);
        let intents: Vec<_> = (0..COUNT).map(|i| intent(1, &[1, i as u8 + 2])).collect();
        let requests: Vec<_> = (0..COUNT).map(|_| node.request_context()).collect();
        let keys: Vec<_> = (0..COUNT).map(|i| format!("addition-{i}")).collect();
        let sessions: Vec<_> = keys.iter().map(|key| session(key)).collect();
        let mut pending: Vec<_> = (0..COUNT)
            .map(|i| {
                Box::pin(node.admit_issue_assignees_durable_in(
                    &requests[i],
                    &sessions[i],
                    &intents[i],
                    AdmissionLimits::default(),
                ))
            })
            .collect();
        let mut results: Vec<_> = (0..COUNT).map(|_| None).collect();
        let mut overlap = false;
        node.runtime().block_on(std::future::poll_fn(|cx| {
            let mut waiting = 0;
            for i in 0..COUNT {
                if results[i].is_none() {
                    match pending[i].as_mut().poll(cx) {
                        Poll::Ready(result) => results[i] = Some(result),
                        Poll::Pending => waiting += 1,
                    }
                }
            }
            overlap |= waiting > 1;
            if results.iter().all(Option::is_some) {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }));
        drop(pending);
        assert!(overlap, "real authority operations were pending together");
        let results: Vec<_> = results
            .into_iter()
            .map(|result| accepted(result.unwrap()))
            .collect();
        assert_eq!(
            results
                .iter()
                .map(|result| result.0)
                .collect::<BTreeSet<_>>()
                .len(),
            COUNT
        );
        let page = complete_history(&node, 1);
        assert_eq!(
            page.issue.as_ref().unwrap().assignees,
            (1..=COUNT as u8 + 1).map(principal).collect::<Vec<_>>()
        );
        assert_eq!(page.issue.as_ref().unwrap().version.get(), COUNT as u64 + 1);
        assert_eq!(page.events.len(), COUNT + 1);
        let observed: BTreeSet<_> = page
            .events
            .iter()
            .skip(1)
            .map(|event| {
                let ForgeEventPayload::IssueChangedNative(change) = &event.payload else {
                    panic!("native issue event");
                };
                let IssueAction::Assign { assignees } = &change.action else {
                    panic!("assignment event");
                };
                assert_eq!(change.actor, actor());
                assignees.clone()
            })
            .collect();
        assert_eq!(
            observed,
            intents
                .iter()
                .map(|intent| intent.assignees.clone())
                .collect()
        );
        let after = snapshot(&node);
        no_code_changes(&before, &after);
        assert_eq!(
            after.snapshot().outbox.len(),
            before.snapshot().outbox.len() + COUNT
        );
        for i in (0..COUNT).rev() {
            assert_eq!(add(&node, &intents[i], &keys[i]).unwrap(), results[i]);
        }
        assert_eq!(snapshot(&node).basis(), after.basis());
        node.shutdown().unwrap();
    }
}

#[test]
fn competing_additions_revalidate_the_last_assignee_slot_before_publication() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = node(&scratch, format);
        accepted(apply(&node, &open(1), "open"));
        let existing = intent(1, &(1..MAX_ASSIGNEES as u8).collect::<Vec<_>>());
        accepted(add(&node, &existing, "existing"));
        let before = snapshot(&node);
        let intents = [
            intent(1, &[MAX_ASSIGNEES as u8]),
            intent(1, &[MAX_ASSIGNEES as u8 + 1]),
        ];
        let requests = [node.request_context(), node.request_context()];
        let keys = ["last-slot-a", "last-slot-b"];
        let sessions = keys.map(session);
        let mut pending: Vec<_> = (0..2)
            .map(|i| {
                Box::pin(node.admit_issue_assignees_durable_in(
                    &requests[i],
                    &sessions[i],
                    &intents[i],
                    AdmissionLimits::default(),
                ))
            })
            .collect();
        let mut results: Vec<_> = (0..2).map(|_| None).collect();
        let mut overlap = false;
        node.runtime().block_on(std::future::poll_fn(|cx| {
            let mut waiting = 0;
            for i in 0..2 {
                if results[i].is_none() {
                    match pending[i].as_mut().poll(cx) {
                        Poll::Ready(result) => results[i] = Some(result),
                        Poll::Pending => waiting += 1,
                    }
                }
            }
            overlap |= waiting > 1;
            if results.iter().all(Option::is_some) {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }));
        drop(pending);
        assert!(
            overlap,
            "independent last-slot requests were pending together"
        );
        let results: Vec<_> = results
            .into_iter()
            .map(|result| result.unwrap().unwrap())
            .collect();
        let committed: Vec<_> = results
            .iter()
            .enumerate()
            .filter_map(|(i, result)| {
                matches!(result.1.outcome, DecisionOutcome::Committed { .. }).then_some(i)
            })
            .collect();
        assert_eq!(
            committed.len(),
            1,
            "only one last-slot addition may publish"
        );
        let winner = committed[0];
        let loser = 1 - winner;
        assert!(matches!(
            results[loser].1.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::ResourceBudgetExceeded,
                ..
            }
        ));
        let mut expected = existing.assignees;
        expected.extend(&intents[winner].assignees);
        let page = complete_history(&node, 1);
        assert_eq!(page.issue.as_ref().unwrap().assignees, expected);
        assert_eq!(page.issue.as_ref().unwrap().version.get(), 3);
        assert_eq!(page.events.len(), 3);
        let after = snapshot(&node);
        no_code_changes(&before, &after);
        assert_eq!(
            after.snapshot().outbox.len(),
            before.snapshot().outbox.len() + 1
        );
        for i in 0..2 {
            assert_eq!(add(&node, &intents[i], keys[i]).unwrap(), results[i]);
        }
        assert_eq!(snapshot(&node).basis(), after.basis());

        accepted(apply(
            &node,
            &change(
                1,
                3,
                IssueAction::Unassign {
                    assignees: vec![principal(1)],
                },
            ),
            "free-slot",
        ));
        assert_eq!(
            add(&node, &intents[loser], keys[loser]).unwrap(),
            results[loser]
        );
        accepted(add(&node, &intents[loser], "new-request-after-slot-freed"));
        assert_eq!(
            complete_history(&node, 1).issue.unwrap().assignees,
            (2..=MAX_ASSIGNEES as u8 + 1)
                .map(principal)
                .collect::<Vec<_>>()
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn additive_capacity_missing_issue_cancellation_and_quota_keep_exact_recovery() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let mut node = node(&scratch, format);
        let first = intent(1, &[1]);
        let missing = add(&node, &first, "missing").unwrap();
        assert!(matches!(
            missing.1.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::EvidenceStale,
                ..
            }
        ));
        accepted(apply(&node, &open(1), "open"));
        assert_eq!(add(&node, &first, "missing").unwrap(), missing);
        accepted(add(&node, &first, "now-existing"));

        let second = intent(1, &[2]);
        let before = snapshot(&node);
        let cancelled = node.request_context();
        cancelled.authority().cancel();
        assert!(
            node.runtime()
                .block_on(node.admit_issue_assignees_durable_in(
                    &cancelled,
                    &session("cancelled"),
                    &second,
                    AdmissionLimits::default()
                ))
                .is_err()
        );
        assert_eq!(snapshot(&node).basis(), before.basis());
        accepted(add(&node, &second, "cancelled"));

        let almost_full = intent(1, &(1..MAX_ASSIGNEES as u8).collect::<Vec<_>>());
        accepted(add(&node, &almost_full, "almost-full"));
        let exact = intent(1, &[MAX_ASSIGNEES as u8]);
        accepted(add(&node, &exact, "exact-bound"));
        let full: Vec<_> = (1..=MAX_ASSIGNEES as u8).map(principal).collect();
        assert_eq!(complete_history(&node, 1).issue.unwrap().assignees, full);
        let overflow = intent(1, &[MAX_ASSIGNEES as u8 + 1]);
        let refused = add(&node, &overflow, "overflow").unwrap();
        assert!(matches!(
            refused.1.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::ResourceBudgetExceeded,
                ..
            }
        ));
        assert_eq!(complete_history(&node, 1).issue.unwrap().assignees, full);
        // Re-adding existing members consumes no capacity, but remains one
        // separately identified event with its normal history and outbox.
        accepted(add(
            &node,
            &intent(1, &[1, MAX_ASSIGNEES as u8]),
            "already-assigned",
        ));
        accepted(apply(
            &node,
            &change(
                1,
                6,
                IssueAction::Unassign {
                    assignees: vec![principal(1)],
                },
            ),
            "make-room",
        ));
        assert_eq!(add(&node, &overflow, "overflow").unwrap(), refused);
        let restored = accepted(add(&node, &overflow, "after-room"));
        assert_eq!(
            complete_history(&node, 1).issue.unwrap().assignees,
            (2..=MAX_ASSIGNEES as u8 + 1)
                .map(principal)
                .collect::<Vec<_>>()
        );
        let settled = snapshot(&node);
        node.push_quota.limit.max_events = 0;
        assert_eq!(add(&node, &overflow, "after-room").unwrap(), restored);
        assert!(add(&node, &first, "quota-denied").is_err());
        assert_eq!(snapshot(&node).basis(), settled.basis());
        node.shutdown().unwrap();
        let reopened = OneNode::open_existing(scratch.config(format)).unwrap();
        assert_eq!(add(&reopened, &overflow, "overflow").unwrap(), refused);
        assert_eq!(add(&reopened, &overflow, "after-room").unwrap(), restored);
        reopened.shutdown().unwrap();
    }
}
