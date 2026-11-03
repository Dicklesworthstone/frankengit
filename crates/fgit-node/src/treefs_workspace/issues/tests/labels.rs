//! Persisted additive labels, bounded concurrent union and exact recovery.
use super::*;
use fgit_forge::ForgeEventPayload;
use fgit_forge::event::issue::{IssueLabelsIntent, MAX_LABELS};
use std::collections::BTreeSet;

fn intent(number: u64, labels: &[&str]) -> IssueLabelsIntent {
    IssueLabelsIntent {
        number: IssueNumber::try_new(number).unwrap(),
        labels: labels.iter().map(|label| (*label).into()).collect(),
    }
}

fn add(
    node: &OneNode,
    intent: &IssueLabelsIntent,
    key: &str,
) -> Result<(TxId, TerminalOutcome), NodeReceiveTransportRefusal> {
    let request = node.request_context();
    node.runtime().block_on(node.admit_issue_labels_durable_in(
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
fn additions_preserve_intervening_metadata_and_recovery_cannot_resurrect_removed_labels() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = node(&scratch, format);
        accepted(apply(&node, &open(7), "open"));
        let submitted = intent(7, &["help-wanted", "triage"]);
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
        accepted(apply(&node, &change(7, 2, IssueAction::Close), "close"));
        accepted(apply(&node, &change(7, 3, IssueAction::Lock), "lock"));
        let before = snapshot(&node);
        let original = accepted(add(&node, &submitted, "add"));
        let second = accepted(add(
            &node,
            &intent(7, &["help-wanted", "priority"]),
            "independent-add",
        ));
        assert_ne!(original.0, second.0);
        let page = complete_history(&node, 7);
        let issue = page.issue.as_ref().unwrap();
        assert_eq!(issue.labels, ["bug", "help-wanted", "priority", "triage"]);
        assert_eq!(issue.version.get(), 6);
        assert_eq!(issue.title, "concurrent title");
        assert_eq!(issue.body, "text é\r\nwithout terminal newline");
        assert_eq!(issue.state, IssueState::Closed);
        assert!(issue.locked);
        assert_eq!(issue.opened_by, actor());
        assert_eq!(issue.comments, 0);
        assert!(issue.assignees.is_empty());
        assert_eq!(issue.milestone, None);
        assert!(matches!(
            &page.events[4].payload,
            ForgeEventPayload::IssueChangedNative(change)
                if change.actor == actor()
                    && change.action == IssueAction::AddLabels { labels: submitted.labels.clone() }
        ));
        let after = snapshot(&node);
        no_code_changes(&before, &after);
        assert_eq!(
            after.snapshot().outbox.len(),
            before.snapshot().outbox.len() + 2
        );
        assert_eq!(add(&node, &submitted, "add").unwrap(), original);
        assert!(add(&node, &intent(7, &["different"]), "add").is_err());
        assert_eq!(snapshot(&node).basis(), after.basis());

        let strict = change(
            7,
            1,
            IssueAction::Edit(IssueEdit {
                labels: Some(vec!["replacement".into()]),
                ..Default::default()
            }),
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
                6,
                IssueAction::Edit(IssueEdit {
                    labels: Some(vec!["bug".into(), "priority".into()]),
                    ..Default::default()
                }),
            ),
            "remove-after-add",
        ));
        let settled = snapshot(&node);
        let final_page = complete_history(&node, 7);
        assert_eq!(
            final_page.issue.as_ref().unwrap().labels,
            ["bug", "priority"]
        );
        assert_eq!(add(&node, &submitted, "add").unwrap(), original);
        assert_eq!(snapshot(&node).basis(), settled.basis());
        node.shutdown().unwrap();

        let mut reopened = OneNode::open_existing(scratch.config(format)).unwrap();
        // Historical recovery precedes intake and must not reapply an old union.
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
        let intents: Vec<_> = (0..COUNT)
            .map(|i| intent(1, &["shared", &format!("worker-{i:02}")]))
            .collect();
        let requests: Vec<_> = (0..COUNT).map(|_| node.request_context()).collect();
        let keys: Vec<_> = (0..COUNT).map(|i| format!("addition-{i}")).collect();
        let sessions: Vec<_> = keys.iter().map(|key| session(key)).collect();
        let mut pending: Vec<_> = (0..COUNT)
            .map(|i| {
                Box::pin(node.admit_issue_labels_durable_in(
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
        let mut expected = vec!["bug".to_owned(), "shared".to_owned()];
        expected.extend((0..COUNT).map(|i| format!("worker-{i:02}")));
        assert_eq!(page.issue.as_ref().unwrap().labels, expected);
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
                let IssueAction::AddLabels { labels } = &change.action else {
                    panic!("label addition event");
                };
                assert_eq!(change.actor, actor());
                labels.clone()
            })
            .collect();
        assert_eq!(
            observed,
            intents.iter().map(|intent| intent.labels.clone()).collect()
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
fn competing_additions_revalidate_the_last_label_slot_before_publication() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = node(&scratch, format);
        accepted(apply(&node, &open(1), "open"));
        // The initial `bug` plus thirty additions leave exactly one free slot.
        let existing = IssueLabelsIntent {
            number: IssueNumber::try_new(1).unwrap(),
            labels: (1..MAX_LABELS - 1)
                .map(|i| format!("label-{i:02}"))
                .collect(),
        };
        accepted(add(&node, &existing, "existing"));
        let before = snapshot(&node);
        let intents = [intent(1, &["label-31"]), intent(1, &["label-32"])];
        let requests = [node.request_context(), node.request_context()];
        let keys = ["last-slot-a", "last-slot-b"];
        let sessions = keys.map(session);
        let mut pending: Vec<_> = (0..2)
            .map(|i| {
                Box::pin(node.admit_issue_labels_durable_in(
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
        assert_ne!(results[winner].0, results[loser].0);
        assert!(matches!(
            results[loser].1.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::ResourceBudgetExceeded,
                ..
            }
        ));
        let mut expected = vec!["bug".to_owned()];
        expected.extend(existing.labels);
        expected.extend(intents[winner].labels.clone());
        let page = complete_history(&node, 1);
        assert_eq!(page.issue.as_ref().unwrap().labels, expected);
        assert_eq!(page.issue.as_ref().unwrap().labels.len(), MAX_LABELS);
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

        // An existing member still commits at capacity and has its own outcome.
        accepted(add(
            &node,
            &intent(1, &["bug", "label-01"]),
            "overlap-at-capacity",
        ));
        assert_eq!(complete_history(&node, 1).issue.unwrap().labels, expected);
        expected.remove(0);
        accepted(apply(
            &node,
            &change(
                1,
                4,
                IssueAction::Edit(IssueEdit {
                    labels: Some(expected),
                    ..Default::default()
                }),
            ),
            "free-slot",
        ));
        assert_eq!(
            add(&node, &intents[loser], keys[loser]).unwrap(),
            results[loser]
        );
        accepted(add(&node, &intents[loser], "new-request-after-slot-freed"));
        assert_eq!(
            complete_history(&node, 1).issue.unwrap().labels,
            (1..=MAX_LABELS)
                .map(|i| format!("label-{i:02}"))
                .collect::<Vec<_>>()
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn missing_issue_cancellation_and_quota_preserve_exact_terminal_recovery() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let mut node = node(&scratch, format);
        let first = intent(1, &["later"]);
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

        let second = intent(1, &["next"]);
        let before = snapshot(&node);
        let cancelled = node.request_context();
        cancelled.authority().cancel();
        assert!(
            node.runtime()
                .block_on(node.admit_issue_labels_durable_in(
                    &cancelled,
                    &session("cancelled"),
                    &second,
                    AdmissionLimits::default(),
                ))
                .is_err()
        );
        assert_eq!(snapshot(&node).basis(), before.basis());
        let recovered = accepted(add(&node, &second, "cancelled"));
        assert_eq!(
            complete_history(&node, 1).issue.unwrap().labels,
            ["bug", "later", "next"]
        );
        let settled = snapshot(&node);
        node.push_quota.limit.max_events = 0;
        assert_eq!(add(&node, &second, "cancelled").unwrap(), recovered);
        assert!(add(&node, &intent(1, &["quota-denied"]), "quota-denied").is_err());
        assert_eq!(snapshot(&node).basis(), settled.basis());
        node.shutdown().unwrap();
        let reopened = OneNode::open_existing(scratch.config(format)).unwrap();
        assert_eq!(add(&reopened, &first, "missing").unwrap(), missing);
        assert_eq!(add(&reopened, &second, "cancelled").unwrap(), recovered);
        reopened.shutdown().unwrap();
    }
}
