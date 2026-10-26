//! Persisted append intent, strict-version twins and exact terminal recovery.
use super::*;
use fgit_forge::ForgeEventPayload;
use fgit_forge::event::issue::IssueCommentIntent;
use std::collections::{BTreeMap, BTreeSet};

fn intent(number: u64, body: &str) -> IssueCommentIntent {
    IssueCommentIntent {
        number: IssueNumber::try_new(number).unwrap(),
        body: body.into(),
    }
}
fn append(
    node: &OneNode,
    intent: &IssueCommentIntent,
    key: &str,
) -> Result<(TxId, TerminalOutcome), NodeReceiveTransportRefusal> {
    let request = node.request_context();
    node.runtime().block_on(node.admit_issue_comment_durable_in(
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
fn append_survives_intervening_edits_and_recovers_exactly_across_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = node(&scratch, format);
        accepted(apply(&node, &open(7), "open"));
        let submitted = intent(7, "Exact é\r\ncomment without newline");
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
        let original = accepted(append(&node, &submitted, "append"));
        let page = complete_history(&node, 7);
        let issue = page.issue.as_ref().unwrap();
        assert_eq!(issue.version.get(), 3);
        assert_eq!(issue.comments, 1);
        assert_eq!(issue.title, "concurrent title");
        assert_eq!(page.events[2].version.get(), 3);
        assert!(
            matches!(&page.events[2].payload, ForgeEventPayload::IssueChangedNative(change)
            if change.actor == actor() && change.action == (IssueAction::Comment { body: submitted.body.clone() }))
        );
        let after = snapshot(&node);
        no_code_changes(&before, &after);
        assert_eq!(
            after.snapshot().outbox.len(),
            before.snapshot().outbox.len() + 1
        );
        assert_eq!(append(&node, &submitted, "append").unwrap(), original);
        assert_eq!(snapshot(&node).basis(), after.basis());
        assert!(append(&node, &intent(7, "changed bytes"), "append").is_err());
        assert_eq!(snapshot(&node).basis(), after.basis());

        // The old comment API still binds its caller-selected predecessor.
        let strict = change(
            7,
            1,
            IssueAction::Comment {
                body: submitted.body.clone(),
            },
        );
        let refusal = apply(&node, &strict, "strict-stale").unwrap();
        assert!(matches!(
            refusal.1.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::EvidenceStale,
                ..
            }
        ));
        assert_eq!(complete_history(&node, 7).issue.unwrap().comments, 1);
        // The profiles are distinct even when the normalized payload matches.
        assert!(apply(&node, &strict, "append").is_err());
        accepted(apply(&node, &change(7, 3, IssueAction::Close), "close"));
        let closed = accepted(append(
            &node,
            &intent(7, "comment on closed issue"),
            "closed-append",
        ));
        let settled = snapshot(&node);
        let page = complete_history(&node, 7);
        assert_eq!(page.issue.as_ref().unwrap().state, IssueState::Closed);
        assert_eq!(page.issue.as_ref().unwrap().comments, 2);
        node.shutdown().unwrap();
        let mut reopened = OneNode::open_existing(scratch.config(format)).unwrap();
        assert_eq!(append(&reopened, &submitted, "append").unwrap(), original);
        assert_eq!(
            append(
                &reopened,
                &intent(7, "comment on closed issue"),
                "closed-append"
            )
            .unwrap(),
            closed
        );
        reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
        assert_eq!(complete_history(&reopened, 7), page);
        assert_eq!(snapshot(&reopened).basis(), settled.basis());
        reopened.shutdown().unwrap();
    }
}

#[test]
fn eight_overlapping_comments_all_commit_once_on_one_persisted_issue() {
    const COUNT: usize = 8;
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = node(&scratch, format);
        accepted(apply(&node, &open(1), "open"));
        let before = snapshot(&node);
        // Two independent requests with identical text must both survive; the
        // grow-only identity is TxId, not a deduplication of comment bodies.
        let intents: Vec<_> = (0..COUNT)
            .map(|i| intent(1, &format!("comment {}", i / 2)))
            .collect();
        let requests: Vec<_> = (0..COUNT).map(|_| node.request_context()).collect();
        let keys: Vec<_> = (0..COUNT).map(|i| format!("append-{i}")).collect();
        let sessions: Vec<_> = keys.iter().map(|key| session(key)).collect();
        let mut pending: Vec<_> = (0..COUNT)
            .map(|i| {
                Box::pin(node.admit_issue_comment_durable_in(
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
        assert_eq!(page.issue.as_ref().unwrap().comments, COUNT as u64);
        assert_eq!(page.issue.as_ref().unwrap().version.get(), COUNT as u64 + 1);
        let mut bodies = BTreeMap::new();
        for event in page.events.iter().skip(1) {
            let ForgeEventPayload::IssueChangedNative(change) = &event.payload else {
                panic!("issue event");
            };
            let IssueAction::Comment { body } = &change.action else {
                panic!("comment event");
            };
            *bodies.entry(body.clone()).or_insert(0usize) += 1;
        }
        assert_eq!(
            bodies,
            (0..COUNT / 2)
                .map(|i| (format!("comment {i}"), 2))
                .collect()
        );
        let settled = snapshot(&node);
        no_code_changes(&before, &settled);
        assert_eq!(
            settled.snapshot().outbox.len(),
            before.snapshot().outbox.len() + COUNT
        );
        for i in (0..COUNT).rev() {
            assert_eq!(append(&node, &intents[i], &keys[i]).unwrap(), results[i]);
        }
        assert_eq!(snapshot(&node).basis(), settled.basis());
        node.shutdown().unwrap();
    }
}

#[test]
fn missing_issue_refusal_cancelled_attempt_and_quota_keep_their_existing_boundaries() {
    let scratch = Scratch::new();
    let mut node = node(&scratch, GitHashAlgorithm::Sha1);
    let comment = intent(1, "one comment");
    let missing = append(&node, &comment, "missing").unwrap();
    assert!(matches!(
        missing.1.outcome,
        DecisionOutcome::Refused {
            code: RefusalCode::EvidenceStale,
            ..
        }
    ));
    accepted(apply(&node, &open(1), "open"));
    assert_eq!(append(&node, &comment, "missing").unwrap(), missing);
    let before = snapshot(&node);
    let cancelled = node.request_context();
    cancelled.authority().cancel();
    assert!(
        node.runtime()
            .block_on(node.admit_issue_comment_durable_in(
                &cancelled,
                &session("cancelled"),
                &comment,
                AdmissionLimits::default(),
            ))
            .is_err()
    );
    assert_eq!(snapshot(&node).basis(), before.basis());
    let terminal = accepted(append(&node, &comment, "cancelled"));
    let settled = snapshot(&node);
    node.push_quota.limit.max_events = 0;
    assert_eq!(append(&node, &comment, "cancelled").unwrap(), terminal);
    assert!(append(&node, &comment, "fresh-denied").is_err());
    assert_eq!(snapshot(&node).basis(), settled.basis());
    node.shutdown().unwrap();
}
