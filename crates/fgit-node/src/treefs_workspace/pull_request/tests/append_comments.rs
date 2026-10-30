//! Stable PR comment intents on real file-backed authority and native objects.
use super::*;
use fgit_forge::event::pull_request_comment::{
    PullRequestAppendCommentCommand, PullRequestCommentCommand,
};
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::task::Poll;

mod anchors;

fn intent(number: u64, body: &str) -> PullRequestAppendCommentCommand {
    PullRequestAppendCommentCommand {
        number: PullRequestNumber::try_new(number).unwrap(),
        body: body.into(),
        anchor: None,
    }
}
fn append(
    node: &OneNode,
    command: &PullRequestAppendCommentCommand,
    key: &str,
) -> Result<(TxId, TerminalOutcome), NodeReceiveTransportRefusal> {
    let request = node.request_context();
    node.runtime()
        .block_on(node.admit_pull_request_append_comment_durable_in(
            &request,
            &session(key),
            command,
            AdmissionLimits::default(),
        ))
}
fn strict(
    node: &OneNode,
    command: &PullRequestAppendCommentCommand,
    previous: u64,
    key: &str,
) -> Result<(TxId, TerminalOutcome), NodeReceiveTransportRefusal> {
    let request = node.request_context();
    node.runtime().block_on(
        node.admit_pull_request_comment_durable_in(
            &request,
            &session(key),
            &PullRequestCommentCommand {
                number: command.number,
                expected_version: AggregateVersion::try_new(previous)
                    .map_or(ExpectedVersion::NewStream, ExpectedVersion::Exactly),
                body: command.body.clone(),
                anchor: command.anchor.clone(),
            },
            AdmissionLimits::default(),
        ),
    )
}
fn discussion(node: &OneNode, number: u64) -> PullRequestCommentsPage {
    let request = node.request_context();
    node.runtime()
        .block_on(node.read_pull_request_comments_in(
            &request,
            &RefVisibility::new(),
            PullRequestNumber::try_new(number).unwrap(),
            0,
            100,
            None,
        ))
        .unwrap()
        .unwrap()
}

#[test]
fn append_preserves_independent_versions_and_recovers_under_quota_and_after_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let mut node = node(&scratch, format);
        let fixture = fixture(&node, &scratch, format);
        let open = command(&fixture, 7);
        accepted(apply(&node, &open, "open"));
        let before = snapshot(&node);
        let submitted = intent(7, "Exact é\r\ncomment without final newline");
        let original = accepted(append(&node, &submitted, "append"));
        let first = discussion(&node, 7);
        assert_eq!(first.comments.len(), 1);
        assert_eq!(first.comments[0].body, submitted.body);
        assert_eq!(first.comments[0].actor, principal());
        assert_eq!(first.discussion_version.unwrap().get(), 1);
        assert_eq!(
            page(&node, 0, 100, None).unwrap().pull_requests[0]
                .event
                .version
                .get(),
            1
        );
        let after = snapshot(&node);
        unchanged_code(&before, &after);
        assert_eq!(
            after.snapshot().outbox.len(),
            before.snapshot().outbox.len() + 1
        );
        assert_eq!(append(&node, &submitted, "append").unwrap(), original);
        assert!(append(&node, &intent(7, "changed bytes"), "append").is_err());
        assert!(strict(&node, &submitted, 0, "append").is_err());
        assert_eq!(snapshot(&node).basis(), after.basis());
        let refusal = strict(&node, &submitted, 0, "strict-stale").unwrap();
        assert!(matches!(
            refusal.1.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::EvidenceStale,
                ..
            }
        ));
        accepted(strict(&node, &submitted, 1, "strict-current"));
        let mut close = open;
        close.expected_version = ExpectedVersion::Exactly(AggregateVersion::FIRST);
        close.action = PullRequestAction::Close;
        accepted(apply(&node, &close, "close"));
        let closed_command = intent(7, "A closed PR keeps its conversation");
        let closed = accepted(append(&node, &closed_command, "closed-append"));
        let final_page = discussion(&node, 7);
        assert_eq!(final_page.comments.len(), 3);
        assert_eq!(
            page(&node, 0, 100, None).unwrap().pull_requests[0]
                .event
                .version
                .get(),
            2
        );
        let settled = snapshot(&node);
        unchanged_code(&before, &settled);
        node.push_quota.limit.max_events = 0;
        assert_eq!(append(&node, &submitted, "append").unwrap(), original);
        assert!(append(&node, &submitted, "quota-contained").is_err());
        assert_eq!(snapshot(&node).basis(), settled.basis());
        node.shutdown().unwrap();
        let mut reopened = OneNode::open_existing(scratch.config(format)).unwrap();
        assert_eq!(append(&reopened, &submitted, "append").unwrap(), original);
        assert_eq!(
            append(&reopened, &closed_command, "closed-append").unwrap(),
            closed
        );
        assert_eq!(
            strict(&reopened, &submitted, 0, "strict-stale").unwrap(),
            refusal
        );
        assert!(append(&reopened, &submitted, "stopped-intake").is_err());
        reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
        assert_eq!(discussion(&reopened, 7), final_page);
        assert_eq!(snapshot(&reopened).basis(), settled.basis());
        reopened.shutdown().unwrap();
    }
}

#[test]
fn eight_overlapping_pr_appends_all_commit_once_without_deduplicating_equal_text() {
    const COUNT: usize = 8;
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = node(&scratch, format);
        let fixture = fixture(&node, &scratch, format);
        accepted(apply(&node, &command(&fixture, 1), "open"));
        let before = snapshot(&node);
        let commands: Vec<_> = (0..COUNT)
            .map(|i| intent(1, &format!("comment {}", i / 2)))
            .collect();
        let requests: Vec<_> = (0..COUNT).map(|_| node.request_context()).collect();
        let keys: Vec<_> = (0..COUNT).map(|i| format!("append-{i}")).collect();
        let sessions: Vec<_> = keys.iter().map(|key| session(key)).collect();
        let mut pending: Vec<_> = (0..COUNT)
            .map(|i| {
                Box::pin(node.admit_pull_request_append_comment_durable_in(
                    &requests[i],
                    &sessions[i],
                    &commands[i],
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
        assert!(overlap, "real authority requests overlap");
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
        let discussion = discussion(&node, 1);
        assert_eq!(discussion.comments.len(), COUNT);
        let mut bodies = BTreeMap::new();
        for (index, comment) in discussion.comments.iter().enumerate() {
            assert_eq!(comment.version.get(), index as u64 + 1);
            assert_eq!(comment.actor, principal());
            *bodies.entry(comment.body.clone()).or_insert(0usize) += 1;
        }
        assert_eq!(
            bodies,
            (0..COUNT / 2)
                .map(|i| (format!("comment {i}"), 2))
                .collect()
        );
        assert_eq!(
            page(&node, 0, 100, None).unwrap().pull_requests[0]
                .event
                .version
                .get(),
            1
        );
        let settled = snapshot(&node);
        unchanged_code(&before, &settled);
        assert_eq!(
            settled.snapshot().outbox.len(),
            before.snapshot().outbox.len() + COUNT
        );
        for i in (0..COUNT).rev() {
            assert_eq!(append(&node, &commands[i], &keys[i]).unwrap(), results[i]);
        }
        assert_eq!(snapshot(&node).basis(), settled.basis());
        node.shutdown().unwrap();
    }
}

#[test]
fn missing_pr_cancellation_and_current_visibility_preserve_boundaries() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = node(&scratch, format);
        let fixture = fixture(&node, &scratch, format);
        let submitted = intent(1, "one comment");
        let missing = append(&node, &submitted, "missing").unwrap();
        assert!(matches!(
            missing.1.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::EvidenceMissing,
                ..
            }
        ));
        accepted(apply(&node, &command(&fixture, 1), "open"));
        assert_eq!(append(&node, &submitted, "missing").unwrap(), missing);
        assert!(discussion(&node, 1).comments.is_empty());
        let before = snapshot(&node);
        let cancelled = node.request_context();
        cancelled.authority().cancel();
        assert!(
            node.runtime()
                .block_on(node.admit_pull_request_append_comment_durable_in(
                    &cancelled,
                    &session("cancelled"),
                    &submitted,
                    AdmissionLimits::default(),
                ))
                .is_err()
        );
        assert_eq!(snapshot(&node).basis(), before.basis());
        accepted(append(&node, &submitted, "cancelled"));
        let head = discussion(&node, 1).source_head;
        for hidden in [source_ref(), target()] {
            let mut visibility = RefVisibility::new();
            visibility
                .push_rule(hidden.as_bytes(), &Default::default())
                .unwrap();
            let request = node.request_context();
            assert!(
                node.runtime()
                    .block_on(node.read_pull_request_comments_in(
                        &request,
                        &visibility,
                        PullRequestNumber::FIRST,
                        0,
                        100,
                        Some(head),
                    ))
                    .unwrap()
                    .is_none()
            );
        }
        node.shutdown().unwrap();
    }
}

#[test]
fn merged_native_pr_keeps_additive_conversation_without_another_ref_effect() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = node(&scratch, format);
        let f = fixture(&node, &scratch, format);
        accepted(apply(&node, &command(&f, 1), "open"));
        let candidate = node
            .put_git_object(
                GitObjectKind::Commit,
                commit(
                    f.tree,
                    &[f.data.target_tip, f.data.source_tip],
                    "reviewed merge",
                ),
            )
            .unwrap()
            .identity();
        let merge = NativeMergeIntent::new(
            PullRequestNumber::FIRST,
            ExpectedVersion::Exactly(AggregateVersion::FIRST),
            NativeMerge {
                source_ref: source_ref(),
                source_tip: f.data.source_tip,
                base_tip: f.base,
                target_ref: target(),
                target_tip_before: f.data.target_tip,
                merge_commit: candidate,
            },
        )
        .unwrap();
        let request = node.request_context();
        let terminal = node
            .runtime()
            .block_on(node.admit_native_merge_durable_in(
                &request,
                &session("merge"),
                &merge,
                AdmissionLimits::default(),
                MergeObjectLimits::default(),
            ))
            .unwrap();
        assert!(matches!(
            terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        let before = snapshot(&node);
        accepted(append(
            &node,
            &intent(1, "Follow up after merge"),
            "after-merge",
        ));
        assert_eq!(discussion(&node, 1).comments.len(), 1);
        assert_eq!(
            page(&node, 0, 100, None).unwrap().pull_requests[0]
                .event
                .version
                .get(),
            2
        );
        unchanged_code(&before, &snapshot(&node));
        node.shutdown().unwrap();
    }
}
