#![forbid(unsafe_code)]
//! Delivery retirement cannot erase accepted metadata. These regressions use
//! native issue/PR admission, a synced receiver, canonical settlement and reopen.

use super::*;
use crate::treefs_workspace::NotificationThreadView;
use fgit_admission::merge::native::issues::{IssueHistoryPage, IssuePage};
use fgit_admission::merge::native::settlement::OutboxDestination;
use fgit_forge::IssueNumber;
use fgit_forge::event::issue::{IssueAction, IssueCommand, IssueEdit, IssueState};
use fgit_forge::event::notification::NotificationTarget;
use fgit_forge::event::pull_request_comment::PullRequestAppendCommentCommand;
use fgit_resource::{ObligationState, ReconcilePolicy};
use fgit_types::{AsciiSlug, Digest};

mod faults;
mod receiver;
use receiver::ReceiptDestination;

fn issue_command(version: u64, action: IssueAction) -> IssueCommand {
    IssueCommand {
        number: IssueNumber::FIRST,
        expected_version: AggregateVersion::try_new(version)
            .map_or(ExpectedVersion::NewStream, ExpectedVersion::Exactly),
        action,
    }
}

fn open_issue() -> IssueCommand {
    issue_command(
        0,
        IssueAction::Open {
            title: "An issue retained after delivery".into(),
            body: "Original é\r\nbody without a final newline".into(),
            labels: vec!["bug".into()],
        },
    )
}

fn publish_issue(node: &OneNode, command: &IssueCommand, key: &str) -> (TxId, TerminalOutcome) {
    let request = node.request_context();
    accepted(node.runtime().block_on(node.admit_issue_durable_in(
        &request,
        &session(key),
        command,
        AdmissionLimits::default(),
    )))
}

fn issue_history(
    node: &OneNode,
    after: u64,
    limit: u16,
    pin: Option<RepositoryAuthorityHeadId>,
) -> IssueHistoryPage {
    let request = node.request_context();
    node.runtime()
        .block_on(node.read_issue_history_in(&request, IssueNumber::FIRST, after, limit, pin))
        .unwrap()
}

fn issues(node: &OneNode, pin: Option<RepositoryAuthorityHeadId>) -> IssuePage {
    let request = node.request_context();
    node.runtime()
        .block_on(node.read_issues_in(&request, 0, 100, pin))
        .unwrap()
}

fn append_comment(node: &OneNode, text: &str, key: &str) -> (TxId, TerminalOutcome) {
    let request = node.request_context();
    accepted(
        node.runtime()
            .block_on(node.admit_pull_request_append_comment_durable_in(
                &request,
                &session(key),
                &PullRequestAppendCommentCommand {
                    number: PullRequestNumber::FIRST,
                    body: text.into(),
                    anchor: None,
                },
                AdmissionLimits::default(),
            )),
    )
}

fn comments(node: &OneNode, pin: Option<RepositoryAuthorityHeadId>) -> PullRequestCommentsPage {
    let request = node.request_context();
    node.runtime()
        .block_on(node.read_pull_request_comments_in(
            &request,
            &RefVisibility::new(),
            PullRequestNumber::FIRST,
            0,
            100,
            pin,
        ))
        .unwrap()
        .unwrap()
}

fn notification(node: &OneNode, target: NotificationTarget) -> NotificationThreadView {
    let request = node.request_context();
    let mut inbox = node
        .runtime()
        .block_on(node.read_notification_target_in(
            &request,
            &session("retirement-inbox-reader"),
            target,
            None,
        ))
        .unwrap();
    assert_eq!(inbox.threads.len(), 1);
    inbox.threads.pop().unwrap()
}

fn same_notification(before: &NotificationThreadView, after: &NotificationThreadView) {
    assert_eq!(after.target, before.target);
    assert_eq!(after.thread_version, before.thread_version);
    assert_eq!(after.title, before.title);
    assert_eq!(after.state, before.state);
    assert_eq!(after.preference_version, before.preference_version);
    assert_eq!(after.mode, before.mode);
    assert_eq!(after.read_through, before.read_through);
    assert_eq!(after.latest_other_version, before.latest_other_version);
    assert_eq!(after.reasons, before.reasons);
    assert_eq!(after.unread, before.unread);
}

fn new_delivery(before: &MaterializedAdmission, after: &MaterializedAdmission) -> AsciiSlug {
    let added: Vec<_> = after
        .snapshot()
        .outbox
        .keys()
        .filter(|key| !before.snapshot().outbox.contains_key(*key))
        .map(|key| key.label())
        .collect();
    assert_eq!(added.len(), 1);
    added[0]
}

/// Drive the actual settlement path and prove the obligation has disappeared,
/// while the immutable event and its authenticated receipt remain available.
fn retire(node: &OneNode, receiver: &mut ReceiptDestination, key: AsciiSlug) -> Digest {
    let before = snapshot(node);
    let request = node.request_context();
    let selected = node
        .runtime()
        .block_on(node.select_forge_delivery_in(
            &request,
            key,
            receiver.destination(),
            Some(before.basis().id()),
        ))
        .unwrap();
    let delivery = selected.as_request();
    let root = delivery.payload_root;
    let bytes = fgit_codec::encode_body(delivery.events).unwrap();
    let request = node.outbox_delivery_context();
    let acknowledged = node
        .runtime()
        .block_on(node.deliver_forge_outbox_in(
            &request,
            &session(&format!("retire-{key}")),
            key,
            receiver,
            ReconcilePolicy::new(std::num::NonZeroU32::new(4).unwrap()),
            AdmissionLimits::default(),
        ))
        .unwrap();
    assert_eq!(acknowledged.state(), ObligationState::Acknowledged);
    assert_eq!(receiver.receipt(key), bytes);
    let after = snapshot(node);
    assert_eq!(
        after.snapshot().outbox.len() + 1,
        before.snapshot().outbox.len()
    );
    assert!(
        !after
            .snapshot()
            .outbox
            .keys()
            .any(|entry| entry.label() == key)
    );
    assert_eq!(
        after.basis().body().forge_position_root,
        before.basis().body().forge_position_root
    );
    unchanged_code(&before, &after);
    let request = node.request_context();
    let receipt = node
        .runtime()
        .block_on(node.read_retired_forge_receipt_in(
            &request,
            key,
            receiver.destination(),
            Some(after.basis().id()),
        ))
        .unwrap();
    assert_eq!(receipt.effect(), &acknowledged);
    assert_eq!(receipt.receipt().payload_root(), root);
    root
}

#[test]
fn issue_history_survives_partial_and_complete_retirement_then_restart_and_mutation() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = node(&scratch, format);
        let initial = snapshot(&node);
        let open = open_issue();
        let opening = publish_issue(&node, &open, "retained-issue-open");
        let opened = snapshot(&node);
        let opening_key = new_delivery(&initial, &opened);
        let first = issue_history(&node, 0, 100, None);
        let edit = issue_command(
            1,
            IssueAction::Edit(IssueEdit {
                title: Some("Edited retained issue".into()),
                ..Default::default()
            }),
        );
        publish_issue(&node, &edit, "retained-issue-edit");
        let edited = snapshot(&node);
        let edit_key = new_delivery(&opened, &edited);
        let expected = issue_history(&node, 0, 100, None);
        let expected_issues = issues(&node, None);
        let inbox = notification(&node, NotificationTarget::Issue(IssueNumber::FIRST));
        let mut receiver = ReceiptDestination::new(scratch.0.join("issue-receiver"));
        retire(&node, &mut receiver, opening_key);

        // v2 is still pending; v1 must come from the authenticated RCR chain.
        let partial = issue_history(&node, 0, 100, None);
        assert_eq!(partial.issue, expected.issue);
        assert_eq!(partial.events, expected.events);
        assert_eq!(issues(&node, None).issues, expected_issues.issues);
        assert_eq!(issue_history(&node, 0, 100, Some(first.source_head)), first);
        assert_eq!(
            issue_history(&node, 0, 100, Some(expected.source_head)),
            expected
        );
        same_notification(
            &inbox,
            &notification(&node, NotificationTarget::Issue(IssueNumber::FIRST)),
        );
        let page_one = issue_history(&node, 0, 1, Some(partial.source_head));
        assert_eq!(page_one.next_after, Some(1));
        let page_two = issue_history(&node, 1, 1, Some(partial.source_head));
        assert_eq!(page_two.next_after, None);
        let mut walked = page_one.events;
        walked.extend(page_two.events);
        assert_eq!(walked, expected.events);

        let comment = issue_command(
            2,
            IssueAction::Comment {
                body: "After retirement é\r\n".into(),
            },
        );
        let before_comment = snapshot(&node);
        publish_issue(&node, &comment, "retained-issue-comment");
        let comment_key = new_delivery(&before_comment, &snapshot(&node));
        retire(&node, &mut receiver, edit_key);
        retire(&node, &mut receiver, comment_key);
        assert!(snapshot(&node).snapshot().outbox.is_empty());
        let complete = issue_history(&node, 0, 100, None);
        let issue = complete.issue.as_ref().unwrap();
        assert_eq!(issue.version.get(), 3);
        assert_eq!(issue.comments, 1);
        assert_eq!(issue.title, "Edited retained issue");
        assert_eq!(complete.events.len(), 3);
        assert_eq!(
            complete.events[2].payload,
            comment.proposed_event(principal()).unwrap().payload
        );
        let retired = snapshot(&node);
        unchanged_code(&initial, &retired);
        node.shutdown().unwrap();

        let mut reopened = OneNode::open_existing(scratch.config(format)).unwrap();
        reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
        assert_eq!(issue_history(&reopened, 0, 100, None), complete);
        assert_eq!(
            publish_issue(&reopened, &open, "retained-issue-open"),
            opening
        );
        assert_eq!(snapshot(&reopened).basis(), retired.basis());
        publish_issue(
            &reopened,
            &issue_command(3, IssueAction::Close),
            "retained-issue-close",
        );
        let closed = issue_history(&reopened, 0, 100, None);
        assert_eq!(closed.issue.as_ref().unwrap().state, IssueState::Closed);
        assert_eq!(closed.issue.as_ref().unwrap().version.get(), 4);
        assert_eq!(closed.events.len(), 4);
        assert_eq!(
            issue_history(&reopened, 0, 100, Some(complete.source_head)),
            complete
        );
        unchanged_code(&retired, &snapshot(&reopened));
        reopened.shutdown().unwrap();
    }
}

#[test]
fn pull_request_comments_and_inbox_survive_retirement_and_keep_visibility_after_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = node(&scratch, format);
        let fixture = fixture(&node, &scratch, format);
        let initial = snapshot(&node);
        let open = command(&fixture, 1);
        let opening = accepted(apply(&node, &open, "retained-pr-open"));
        let opened = snapshot(&node);
        let open_key = new_delivery(&initial, &opened);
        let mut edit = open.clone();
        edit.action = PullRequestAction::Update;
        edit.expected_version = ExpectedVersion::Exactly(AggregateVersion::FIRST);
        edit.data.title = "Edited retained PR".into();
        accepted(apply(&node, &edit, "retained-pr-edit"));
        let edited = snapshot(&node);
        let edit_key = new_delivery(&opened, &edited);
        append_comment(
            &node,
            "First retained comment é\r\n",
            "retained-pr-comment-1",
        );
        let commented = snapshot(&node);
        let first_comment_key = new_delivery(&edited, &commented);
        append_comment(&node, "Second retained comment", "retained-pr-comment-2");
        let second_comment_key = new_delivery(&commented, &snapshot(&node));
        let expected = page(&node, 0, 100, None).unwrap();
        let expected_comments = comments(&node, None);
        let inbox = notification(
            &node,
            NotificationTarget::PullRequest(PullRequestNumber::FIRST),
        );
        let mut receiver = ReceiptDestination::new(scratch.0.join("pr-receiver"));
        retire(&node, &mut receiver, open_key);
        retire(&node, &mut receiver, first_comment_key);

        assert_eq!(
            page(&node, 0, 100, None).unwrap().pull_requests,
            expected.pull_requests
        );
        assert_eq!(comments(&node, None).comments, expected_comments.comments);
        assert_eq!(
            page(&node, 0, 100, Some(expected.source_head)).unwrap(),
            expected
        );
        assert_eq!(
            comments(&node, Some(expected_comments.source_head)),
            expected_comments
        );
        same_notification(
            &inbox,
            &notification(
                &node,
                NotificationTarget::PullRequest(PullRequestNumber::FIRST),
            ),
        );

        edit.expected_version = ExpectedVersion::Exactly(AggregateVersion::try_new(2).unwrap());
        edit.data.title = "PR changed after retirement".into();
        let before_edit = snapshot(&node);
        accepted(apply(&node, &edit, "retained-pr-edit-again"));
        let latest_key = new_delivery(&before_edit, &snapshot(&node));
        for key in [edit_key, second_comment_key, latest_key] {
            retire(&node, &mut receiver, key);
        }
        assert_eq!(snapshot(&node).snapshot().outbox, initial.snapshot().outbox);
        let complete = page(&node, 0, 100, None).unwrap();
        let complete_comments = comments(&node, None);
        assert_eq!(complete.pull_requests[0].event.version.get(), 3);
        assert_eq!(complete.pull_requests[0].opened_by, Some(principal()));
        assert_eq!(complete_comments.comments.len(), 2);
        assert_eq!(complete_comments.discussion_version.unwrap().get(), 2);
        let inbox = notification(
            &node,
            NotificationTarget::PullRequest(PullRequestNumber::FIRST),
        );
        let retired = snapshot(&node);
        unchanged_code(&initial, &retired);
        node.shutdown().unwrap();

        let mut reopened = OneNode::open_existing(scratch.config(format)).unwrap();
        reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
        assert_eq!(page(&reopened, 0, 100, None).unwrap(), complete);
        assert_eq!(comments(&reopened, None), complete_comments);
        same_notification(
            &inbox,
            &notification(
                &reopened,
                NotificationTarget::PullRequest(PullRequestNumber::FIRST),
            ),
        );
        assert_eq!(
            apply(&reopened, &open, "retained-pr-open").unwrap(),
            opening
        );
        assert_eq!(snapshot(&reopened).basis(), retired.basis());
        for hidden in [source_ref(), target()] {
            let mut visibility = RefVisibility::new();
            visibility
                .push_rule(hidden.as_bytes(), &Default::default())
                .unwrap();
            let request = reopened.request_context();
            assert!(
                reopened
                    .runtime()
                    .block_on(reopened.read_pull_requests_in(
                        &request,
                        &visibility,
                        0,
                        100,
                        Some(complete.source_head),
                    ))
                    .unwrap()
                    .pull_requests
                    .is_empty()
            );
            assert!(
                reopened
                    .runtime()
                    .block_on(reopened.read_pull_request_comments_in(
                        &request,
                        &visibility,
                        PullRequestNumber::FIRST,
                        0,
                        100,
                        Some(complete.source_head),
                    ))
                    .unwrap()
                    .is_none()
            );
        }
        let cancelled = reopened.request_context();
        cancelled.authority().cancel();
        assert!(
            reopened
                .runtime()
                .block_on(reopened.read_pull_requests_in(
                    &cancelled,
                    &RefVisibility::new(),
                    0,
                    100,
                    None,
                ))
                .is_err()
        );
        assert!(
            reopened
                .runtime()
                .block_on(reopened.read_pull_request_comments_in(
                    &cancelled,
                    &RefVisibility::new(),
                    PullRequestNumber::FIRST,
                    0,
                    100,
                    None,
                ))
                .is_err()
        );
        assert_eq!(snapshot(&reopened).basis(), retired.basis());

        append_comment(
            &reopened,
            "A new comment after restart",
            "retained-pr-comment-3",
        );
        edit.action = PullRequestAction::Close;
        edit.expected_version = ExpectedVersion::Exactly(AggregateVersion::try_new(3).unwrap());
        accepted(apply(&reopened, &edit, "retained-pr-close"));
        assert_eq!(
            page(&reopened, 0, 100, None).unwrap().pull_requests[0]
                .event
                .version
                .get(),
            4
        );
        assert_eq!(comments(&reopened, None).comments.len(), 3);
        assert_eq!(
            comments(&reopened, Some(complete.source_head)),
            complete_comments
        );
        unchanged_code(&retired, &snapshot(&reopened));
        reopened.shutdown().unwrap();
    }
}
