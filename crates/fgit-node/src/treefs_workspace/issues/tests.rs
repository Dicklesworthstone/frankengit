use super::*;
use fgit_authority::IdempotencyKey;
use fgit_forge::{AggregateVersion, ExpectedVersion};
use fgit_forge::event::issue::{IssueAction, IssueEdit, IssueState};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, HeadGeneration, PrincipalId, RepositoryId, TenantId};
use crate::{MaterializedAdmission, NodeConfig};
use std::{fs, future::Future, path::PathBuf, sync::atomic::{AtomicU64, Ordering}, task::Poll};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("fg-issue-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&path).unwrap(); Self(path)
    }
    fn config(&self, format: GitHashAlgorithm) -> NodeConfig {
        NodeConfig::new(self.0.join("node"), TenantId::from_bytes([0x91;16]), RepositoryId::from_bytes([0x92;16]))
            .with_object_format(format).with_worker_threads(2)
    }
}
impl Drop for Scratch { fn drop(&mut self) { fs::remove_dir_all(&self.0).unwrap(); } }
fn actor() -> PrincipalId { PrincipalId::from_bytes([0x93;16]) }
fn session(key: &str) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(actor(), IdempotencyKey::new(key.as_bytes().to_vec()).unwrap())
}
fn node(scratch: &Scratch, format: GitHashAlgorithm) -> OneNode {
    let (mut node, _) = OneNode::init(scratch.config(format)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap(); node
}
fn open(number: u64) -> IssueCommand {
    IssueCommand { number: IssueNumber::try_new(number).unwrap(), expected_version: ExpectedVersion::NewStream,
        action: IssueAction::Open { title: format!("Issue {number}"), body: "text é\r\nwithout terminal newline".into(), labels: vec!["bug".into()] } }
}
fn change(number: u64, version: u64, action: IssueAction) -> IssueCommand {
    IssueCommand { number: IssueNumber::try_new(number).unwrap(), expected_version: ExpectedVersion::Exactly(AggregateVersion::try_new(version).unwrap()), action }
}
fn apply(node: &OneNode, command: &IssueCommand, key: &str) -> Result<(TxId, TerminalOutcome), NodeReceiveTransportRefusal> {
    let request = node.request_context();
    node.runtime().block_on(node.admit_issue_durable_in(&request, &session(key), command, AdmissionLimits::default()))
}
fn accepted(result: Result<(TxId, TerminalOutcome), NodeReceiveTransportRefusal>) -> (TxId, TerminalOutcome) {
    let result = result.unwrap(); assert!(matches!(result.1.outcome, DecisionOutcome::Committed { .. }), "{result:?}"); result
}
fn snapshot(node: &OneNode) -> MaterializedAdmission {
    let request = node.request_context(); node.runtime().block_on(node.materialize_admission_in(&request)).unwrap()
}
fn history(node: &OneNode, number: u64, after: u64, pin: Option<RepositoryAuthorityHeadId>) -> Result<issues::IssueHistoryPage, IssueReadRefusal> {
    let request = node.request_context();
    node.runtime().block_on(node.read_issue_history_in(&request, IssueNumber::try_new(number).unwrap(), after, 2, pin))
}
fn no_code_changes(before: &MaterializedAdmission, after: &MaterializedAdmission) {
    assert_eq!(before.snapshot().refs, after.snapshot().refs);
    assert_eq!(before.snapshot().head_target, after.snapshot().head_target);
    assert_eq!(before.basis().body().ref_root, after.basis().body().ref_root);
    assert_eq!(before.basis().body().retention_root, after.basis().body().retention_root);
    assert_eq!(before.basis().body().policy_epoch, after.basis().body().policy_epoch);
    assert_eq!(before.selected_closure().closure(), after.selected_closure().closure());
}

#[test]
fn durable_issue_lifecycle_rebuilds_after_reopen_and_keeps_exact_historical_results() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new(); let node = node(&scratch, format);
        let before = snapshot(&node); let command = open(7);
        let original = accepted(apply(&node, &command, "open"));
        let edited = change(7, 1, IssueAction::Edit(IssueEdit { title: Some("Edited é".into()), labels: Some(vec![]), ..Default::default() }));
        accepted(apply(&node, &edited, "edit"));
        let comment = change(7, 2, IssueAction::Comment { body: "<script>\r\nnot executable".into() });
        let commented = accepted(apply(&node, &comment, "comment"));
        accepted(apply(&node, &change(7, 3, IssueAction::Close), "close"));
        accepted(apply(&node, &change(7, 4, IssueAction::Reopen), "reopen"));
        let after = snapshot(&node); no_code_changes(&before, &after);
        assert_eq!(after.snapshot().outbox.len(), before.snapshot().outbox.len()+5);
        assert_ne!(after.basis().body().forge_position_root, before.basis().body().forge_position_root);
        assert_eq!(apply(&node, &command, "open").unwrap(), original);
        assert_eq!(apply(&node, &comment, "comment").unwrap(), commented);
        assert_eq!(snapshot(&node).basis(), after.basis());
        let page = history(&node, 7, 0, None).unwrap();
        let issue = page.issue.as_ref().unwrap();
        assert_eq!(issue.state, IssueState::Open); assert_eq!(issue.version.get(), 5);
        assert_eq!(issue.comments, 1); assert!(issue.labels.is_empty()); assert_eq!(issue.opened_by, actor());
        assert_eq!(issue.title, "Edited é"); assert_eq!(issue.body, "text é\r\nwithout terminal newline");
        assert_eq!(page.next_after, Some(2));
        let next = history(&node, 7, 2, Some(page.source_head)).unwrap();
        assert_eq!(next.events[0].payload, comment.proposed_event(actor()).unwrap().payload);
        let final_page = history(&node, 7, 4, Some(page.source_head)).unwrap(); assert!(final_page.next_after.is_none());
        node.shutdown().unwrap();
        let mut reopened = OneNode::open_existing(scratch.config(format)).unwrap();
        // Historical recovery remains available even before serving resumes.
        assert_eq!(apply(&reopened, &command, "open").unwrap(), original);
        reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
        assert_eq!(history(&reopened, 7, 0, None).unwrap(), page);
        assert_eq!(snapshot(&reopened).basis(), after.basis()); reopened.shutdown().unwrap();
    }
}

#[test]
fn genuinely_overlapping_issue_edits_publish_one_winner_and_one_stale_decision() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new(); let node = node(&scratch, format); accepted(apply(&node, &open(1), "open"));
        let a = change(1, 1, IssueAction::Edit(IssueEdit { title: Some("First".into()), ..Default::default() }));
        let b = change(1, 1, IssueAction::Edit(IssueEdit { title: Some("Second".into()), ..Default::default() }));
        let (ra, rb) = (node.request_context(), node.request_context());
        let (sa, sb) = (session("a"), session("b"));
        let mut fa = Box::pin(node.admit_issue_durable_in(&ra, &sa, &a, AdmissionLimits::default()));
        let mut fb = Box::pin(node.admit_issue_durable_in(&rb, &sb, &b, AdmissionLimits::default()));
        let (mut left, mut right, mut overlap) = (None, None, false);
        let (a_result, b_result) = node.runtime().block_on(std::future::poll_fn(|cx| {
            if left.is_none() && let Poll::Ready(value) = fa.as_mut().poll(cx) { left = Some(value); }
            if right.is_none() && let Poll::Ready(value) = fb.as_mut().poll(cx) { right = Some(value); }
            overlap |= left.is_none() && right.is_none();
            if left.is_some() && right.is_some() { Poll::Ready((left.take().unwrap().unwrap(), right.take().unwrap().unwrap())) } else { Poll::Pending }
        }));
        drop(fa); drop(fb); assert!(overlap, "both real authority operations must be pending together");
        let outcomes = [&a_result.1.outcome, &b_result.1.outcome];
        assert_eq!(outcomes.iter().filter(|outcome| matches!(outcome, DecisionOutcome::Committed { .. })).count(), 1);
        assert_eq!(outcomes.iter().filter(|outcome| matches!(outcome, DecisionOutcome::Refused { code: RefusalCode::EvidenceStale, .. })).count(), 1);
        assert_eq!(history(&node, 1, 0, None).unwrap().issue.unwrap().version.get(), 2);
        let settled = snapshot(&node);
        assert_eq!(settled.snapshot().outbox.len(), 2);
        assert_eq!(apply(&node, &a, "a").unwrap(), a_result); assert_eq!(apply(&node, &b, "b").unwrap(), b_result);
        assert_eq!(snapshot(&node).basis(), settled.basis()); node.shutdown().unwrap();
    }
}

#[test]
fn missing_wrong_state_changed_key_and_cancelled_commands_do_not_fabricate_success() {
    let scratch = Scratch::new(); let mut node = node(&scratch, GitHashAlgorithm::Sha1);
    let absent = change(1, 1, IssueAction::Close);
    let refused = apply(&node, &absent, "missing").unwrap();
    assert!(matches!(refused.1.outcome, DecisionOutcome::Refused { code: RefusalCode::EvidenceStale, .. }));
    let command = open(1); let original = accepted(apply(&node, &command, "open"));
    assert_eq!(apply(&node, &absent, "missing").unwrap(), refused);
    let before = snapshot(&node); let request = node.request_context(); request.authority().cancel();
    assert!(node.runtime().block_on(node.admit_issue_durable_in(&request, &session("cancel"), &open(2), AdmissionLimits::default())).is_err());
    assert_eq!(snapshot(&node).basis(), before.basis());
    assert!(apply(&node, &open(2), "open").is_err()); assert_eq!(snapshot(&node).basis(), before.basis());
    let wrong = apply(&node, &change(1, 1, IssueAction::Reopen), "wrong-state").unwrap();
    assert!(matches!(wrong.1.outcome, DecisionOutcome::Refused { code: RefusalCode::ProtectedRefTransitionDenied, .. }));
    node.push_quota.limit.max_events = 0;
    assert_eq!(apply(&node, &command, "open").unwrap(), original);
    assert_eq!(apply(&node, &absent, "missing").unwrap(), refused);
    assert!(matches!(apply(&node, &open(2), "new"), Err(NodeReceiveTransportRefusal::QuotaContained { .. })));
    node.shutdown().unwrap();
}

#[test]
fn issue_and_timeline_pagination_are_numeric_snapshot_pinned_and_read_only() {
    let scratch = Scratch::new(); let node = node(&scratch, GitHashAlgorithm::Sha256);
    for number in [10, 2, 1] { accepted(apply(&node, &open(number), &format!("open-{number}"))); }
    let request = node.request_context();
    let first = node.runtime().block_on(node.read_issues_in(&request, 0, 2, None)).unwrap();
    assert_eq!(first.issues.iter().map(|issue| issue.number.get()).collect::<Vec<_>>(), vec![1,2]);
    assert_eq!(first.next_after, Some(2)); let before = snapshot(&node);
    assert!(matches!(node.runtime().block_on(node.read_issues_in(&request, 2, 2, None)), Err(IssueReadRefusal::SnapshotRequired)));
    let second = node.runtime().block_on(node.read_issues_in(&request, 2, 2, Some(first.source_head))).unwrap();
    assert_eq!(second.issues[0].number.get(),10); assert!(second.next_after.is_none());
    assert!(history(&node, 99, 0, None).unwrap().issue.is_none()); assert_eq!(snapshot(&node).basis(), before.basis());
    accepted(apply(&node, &change(1, 1, IssueAction::Close), "close"));
    assert!(matches!(node.runtime().block_on(node.read_issues_in(&request, 2, 2, Some(first.source_head))), Err(IssueReadRefusal::SnapshotMoved)));
    assert!(matches!(history(&node, 1, 1, Some(first.source_head)), Err(IssueReadRefusal::SnapshotMoved)));
    node.shutdown().unwrap();
}
