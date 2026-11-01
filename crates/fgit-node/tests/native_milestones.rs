#![forbid(unsafe_code)]
//! Real embedded authority, exact metadata publication, and fresh-config reopen.
//! No substitute milestone store or progress counter participates in these tests.

use fgit_admission::{
    AdmissionLimits,
    merge::native::{issues, milestones},
};
use fgit_authority::{IdempotencyKey, TerminalOutcome};
use fgit_forge::event::issue::{IssueAction, IssueCommand, IssueState};
use fgit_forge::event::milestone::{
    MilestoneAction, MilestoneCommand, MilestoneEdit, MilestoneState,
};
use fgit_forge::{AggregateVersion, ExpectedVersion, IssueNumber, MilestoneNumber};
use fgit_node::{
    LoopbackReceiveSession, MaterializedAdmission, MilestoneReadRefusal, NodeConfig,
    NodeReceiveTransportRefusal, OneNode,
};
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, HeadGeneration, PrincipalId, RefusalCode,
    RepositoryAuthorityHeadId, RepositoryId, TenantId, TxId,
};
use std::{
    fs,
    future::Future,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    task::Poll,
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fg-milestones-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn config(&self, format: GitHashAlgorithm) -> NodeConfig {
        NodeConfig::new(
            self.0.join("node"),
            TenantId::from_bytes([0xd1; 16]),
            RepositoryId::from_bytes([0xd2; 16]),
        )
        .with_object_format(format)
        .with_worker_threads(2)
    }
    fn node(&self, format: GitHashAlgorithm) -> OneNode {
        let (mut node, _) = OneNode::init(self.config(format)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        node
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn actor() -> PrincipalId {
    PrincipalId::from_bytes([0xd3; 16])
}
fn session(key: &str) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(
        actor(),
        IdempotencyKey::new(key.as_bytes().to_vec()).unwrap(),
    )
}
fn expected(version: u64) -> ExpectedVersion {
    if version == 0 {
        ExpectedVersion::NewStream
    } else {
        ExpectedVersion::Exactly(AggregateVersion::try_new(version).unwrap())
    }
}
fn milestone(number: u64, version: u64, action: MilestoneAction) -> MilestoneCommand {
    MilestoneCommand {
        number: MilestoneNumber::try_new(number).unwrap(),
        expected_version: expected(version),
        action,
    }
}
fn opening(number: u64) -> MilestoneCommand {
    milestone(
        number,
        0,
        MilestoneAction::Open {
            title: format!("Release {number}"),
            body: "Acceptance é\r\n<script>plain text</script>".into(),
            due_at: Some(0),
        },
    )
}
fn issue(number: u64, version: u64, action: IssueAction) -> IssueCommand {
    IssueCommand {
        number: IssueNumber::try_new(number).unwrap(),
        expected_version: expected(version),
        action,
    }
}
fn issue_open(number: u64) -> IssueCommand {
    issue(
        number,
        0,
        IssueAction::Open {
            title: format!("Task {number}"),
            body: "Original task".into(),
            labels: vec!["release".into()],
        },
    )
}
fn assignment(number: u64, version: u64, target: u64, target_version: u64) -> IssueCommand {
    issue(
        number,
        version,
        IssueAction::SetMilestone {
            milestone: MilestoneNumber::try_new(target).unwrap(),
            expected_milestone_version: AggregateVersion::try_new(target_version).unwrap(),
        },
    )
}
type Outcome = Result<(TxId, TerminalOutcome), NodeReceiveTransportRefusal>;
fn apply(node: &OneNode, command: &MilestoneCommand, key: &str) -> Outcome {
    node.runtime().block_on(node.admit_milestone_durable_in(
        &node.request_context(),
        &session(key),
        command,
        AdmissionLimits::default(),
    ))
}
fn apply_issue(node: &OneNode, command: &IssueCommand, key: &str) -> Outcome {
    node.runtime().block_on(node.admit_issue_durable_in(
        &node.request_context(),
        &session(key),
        command,
        AdmissionLimits::default(),
    ))
}
fn committed(result: Outcome) -> (TxId, TerminalOutcome) {
    let result = result.unwrap();
    assert!(
        matches!(result.1.outcome, DecisionOutcome::Committed { .. }),
        "{result:?}"
    );
    result
}
fn refused(result: Outcome, expected: RefusalCode) -> (TxId, TerminalOutcome) {
    let result = result.unwrap();
    assert!(
        matches!(result.1.outcome, DecisionOutcome::Refused { code, .. } if code == expected),
        "{result:?}"
    );
    result
}
fn history(
    node: &OneNode,
    number: u64,
    head: Option<RepositoryAuthorityHeadId>,
) -> milestones::MilestoneHistoryPage {
    node.runtime()
        .block_on(node.read_milestone_history_in(
            &node.request_context(),
            MilestoneNumber::try_new(number).unwrap(),
            0,
            100,
            head,
        ))
        .unwrap()
}
fn issue_history(node: &OneNode, number: u64) -> issues::IssueHistoryPage {
    node.runtime()
        .block_on(node.read_issue_history_in(
            &node.request_context(),
            IssueNumber::try_new(number).unwrap(),
            0,
            100,
            None,
        ))
        .unwrap()
}
fn snapshot(node: &OneNode) -> MaterializedAdmission {
    node.runtime()
        .block_on(node.materialize_admission_in(&node.request_context()))
        .unwrap()
}
fn no_code_changes(before: &MaterializedAdmission, after: &MaterializedAdmission) {
    assert_eq!(before.snapshot().refs, after.snapshot().refs);
    assert_eq!(before.snapshot().head_target, after.snapshot().head_target);
    assert_eq!(
        before.basis().body().ref_root,
        after.basis().body().ref_root
    );
    assert_eq!(
        before.basis().body().retention_root,
        after.basis().body().retention_root
    );
    assert_eq!(
        before.basis().body().policy_epoch,
        after.basis().body().policy_epoch
    );
    assert_eq!(
        before.selected_closure().closure(),
        after.selected_closure().closure()
    );
}
fn progress(
    page: &milestones::MilestoneHistoryPage,
    open: u64,
    closed: u64,
    state: MilestoneState,
) {
    let summary = page.milestone.as_ref().unwrap();
    assert_eq!(
        (
            summary.open_issues,
            summary.closed_issues,
            summary.milestone.state
        ),
        (open, closed, state)
    );
}

#[test]
fn same_head_membership_progress_and_original_outcomes_survive_a_fresh_node_config() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = scratch.node(format);
        let before = snapshot(&node);
        let open = opening(7);
        let original = committed(apply(&node, &open, "milestone-open"));
        for number in [1, 2] {
            committed(apply_issue(
                &node,
                &issue_open(number),
                &format!("issue-open-{number}"),
            ));
        }
        let set = assignment(1, 1, 7, 1);
        let assigned = committed(apply_issue(&node, &set, "assign-one"));
        committed(apply_issue(&node, &assignment(2, 1, 7, 1), "assign-two"));
        committed(apply_issue(
            &node,
            &issue(2, 2, IssueAction::Close),
            "close-task",
        ));
        let pinned = history(&node, 7, None);
        progress(&pinned, 1, 1, MilestoneState::Open);
        assert_eq!(pinned.milestone.as_ref().unwrap().milestone.due_at, Some(0));
        committed(apply(
            &node,
            &milestone(
                7,
                1,
                MilestoneAction::Edit(MilestoneEdit {
                    title: Some("Revised release".into()),
                    due_at: Some(None),
                    ..Default::default()
                }),
            ),
            "edit-release",
        ));
        committed(apply(
            &node,
            &milestone(7, 2, MilestoneAction::Close),
            "close-release",
        ));
        assert_eq!(
            issue_history(&node, 1).issue.unwrap().milestone,
            Some(MilestoneNumber::try_new(7).unwrap())
        );
        committed(apply_issue(
            &node,
            &issue(2, 3, IssueAction::ClearMilestone),
            "clear-task",
        ));
        let current = history(&node, 7, None);
        progress(&current, 1, 0, MilestoneState::Closed);
        assert_eq!(current.milestone.as_ref().unwrap().milestone.due_at, None);
        assert_eq!(history(&node, 7, Some(pinned.source_head)), pinned);
        assert_eq!(apply(&node, &open, "milestone-open").unwrap(), original);
        assert_eq!(apply_issue(&node, &set, "assign-one").unwrap(), assigned);
        let after = snapshot(&node);
        no_code_changes(&before, &after);
        assert_eq!(
            after.snapshot().outbox.len(),
            before.snapshot().outbox.len() + 9
        );
        let mut changed = open.clone();
        changed.action = MilestoneAction::Open {
            title: "Changed retry".into(),
            body: String::new(),
            due_at: None,
        };
        assert!(apply(&node, &changed, "milestone-open").is_err());
        assert_eq!(snapshot(&node).basis(), after.basis());
        node.shutdown().unwrap();

        // No cloned NodeConfig or shared materializer/cache survives this open.
        let mut reopened = OneNode::open_existing(scratch.config(format)).unwrap();
        assert_eq!(apply(&reopened, &open, "milestone-open").unwrap(), original);
        assert_eq!(
            apply_issue(&reopened, &set, "assign-one").unwrap(),
            assigned
        );
        assert!(apply(&reopened, &opening(8), "new-while-stopped").is_err());
        reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
        assert_eq!(history(&reopened, 7, None), current);
        assert_eq!(history(&reopened, 7, Some(pinned.source_head)), pinned);
        assert_eq!(snapshot(&reopened).basis(), after.basis());
        committed(apply(
            &reopened,
            &milestone(7, 3, MilestoneAction::Reopen),
            "reopen-release",
        ));
        committed(apply_issue(
            &reopened,
            &assignment(2, 4, 7, 4),
            "reattach-closed-task",
        ));
        progress(&history(&reopened, 7, None), 1, 1, MilestoneState::Open);
        assert_eq!(
            issue_history(&reopened, 2).issue.unwrap().state,
            IssueState::Closed
        );
        reopened.shutdown().unwrap();
    }
}

#[test]
fn missing_stale_closed_and_cancelled_selections_refuse_without_inherited_authority() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = scratch.node(format);
        committed(apply_issue(&node, &issue_open(1), "open-task"));
        let absent = assignment(1, 1, 7, 1);
        let missing = refused(
            apply_issue(&node, &absent, "missing-target"),
            RefusalCode::EvidenceStale,
        );
        committed(apply(&node, &opening(7), "open-target"));
        assert_eq!(
            apply_issue(&node, &absent, "missing-target").unwrap(),
            missing
        );
        committed(apply(
            &node,
            &milestone(
                7,
                1,
                MilestoneAction::Edit(MilestoneEdit {
                    body: Some("later".into()),
                    ..Default::default()
                }),
            ),
            "edit-target",
        ));
        refused(
            apply_issue(&node, &absent, "stale-target"),
            RefusalCode::EvidenceStale,
        );
        committed(apply(
            &node,
            &milestone(7, 2, MilestoneAction::Close),
            "close-target",
        ));
        let closed = assignment(1, 1, 7, 3);
        let denied = refused(
            apply_issue(&node, &closed, "closed-target"),
            RefusalCode::ProtectedRefTransitionDenied,
        );
        assert_eq!(
            issue_history(&node, 1).issue.unwrap().version,
            AggregateVersion::FIRST
        );
        committed(apply(
            &node,
            &milestone(7, 3, MilestoneAction::Reopen),
            "reopen-target",
        ));
        assert_eq!(
            apply_issue(&node, &closed, "closed-target").unwrap(),
            denied
        );
        committed(apply_issue(
            &node,
            &issue(1, 1, IssueAction::Close),
            "close-task",
        ));
        committed(apply_issue(
            &node,
            &issue(1, 2, IssueAction::Lock),
            "lock-task",
        ));
        committed(apply_issue(
            &node,
            &assignment(1, 3, 7, 4),
            "attach-closed-locked",
        ));
        let selected = issue_history(&node, 1).issue.unwrap();
        assert!(selected.locked);
        assert_eq!(selected.state, IssueState::Closed);
        progress(&history(&node, 7, None), 0, 1, MilestoneState::Open);
        refused(
            apply_issue(&node, &assignment(1, 3, 7, 4), "stale-task"),
            RefusalCode::EvidenceStale,
        );
        committed(apply(
            &node,
            &milestone(7, 4, MilestoneAction::Close),
            "close-target-again",
        ));
        committed(apply_issue(
            &node,
            &issue(1, 4, IssueAction::ClearMilestone),
            "clear-closed-locked",
        ));
        let cleared = issue_history(&node, 1).issue.unwrap();
        assert_eq!(cleared.milestone, None);
        assert!(cleared.locked);
        assert_eq!(cleared.state, IssueState::Closed);

        let stable = snapshot(&node);
        let cancelled = node.request_context();
        cancelled.cancel();
        assert!(
            node.runtime()
                .block_on(node.admit_milestone_durable_in(
                    &cancelled,
                    &session("cancel-release"),
                    &opening(8),
                    AdmissionLimits::default(),
                ))
                .is_err()
        );
        assert!(
            node.runtime()
                .block_on(node.read_milestones_in(&cancelled, 0, 10, None))
                .is_err()
        );
        assert!(matches!(
            node.runtime().block_on(node.admit_milestone_durable_in(
                &node.request_context(),
                &LoopbackReceiveSession::anonymous(),
                &opening(8),
                AdmissionLimits::default(),
            )),
            Err(NodeReceiveTransportRefusal::Unauthenticated)
        ));
        assert_eq!(snapshot(&node).basis(), stable.basis());
        let request = node.request_context();
        assert!(matches!(
            node.runtime()
                .block_on(node.read_milestones_in(&request, 1, 10, None)),
            Err(MilestoneReadRefusal::SnapshotRequired)
        ));
        assert!(matches!(
            node.runtime()
                .block_on(node.read_milestones_in(&request, 0, 101, None)),
            Err(MilestoneReadRefusal::InvalidLimit)
        ));
        assert!(history(&node, 99, None).milestone.is_none());
        assert_eq!(snapshot(&node).basis(), stable.basis());
        node.shutdown().unwrap();
    }
}

#[test]
fn concurrent_target_closure_and_membership_publish_only_a_legal_serial_order() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = scratch.node(format);
        committed(apply(&node, &opening(7), "open-target"));
        committed(apply_issue(&node, &issue_open(1), "open-task"));
        let close = milestone(7, 1, MilestoneAction::Close);
        let set = assignment(1, 1, 7, 1);
        let (left_request, right_request) = (node.request_context(), node.request_context());
        let (left_session, right_session) = (session("race-close"), session("race-set"));
        let mut left = Box::pin(node.admit_milestone_durable_in(
            &left_request,
            &left_session,
            &close,
            AdmissionLimits::default(),
        ));
        let mut right = Box::pin(node.admit_issue_durable_in(
            &right_request,
            &right_session,
            &set,
            AdmissionLimits::default(),
        ));
        let (mut left_result, mut right_result, mut overlap) = (None, None, false);
        let (closed, assigned) = node.runtime().block_on(std::future::poll_fn(|cx| {
            if left_result.is_none()
                && let Poll::Ready(result) = left.as_mut().poll(cx)
            {
                left_result = Some(result);
            }
            if right_result.is_none()
                && let Poll::Ready(result) = right.as_mut().poll(cx)
            {
                right_result = Some(result);
            }
            overlap |= left_result.is_none() && right_result.is_none();
            if left_result.is_some() && right_result.is_some() {
                Poll::Ready((
                    left_result.take().unwrap().unwrap(),
                    right_result.take().unwrap().unwrap(),
                ))
            } else {
                Poll::Pending
            }
        }));
        drop(left);
        drop(right);
        assert!(
            overlap,
            "both real authority calls must have been pending together"
        );
        assert!(matches!(
            closed.1.outcome,
            DecisionOutcome::Committed { .. }
        ));
        let summary = history(&node, 7, None);
        match assigned.1.outcome {
            DecisionOutcome::Committed { .. } => {
                assert!(
                    assigned.1.decision_sequence < closed.1.decision_sequence,
                    "membership cannot inherit a stale target after its closure"
                );
                progress(&summary, 1, 0, MilestoneState::Closed);
            }
            DecisionOutcome::Refused { code, .. } => {
                assert_eq!(code, RefusalCode::EvidenceStale);
                assert!(closed.1.decision_sequence < assigned.1.decision_sequence);
                progress(&summary, 0, 0, MilestoneState::Closed);
                assert_eq!(
                    issue_history(&node, 1).issue.unwrap().version,
                    AggregateVersion::FIRST
                );
            }
        }
        let stable = snapshot(&node);
        assert_eq!(apply(&node, &close, "race-close").unwrap(), closed);
        assert_eq!(apply_issue(&node, &set, "race-set").unwrap(), assigned);
        assert_eq!(snapshot(&node).basis(), stable.basis());
        node.shutdown().unwrap();
    }
}
