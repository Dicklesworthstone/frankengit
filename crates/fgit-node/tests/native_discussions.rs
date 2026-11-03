#![forbid(unsafe_code)]
//! Discussions persist through real node admission, retained reads and fresh reopen.
use fgit_admission::AdmissionLimits;
use fgit_authority::{IdempotencyKey, TerminalOutcome};
use fgit_forge::event::discussion::{
    DiscussionAction, DiscussionCommand, DiscussionEdit, DiscussionState,
};
use fgit_forge::event::issue::{IssueAction, IssueCommand};
use fgit_forge::{AggregateVersion, DiscussionNumber, ExpectedVersion, IssueNumber};
use fgit_node::{
    DiscussionReadRefusal, LoopbackReceiveSession, NodeConfig, NodeReceiveTransportRefusal, OneNode,
};
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, HeadGeneration, PrincipalId, RefusalCode,
    RepositoryAuthorityHeadId, RepositoryId, TenantId, TxId,
};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fg-native-discussions-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn config(&self, format: GitHashAlgorithm) -> NodeConfig {
        NodeConfig::new(
            self.0.join("node"),
            TenantId::from_bytes([0xc1; 16]),
            RepositoryId::from_bytes([0xc2; 16]),
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
fn session(key: &str) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(
        PrincipalId::from_bytes([0xc3; 16]),
        IdempotencyKey::new(key.as_bytes().to_vec()).unwrap(),
    )
}
fn command(number: u64, version: u64, action: DiscussionAction) -> DiscussionCommand {
    DiscussionCommand {
        number: DiscussionNumber::try_new(number).unwrap(),
        expected_version: if version == 0 {
            ExpectedVersion::NewStream
        } else {
            ExpectedVersion::Exactly(AggregateVersion::try_new(version).unwrap())
        },
        action,
    }
}
fn opening(number: u64) -> DiscussionCommand {
    command(
        number,
        0,
        DiscussionAction::Open {
            title: format!("Design {number}"),
            body: "Native discussion é\n<script>untrusted</script>".into(),
        },
    )
}
type Outcome = Result<(TxId, TerminalOutcome), NodeReceiveTransportRefusal>;
fn apply(node: &OneNode, value: &DiscussionCommand, key: &str) -> Outcome {
    node.runtime().block_on(node.admit_discussion_durable_in(
        &node.request_context(),
        &session(key),
        value,
        AdmissionLimits::default(),
    ))
}
fn committed(value: Outcome) -> (TxId, TerminalOutcome) {
    let value = value.unwrap();
    assert!(
        matches!(value.1.outcome, DecisionOutcome::Committed { .. }),
        "{value:?}"
    );
    value
}
fn refused(value: Outcome, expected: RefusalCode) -> (TxId, TerminalOutcome) {
    let value = value.unwrap();
    assert!(
        matches!(value.1.outcome, DecisionOutcome::Refused { code, .. } if code == expected),
        "{value:?}"
    );
    value
}
fn history(
    node: &OneNode,
    number: u64,
    head: Option<RepositoryAuthorityHeadId>,
) -> fgit_admission::merge::native::discussions::DiscussionHistoryPage {
    node.runtime()
        .block_on(node.read_discussion_history_in(
            &node.request_context(),
            DiscussionNumber::try_new(number).unwrap(),
            0,
            100,
            head,
        ))
        .unwrap()
}

#[test]
fn lifecycle_retained_pages_and_original_terminals_survive_fresh_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = scratch.node(format);
        let before = node
            .runtime()
            .block_on(node.materialize_admission_in(&node.request_context()))
            .unwrap();
        let issue = IssueCommand {
            number: IssueNumber::try_new(7).unwrap(),
            expected_version: ExpectedVersion::NewStream,
            action: IssueAction::Open {
                title: "Separate issue".into(),
                body: String::new(),
                labels: Vec::new(),
            },
        };
        committed(node.runtime().block_on(node.admit_issue_durable_in(
            &node.request_context(),
            &session("issue-seven"),
            &issue,
            AdmissionLimits::default(),
        )));
        let open = opening(7);
        let original = committed(apply(&node, &open, "discussion-open"));
        let comment = command(
            7,
            1,
            DiscussionAction::Comment {
                body: "first response".into(),
            },
        );
        let original_comment = committed(apply(&node, &comment, "first-comment"));
        let pinned = history(&node, 7, None);
        assert_eq!(pinned.discussion.as_ref().unwrap().comments, 1);
        committed(apply(
            &node,
            &command(
                7,
                2,
                DiscussionAction::Edit(DiscussionEdit {
                    title: Some("Revised design".into()),
                    body: Some("updated body".into()),
                }),
            ),
            "edit",
        ));
        committed(apply(
            &node,
            &command(7, 3, DiscussionAction::Close),
            "close",
        ));
        committed(apply(
            &node,
            &command(
                7,
                4,
                DiscussionAction::Comment {
                    body: "closed still discusses".into(),
                },
            ),
            "closed-comment",
        ));
        committed(apply(
            &node,
            &command(7, 5, DiscussionAction::Reopen),
            "reopen",
        ));
        committed(apply(&node, &command(7, 6, DiscussionAction::Lock), "lock"));
        let blocked = command(
            7,
            7,
            DiscussionAction::Comment {
                body: "blocked".into(),
            },
        );
        let denied = refused(
            apply(&node, &blocked, "blocked-comment"),
            RefusalCode::ProtectedRefTransitionDenied,
        );
        refused(
            apply(&node, &command(7, 1, DiscussionAction::Close), "stale"),
            RefusalCode::EvidenceStale,
        );
        committed(apply(
            &node,
            &command(7, 7, DiscussionAction::Unlock),
            "unlock",
        ));
        committed(apply(
            &node,
            &command(
                7,
                8,
                DiscussionAction::Comment {
                    body: "allowed again".into(),
                },
            ),
            "last-comment",
        ));
        assert_eq!(apply(&node, &blocked, "blocked-comment").unwrap(), denied);
        assert_eq!(apply(&node, &open, "discussion-open").unwrap(), original);
        assert_eq!(
            apply(&node, &comment, "first-comment").unwrap(),
            original_comment
        );
        assert_eq!(history(&node, 7, Some(pinned.source_head)), pinned);
        let suffix = node
            .runtime()
            .block_on(node.read_discussion_history_in(
                &node.request_context(),
                DiscussionNumber::try_new(7).unwrap(),
                1,
                1,
                Some(pinned.source_head),
            ))
            .unwrap();
        assert_eq!(suffix.events.len(), 1);
        assert_eq!(suffix.events[0].version.get(), 2);
        assert_eq!(suffix.next_after, None);
        let current = history(&node, 7, None);
        let state = current.discussion.as_ref().unwrap();
        assert_eq!(
            (state.version.get(), state.comments, state.locked),
            (9, 3, false)
        );
        assert_eq!(state.state, DiscussionState::Open);
        assert_eq!(state.title, "Revised design");
        let issue_state = node
            .runtime()
            .block_on(node.read_issue_history_in(
                &node.request_context(),
                IssueNumber::try_new(7).unwrap(),
                0,
                10,
                None,
            ))
            .unwrap()
            .issue
            .unwrap();
        assert_eq!(issue_state.title, "Separate issue");
        assert_eq!(issue_state.version.get(), 1);
        let after = node
            .runtime()
            .block_on(node.materialize_admission_in(&node.request_context()))
            .unwrap();
        assert_eq!(before.snapshot().refs, after.snapshot().refs);
        assert_eq!(
            before.basis().body().ref_root,
            after.basis().body().ref_root
        );
        assert_eq!(
            before.basis().body().policy_epoch,
            after.basis().body().policy_epoch
        );
        assert_eq!(
            before.selected_closure().closure(),
            after.selected_closure().closure()
        );
        let mut changed = open.clone();
        changed.action = DiscussionAction::Open {
            title: "Changed retry".into(),
            body: String::new(),
        };
        assert!(apply(&node, &changed, "discussion-open").is_err());
        node.shutdown().unwrap();

        // A fresh configuration retains no admission cache or run-local data.
        let mut reopened = OneNode::open_existing(scratch.config(format)).unwrap();
        assert_eq!(
            apply(&reopened, &open, "discussion-open").unwrap(),
            original
        );
        assert_eq!(
            apply(&reopened, &blocked, "blocked-comment").unwrap(),
            denied
        );
        assert!(apply(&reopened, &opening(8), "new-while-stopped").is_err());
        let generation = reopened
            .runtime()
            .block_on(reopened.authenticate_authority_head())
            .unwrap()
            .receipt()
            .generation();
        reopened.bring_into_service(generation).unwrap();
        assert_eq!(history(&reopened, 7, None), current);
        assert_eq!(history(&reopened, 7, Some(pinned.source_head)), pinned);
        committed(apply(&reopened, &opening(42), "second-discussion"));
        let first = reopened
            .runtime()
            .block_on(reopened.read_discussions_in(&reopened.request_context(), 0, 1, None))
            .unwrap();
        assert_eq!(first.discussions[0].number.get(), 7);
        assert_eq!(first.next_after, Some(7));
        committed(apply(&reopened, &opening(13), "between-pages"));
        let second = reopened
            .runtime()
            .block_on(reopened.read_discussions_in(
                &reopened.request_context(),
                7,
                1,
                Some(first.source_head),
            ))
            .unwrap();
        assert_eq!(second.discussions[0].number.get(), 42);
        assert_eq!(second.next_after, None);
        reopened.shutdown().unwrap();
    }
}

#[test]
fn missing_stale_cancelled_and_unpinned_operations_refuse_without_mutating_state() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = scratch.node(format);
        assert!(history(&node, 9, None).discussion.is_none());
        let missing = command(9, 1, DiscussionAction::Close);
        let refusal = refused(
            apply(&node, &missing, "missing"),
            RefusalCode::EvidenceStale,
        );
        committed(apply(&node, &opening(9), "open-later"));
        assert_eq!(apply(&node, &missing, "missing").unwrap(), refusal);
        let stable = history(&node, 9, None);
        assert!(matches!(
            node.runtime().block_on(node.admit_discussion_durable_in(
                &node.request_context(),
                &LoopbackReceiveSession::anonymous(),
                &opening(10),
                AdmissionLimits::default(),
            )),
            Err(NodeReceiveTransportRefusal::Unauthenticated)
        ));
        let cancelled = node.request_context();
        cancelled.cancel();
        assert!(
            node.runtime()
                .block_on(node.admit_discussion_durable_in(
                    &cancelled,
                    &session("cancelled"),
                    &opening(10),
                    AdmissionLimits::default()
                ))
                .is_err()
        );
        assert!(
            node.runtime()
                .block_on(node.read_discussions_in(&cancelled, 0, 10, None))
                .is_err()
        );
        assert!(matches!(
            node.runtime()
                .block_on(node.read_discussions_in(&node.request_context(), 9, 10, None)),
            Err(DiscussionReadRefusal::SnapshotRequired)
        ));
        for limit in [0, 101] {
            assert!(matches!(
                node.runtime().block_on(node.read_discussions_in(
                    &node.request_context(),
                    0,
                    limit,
                    None
                )),
                Err(DiscussionReadRefusal::InvalidLimit)
            ));
        }
        assert_eq!(history(&node, 9, None), stable);
        node.shutdown().unwrap();
    }
}
