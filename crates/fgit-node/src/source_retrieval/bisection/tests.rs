use super::*;
use crate::{LoopbackReceiveSession, NodeConfig};
use fgit_admission::AdmissionLimits;
use fgit_authority::{IdempotencyKey, TerminalOutcome};
use fgit_forge::event::issue::{IssueAction, IssueCommand};
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData};
use fgit_forge::{AggregateVersion, ExpectedVersion};
use fgit_types::{DecisionOutcome, HeadGeneration, PrincipalId};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fg-native-bisect-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn config(&self, format: GitHashAlgorithm) -> NodeConfig {
        NodeConfig::new(
            self.0.join("node"),
            TenantId::from_bytes([0x41; 16]),
            RepositoryId::from_bytes([0x42; 16]),
        )
        .with_object_format(format)
        .with_worker_threads(2)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn node(scratch: &Scratch, format: GitHashAlgorithm) -> OneNode {
    let (mut node, _) = OneNode::init(scratch.config(format)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    node
}
fn session(key: &str) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(
        PrincipalId::from_bytes([0x43; 16]),
        IdempotencyKey::new(key.as_bytes().to_vec()).unwrap(),
    )
}
fn seq(n: u64) -> DecisionSequence {
    DecisionSequence::try_new(n).unwrap()
}
fn command(version: u64, action: IssueAction) -> IssueCommand {
    IssueCommand {
        number: IssueNumber::FIRST,
        expected_version: if version == 0 {
            ExpectedVersion::NewStream
        } else {
            ExpectedVersion::Exactly(AggregateVersion::try_new(version).unwrap())
        },
        action,
    }
}
fn open() -> IssueAction {
    IssueAction::Open {
        title: "actual native history".into(),
        body: "not an executable predicate".into(),
        labels: Vec::new(),
    }
}
fn apply(node: &OneNode, version: u64, action: IssueAction) -> TerminalOutcome {
    let request = node.command_request_context(None);
    let result = node
        .runtime()
        .block_on(node.admit_issue_durable_in(
            &request,
            &session(&format!("issue-{version}")),
            &command(version, action),
            AdmissionLimits::default(),
        ))
        .unwrap();
    assert!(matches!(
        result.1.outcome,
        DecisionOutcome::Committed { .. }
    ));
    result.1
}
fn search(node: &OneNode, query: &Query) -> Result<Report, Error> {
    let request = node.command_request_context(None);
    node.runtime()
        .block_on(node.bisect_forge_trusted_local_in(&request, query))
}
fn json_digest(text: &str) -> String {
    let (prefix, tail) = text.rsplit_once(",\"receipt_sha256\":\"").unwrap();
    let input = format!("{prefix}}}");
    let digest = fgit_crypto::sha256_digest(input.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    assert_eq!(tail, format!("{digest}\"}}"));
    digest
}

#[test]
fn real_issue_transitions_find_first_closed_state_and_survive_cold_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = node(&scratch, format);
        apply(&node, 0, open());
        let closed = apply(&node, 1, IssueAction::Close);
        apply(&node, 2, IssueAction::Reopen);
        apply(&node, 3, IssueAction::Close);
        let query = Query::new(
            seq(1),
            Predicate::IssueState {
                number: IssueNumber::FIRST,
                state: IssueState::Closed,
            },
        );
        let report = search(&node, &query).unwrap();
        assert!(report.matched());
        assert_eq!(
            report.search.transition_found,
            Some(closed.decision_sequence)
        );
        assert_eq!(report.history_events, 4);
        assert_eq!(report.history_batches, 4);
        assert_eq!(report.search.steps_taken, 2);
        let encoded = report.to_json();
        json_digest(&encoded);
        assert_eq!(search(&node, &query).unwrap().to_json(), encoded);
        let mut bounded = query.clone();
        bounded.max_probes = 1;
        let refused = search(&node, &bounded).unwrap();
        assert!(!refused.complete());
        assert!(refused.search.transition_found.is_none());
        assert!(refused.to_json().contains("probe_budget_exhausted"));
        let mut later = query.clone();
        later.start = seq(3);
        assert_eq!(
            search(&node, &later).unwrap().search.transition_found,
            Some(seq(4))
        );
        let absent = Query::new(
            seq(1),
            Predicate::IssueState {
                number: IssueNumber::try_new(2).unwrap(),
                state: IssueState::Closed,
            },
        );
        let missing = search(&node, &absent).unwrap();
        assert!(missing.complete());
        assert!(!missing.matched());
        assert_eq!(missing.search.steps_taken, 4);
        let mut pinned = query.clone();
        pinned.expected_head = Some(report.source_head);
        let pinned_report = search(&node, &pinned).unwrap();
        assert_ne!(json_digest(&pinned_report.to_json()), json_digest(&encoded));
        let mut changed = report.clone();
        changed.incarnation = RepositoryIncarnationId::from_bytes([0x89; 16]);
        assert_ne!(json_digest(&changed.to_json()), json_digest(&encoded));
        node.shutdown().unwrap();
        let reopened = OneNode::open_existing(scratch.config(format)).unwrap();
        assert_eq!(search(&reopened, &query).unwrap().to_json(), encoded);
        reopened.shutdown().unwrap();
    }
}

#[test]
fn actual_head_movement_and_stopped_contexts_refuse_without_new_decisions() {
    let scratch = Scratch::new();
    let node = node(&scratch, GitHashAlgorithm::Sha256);
    apply(&node, 0, open());
    let mut query = Query::new(
        seq(1),
        Predicate::IssueState {
            number: IssueNumber::FIRST,
            state: IssueState::Open,
        },
    );
    let before = search(&node, &query).unwrap();
    apply(&node, 1, IssueAction::Close);
    let request = node.command_request_context(None);
    assert_eq!(
        node.runtime()
            .block_on(node.revalidate_bisection_in(&request, before.source_head))
            .unwrap_err()
            .code,
        "snapshot_changed"
    );
    query.expected_head = Some(before.source_head);
    assert_eq!(search(&node, &query).unwrap_err().code, "snapshot_changed");
    query.expected_head = None;
    let request = node.command_request_context(None);
    request.cancel();
    assert_eq!(
        node.runtime()
            .block_on(node.bisect_forge_trusted_local_in(&request, &query))
            .unwrap_err()
            .code,
        "request_stopped"
    );
    query.end = Some(seq(3));
    assert_eq!(search(&node, &query).unwrap_err().code, "missing_position");
    query.end = None;
    let current = search(&node, &query).unwrap();
    assert_eq!(current.history_batches, 2);
    assert_eq!(current.search.range.end(), seq(2));
    node.shutdown().unwrap();
}

fn loose(
    root: &Path,
    format: GitHashAlgorithm,
    kind: fgit_git_object::ObjectType,
    body: &[u8],
) -> GitOid {
    let id = fgit_crypto::git_object_id(format, kind, body);
    let text = id.to_string();
    let path = root.join("objects").join(&text[..2]).join(&text[2..]);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut raw = format!("{} {}\0", kind.label(), body.len()).into_bytes();
    raw.extend(body);
    let n = u16::try_from(raw.len()).unwrap();
    let mut bytes = vec![0x78, 0x01, 0x01];
    bytes.extend(n.to_le_bytes());
    bytes.extend((!n).to_le_bytes());
    bytes.extend(&raw);
    let (mut a, mut b) = (1_u32, 0_u32);
    for byte in raw {
        a = (a + u32::from(byte)) % 65521;
        b = (b + a) % 65521;
    }
    bytes.extend(((b << 16) | a).to_be_bytes());
    fs::write(path, bytes).unwrap();
    id
}
fn import(node: &OneNode, root: &Path, format: GitHashAlgorithm) -> GitOid {
    use fgit_git_object::ObjectType;
    let blob = loose(root, format, ObjectType::Blob, b"bisection fixture\n");
    let tree = loose(
        root,
        format,
        ObjectType::Tree,
        &[b"100644 file\0".as_slice(), blob.as_bytes()].concat(),
    );
    let commit = loose(root, format, ObjectType::Commit, format!("tree {tree}\nauthor Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n\nfixture\n").as_bytes());
    fs::create_dir_all(root.join("refs/heads")).unwrap();
    fs::write(root.join("refs/heads/main"), format!("{commit}\n")).unwrap();
    fs::write(root.join("refs/heads/topic"), format!("{commit}\n")).unwrap();
    fs::write(root.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
    let request = node.import_request_context(None);
    let receipt = node
        .runtime()
        .block_on(node.import_loose_git_directory_durable_in(
            &request,
            root,
            PrincipalId::from_bytes([0x43; 16]),
            b"bisect-ref-import",
        ))
        .unwrap();
    assert!(!receipt.commands.is_empty());
    assert!(
        receipt
            .commands
            .iter()
            .all(|command| matches!(command.terminal.outcome, DecisionOutcome::Committed { .. }))
    );
    commit
}

#[test]
fn real_ref_and_native_pull_lifecycle_do_not_use_legacy_digest_projection() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = node(&scratch, format);
        apply(&node, 0, open());
        let source = scratch.0.join("source");
        let tip = import(&node, &source, format);
        let data = PullRequestData {
            source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
            target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
            source_tip: tip,
            target_tip: tip,
            title: "native, not legacy".into(),
            body: String::new(),
        };
        let mut closed = None;
        for (version, action) in [
            (0, PullRequestAction::Open),
            (1, PullRequestAction::Close),
            (2, PullRequestAction::Reopen),
        ] {
            let command = PullRequestCommand {
                number: PullRequestNumber::FIRST,
                expected_version: if version == 0 {
                    ExpectedVersion::NewStream
                } else {
                    ExpectedVersion::Exactly(AggregateVersion::try_new(version).unwrap())
                },
                action,
                data: data.clone(),
            };
            let request = node.command_request_context(None);
            let (_, outcome) = node
                .runtime()
                .block_on(node.admit_pull_request_durable_in(
                    &request,
                    &session(&format!("pull-{version}")),
                    &command,
                    AdmissionLimits::default(),
                ))
                .unwrap();
            assert!(matches!(outcome.outcome, DecisionOutcome::Committed { .. }));
            if action == PullRequestAction::Close {
                closed = Some(outcome.decision_sequence);
            }
        }
        let query = Query::new(
            seq(1),
            Predicate::PullRequestState {
                number: PullRequestNumber::FIRST,
                state: PullState::Closed,
            },
        );
        assert_eq!(
            search(&node, &query).unwrap().search.transition_found,
            closed
        );
        let reference = Query::new(
            seq(1),
            Predicate::RefEquals {
                name: data.target_ref.clone(),
                target: tip,
            },
        );
        let found = search(&node, &reference).unwrap();
        assert!(found.matched());
        assert_eq!(found.search.steps_taken, 2);
        let absent = Query::new(
            seq(1),
            Predicate::RefAbsent {
                name: data.target_ref,
            },
        );
        assert_eq!(
            search(&node, &absent).unwrap().search.transition_found,
            Some(seq(1))
        );
        let policy = Query::new(seq(1), Predicate::PolicyAtLeast(PolicyEpoch::FIRST));
        let epoch = search(&node, &policy).unwrap();
        assert!(epoch.matched());
        assert!(matches!(
            epoch.search.monotonicity_shape,
            MonotonicityShape::GuaranteedMonotone { .. }
        ));
        let wrong = Query::new(
            seq(1),
            Predicate::RefEquals {
                name: RefName::try_new(b"refs/heads/main").unwrap(),
                target: GitOid::from_hex(
                    if format == GitHashAlgorithm::Sha1 {
                        GitHashAlgorithm::Sha256
                    } else {
                        GitHashAlgorithm::Sha1
                    },
                    &"1".repeat(if format == GitHashAlgorithm::Sha1 {
                        64
                    } else {
                        40
                    }),
                )
                .unwrap(),
            },
        );
        assert_eq!(search(&node, &wrong).unwrap_err().code, "object_format");
        fs::remove_dir_all(source).unwrap();
        node.shutdown().unwrap();
        let reopened = OneNode::open_existing(scratch.config(format)).unwrap();
        assert_eq!(
            search(&reopened, &query).unwrap().search.transition_found,
            closed
        );
        reopened.shutdown().unwrap();
    }
}
