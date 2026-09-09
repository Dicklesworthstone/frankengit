//! Original node composition against file-backed authority, without Git or a
//! substitute in-memory repository. Imports and all lifecycle calls are real.

use super::*;
use fgit_admission::merge::native::{NativeMergeIntent, objects::MergeObjectLimits};
use fgit_authority::IdempotencyKey;
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::aggregate::{AggregateVersion, ExpectedVersion, PullRequestNumber};
use fgit_forge::event::{ForgeEventPayload, NativeMerge};
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestData};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, HeadGeneration, PrincipalId, RefName, RepositoryId, TenantId};
use crate::{MaterializedAdmission, NodeConfig};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("fgit-native-pr-{}-{}",
            std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&path).unwrap(); Self(path)
    }
    fn config(&self, format: GitHashAlgorithm) -> NodeConfig {
        NodeConfig::new(self.0.join("node"), TenantId::from_bytes([0xb1; 16]),
            RepositoryId::from_bytes([0xb2; 16])).with_object_format(format).with_worker_threads(2)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) { fs::remove_dir_all(&self.0).unwrap(); }
}
fn principal() -> PrincipalId { PrincipalId::from_bytes([0xb3; 16]) }
fn target() -> RefName { RefName::try_new(b"refs/heads/main").unwrap() }
fn source_ref() -> RefName { RefName::try_new(b"refs/heads/topic").unwrap() }
fn session(key: &str) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(principal(), IdempotencyKey::new(key.as_bytes().to_vec()).unwrap())
}
fn commit(tree: GitOid, parents: &[GitOid], label: &str) -> Vec<u8> {
    let mut body = format!("tree {tree}\n");
    for parent in parents { body.push_str(&format!("parent {parent}\n")); }
    body.push_str("author Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\n");
    body.push_str(label); body.push('\n'); body.into_bytes()
}
fn loose(root: &Path, format: GitHashAlgorithm, kind: GitObjectKind, label: &str, body: &[u8]) -> GitOid {
    let id = git_object_id(format, kind, body);
    let raw = [format!("{label} {}\0", body.len()).as_bytes(), body].concat();
    let length = u16::try_from(raw.len()).unwrap();
    let mut encoded = vec![0x78, 0x01, 0x01];
    encoded.extend(length.to_le_bytes()); encoded.extend((!length).to_le_bytes()); encoded.extend(&raw);
    let (a, b) = raw.iter().fold((1_u32, 0_u32), |(a, b), value| {
        let next = (a + u32::from(*value)) % 65_521; (next, (b + next) % 65_521)
    });
    encoded.extend(((b << 16) | a).to_be_bytes());
    let hex = id.to_string(); let directory = root.join("objects").join(&hex[..2]);
    fs::create_dir_all(&directory).unwrap(); fs::write(directory.join(&hex[2..]), encoded).unwrap(); id
}
struct Fixture { base: GitOid, tree: GitOid, data: PullRequestData }
fn fixture(node: &OneNode, scratch: &Scratch, format: GitHashAlgorithm) -> Fixture {
    let root = scratch.0.join("source"); fs::create_dir_all(root.join("refs/heads")).unwrap();
    fs::write(root.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
    fs::write(root.join("config"), match format {
        GitHashAlgorithm::Sha1 => "[core]\nrepositoryformatversion = 0\nbare = true\n",
        GitHashAlgorithm::Sha256 => "[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n",
    }).unwrap();
    let blob = loose(&root, format, GitObjectKind::Blob, "blob", b"unchanged content\n");
    let tree = loose(&root, format, GitObjectKind::Tree, "tree",
        &[b"100644 file.txt\0".as_slice(), blob.as_bytes()].concat());
    let base = loose(&root, format, GitObjectKind::Commit, "commit", &commit(tree, &[], "base"));
    let ours = loose(&root, format, GitObjectKind::Commit, "commit", &commit(tree, &[base], "target"));
    let theirs = loose(&root, format, GitObjectKind::Commit, "commit", &commit(tree, &[base], "source"));
    fs::write(root.join("refs/heads/main"), format!("{ours}\n")).unwrap();
    fs::write(root.join("refs/heads/topic"), format!("{theirs}\n")).unwrap();
    let request = node.request_context();
    let imported = node.runtime().block_on(node.import_loose_git_directory_durable_in(
        &request, &root, principal(), b"pr-fixture-import",
    )).unwrap();
    assert!(imported.commands.iter().all(|command| matches!(command.terminal.outcome, DecisionOutcome::Committed { .. })));
    Fixture { base, tree, data: PullRequestData { source_ref: source_ref(), target_ref: target(),
        source_tip: theirs, target_tip: ours, title: "A native pull request".into(),
        body: "Untrusted <script> content\nUnicode: é\n".into() } }
}
fn node(scratch: &Scratch, format: GitHashAlgorithm) -> OneNode {
    let (mut node, _) = OneNode::init(scratch.config(format)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap(); node
}
fn command(fixture: &Fixture, number: u64) -> PullRequestCommand {
    PullRequestCommand { number: PullRequestNumber::try_new(number).unwrap(),
        expected_version: ExpectedVersion::NewStream, action: PullRequestAction::Open,
        data: fixture.data.clone() }
}
fn apply(node: &OneNode, command: &PullRequestCommand, key: &str) -> Result<(TxId, TerminalOutcome), NodeReceiveTransportRefusal> {
    let request = node.request_context();
    node.runtime().block_on(node.admit_pull_request_durable_in(
        &request, &session(key), command, AdmissionLimits::default(),
    ))
}
fn accepted(result: Result<(TxId, TerminalOutcome), NodeReceiveTransportRefusal>) -> (TxId, TerminalOutcome) {
    let value = result.unwrap(); assert!(matches!(value.1.outcome, DecisionOutcome::Committed { .. }), "{value:?}"); value
}
fn snapshot(node: &OneNode) -> MaterializedAdmission {
    let request = node.request_context(); node.runtime().block_on(node.materialize_admission_in(&request)).unwrap()
}
fn page(node: &OneNode, after: u64, limit: u16, head: Option<RepositoryAuthorityHeadId>) -> Result<PullRequestPage, PullRequestReadRefusal> {
    let request = node.request_context();
    node.runtime().block_on(node.read_pull_requests_in(&request, &RefVisibility::new(), after, limit, head))
}
fn unchanged_code(before: &MaterializedAdmission, after: &MaterializedAdmission) {
    assert_eq!(before.snapshot().refs, after.snapshot().refs);
    assert_eq!(before.snapshot().head_target, after.snapshot().head_target);
    assert_eq!(before.basis().body().ref_root, after.basis().body().ref_root);
    assert_eq!(before.basis().body().retention_root, after.basis().body().retention_root);
    assert_eq!(before.basis().body().policy_epoch, after.basis().body().policy_epoch);
}

#[test]
fn real_open_update_close_and_reopen_preserve_code_and_original_outcomes() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new(); let node = node(&scratch, format); let f = fixture(&node, &scratch, format);
        let open = command(&f, 7); let before = snapshot(&node);
        let opening = accepted(apply(&node, &open, "open")); let opened = snapshot(&node);
        unchanged_code(&before, &opened);
        assert_eq!(opened.basis().generation().get(), before.basis().generation().get() + 1);
        assert_ne!(opened.basis().body().forge_position_root, before.basis().body().forge_position_root);
        assert_ne!(opened.basis().body().outbox_root, before.basis().body().outbox_root);
        assert_eq!(opened.snapshot().outbox.len(), before.snapshot().outbox.len() + 1);
        let rows = page(&node, 0, 100, None).unwrap();
        assert_eq!(rows.pull_requests.len(), 1);
        assert_eq!(rows.pull_requests[0].data, Some(f.data.clone()));
        assert_eq!(rows.pull_requests[0].opened_by, Some(principal()));
        let mut update = open.clone(); update.action = PullRequestAction::Update;
        update.expected_version = ExpectedVersion::Exactly(AggregateVersion::FIRST);
        update.data.title = "Updated title".into();
        accepted(apply(&node, &update, "update"));
        let updated = page(&node, 0, 100, None).unwrap();
        assert_eq!(updated.pull_requests[0].data.as_ref().unwrap().title, "Updated title");
        assert_eq!(updated.pull_requests[0].event.version.get(), 2);
        assert_eq!(updated.pull_requests[0].opened_by, Some(principal()));
        let mut close = update.clone(); close.action = PullRequestAction::Close;
        close.expected_version = ExpectedVersion::Exactly(AggregateVersion::try_new(2).unwrap());
        let closing = accepted(apply(&node, &close, "close"));
        let closed = snapshot(&node); unchanged_code(&before, &closed);
        assert_eq!(apply(&node, &open, "open").unwrap(), opening);
        assert_eq!(apply(&node, &close, "close").unwrap(), closing);
        assert_eq!(snapshot(&node).basis(), closed.basis());
        let request = node.request_context(); let history = node.runtime().block_on(node.snapshot_history_in(&request)).unwrap();
        assert_eq!(history.last().unwrap().batch.committed_rcrs[0].tx_id, closing.0);
        assert!(matches!(&history.last().unwrap().forge_events[0].payload,
            ForgeEventPayload::PullRequestChangedNative(change) if change.action == PullRequestAction::Close));
        node.shutdown().unwrap();
        let mut reopened = OneNode::open_existing(scratch.config(format)).unwrap();
        reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
        let recovered = page(&reopened, 0, 100, None).unwrap();
        assert_eq!(recovered.pull_requests[0].event.version.get(), 3);
        assert_eq!(recovered.pull_requests[0].data, Some(update.data));
        assert_eq!(recovered.pull_requests[0].opened_by, Some(principal()));
        assert_eq!(apply(&reopened, &open, "open").unwrap(), opening);
        assert_eq!(snapshot(&reopened).basis(), closed.basis());
        reopened.shutdown().unwrap();
    }
}

#[test]
fn stale_version_competitor_and_reused_key_cannot_overwrite_or_revive() {
    let scratch = Scratch::new(); let node = node(&scratch, GitHashAlgorithm::Sha1);
    let f = fixture(&node, &scratch, GitHashAlgorithm::Sha1);
    let open = command(&f, 1); accepted(apply(&node, &open, "open"));
    let mut winner = open.clone(); winner.action = PullRequestAction::Update;
    winner.expected_version = ExpectedVersion::Exactly(AggregateVersion::FIRST); winner.data.title = "Winner".into();
    let mut loser = winner.clone(); loser.data.title = "Loser".into();
    accepted(apply(&node, &winner, "winner")); let before = snapshot(&node);
    assert!(apply(&node, &loser, "winner").is_err()); assert_eq!(snapshot(&node).basis(), before.basis());
    let refused = apply(&node, &loser, "loser").unwrap();
    assert!(matches!(refused.1.outcome, DecisionOutcome::Refused { code: RefusalCode::EvidenceStale, .. }));
    let after = snapshot(&node); unchanged_code(&before, &after);
    assert_eq!(before.basis().body().forge_position_root, after.basis().body().forge_position_root);
    assert_eq!(before.basis().body().outbox_root, after.basis().body().outbox_root);
    assert_eq!(apply(&node, &loser, "loser").unwrap(), refused);
    assert_eq!(snapshot(&node).basis(), after.basis());
    let mut close = winner.clone(); close.action = PullRequestAction::Close;
    close.expected_version = ExpectedVersion::Exactly(AggregateVersion::try_new(2).unwrap());
    accepted(apply(&node, &close, "close"));
    let mut resurrection = close.clone(); resurrection.action = PullRequestAction::Update;
    resurrection.expected_version = ExpectedVersion::Exactly(AggregateVersion::try_new(3).unwrap());
    let refused = apply(&node, &resurrection, "resurrection").unwrap();
    assert!(matches!(refused.1.outcome, DecisionOutcome::Refused { code: RefusalCode::ProtectedRefTransitionDenied, .. }));
    assert_eq!(page(&node, 0, 100, None).unwrap().pull_requests[0].data.as_ref().unwrap().title, "Winner");
    node.shutdown().unwrap();
}

#[test]
fn terminal_retries_survive_quota_containment_and_stopped_intake() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new(); let mut node = node(&scratch, format);
        let f = fixture(&node, &scratch, format);
        let open = command(&f, 1);
        let committed = accepted(apply(&node, &open, "original-open"));
        let refused = apply(&node, &open, "stale-open").unwrap();
        assert!(matches!(refused.1.outcome,
            DecisionOutcome::Refused { code: RefusalCode::EvidenceStale, .. }));
        let settled = snapshot(&node);
        let cancelled = node.request_context();
        cancelled.authority().cancel();
        assert!(node.runtime().block_on(node.admit_pull_request_durable_in(
            &cancelled, &session("original-open"), &open, AdmissionLimits::default(),
        )).is_err());
        assert_eq!(apply(&node, &open, "original-open").unwrap(), committed);
        assert_eq!(snapshot(&node).basis(), settled.basis());
        // Deterministic operator containment, with no sleeps or clock races.
        node.push_quota.limit.max_events = 0;
        assert_eq!(apply(&node, &open, "original-open").unwrap(), committed);
        assert_eq!(apply(&node, &open, "stale-open").unwrap(), refused);
        assert!(matches!(apply(&node, &command(&f, 2), "new-open"),
            Err(NodeReceiveTransportRefusal::QuotaContained { .. })));
        let mut changed = open.clone(); changed.data.title = "Different request".into();
        assert!(apply(&node, &changed, "original-open").is_err());
        assert_eq!(snapshot(&node).basis(), settled.basis());
        node.shutdown().unwrap();

        // Reopen without bringing the cell into service: recovery is read-like,
        // but an uncommitted command must still fail the publication gate.
        let reopened = OneNode::open_existing(scratch.config(format)).unwrap();
        assert_eq!(apply(&reopened, &open, "original-open").unwrap(), committed);
        assert_eq!(apply(&reopened, &open, "stale-open").unwrap(), refused);
        assert!(matches!(apply(&reopened, &command(&f, 2), "new-open"),
            Err(NodeReceiveTransportRefusal::CellState(_)
                | NodeReceiveTransportRefusal::StagedWithoutPublication { .. })));
        assert!(apply(&reopened, &changed, "original-open").is_err());
        assert_eq!(snapshot(&reopened).basis(), settled.basis());
        reopened.shutdown().unwrap();
    }
}

#[test]
fn pagination_is_numeric_pinned_and_filters_both_branch_names() {
    let scratch = Scratch::new(); let node = node(&scratch, GitHashAlgorithm::Sha256);
    let f = fixture(&node, &scratch, GitHashAlgorithm::Sha256);
    for number in [10, 2, 1] { accepted(apply(&node, &command(&f, number), &format!("open-{number}"))); }
    let before = snapshot(&node); let first = page(&node, 0, 2, None).unwrap();
    assert_eq!(first.pull_requests.iter().map(|view| view.number.get()).collect::<Vec<_>>(), [1, 2]);
    assert_eq!(first.next_after, Some(2));
    let second = page(&node, 2, 2, Some(first.source_head)).unwrap();
    assert_eq!(second.pull_requests[0].number.get(), 10); assert_eq!(second.next_after, None);
    assert_eq!(page(&node, 10, 2, None).unwrap().pull_requests.len(), 0);
    assert_eq!(snapshot(&node).basis(), before.basis());
    for hidden in [target(), source_ref()] {
        let mut visibility = RefVisibility::new(); visibility.push_rule(hidden.as_bytes(), &Default::default()).unwrap();
        let request = node.request_context();
        let result = node.runtime().block_on(node.read_pull_requests_in(&request, &visibility, 0, 100, None)).unwrap();
        assert!(result.pull_requests.is_empty()); assert_eq!(result.next_after, None);
    }
    accepted(apply(&node, &command(&f, 3), "newer"));
    assert!(matches!(page(&node, 2, 2, Some(first.source_head)), Err(PullRequestReadRefusal::SnapshotMoved)));
    assert!(matches!(page(&node, 0, 0, None), Err(PullRequestReadRefusal::InvalidLimit)));
    node.shutdown().unwrap();
}

#[test]
fn merge_uses_active_pr_coordinates_and_retains_title_and_opener() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new(); let node = node(&scratch, format); let f = fixture(&node, &scratch, format);
        let open = command(&f, 1); accepted(apply(&node, &open, "open-merge"));
        let candidate = node.put_git_object(GitObjectKind::Commit,
            commit(f.tree, &[f.data.target_tip, f.data.source_tip], "reviewed merge")).unwrap().identity();
        let intent = NativeMergeIntent::new(PullRequestNumber::FIRST, ExpectedVersion::Exactly(AggregateVersion::FIRST), NativeMerge {
            source_ref: source_ref(), source_tip: f.data.source_tip, base_tip: f.base,
            target_ref: target(), target_tip_before: f.data.target_tip, merge_commit: candidate,
        }).unwrap();
        let request = node.request_context();
        let terminal = node.runtime().block_on(node.admit_native_merge_durable_in(
            &request, &session("merge"), &intent, AdmissionLimits::default(), MergeObjectLimits::default(),
        )).unwrap();
        assert!(matches!(terminal.outcome, DecisionOutcome::Committed { .. }));
        let result = page(&node, 0, 100, None).unwrap();
        assert_eq!(result.pull_requests[0].data, Some(f.data.clone()));
        assert_eq!(result.pull_requests[0].opened_by, Some(principal()));
        assert!(matches!(&result.pull_requests[0].event.payload,
            ForgeEventPayload::MergeCommittedNative(merge) if merge.merge_commit == candidate));
        let mut mutation = open; mutation.action = PullRequestAction::Update;
        mutation.expected_version = ExpectedVersion::Exactly(AggregateVersion::try_new(2).unwrap());
        let denied = apply(&node, &mutation, "after-merge").unwrap();
        assert!(matches!(denied.1.outcome, DecisionOutcome::Refused { code: RefusalCode::ProtectedRefTransitionDenied, .. }));
        node.shutdown().unwrap();
        let mut reopened = OneNode::open_existing(scratch.config(format)).unwrap();
        reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
        assert_eq!(page(&reopened, 0, 100, None).unwrap().pull_requests, result.pull_requests);
        reopened.shutdown().unwrap();
    }
}

#[test]
fn closed_pr_cannot_authorize_a_merge_and_serving_gate_precedes_mutation() {
    let scratch = Scratch::new();
    let (mut stopped, _) = OneNode::init(scratch.config(GitHashAlgorithm::Sha1)).unwrap();
    stopped.bring_into_service(HeadGeneration::FIRST).unwrap();
    let f = fixture(&stopped, &scratch, GitHashAlgorithm::Sha1);
    let open = command(&f, 1); accepted(apply(&stopped, &open, "open"));
    let mut close = open.clone(); close.action = PullRequestAction::Close;
    close.expected_version = ExpectedVersion::Exactly(AggregateVersion::FIRST);
    accepted(apply(&stopped, &close, "close"));
    let before = snapshot(&stopped);
    let candidate = stopped.put_git_object(GitObjectKind::Commit,
        commit(f.tree, &[f.data.target_tip, f.data.source_tip], "must refuse")).unwrap().identity();
    let intent = NativeMergeIntent::new(open.number, ExpectedVersion::Exactly(AggregateVersion::try_new(2).unwrap()), NativeMerge {
        source_ref: source_ref(), source_tip: f.data.source_tip, base_tip: f.base,
        target_ref: target(), target_tip_before: f.data.target_tip, merge_commit: candidate,
    }).unwrap();
    let request = stopped.request_context();
    let refused = stopped.runtime().block_on(stopped.admit_native_merge_durable_in(
        &request, &session("closed-merge"), &intent, AdmissionLimits::default(), MergeObjectLimits::default(),
    )).unwrap();
    assert!(matches!(refused.outcome, DecisionOutcome::Refused { code: RefusalCode::ProtectedRefTransitionDenied, .. }));
    unchanged_code(&before, &snapshot(&stopped));
    stopped.shutdown().unwrap();
    let unopened = OneNode::open_existing(scratch.config(GitHashAlgorithm::Sha1)).unwrap();
    assert!(apply(&unopened, &command(&f, 9), "unserving").is_err());
    unopened.shutdown().unwrap();
}
