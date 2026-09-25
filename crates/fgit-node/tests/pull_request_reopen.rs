//! Reopen through the public node API and file-backed authority. No Git subprocess
//! or in-memory substitute. These tests must run to establish executable evidence.
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_admission::merge::native::pull_request::PullRequestPage;
use fgit_authority::{IdempotencyKey, TerminalOutcome};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData};
use fgit_forge::{AggregateVersion, ExpectedVersion, ForgeEventPayload, PullRequestNumber};
use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode};
use fgit_types::{
    DecisionOutcome, Digest, GitHashAlgorithm, GitOid, HeadGeneration, PrincipalId,
    RefName, RefusalCode, RepositoryAuthorityHeadId, RepositoryId, TenantId, TxId,
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "fgit-reopen-api-{}-{}-{}", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&root).unwrap();
        Self(root)
    }
    fn config(&self, format: GitHashAlgorithm) -> NodeConfig {
        NodeConfig::new(self.0.join("node"), TenantId::from_bytes([1; 16]), RepositoryId::from_bytes([2; 16]))
            .with_object_format(format).with_worker_threads(2)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) { fs::remove_dir_all(&self.0).unwrap(); }
}
fn actor() -> PrincipalId { PrincipalId::from_bytes([3; 16]) }
fn loose(root: &Path, format: GitHashAlgorithm, kind: GitObjectKind, label: &str, body: &[u8]) -> GitOid {
    let id = git_object_id(format, kind, body);
    let raw = [format!("{label} {}\0", body.len()).as_bytes(), body].concat();
    let length = u16::try_from(raw.len()).unwrap();
    let mut encoded = vec![0x78, 0x01, 0x01];
    encoded.extend(length.to_le_bytes());
    encoded.extend((!length).to_le_bytes());
    encoded.extend(&raw);
    let (a, b) = raw.iter().fold((1_u32, 0_u32), |(a, b), value| {
        let next = (a + u32::from(*value)) % 65_521;
        (next, (b + next) % 65_521)
    });
    encoded.extend(((b << 16) | a).to_be_bytes());
    let hex = id.to_string();
    let dir = root.join("objects").join(&hex[..2]);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join(&hex[2..]), encoded).unwrap();
    id
}
fn initialize(scratch: &Scratch, format: GitHashAlgorithm) -> (OneNode, PullRequestCommand) {
    let (mut node, _) = OneNode::init(scratch.config(format)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let root = scratch.0.join("source");
    fs::create_dir_all(root.join("refs/heads")).unwrap();
    fs::write(root.join("HEAD"), "ref: refs/heads/main\n").unwrap();
    fs::write(root.join("config"), match format {
        GitHashAlgorithm::Sha1 => "[core]\nrepositoryformatversion = 0\nbare = true\n",
        GitHashAlgorithm::Sha256 => "[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n",
    }).unwrap();
    let tree = loose(&root, format, GitObjectKind::Tree, "tree", b"");
    let make_commit = |label: &str| format!(
        "tree {tree}\nauthor Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\n{label}\n"
    ).into_bytes();
    let target_tip = loose(&root, format, GitObjectKind::Commit, "commit", &make_commit("target"));
    let source_tip = loose(&root, format, GitObjectKind::Commit, "commit", &make_commit("source"));
    fs::write(root.join("refs/heads/main"), format!("{target_tip}\n")).unwrap();
    fs::write(root.join("refs/heads/topic"), format!("{source_tip}\n")).unwrap();
    let request = node.request_context();
    let imported = node.runtime().block_on(node.import_loose_git_directory_durable_in(
        &request, &root, actor(), b"reopen-fixture-import",
    )).unwrap();
    assert!(imported.commands.iter().all(|command| matches!(command.terminal.outcome, DecisionOutcome::Committed { .. })));
    (node, PullRequestCommand {
        number: PullRequestNumber::FIRST, expected_version: ExpectedVersion::NewStream,
        action: PullRequestAction::Open,
        data: PullRequestData {
            source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
            target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
            source_tip, target_tip, title: "Original PR".into(), body: "Original body\né".into(),
        },
    })
}
fn apply(node: &OneNode, command: &PullRequestCommand, principal: PrincipalId, key: &str) -> (TxId, TerminalOutcome) {
    let request = node.request_context();
    let session = LoopbackReceiveSession::authenticated(principal, IdempotencyKey::new(key.as_bytes().to_vec()).unwrap());
    node.runtime().block_on(node.admit_pull_request_durable_in(&request, &session, command, Default::default())).unwrap()
}
fn accepted(value: (TxId, TerminalOutcome)) -> (TxId, TerminalOutcome) {
    assert!(matches!(value.1.outcome, DecisionOutcome::Committed { .. }), "{value:?}");
    value
}
fn page(node: &OneNode) -> PullRequestPage {
    let request = node.request_context();
    node.runtime().block_on(node.read_pull_requests_in(&request, &Default::default(), 0, 100, None)).unwrap()
}
// Source identity, ref root, retention root, forge root, outbox root and count.
fn roots(node: &OneNode) -> (RepositoryAuthorityHeadId, Digest, Digest, Digest, Digest, usize) {
    let request = node.request_context();
    let selected = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
    let head = selected.basis().body();
    (selected.basis().id(), head.ref_root, head.retention_root, head.forge_position_root,
        head.outbox_root, selected.snapshot().outbox.len())
}
fn next(command: &PullRequestCommand, action: PullRequestAction, version: u64) -> PullRequestCommand {
    PullRequestCommand { action, expected_version: ExpectedVersion::Exactly(AggregateVersion::try_new(version).unwrap()), ..command.clone() }
}

#[test]
fn reopening_publishes_metadata_and_outbox_together_and_retries_survive_later_close_and_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (node, open) = initialize(&scratch, format);
        let opening = accepted(apply(&node, &open, actor(), "open"));
        let close = next(&open, PullRequestAction::Close, 1);
        accepted(apply(&node, &close, actor(), "close"));
        let before = roots(&node);
        let resumer = PrincipalId::from_bytes([4; 16]);
        let mut reopen = next(&open, PullRequestAction::Reopen, 2);
        reopen.data.title = "Resumed by another authorized operator".into();
        reopen.data.body = "Revised full metadata\né".into();
        let resumed = accepted(apply(&node, &reopen, resumer, "reopen"));
        let after = roots(&node);
        assert_eq!((before.1, before.2), (after.1, after.2));
        assert_ne!(before.3, after.3);
        assert_ne!(before.4, after.4);
        assert_eq!(after.5, before.5 + 1);
        let rows = page(&node);
        assert_eq!(rows.pull_requests.len(), 1);
        let row = &rows.pull_requests[0];
        assert_eq!(row.event.version.get(), 3);
        assert_eq!(row.data, Some(reopen.data.clone()));
        assert_eq!(row.opened_by, Some(actor()));
        assert_eq!(row.last_metadata_actor, Some(resumer));
        assert!(matches!(&row.event.payload, ForgeEventPayload::PullRequestChangedNative(change) if change.action == PullRequestAction::Reopen));
        assert_eq!(apply(&node, &reopen, resumer, "reopen"), resumed);
        assert_eq!(roots(&node), after);
        let close_again = next(&reopen, PullRequestAction::Close, 3);
        accepted(apply(&node, &close_again, resumer, "close-again"));
        let closed = roots(&node);
        node.shutdown().unwrap();
        let mut reopened_node = OneNode::open_existing(scratch.config(format)).unwrap();
        reopened_node.bring_into_service(HeadGeneration::FIRST).unwrap();
        assert_eq!(apply(&reopened_node, &reopen, resumer, "reopen"), resumed);
        assert_eq!(apply(&reopened_node, &open, actor(), "open"), opening);
        assert_eq!(roots(&reopened_node), closed, "old successful reopen cannot reopen a later closure");
        let recovered = page(&reopened_node);
        let row = &recovered.pull_requests[0];
        assert_eq!(row.event.version.get(), 4);
        assert!(matches!(&row.event.payload, ForgeEventPayload::PullRequestChangedNative(change) if change.action == PullRequestAction::Close));
        reopened_node.shutdown().unwrap();
    }
}

#[test]
fn reopening_refuses_active_stale_retargeted_and_moved_tip_requests_without_new_forge_effects() {
    let scratch = Scratch::new();
    let (node, open) = initialize(&scratch, GitHashAlgorithm::Sha1);
    accepted(apply(&node, &open, actor(), "open"));
    let active_reopen = next(&open, PullRequestAction::Reopen, 1);
    let denied = apply(&node, &active_reopen, actor(), "active");
    assert!(matches!(denied.1.outcome, DecisionOutcome::Refused { code: RefusalCode::ProtectedRefTransitionDenied, .. }));
    accepted(apply(&node, &next(&open, PullRequestAction::Close, 1), actor(), "close"));
    let reopen = next(&open, PullRequestAction::Reopen, 2);
    let mut retarget = reopen.clone();
    retarget.data.target_ref = RefName::try_new(b"refs/heads/other").unwrap();
    let mut moved = reopen.clone();
    moved.data.source_tip = moved.data.target_tip;
    for (key, command, code) in [
        ("retarget", retarget, RefusalCode::ProtectedRefTransitionDenied),
        ("moved", moved, RefusalCode::TargetRefMoved),
    ] {
        let before = roots(&node);
        let refused = apply(&node, &command, actor(), key);
        assert!(matches!(refused.1.outcome, DecisionOutcome::Refused { code: observed, .. } if observed == code));
        let after = roots(&node);
        assert_eq!((before.1, before.2, before.3, before.4, before.5), (after.1, after.2, after.3, after.4, after.5));
        assert_eq!(apply(&node, &command, actor(), key), refused);
        assert_eq!(roots(&node), after);
    }
    accepted(apply(&node, &reopen, actor(), "winner"));
    let before = roots(&node);
    let mut competitor = reopen.clone();
    competitor.data.body.push_str(" different request");
    let refused = apply(&node, &competitor, actor(), "competitor");
    assert!(matches!(refused.1.outcome, DecisionOutcome::Refused { code: RefusalCode::EvidenceStale, .. }));
    let after = roots(&node);
    assert_eq!((before.3, before.4, before.5), (after.3, after.4, after.5));
    assert_eq!(page(&node).pull_requests[0].data, Some(reopen.data));
    node.shutdown().unwrap();
}
