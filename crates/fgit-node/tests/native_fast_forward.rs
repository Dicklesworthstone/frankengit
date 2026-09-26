#![forbid(unsafe_code)]
//! Actual file-backed node/admission tests; no subprocess Git or mock authority.
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_admission::merge::native::{NativeMergeIntent, objects::MergeObjectLimits};
use fgit_admission::merge::native::pull_request::PullRequestPage;
use fgit_authority::{IdempotencyKey, TerminalOutcome};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::event::protection::{ProtectedBranch, ProtectionCommand, ReviewProtection};
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData};
use fgit_forge::{AggregateVersion, ExpectedVersion, ForgeEventPayload, PullRequestNumber};
use fgit_node::{LoopbackReceiveSession, NodeConfig, NodeReceiveTransportRefusal, OneNode};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid, HeadGeneration, PolicyEpoch, PrincipalId, RefName, RefusalCode, RepositoryId, TenantId};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("fgit-fast-forward-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch { fn drop(&mut self) { fs::remove_dir_all(&self.0).unwrap(); } }
fn actor(n: u8) -> PrincipalId { PrincipalId::from_bytes([n; 16]) }
fn session(who: u8, key: &[u8]) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(actor(who), IdempotencyKey::new(key.to_vec()).unwrap())
}
fn main_ref() -> RefName { RefName::try_new(b"refs/heads/main").unwrap() }
fn topic_ref() -> RefName { RefName::try_new(b"refs/heads/topic").unwrap() }
fn config(root: &Path, format: GitHashAlgorithm) -> NodeConfig {
    NodeConfig::new(root.join("node"), TenantId::from_bytes([0xe1; 16]), RepositoryId::from_bytes([0xe2; 16])).with_object_format(format)
}
fn loose(root: &Path, format: GitHashAlgorithm, kind: GitObjectKind, label: &str, body: &[u8]) -> GitOid {
    let id = git_object_id(format, kind, body);
    let raw = [format!("{label} {}\0", body.len()).as_bytes(), body].concat();
    let length = u16::try_from(raw.len()).unwrap();
    let mut zlib = vec![0x78, 0x01, 0x01];
    zlib.extend(length.to_le_bytes()); zlib.extend((!length).to_le_bytes()); zlib.extend(&raw);
    let (a, b) = raw.iter().fold((1_u32, 0_u32), |(a, b), byte| { let a = (a + u32::from(*byte)) % 65_521; (a, (b + a) % 65_521) });
    zlib.extend(((b << 16) | a).to_be_bytes());
    let name = id.to_string(); let directory = root.join("objects").join(&name[..2]);
    fs::create_dir_all(&directory).unwrap(); fs::write(directory.join(&name[2..]), zlib).unwrap(); id
}
fn commit(tree: GitOid, parents: &[GitOid], message: &str) -> Vec<u8> {
    let mut body = format!("tree {tree}\n");
    for parent in parents { body.push_str(&format!("parent {parent}\n")); }
    body.push_str("author Fixture <test@example.invalid> 1 +0000\ncommitter Fixture <test@example.invalid> 1 +0000\n\n");
    body.push_str(message); body.into_bytes()
}
struct Fixture { node: OneNode, tree: GitOid, target: GitOid, source: GitOid, data: PullRequestData }
fn fixture(root: &Path, format: GitHashAlgorithm, divergent: bool) -> Fixture {
    let (mut node, _) = OneNode::init(config(root, format)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let path = root.join("source"); fs::create_dir_all(path.join("refs/heads")).unwrap();
    fs::write(path.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
    fs::write(path.join("config"), match format {
        GitHashAlgorithm::Sha1 => "[core]\nrepositoryformatversion = 0\nbare = true\n",
        GitHashAlgorithm::Sha256 => "[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n",
    }).unwrap();
    let tree = loose(&path, format, GitObjectKind::Tree, "tree", b"");
    let base = loose(&path, format, GitObjectKind::Commit, "commit", &commit(tree, &[], "base\n"));
    let target = loose(&path, format, GitObjectKind::Commit, "commit", &commit(tree, &[base], "target\n"));
    let source = loose(&path, format, GitObjectKind::Commit, "commit", &commit(tree, &[if divergent { base } else { target }], "topic\n"));
    fs::write(path.join("refs/heads/main"), format!("{target}\n")).unwrap();
    fs::write(path.join("refs/heads/topic"), format!("{source}\n")).unwrap();
    let request = node.request_context();
    let imported = node.runtime().block_on(node.import_loose_git_directory_durable_in(&request, &path, actor(1), b"fixture-import")).unwrap();
    assert_eq!(imported.commands.len(), 2);
    for command in imported.commands { committed(command.terminal); }
    let data = PullRequestData { source_ref: topic_ref(), target_ref: main_ref(), source_tip: source, target_tip: target, title: "Fast-forward PR".into(), body: "Preserve exact existing source history.".into() };
    let command = PullRequestCommand { number: PullRequestNumber::FIRST, expected_version: ExpectedVersion::NewStream, action: PullRequestAction::Open, data: data.clone() };
    let request = node.request_context();
    let (_, opened) = node.runtime().block_on(node.admit_pull_request_durable_in(&request, &session(1, b"open-pr"), &command, Default::default())).unwrap();
    committed(opened);
    Fixture { node, tree, target, source, data }
}
fn intent(f: &Fixture) -> NativeMergeIntent {
    NativeMergeIntent::fast_forward_only(PullRequestNumber::FIRST, AggregateVersion::FIRST, topic_ref(), f.source, main_ref(), f.target).unwrap()
}
fn apply(node: &OneNode, intent: &NativeMergeIntent, key: &[u8], limits: MergeObjectLimits) -> Result<TerminalOutcome, NodeReceiveTransportRefusal> {
    let request = node.request_context();
    node.runtime().block_on(node.admit_native_merge_durable_in(&request, &session(2, key), intent, Default::default(), limits))
}
fn committed(outcome: TerminalOutcome) -> TerminalOutcome {
    assert!(matches!(outcome.outcome, DecisionOutcome::Committed { .. }), "{outcome:?}"); outcome
}
fn denied(outcome: TerminalOutcome, code: RefusalCode) -> TerminalOutcome {
    assert!(matches!(outcome.outcome, DecisionOutcome::Refused { code: actual, .. } if actual == code), "{outcome:?}"); outcome
}
fn refs(node: &OneNode) -> BTreeMap<RefName, GitOid> {
    let request = node.request_context();
    node.runtime().block_on(node.materialize_admission_in(&request)).unwrap().snapshot().refs.clone()
}
fn page(node: &OneNode) -> PullRequestPage {
    let request = node.request_context();
    node.runtime().block_on(node.read_pull_requests_in(&request, &Default::default(), 0, 10, None)).unwrap()
}

#[test]
fn ff_publishes_existing_tip_pr_and_outbox_atomically_then_recovers_after_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new(); let mut f = fixture(&scratch.0, format, false);
        let offered = intent(&f); let request = f.node.request_context();
        let before = f.node.runtime().block_on(f.node.materialize_admission_in(&request)).unwrap();
        let source_body = f.node.read_git_object(f.source).unwrap().payload().to_vec();
        let terminal = committed(apply(&f.node, &offered, b"ff-one", Default::default()).unwrap());
        let request = f.node.request_context();
        let after = f.node.runtime().block_on(f.node.materialize_admission_in(&request)).unwrap();
        assert_eq!(after.snapshot().refs[&main_ref()], f.source);
        assert_eq!(after.snapshot().refs[&topic_ref()], f.source);
        assert_eq!(after.snapshot().head_target, before.snapshot().head_target);
        assert_eq!(after.selected_closure().closure(), before.selected_closure().closure(), "no objects are created or newly admitted");
        assert_eq!(after.snapshot().outbox.len(), before.snapshot().outbox.len() + 1);
        assert_ne!(after.basis().body().forge_position_root, before.basis().body().forge_position_root);
        assert_eq!(after.basis().body().retention_root, before.basis().body().retention_root);
        let history = f.node.runtime().block_on(f.node.snapshot_history_in(&request)).unwrap();
        let last = history.last().unwrap();
        assert_eq!(last.batch.committed_rcrs.len(), 1);
        assert_eq!(last.forge_events, vec![offered.event().clone()]);
        let record = &last.batch.committed_rcrs[0];
        assert_eq!(record.resulting_ref_root, after.basis().body().ref_root);
        assert_eq!(record.resulting_forge_position_root, after.basis().body().forge_position_root);
        let row = page(&f.node).pull_requests.remove(0);
        assert_eq!(row.event, *offered.event());
        assert_eq!(row.data, Some(f.data.clone()));
        assert_eq!(row.opened_by, Some(actor(1)));
        assert_eq!(f.node.read_git_object(f.source).unwrap().payload(), source_body);
        let selected_head = after.basis().id();
        f.node.shutdown().unwrap();
        let mut reopened = OneNode::open_existing(config(&scratch.0, format)).unwrap();
        reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
        assert_eq!(apply(&reopened, &offered, b"ff-one", Default::default()).unwrap(), terminal);
        assert_eq!(page(&reopened).source_head, selected_head, "retry cannot append another decision or delivery");
        assert_eq!(refs(&reopened)[&main_ref()], f.source);
        reopened.shutdown().unwrap();
    }
}

#[test]
fn divergent_history_is_a_recoverable_terminal_refusal_not_a_synthesized_merge() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new(); let mut f = fixture(&scratch.0, format, true);
        let offered = intent(&f); let before = refs(&f.node);
        let terminal = denied(apply(&f.node, &offered, b"divergent", Default::default()).unwrap(), RefusalCode::NonFastForwardRefused);
        assert_eq!(refs(&f.node), before);
        assert!(matches!(page(&f.node).pull_requests[0].event.payload, ForgeEventPayload::PullRequestChangedNative(_)));
        assert_eq!(apply(&f.node, &offered, b"divergent", Default::default()).unwrap(), terminal);
        f.node.shutdown().unwrap();
    }
}

#[test]
fn versions_source_selection_and_legacy_method_are_not_bypassed() {
    let scratch = Scratch::new(); let mut f = fixture(&scratch.0, GitHashAlgorithm::Sha1, false);
    let offered = intent(&f); let before = refs(&f.node);
    let stale_version = NativeMergeIntent::fast_forward_only(PullRequestNumber::FIRST, AggregateVersion::try_new(2).unwrap(), topic_ref(), f.source, main_ref(), f.target).unwrap();
    denied(apply(&f.node, &stale_version, b"stale-version", Default::default()).unwrap(), RefusalCode::EvidenceStale);
    let staged = f.node.put_git_object(GitObjectKind::Commit, commit(f.tree, &[f.source], "unpublished source\n")).unwrap().identity();
    let unselected = NativeMergeIntent::fast_forward_only(PullRequestNumber::FIRST, AggregateVersion::FIRST, topic_ref(), staged, main_ref(), f.target).unwrap();
    denied(apply(&f.node, &unselected, b"unselected", Default::default()).unwrap(), RefusalCode::TargetRefMoved);
    let legacy = NativeMergeIntent::new(PullRequestNumber::FIRST, ExpectedVersion::Exactly(AggregateVersion::FIRST), offered.merge().unwrap().clone()).unwrap();
    denied(apply(&f.node, &legacy, b"legacy", Default::default()).unwrap(), RefusalCode::EvidenceInvalid);
    assert_eq!(refs(&f.node), before);
    assert!(apply(&f.node, &offered, b"legacy", Default::default()).is_err(), "a changed method under the old key is rejected");
    committed(apply(&f.node, &offered, b"explicit-ff", Default::default()).unwrap());
    f.node.shutdown().unwrap();
}

#[test]
fn budget_exhaustion_keeps_the_same_seal_retryable() {
    let scratch = Scratch::new(); let mut f = fixture(&scratch.0, GitHashAlgorithm::Sha256, false);
    let offered = intent(&f); let before = refs(&f.node);
    assert!(apply(&f.node, &offered, b"bounded", MergeObjectLimits { max_objects: 1, ..Default::default() }).is_err());
    assert_eq!(refs(&f.node), before);
    committed(apply(&f.node, &offered, b"bounded", Default::default()).unwrap());
    f.node.shutdown().unwrap();
}

#[test]
fn fast_forward_does_not_bypass_mandatory_reviews() {
    let scratch = Scratch::new(); let mut f = fixture(&scratch.0, GitHashAlgorithm::Sha1, false);
    let command = ProtectionCommand {
        expected_version: ExpectedVersion::NewStream, expected_epoch: PolicyEpoch::FIRST,
        protection: ReviewProtection { administrators: vec![actor(1)], branches: vec![ProtectedBranch { name: main_ref(), reviewers: vec![actor(3)] }] },
    };
    let request = f.node.request_context();
    let (_, activated) = f.node.runtime().block_on(f.node.admit_review_protection_durable_in(&request, &session(1, b"activate"), &command, Default::default())).unwrap();
    committed(activated);
    let before = refs(&f.node);
    let terminal = apply(&f.node, &intent(&f), b"missing-approval", Default::default()).unwrap();
    assert!(matches!(terminal.outcome, DecisionOutcome::Refused { .. }), "{terminal:?}");
    assert_eq!(refs(&f.node), before);
    f.node.shutdown().unwrap();
}
