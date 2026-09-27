//! File-backed native fixture shared by the command boundary regressions.
//! Uses the admitted loose-import path, not a Git subprocess or mock authority.
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_authority::{IdempotencyKey, TerminalOutcome};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData};
use fgit_forge::{ExpectedVersion, PullRequestNumber};
use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid, HeadGeneration, PrincipalId, RefName, RepositoryId, TenantId};

static NEXT: AtomicU64 = AtomicU64::new(0);
pub struct Scratch(pub PathBuf);
impl Scratch {
    pub fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "fg-fast-forward-command-{}-{}",
            std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        Self(root)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}
pub fn actor(byte: u8) -> PrincipalId { PrincipalId::from_bytes([byte; 16]) }
pub fn main_ref() -> RefName { RefName::try_new(b"refs/heads/main").unwrap() }
pub fn topic_ref() -> RefName { RefName::try_new(b"refs/heads/topic").unwrap() }
pub fn session(key: &[u8]) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(actor(2), IdempotencyKey::new(key.to_vec()).unwrap())
}
pub fn config(root: &Path, format: GitHashAlgorithm) -> NodeConfig {
    NodeConfig::new(root.join("node"), TenantId::from_bytes([0xe1; 16]), RepositoryId::from_bytes([0xe2; 16]))
        .with_object_format(format)
        .with_worker_threads(2)
}
fn loose(root: &Path, format: GitHashAlgorithm, kind: GitObjectKind, label: &str, body: &[u8]) -> GitOid {
    let oid = git_object_id(format, kind, body);
    let raw = [format!("{label} {}\0", body.len()).as_bytes(), body].concat();
    let length = u16::try_from(raw.len()).unwrap();
    // One RFC 1951 stored block inside a zlib frame, with its actual Adler-32.
    let mut frame = vec![0x78, 0x01, 0x01];
    frame.extend(length.to_le_bytes());
    frame.extend((!length).to_le_bytes());
    frame.extend(&raw);
    let (a, b) = raw.iter().fold((1_u32, 0_u32), |(a, b), byte| {
        let a = (a + u32::from(*byte)) % 65_521;
        (a, (b + a) % 65_521)
    });
    frame.extend(((b << 16) | a).to_be_bytes());
    let name = oid.to_string();
    let directory = root.join("objects").join(&name[..2]);
    fs::create_dir_all(&directory).unwrap();
    fs::write(directory.join(&name[2..]), frame).unwrap();
    oid
}
fn body(tree: GitOid, parents: &[GitOid], message: &str) -> Vec<u8> {
    let mut out = format!("tree {tree}\n");
    for parent in parents { out.push_str(&format!("parent {parent}\n")); }
    out.push_str("author Fixture <test@example.invalid> 1 +0000\ncommitter Fixture <test@example.invalid> 1 +0000\n\n");
    out.push_str(message);
    out.into_bytes()
}
pub fn committed(terminal: TerminalOutcome) -> TerminalOutcome {
    assert!(matches!(terminal.outcome, DecisionOutcome::Committed { .. }), "{terminal:?}");
    terminal
}
pub struct Fixture {
    pub node: OneNode,
    pub target: GitOid,
    pub source: GitOid,
}
pub fn fixture(root: &Path, format: GitHashAlgorithm, divergent: bool) -> Fixture {
    let (mut node, _) = OneNode::init(config(root, format)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let path = root.join("source");
    fs::create_dir_all(path.join("refs/heads")).unwrap();
    fs::write(path.join("HEAD"), "ref: refs/heads/main\n").unwrap();
    fs::write(path.join("config"), match format {
        GitHashAlgorithm::Sha1 => "[core]\nrepositoryformatversion = 0\nbare = true\n",
        GitHashAlgorithm::Sha256 => "[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n",
    }).unwrap();
    let tree = loose(&path, format, GitObjectKind::Tree, "tree", b"");
    let base = loose(&path, format, GitObjectKind::Commit, "commit", &body(tree, &[], "base\n"));
    let target = loose(&path, format, GitObjectKind::Commit, "commit", &body(tree, &[base], "target\n"));
    let source = loose(&path, format, GitObjectKind::Commit, "commit", &body(tree, &[if divergent { base } else { target }], "source\n"));
    fs::write(path.join("refs/heads/main"), format!("{target}\n")).unwrap();
    fs::write(path.join("refs/heads/topic"), format!("{source}\n")).unwrap();
    let request = node.request_context();
    let imported = node.runtime().block_on(node.import_loose_git_directory_durable_in(
        &request, &path, actor(1), b"fixture-import"
    )).unwrap();
    assert_eq!(imported.commands.len(), 2);
    for command in imported.commands { committed(command.terminal); }
    let command = PullRequestCommand {
        number: PullRequestNumber::FIRST,
        expected_version: ExpectedVersion::NewStream,
        action: PullRequestAction::Open,
        data: PullRequestData {
            source_ref: topic_ref(), target_ref: main_ref(),
            source_tip: source, target_tip: target,
            title: "Keep source history".into(), body: "Do not manufacture a merge commit.".into(),
        },
    };
    let request = node.request_context();
    let opener = LoopbackReceiveSession::authenticated(actor(1), IdempotencyKey::new(b"open-pr".to_vec()).unwrap());
    committed(node.runtime().block_on(node.admit_pull_request_durable_in(
        &request, &opener, &command, Default::default()
    )).unwrap().1);
    Fixture { node, target, source }
}
