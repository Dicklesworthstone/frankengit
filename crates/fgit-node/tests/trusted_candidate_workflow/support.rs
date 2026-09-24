//! Real imported source and native patch candidates shared by node/CLI tests.
//! No alternate workflow, pack, authority or publication implementation.
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::preparation::MergeMetadata;
use fgit_node::{NodeConfig, OneNode, WorkspacePatchCandidate};
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, GitOid, PrincipalId, RefName, RepositoryId, TenantId,
};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
pub const TENANT: TenantId = TenantId::from_bytes([0x41; 16]);
pub const REPOSITORY: RepositoryId = RepositoryId::from_bytes([0x42; 16]);
pub const PRINCIPAL: PrincipalId = PrincipalId::from_bytes([0x43; 16]);
pub struct Fixture {
    pub root: PathBuf,
    pub node: Option<OneNode>,
    pub config: NodeConfig,
    pub tip: GitOid,
    pub workflow: GitOid,
}
impl Fixture {
    pub fn new(format: GitHashAlgorithm, workflow: &str) -> Self {
        let root = loop {
            let path = std::env::temp_dir().join(format!(
                "fg-candidate-workflow-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&path) {
                Ok(()) => break path,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => panic!("fixture directory: {e}"),
            }
        };
        fs::create_dir(root.join("runs")).unwrap();
        fs::set_permissions(root.join("runs"), fs::Permissions::from_mode(0o700)).unwrap();
        let source = root.join("source");
        fs::create_dir_all(source.join("refs/heads")).unwrap();
        fs::write(source.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
        fs::write(source.join("config"), match format {
            GitHashAlgorithm::Sha1 => "[core]\nrepositoryformatversion=0\nbare=true\n",
            GitHashAlgorithm::Sha256 => "[core]\nrepositoryformatversion=1\nbare=true\n[extensions]\nobjectformat=sha256\n",
        }).unwrap();
        let workflow = loose(&source, format, GitObjectKind::Blob, workflow.as_bytes());
        let input = loose(&source, format, GitObjectKind::Blob, b"original\n");
        let tree = loose(
            &source,
            format,
            GitObjectKind::Tree,
            &[
                b"100644 input.txt\0".as_slice(),
                input.as_bytes(),
                b"100644 workflow.yml\0",
                workflow.as_bytes(),
            ]
            .concat(),
        );
        let body = format!(
            "tree {tree}\nauthor Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\nbase workflow inputs\n"
        );
        let tip = loose(&source, format, GitObjectKind::Commit, body.as_bytes());
        fs::write(source.join("refs/heads/main"), format!("{tip}\n")).unwrap();
        let config = NodeConfig::new(root.join("node"), TENANT, REPOSITORY)
            .with_object_format(format)
            .with_worker_threads(2);
        let (mut node, _) = OneNode::init(config.clone()).unwrap();
        serve(&mut node);
        let result = node
            .runtime()
            .block_on(node.import_loose_git_directory_durable_in(
                &node.request_context(),
                &source,
                PRINCIPAL,
                b"candidate-workflow-fixture",
            ))
            .unwrap();
        assert!(
            result
                .commands
                .iter()
                .all(|c| matches!(c.terminal.outcome, DecisionOutcome::Committed { .. }))
        );
        Self {
            root,
            node: Some(node),
            config,
            tip,
            workflow,
        }
    }
    pub const fn node(&self) -> &OneNode {
        self.node.as_ref().unwrap()
    }
    pub fn parent(&self) -> PathBuf {
        self.root.join("runs")
    }
    pub fn reopen(&mut self) {
        if let Some(node) = self.node.take() {
            node.shutdown().unwrap();
        }
        let mut node = OneNode::open_existing(self.config.clone()).unwrap();
        serve(&mut node);
        self.node = Some(node);
    }
    /// Generate actual transport using the production patch and bundle engines.
    pub fn replace_file(&self, path: &str, before: &str, after: &str) -> WorkspacePatchCandidate {
        assert!(before.ends_with('\n') && after.ends_with('\n'));
        let mut patch = format!(
            "diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -1,{} +1,{} @@\n",
            before.lines().count(),
            after.lines().count()
        );
        for line in before.lines() {
            patch.push('-');
            patch.push_str(line);
            patch.push('\n');
        }
        for line in after.lines() {
            patch.push('+');
            patch.push_str(line);
            patch.push('\n');
        }
        let metadata = MergeMetadata {
            author: "Fixture <fixture@example.invalid>".into(),
            committer: "Fixture <fixture@example.invalid>".into(),
            timestamp: 2,
            message: b"candidate workflow inputs\n".to_vec(),
        };
        self.node()
            .runtime()
            .block_on(self.node().prepare_trusted_patch_in(
                &self.node().request_context(),
                &reference(),
                self.tip,
                [7; 16],
                patch.as_bytes(),
                &metadata,
                Default::default(),
            ))
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(node) = self.node.take() {
            let _ = node.shutdown();
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn serve(node: &mut OneNode) {
    let head = node
        .runtime()
        .block_on(node.authenticate_authority_head())
        .unwrap();
    node.bring_into_service(head.receipt().generation())
        .unwrap();
}
pub fn generation(node: &OneNode) -> u64 {
    node.runtime()
        .block_on(node.authenticate_authority_head())
        .unwrap()
        .receipt()
        .generation()
        .get()
}
pub fn reference() -> RefName {
    RefName::try_new(b"refs/heads/main").unwrap()
}
pub fn inputs() -> Vec<Vec<u8>> {
    vec![b"workflow.yml".to_vec(), b"input.txt".to_vec()]
}
fn loose(root: &Path, format: GitHashAlgorithm, kind: GitObjectKind, body: &[u8]) -> GitOid {
    let id = git_object_id(format, kind, body);
    let bytes = [
        format!("{} {}\0", kind.label(), body.len()).as_bytes(),
        body,
    ]
    .concat();
    let n = u16::try_from(bytes.len()).unwrap();
    let mut z = vec![0x78, 0x01, 0x01];
    z.extend(n.to_le_bytes());
    z.extend((!n).to_le_bytes());
    z.extend(&bytes);
    let (a, b) = bytes.iter().fold((1_u32, 0_u32), |(a, b), byte| {
        let a = (a + u32::from(*byte)) % 65521;
        (a, (b + a) % 65521)
    });
    z.extend(((b << 16) | a).to_be_bytes());
    let hex = id.to_string();
    let dir = root.join("objects").join(&hex[..2]);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join(&hex[2..]), z).unwrap();
    id
}
