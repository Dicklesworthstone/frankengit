//! Real file-backed nodes, imported native histories and native candidate packs.
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::event::NativeMerge;
use fgit_forge::preparation::{MergeMetadata, MergePreparation};
use fgit_node::{NodeConfig, OneNode};
use fgit_pack::{CanonicalObjectSource, CanonicalPackObject, PackLimits, PackPlanner, PackWriteError, PackWriteProfile, PackWriter};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid, PrincipalId, RefName,
    RepositoryAuthorityHeadId, RepositoryId, TenantId};

pub const TENANT: TenantId = TenantId::from_bytes([0x71; 16]);
pub const REPOSITORY: RepositoryId = RepositoryId::from_bytes([0x72; 16]);
pub const OWNER: PrincipalId = PrincipalId::from_bytes([0x73; 16]);
pub const WORKFLOW: &str = "name: merge-check\non: push\njobs:\n  a:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: test \"$(cat left)\" = target && test \"$(cat right)\" = source || exit 7; printf merged; printf temporary > job-only\n  b:\n    runs-on: fgit-trusted-local\n    needs: a\n    steps:\n      - run: test ! -e job-only && test \"$(cat left)\" = target && test \"$(cat right)\" = source || exit 8; printf fresh\n";
static NEXT: AtomicU64 = AtomicU64::new(0);
pub struct Fixture {
    pub root: PathBuf, pub node: Option<OneNode>, pub config: NodeConfig,
    pub base: GitOid, pub target: GitOid, pub source: GitOid, pub workflow: GitOid,
    pub genesis: RepositoryAuthorityHeadId,
}
impl Fixture {
    pub fn new(format: GitHashAlgorithm, workflow_text: &str) -> Self {
        let root = loop {
            let path = std::env::temp_dir().join(format!("fg-merge-workflow-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
            match fs::create_dir(&path) {
                Ok(()) => break path,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => panic!("fixture: {e}"),
            }
        };
        fs::create_dir(root.join("runs")).unwrap();
        fs::set_permissions(root.join("runs"), fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.join("source"); fs::create_dir_all(path.join("refs/heads")).unwrap();
        fs::write(path.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        fs::write(path.join("config"), match format {
            GitHashAlgorithm::Sha1 => "[core]\nbare=true\nrepositoryformatversion=0\n",
            GitHashAlgorithm::Sha256 => "[core]\nbare=true\nrepositoryformatversion=1\n[extensions]\nobjectformat=sha256\n",
        }).unwrap();
        let workflow = loose(&path, format, GitObjectKind::Blob, workflow_text.as_bytes());
        let tree = |left: &[u8], right: &[u8]| {
            let a = loose(&path, format, GitObjectKind::Blob, left);
            let b = loose(&path, format, GitObjectKind::Blob, right);
            loose(&path, format, GitObjectKind::Tree, &tree_bytes(a, b, workflow))
        };
        let base = loose(&path, format, GitObjectKind::Commit, &commit_bytes(tree(b"base\n", b"base\n"), &[], "base"));
        let target = loose(&path, format, GitObjectKind::Commit, &commit_bytes(tree(b"target\n", b"base\n"), &[base], "target"));
        let source = loose(&path, format, GitObjectKind::Commit, &commit_bytes(tree(b"base\n", b"source\n"), &[base], "source"));
        fs::write(path.join("refs/heads/main"), format!("{target}\n")).unwrap();
        fs::write(path.join("refs/heads/topic"), format!("{source}\n")).unwrap();
        let config = NodeConfig::new(root.join("node"), TENANT, REPOSITORY).with_object_format(format).with_worker_threads(2);
        let (mut node, _) = OneNode::init(config.clone()).unwrap();
        let head = node.runtime().block_on(node.authenticate_authority_head()).unwrap();
        node.bring_into_service(head.receipt().generation()).unwrap();
        let genesis = node.runtime().block_on(node.materialize_admission()).unwrap().basis().id();
        let imported = node.runtime().block_on(node.import_loose_git_directory_durable_in(&node.request_context(), &path, OWNER, b"merge-workflow-fixture")).unwrap();
        assert!(imported.commands.iter().all(|row| matches!(row.terminal.outcome, DecisionOutcome::Committed { .. })));
        Self { root, node: Some(node), config, base, target, source, workflow, genesis }
    }
    pub fn node(&self) -> &OneNode { self.node.as_ref().unwrap() }
    pub fn parent(&self) -> PathBuf { self.root.join("runs") }
    pub fn reopen(&mut self) {
        if let Some(node) = self.node.take() { node.shutdown().unwrap(); }
        let mut node = OneNode::open_existing(self.config.clone()).unwrap();
        let head = node.runtime().block_on(node.authenticate_authority_head()).unwrap();
        node.bring_into_service(head.receipt().generation()).unwrap(); self.node = Some(node);
    }
    pub fn prepared(&self) -> (NativeMerge, Vec<u8>) {
        let prepared = self.node().runtime().block_on(self.node().prepare_merge_bundle_in(&self.node().request_context(),
            &target_ref(), &source_ref(), &Default::default(), &MergeMetadata { author: "Test <t@example.invalid>".into(),
                committer: "Test <t@example.invalid>".into(), timestamp: 9, message: b"merge candidate\n".to_vec() }, Default::default())).unwrap();
        let MergePreparation::Clean(plan) = prepared.outcome else { panic!("clean fixture"); };
        (self.coordinates(plan.commit), prepared.bundle.unwrap())
    }
    pub fn coordinates(&self, candidate: GitOid) -> NativeMerge {
        NativeMerge { target_ref: target_ref(), target_tip_before: self.target, source_ref: source_ref(),
            source_tip: self.source, base_tip: self.base, merge_commit: candidate }
    }
    /// Caller-chosen actual merge bytes: deliberately not the automatic planner.
    pub fn custom(&self, workflow: &str, parents: &[GitOid]) -> (NativeMerge, Vec<u8>) {
        let format = self.target.algorithm(); let mut objects = Objects(BTreeMap::new());
        let left = objects.put(format, GitObjectKind::Blob, b"target\n".to_vec());
        let right = objects.put(format, GitObjectKind::Blob, b"source\n".to_vec());
        let workflow = objects.put(format, GitObjectKind::Blob, workflow.as_bytes().to_vec());
        let tree = objects.put(format, GitObjectKind::Tree, tree_bytes(left, right, workflow));
        let candidate = objects.put(format, GitObjectKind::Commit, commit_bytes(tree, parents, "reviewed custom merge"));
        let limits = PackLimits::default(); let ids = objects.0.keys().copied().collect::<Vec<_>>();
        let plan = PackPlanner::new(format, PackWriteProfile::COMPRESSED_NO_DELTA_V1, limits.clone())
            .plan_selected(&objects, &ids, &mut || true).unwrap();
        let (pack, _) = PackWriter::new(limits).write(&plan, &mut || true).unwrap();
        let mut bundle = match format {
            GitHashAlgorithm::Sha1 => b"# v2 git bundle\n".to_vec(),
            GitHashAlgorithm::Sha256 => b"# v3 git bundle\n@object-format=sha256\n".to_vec(),
        };
        bundle.extend_from_slice(format!("-{} target\n-{} source\n{candidate} refs/heads/main\n\n", self.target, self.source).as_bytes());
        bundle.extend_from_slice(&pack); (self.coordinates(candidate), bundle)
    }
}
impl Drop for Fixture { fn drop(&mut self) { if let Some(node) = self.node.take() { let _ = node.shutdown(); } let _ = fs::remove_dir_all(&self.root); } }
pub fn target_ref() -> RefName { RefName::try_new(b"refs/heads/main").unwrap() }
pub fn source_ref() -> RefName { RefName::try_new(b"refs/heads/topic").unwrap() }
pub fn inputs() -> Vec<Vec<u8>> { vec![b"left".to_vec(), b"right".to_vec(), b"workflow.yml".to_vec()] }
pub fn generation(node: &OneNode) -> u64 { node.runtime().block_on(node.authenticate_authority_head()).unwrap().receipt().generation().get() }
fn tree_bytes(left: GitOid, right: GitOid, workflow: GitOid) -> Vec<u8> {
    [b"100644 left\0".as_slice(), left.as_bytes(), b"100644 right\0", right.as_bytes(), b"100644 workflow.yml\0", workflow.as_bytes()].concat()
}
fn commit_bytes(tree: GitOid, parents: &[GitOid], message: &str) -> Vec<u8> {
    let mut body = format!("tree {tree}\n");
    for parent in parents { body.push_str(&format!("parent {parent}\n")); }
    body.push_str(&format!("author Test <t@example.invalid> 1 +0000\ncommitter Test <t@example.invalid> 2 +0000\n\n{message}\n")); body.into_bytes()
}
fn loose(root: &Path, format: GitHashAlgorithm, kind: GitObjectKind, body: &[u8]) -> GitOid {
    let id = git_object_id(format, kind, body);
    let raw = [format!("{} {}\0", kind.label(), body.len()).as_bytes(), body].concat();
    let n = u16::try_from(raw.len()).unwrap(); let mut bytes = vec![0x78, 0x01, 0x01];
    bytes.extend(n.to_le_bytes()); bytes.extend((!n).to_le_bytes()); bytes.extend(&raw);
    let (a, b) = raw.iter().fold((1_u32, 0_u32), |(a, b), byte| { let a = (a + u32::from(*byte)) % 65521; (a, (b + a) % 65521) });
    bytes.extend(((b << 16) | a).to_be_bytes()); let text = id.to_string();
    fs::create_dir_all(root.join("objects").join(&text[..2])).unwrap();
    fs::write(root.join("objects").join(&text[..2]).join(&text[2..]), bytes).unwrap(); id
}
struct Objects(BTreeMap<GitOid, (GitObjectKind, Vec<u8>)>);
impl Objects {
    fn put(&mut self, format: GitHashAlgorithm, kind: GitObjectKind, body: Vec<u8>) -> GitOid {
        let id = git_object_id(format, kind, &body); self.0.insert(id, (kind, body)); id
    }
}
impl CanonicalObjectSource for Objects {
    fn load(&self, id: &GitOid) -> Result<CanonicalPackObject, PackWriteError> {
        let (kind, body) = self.0.get(id).ok_or(PackWriteError::MissingCanonicalObject(*id))?;
        Ok(CanonicalPackObject::new(*id, *kind, body.clone(), Vec::new(), 0, 0))
    }
}
