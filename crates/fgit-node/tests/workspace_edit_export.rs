#![forbid(unsafe_code)]
//! Real embedded authority -> typed edits -> native object export.

use fgit_crypto::{GitObjectKind, NativeObjectIdentity, Sha1, git_object_id};
use fgit_node::{NodeConfig, NodeWorkspaceRefusal, OneNode};
use fgit_treefs::{
    EntryClass, ExportLimits, FileMode, IntentLog, TreeCapability, TreeEditIntent, TreePath,
    WorkspaceId,
};
use fgit_types::numeric::HeadGeneration;
use fgit_types::{GitHashAlgorithm, GitOid, PrincipalId, RefName, RepositoryId, TenantId};
use fgit_wire::WireLimits;
use fgit_wire::visibility::RefVisibility;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
const REPOSITORY: RepositoryId = RepositoryId::from_bytes([0x82; 16]);

struct Fixture {
    root: PathBuf,
    node: Option<OneNode>,
    commit: GitOid,
    untouched: GitOid,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "fgit-workspace-export-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let source = root.join("source");
        fs::create_dir_all(source.join("refs/heads")).unwrap();
        fs::write(source.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
        let edit = loose(&source, GitObjectKind::Blob, "blob", b"before\n");
        let untouched = loose(&source, GitObjectKind::Blob, "blob", b"must survive\n");
        let tree_body = [
            b"100644 edit.txt\0".as_slice(), edit.as_bytes(),
            b"100644 keep.txt\0".as_slice(), untouched.as_bytes(),
        ].concat();
        let tree = loose(&source, GitObjectKind::Tree, "tree", &tree_body);
        let commit = loose(&source, GitObjectKind::Commit, "commit", format!(
            "tree {tree}\nauthor Test <test@example.invalid> 0 +0000\ncommitter Test <test@example.invalid> 0 +0000\n\nsource\n"
        ).as_bytes());
        fs::write(source.join("refs/heads/main"), format!("{commit}\n")).unwrap();
        let (mut node, _) = OneNode::init(NodeConfig::new(
            root.join("node"), TenantId::from_bytes([0x81; 16]), REPOSITORY,
        )).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let request = node.request_context();
        node.runtime().block_on(node.import_loose_git_directory_durable_in(
            &request, &source, PrincipalId::from_bytes([0x83; 16]), b"edit-export-source",
        )).unwrap();
        Self { root, node: Some(node), commit, untouched }
    }
    fn node(&self) -> &OneNode { self.node.as_ref().unwrap() }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.node.take().unwrap().shutdown().unwrap();
        fs::remove_dir_all(&self.root).unwrap();
    }
}
fn loose(root: &Path, kind: GitObjectKind, label: &str, body: &[u8]) -> GitOid {
    let oid = git_object_id(GitHashAlgorithm::Sha1, kind, body);
    let raw = [format!("{label} {}\0", body.len()).as_bytes(), body].concat();
    let length = u16::try_from(raw.len()).unwrap();
    let mut encoded = vec![0x78, 0x01, 0x01];
    encoded.extend(length.to_le_bytes());
    encoded.extend((!length).to_le_bytes());
    encoded.extend(&raw);
    let (a, b) = raw.iter().fold((1u32, 0u32), |(a, b), byte| {
        let a = (a + u32::from(*byte)) % 65521;
        (a, (b + a) % 65521)
    });
    encoded.extend(((b << 16) | a).to_be_bytes());
    let hex = oid.to_string();
    let directory = root.join("objects").join(&hex[..2]);
    fs::create_dir_all(&directory).unwrap();
    fs::write(directory.join(&hex[2..]), encoded).unwrap();
    oid
}
fn path(name: &str) -> TreePath { TreePath::parse_default(name.as_bytes()).unwrap() }
fn capability(complete: bool) -> TreeCapability {
    let mut reads = vec![path("edit.txt")];
    if complete { reads.push(path("keep.txt")); }
    TreeCapability::new(WorkspaceId::from_bytes([0x84; 16]), REPOSITORY, reads, vec![path("edit.txt")])
}
fn edit() -> IntentLog {
    let mut log = IntentLog::new();
    log.push(TreeEditIntent::Write {
        path: path("edit.txt"), content: b"after\n".to_vec(),
        mode: FileMode::Executable, entry_class: EntryClass::Content,
    });
    log
}
fn reference() -> RefName { RefName::try_new(b"refs/heads/main").unwrap() }

#[test]
fn exported_edit_preserves_unmodified_files_and_publishes_no_ref() {
    let fixture = Fixture::new();
    let node = fixture.node();
    let request = node.request_context();
    let export = node.runtime().block_on(node.export_workspace_edits_in::<Sha1>(
        &request, &reference(), fixture.commit, &RefVisibility::new(),
        &mut capability(true), &edit(), 0, ExportLimits::default(),
    )).unwrap();
    assert!(export.plan.verify_all());
    assert_eq!(export.source_commit.digest_bytes(), fixture.commit.as_bytes());
    assert_eq!(export.changed_paths, vec![path("edit.txt")]);
    assert_eq!(export.plan.object_count(), 2, "only the new blob and root tree");
    let root = export.plan.get(export.plan.root_tree()).unwrap().body();
    assert!(root.windows(b"100755 edit.txt\0".len()).any(|w| w == b"100755 edit.txt\0"));
    assert!(root.windows(b"100644 keep.txt\0".len()).any(|w| w == b"100644 keep.txt\0"));
    assert!(root.ends_with(fixture.untouched.as_bytes()), "untouched identity must survive");
    let current = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
    assert_eq!(current.snapshot().refs[&reference()], fixture.commit);
}

#[test]
fn incomplete_export_scope_refuses_instead_of_deleting_hidden_siblings() {
    let fixture = Fixture::new();
    let node = fixture.node();
    let request = node.request_context();
    let result = node.runtime().block_on(node.export_workspace_edits_in::<Sha1>(
        &request, &reference(), fixture.commit, &RefVisibility::new(),
        &mut capability(false), &edit(), 0, ExportLimits::default(),
    ));
    assert!(matches!(result, Err(NodeWorkspaceRefusal::IncompleteWorkspaceExportScope)));
    let permitted = node.runtime().block_on(node.export_workspace_edits_in::<Sha1>(
        &request, &reference(), fixture.commit, &RefVisibility::new(),
        &mut capability(true), &edit(), 0, ExportLimits::default(),
    ));
    assert!(permitted.is_ok());
}

#[test]
fn stale_hidden_and_over_budget_exports_never_produce_candidates() {
    let fixture = Fixture::new();
    let node = fixture.node();
    let request = node.request_context();
    let stale = node.runtime().block_on(node.export_workspace_edits_in::<Sha1>(
        &request, &reference(), fixture.untouched, &RefVisibility::new(),
        &mut capability(true), &edit(), 0, ExportLimits::default(),
    ));
    assert!(matches!(stale, Err(NodeWorkspaceRefusal::StaleWorkspaceBase)));
    let mut visibility = RefVisibility::new();
    visibility.push_rule(b"refs/heads/main", &WireLimits::default()).unwrap();
    let hidden = node.runtime().block_on(node.export_workspace_edits_in::<Sha1>(
        &request, &reference(), fixture.commit, &visibility,
        &mut capability(true), &edit(), 0, ExportLimits::default(),
    ));
    assert!(matches!(hidden, Err(NodeWorkspaceRefusal::RefUnavailable)));
    let limited = node.runtime().block_on(node.export_workspace_edits_in::<Sha1>(
        &request, &reference(), fixture.commit, &RefVisibility::new(),
        &mut capability(true), &edit(), 0, ExportLimits { max_total_bytes: 1, ..ExportLimits::default() },
    ));
    assert!(matches!(limited, Err(NodeWorkspaceRefusal::WorkspaceEditLimit)));
}
