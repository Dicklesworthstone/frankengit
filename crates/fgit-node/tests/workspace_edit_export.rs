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

#[cfg(target_os = "linux")]
fn private_parent(fixture: &Fixture) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let parent = fixture.root.join("private-workspaces");
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    parent
}

#[cfg(target_os = "linux")]
#[test]
fn trusted_tool_reads_sparse_inputs_and_exports_an_exact_native_commit() {
    use std::process::Command;
    use std::time::Duration;
    let fixture = Fixture::new();
    let parent = private_parent(&fixture);
    let node = fixture.node();
    let request = node.request_context();
    let reads = vec![b"edit.txt".to_vec(), b"new.txt".to_vec()];
    let writes = reads.clone();
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "test ! -e keep.txt && printf 'after\n' > edit.txt && printf 'new\n' > new.txt && chmod 755 new.txt"]);
    let result = node.runtime().block_on(node.run_trusted_workspace_tool_in(
        &request, &reference(), [0x85; 16], &parent, &reads, &writes,
        &mut command, Duration::from_secs(10), ("Test <test@example.invalid>", 1, b"tool candidate\n"),
    )).unwrap();
    let edit = git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, b"after\n");
    let new = git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, b"new\n");
    let expected_tree = git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Tree, &[
        b"100644 edit.txt\0".as_slice(), edit.as_bytes(),
        b"100644 keep.txt\0".as_slice(), fixture.untouched.as_bytes(),
        b"100755 new.txt\0".as_slice(), new.as_bytes(),
    ].concat());
    assert_eq!(result.root_tree, expected_tree);
    let expected_commit = git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Commit,
        format!("tree {expected_tree}\nparent {}\nauthor Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n\ntool candidate\n", fixture.commit).as_bytes());
    assert_eq!(result.candidate_commit, expected_commit);
    assert_eq!(result.source_commit, fixture.commit);
    assert_eq!(result.changed_paths, writes);
    assert_eq!(result.object_count, 4);
    assert_eq!(&result.pack_bytes()[..4], b"PACK");
    assert_eq!(u32::from_be_bytes(result.pack_bytes()[8..12].try_into().unwrap()), 4);
    assert_eq!(fs::read_dir(&parent).unwrap().count(), 0, "workspace lease reaped");
    let current = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
    assert_eq!(current.snapshot().refs[&reference()], fixture.commit, "candidate did not publish");
}

#[cfg(target_os = "linux")]
#[test]
fn tool_failure_and_undeclared_input_changes_clean_up_without_candidates() {
    use std::process::Command;
    use std::time::Duration;
    let fixture = Fixture::new();
    let parent = private_parent(&fixture);
    let node = fixture.node();
    let request = node.request_context();
    for script in ["exit 7", "printf forbidden > keep.txt"] {
        let mut command = Command::new("/bin/sh"); command.args(["-c", script]);
        let result = node.runtime().block_on(node.run_trusted_workspace_tool_in(
            &request, &reference(), [0x86; 16], &parent,
            &[b"edit.txt".to_vec(), b"keep.txt".to_vec()], &[b"edit.txt".to_vec()],
            &mut command, Duration::from_secs(10), ("Test <test@example.invalid>", 1, b"refused\n"),
        ));
        assert!(result.is_err());
        assert_eq!(fs::read_dir(&parent).unwrap().count(), 0);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn timed_out_tool_reports_retained_workspace_instead_of_claiming_descendant_cleanup() {
    use std::process::Command;
    use std::time::Duration;
    let fixture = Fixture::new();
    let parent = private_parent(&fixture);
    let node = fixture.node();
    let request = node.request_context();
    let mut command = Command::new("/bin/sleep"); command.arg("10");
    let error = node.runtime().block_on(node.run_trusted_workspace_tool_in(
        &request, &reference(), [0x87; 16], &parent,
        &[b"edit.txt".to_vec()], &[b"edit.txt".to_vec()], &mut command,
        Duration::from_secs(2), ("Test <test@example.invalid>", 1, b"timeout\n"),
    )).unwrap_err();
    assert!(error.retained_workspace().expect("containment path survives final checks").is_dir());
}
