#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]
//! A real authority import followed by the production node -> TreeFS -> host
//! adapter path. No test implementation of TreeFS ObjectSource is involved.

use fgit_crypto::{GitObjectKind, Sha1, Sha256, git_object_id};
use fgit_node::{NodeConfig, NodeWorkspaceRefusal, OneNode};
use fgit_resource::{
    Grade, LeakDisposition, ObligationLedger, RegionCloseOutcome, RegionId, ResourceVector,
};
use fgit_runner::sparse_workspace::{SparseWorkspace, SparseWorkspacePlan};
use fgit_treefs::{SparseLimits, TreeCapability, TreeEditIntent, TreePath, WorkspaceId};
use fgit_types::numeric::HeadGeneration;
use fgit_types::{GitHashAlgorithm, GitOid, PrincipalId, RefName, RepositoryId, TenantId};
use fgit_wire::WireLimits;
use fgit_wire::visibility::RefVisibility;
use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "fgit-node-treefs-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        Self(root)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("owned node test scratch");
    }
}
fn config(root: &Path) -> NodeConfig {
    NodeConfig::new(
        root.join("node"),
        TenantId::from_bytes([0x71; 16]),
        RepositoryId::from_bytes([0x72; 16]),
    )
}
fn cap() -> TreeCapability {
    let p = TreePath::parse_default(b"file.txt").unwrap();
    TreeCapability::new(
        WorkspaceId::from_bytes([0x73; 16]),
        RepositoryId::from_bytes([0x72; 16]),
        vec![p.clone()],
        vec![p],
    )
}
fn reference() -> RefName {
    RefName::try_new(b"refs/heads/main").unwrap()
}
fn loose(root: &Path, kind: GitObjectKind, label: &str, body: &[u8]) -> GitOid {
    let oid = git_object_id(GitHashAlgorithm::Sha1, kind, body);
    let raw = [format!("{label} {}\0", body.len()).as_bytes(), body].concat();
    let length = u16::try_from(raw.len()).unwrap();
    let mut zlib = vec![0x78, 0x01, 0x01];
    zlib.extend(length.to_le_bytes());
    zlib.extend((!length).to_le_bytes());
    zlib.extend(&raw);
    let (a, b) = raw.iter().fold((1u32, 0u32), |(a, b), byte| {
        let a = (a + u32::from(*byte)) % 65521;
        (a, (b + a) % 65521)
    });
    zlib.extend(((b << 16) | a).to_be_bytes());
    let hex = oid.to_string();
    let dir = root.join("objects").join(&hex[..2]);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join(&hex[2..]), zlib).unwrap();
    oid
}
fn import(node: &OneNode, root: &Path) {
    let source = root.join("source");
    fs::create_dir_all(source.join("refs/heads")).unwrap();
    fs::write(source.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
    let blob = loose(
        &source,
        GitObjectKind::Blob,
        "blob",
        b"authority-selected bytes\n",
    );
    let tree = loose(
        &source,
        GitObjectKind::Tree,
        "tree",
        &[b"100644 file.txt\0".as_slice(), blob.as_bytes()].concat(),
    );
    let commit=loose(&source,GitObjectKind::Commit,"commit",format!("tree {tree}\nauthor Test <test@example.invalid> 0 +0000\ncommitter Test <test@example.invalid> 0 +0000\n\nworkspace source\n").as_bytes());
    fs::write(source.join("refs/heads/main"), format!("{commit}\n")).unwrap();
    let request = node.request_context();
    node.runtime()
        .block_on(node.import_loose_git_directory_durable_in(
            &request,
            &source,
            PrincipalId::from_bytes([0x74; 16]),
            b"treefs-host-source-import",
        ))
        .unwrap();
}

#[test]
fn authority_selected_ref_reaches_a_real_host_workspace_and_survives_process_reopen() {
    let s = Scratch::new();
    let (mut node, _) = OneNode::init(config(&s.0)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    import(&node, &s.0);
    let request = node.request_context();
    let m = node
        .runtime()
        .block_on(node.sparse_workspace_manifest_in::<Sha1>(
            &request,
            &reference(),
            &RefVisibility::new(),
            &mut cap(),
            0,
            SparseLimits::default(),
        ))
        .unwrap();
    assert_eq!(m.entries().len(), 1);
    assert_eq!(
        m.entries()[0].kind().body().unwrap(),
        b"authority-selected bytes\n"
    );
    let selected = node
        .runtime()
        .block_on(node.materialize_admission_in(&request))
        .unwrap();
    assert_eq!(
        m.receipt().source_commit_oid().as_bytes(),
        selected.snapshot().refs[&reference()].as_bytes()
    );
    let p = SparseWorkspacePlan::new(
        Arc::new(m),
        vec![TreePath::parse_default(b"file.txt").unwrap()],
        &cap(),
        0,
        SparseLimits::default(),
    )
    .unwrap();
    let l = ObligationLedger::root(
        RegionId::new(91),
        LeakDisposition::RecordAndContinue,
        ResourceVector::from_grades(&[
            (Grade::Bytes, 1024 * 1024 * 1024),
            (Grade::Objects, 100_000),
        ]),
    );
    let r = l
        .reserve(p.reservation(), l.grant(p.budget()).unwrap())
        .unwrap();
    let mut workspace = SparseWorkspace::materialize(
        p,
        File::open(&s.0).unwrap(),
        TreePath::parse_default(b"workspace").unwrap(),
        r,
        &cap(),
        0,
        &|_| false,
    )
    .unwrap();
    fs::write(
        workspace.tool_directory().join("file.txt"),
        b"ordinary tool output\n",
    )
    .unwrap();
    let log = workspace.import(&cap(), 0, &|_| false).unwrap();
    assert!(
        matches!(&log.intents()[0],TreeEditIntent::Write{content,..} if content==b"ordinary tool output\n")
    );
    let _settled = workspace.close().unwrap();
    assert!(matches!(l.close(), RegionCloseOutcome::Quiescent(_)));
    // Workspace output is still an intent, not a ref publication.
    let unchanged = node
        .runtime()
        .block_on(node.sparse_workspace_manifest_in::<Sha1>(
            &request,
            &reference(),
            &RefVisibility::new(),
            &mut cap(),
            0,
            SparseLimits::default(),
        ))
        .unwrap();
    assert_eq!(
        unchanged.entries()[0].kind().body().unwrap(),
        b"authority-selected bytes\n"
    );
    node.shutdown().unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "node_workspace_reopen_driver",
            "--nocapture",
        ])
        .env_clear()
        .env("FGIT_NODE_TREEFS_REOPEN", &s.0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        if started.elapsed() > Duration::from_secs(30) {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("reopen process exceeded deadline");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn hidden_unknown_wrong_domain_and_revoked_requests_do_not_disclose_object_data() {
    let s = Scratch::new();
    let (mut node, _) = OneNode::init(config(&s.0)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    import(&node, &s.0);
    let request = node.request_context();
    let mut hidden = RefVisibility::new();
    hidden
        .push_rule(b"refs/heads/main", &WireLimits::default())
        .unwrap();
    assert!(matches!(
        node.runtime()
            .block_on(node.sparse_workspace_manifest_in::<Sha1>(
                &request,
                &reference(),
                &hidden,
                &mut cap(),
                0,
                SparseLimits::default()
            )),
        Err(NodeWorkspaceRefusal::RefUnavailable)
    ));
    let absent = RefName::try_new(b"refs/heads/absent").unwrap();
    assert!(matches!(
        node.runtime()
            .block_on(node.sparse_workspace_manifest_in::<Sha1>(
                &request,
                &absent,
                &RefVisibility::new(),
                &mut cap(),
                0,
                SparseLimits::default()
            )),
        Err(NodeWorkspaceRefusal::RefUnavailable)
    ));
    assert!(matches!(
        node.runtime()
            .block_on(node.sparse_workspace_manifest_in::<Sha256>(
                &request,
                &reference(),
                &RefVisibility::new(),
                &mut cap(),
                0,
                SparseLimits::default()
            )),
        Err(NodeWorkspaceRefusal::ObjectFormatMismatch)
    ));
    let mut revoked = cap();
    revoked.revoke();
    assert!(
        node.runtime()
            .block_on(node.sparse_workspace_manifest_in::<Sha1>(
                &request,
                &reference(),
                &RefVisibility::new(),
                &mut revoked,
                0,
                SparseLimits::default()
            ))
            .is_err()
    );
    assert!(
        node.runtime()
            .block_on(node.sparse_workspace_manifest_in::<Sha1>(
                &request,
                &reference(),
                &RefVisibility::new(),
                &mut cap(),
                0,
                SparseLimits::default()
            ))
            .is_ok()
    );
    node.shutdown().unwrap();
}

#[test]
#[ignore = "bounded subprocess entrypoint executed by the authority/host parent test"]
fn node_workspace_reopen_driver() {
    let root =
        PathBuf::from(std::env::var_os("FGIT_NODE_TREEFS_REOPEN").expect("parent supplies root"));
    let mut node = OneNode::open_existing(config(&root)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let request = node.request_context();
    let m = node
        .runtime()
        .block_on(node.sparse_workspace_manifest_in::<Sha1>(
            &request,
            &reference(),
            &RefVisibility::new(),
            &mut cap(),
            0,
            SparseLimits::default(),
        ))
        .unwrap();
    assert_eq!(
        m.entries()[0].kind().body().unwrap(),
        b"authority-selected bytes\n"
    );
    node.shutdown().unwrap();
}
