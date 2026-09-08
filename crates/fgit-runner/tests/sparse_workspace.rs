#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]
//! Real host I/O and subprocess recovery; canonical Git bytes are stored on
//! disk and re-read through BaseView. Fixture RCR IDs do not claim authority
//! publication, and these tests do not claim hostile-process containment.

use fgit_crypto::{GitObjectKind, GitOid, NativeObjectIdentity, Sha1};
use fgit_git_object::{AcceptanceProfile, ParseLimits, TreeEntry, emit_tree};
use fgit_resource::{
    Grade, LeakDisposition, ObligationLedger, RegionCloseOutcome, RegionId, ReservedObligation,
    ResourceVector, TerminalEvidence,
};
use fgit_runner::sparse_workspace::{
    HostEpoch, HostRefusal, SparseDirectoryLease, SparseWorkspace, SparseWorkspacePlan,
};
use fgit_treefs::{
    BaseView, ExportLimits, ExportPlanner, ObjectSource, ObjectSourceError, PathPolicy, ReadGrant,
    SparseLimits, SparseManifest, TreeCapability, TreePath, WorkspaceId,
};
use fgit_types::{CodecVersion, DigestAlgorithmId, DigestBytes, RepositoryCommitId, RepositoryId};
use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

type Oid = GitOid<Sha1>;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "fgit-host-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p).expect("unique test root");
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
        Self(p)
    }
    fn parent(&self) -> File {
        File::open(&self.0).unwrap()
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("remove only owned test scratch");
    }
}
#[derive(Clone)]
struct DiskSource(PathBuf);
impl DiskSource {
    fn put(&self, kind: GitObjectKind, body: &[u8]) -> Oid {
        let oid = Oid::of_object(kind, body);
        let path = self.0.join(hex(&oid));
        match File::create_new(&path) {
            Ok(mut f) => {
                f.write_all(body).unwrap();
                f.sync_all().unwrap();
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                assert_eq!(fs::read(path).unwrap(), body)
            }
            Err(e) => panic!("object write: {e}"),
        }
        oid
    }
    fn tree(&self, entries: &[TreeEntry]) -> Oid {
        self.put(
            GitObjectKind::Tree,
            &emit_tree(
                entries,
                AcceptanceProfile::GitCompatibleImport,
                &ParseLimits::default(),
            )
            .unwrap(),
        )
    }
}
impl ObjectSource<Sha1> for DiskSource {
    fn read_object(
        &self,
        oid: &Oid,
        _: GitObjectKind,
        _: &ReadGrant,
    ) -> Result<Vec<u8>, ObjectSourceError> {
        fs::read(self.0.join(hex(oid)))
            .map_err(|_| ObjectSourceError::NotFound { oid_hex: hex(oid) })
    }
}
fn hex(oid: &Oid) -> String {
    oid.digest_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn path(p: &[u8]) -> TreePath {
    TreePath::parse_default(p).unwrap()
}
fn entry(mode: &[u8], name: &[u8], oid: Oid) -> TreeEntry {
    TreeEntry {
        mode: mode.to_vec(),
        name: name.to_vec(),
        object_id: oid.digest_bytes().to_vec(),
    }
}
fn capability() -> TreeCapability {
    TreeCapability::new(
        WorkspaceId::from_bytes([6; 16]),
        RepositoryId::from_bytes([9; 16]),
        vec![path(b"src"), path(b"README"), path(b"generated")],
        vec![path(b"src"), path(b"generated")],
    )
}
fn fixture(
    root: &Path,
    extra: Option<(&[u8], &[u8])>,
) -> (DiskSource, BaseView<Sha1>, Arc<SparseManifest<Sha1>>) {
    let dir = root.join("objects");
    if !dir.exists() {
        fs::create_dir(&dir).unwrap();
    }
    let source = DiskSource(dir);
    let blob = source.put(GitObjectKind::Blob, b"original\n");
    let mut leaves = vec![
        entry(b"100644", b"input", blob),
        entry(b"100755", b"tool", blob),
    ];
    if let Some((name, mode)) = extra {
        leaves.push(entry(mode, name, blob));
    }
    leaves.sort_by(|a, b| a.name.cmp(&b.name));
    let subtree = source.tree(&leaves);
    let tree = source.tree(&[
        entry(b"100644", b"README", blob),
        entry(b"40000", b"src", subtree),
    ]);
    let commit = source.put(GitObjectKind::Commit, format!("tree {}\nauthor Test <test@example.invalid> 0 +0000\ncommitter Test <test@example.invalid> 0 +0000\n\nHost fixture\n", hex(&tree)).as_bytes());
    let rcr = RepositoryCommitId::from_digest(
        DigestAlgorithmId::try_new(0x8043).unwrap(),
        CodecVersion::new(1, 0),
        DigestBytes::try_new(&[5; 32]).unwrap(),
    );
    let base = BaseView::new(
        RepositoryId::from_bytes([9; 16]),
        rcr,
        commit,
        tree,
        ParseLimits::default(),
        PathPolicy::default(),
    );
    let manifest = SparseManifest::build(
        &base,
        &source,
        &mut capability(),
        0,
        SparseLimits::default(),
    )
    .unwrap();
    (source, base, Arc::new(manifest))
}
fn plan(manifest: Arc<SparseManifest<Sha1>>) -> SparseWorkspacePlan<Sha1> {
    SparseWorkspacePlan::new(
        manifest,
        vec![
            path(b"src/input"),
            path(b"src/tool"),
            path(b"generated/output"),
        ],
        &capability(),
        0,
        SparseLimits {
            max_entries: 100,
            max_entry_bytes: 65536,
            max_payload_bytes: 131072,
        },
    )
    .unwrap()
}
fn ledger() -> ObligationLedger {
    ObligationLedger::root(
        RegionId::new(7),
        LeakDisposition::RecordAndContinue,
        ResourceVector::from_grades(&[(Grade::Bytes, 8 * 1024 * 1024), (Grade::Objects, 10000)]),
    )
}
fn reserve(
    l: &ObligationLedger,
    p: &SparseWorkspacePlan<Sha1>,
) -> ReservedObligation<SparseDirectoryLease> {
    l.reserve(p.reservation(), l.grant(p.budget()).unwrap())
        .unwrap()
}
fn create(
    s: &Scratch,
    l: &ObligationLedger,
    p: SparseWorkspacePlan<Sha1>,
    name: &[u8],
) -> SparseWorkspace<Sha1> {
    let r = reserve(l, &p);
    SparseWorkspace::materialize(p, s.parent(), path(name), r, &capability(), 0, &|_| false)
        .unwrap()
}
fn quiescent(l: ObligationLedger) {
    assert!(matches!(l.close(), RegionCloseOutcome::Quiescent(_)));
}

#[test]
fn actual_tool_edit_import_and_disk_object_reopen_preserve_git_identity() {
    let scratch = Scratch::new();
    let (source, base, manifest) = fixture(&scratch.0, None);
    let l = ledger();
    let p = plan(manifest.clone());
    let start = Instant::now();
    let mut w = create(&scratch, &l, p, b"work");
    let creation = start.elapsed();
    assert_eq!(
        fs::read(w.tool_directory().join("src/input")).unwrap(),
        b"original\n"
    );
    assert_eq!(
        fs::metadata(w.tool_directory().join("src/tool"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    run_child(&scratch.0, "tool", Some(&w.tool_directory()));
    let log = w.import(&capability(), 0, &|_| false).unwrap();
    assert_eq!(log.len(), 3);
    let (overlay, evaluation) = log.evaluate(&|p| manifest.entries().iter().any(|e| e.path() == p));
    assert!(evaluation.errors().is_empty());
    let exported = ExportPlanner::new(ExportLimits::default(), ParseLimits::default())
        .plan(&base, &source, &mut capability(), &overlay, 0, &|| false)
        .unwrap();
    assert!(exported.verify_all());
    assert_ne!(exported.root_tree(), base.base_tree_oid());
    for object in exported.objects() {
        source.put(object.kind(), object.body());
    }
    let reopened = BaseView::new(
        base.repository_id(),
        base.base_rcr_id(),
        *base.base_commit_oid(),
        *exported.root_tree(),
        ParseLimits::default(),
        PathPolicy::default(),
    );
    let reopened_source = DiskSource(source.0.clone());
    let mut cap = capability();
    // Include the explicitly generated output in the read capability.
    cap = TreeCapability::new(
        cap.workspace_id(),
        cap.repository_id(),
        vec![path(b"src"), path(b"README"), path(b"generated")],
        vec![path(b"src")],
    );
    let rebuilt = SparseManifest::build(
        &reopened,
        &reopened_source,
        &mut cap,
        0,
        SparseLimits::default(),
    )
    .unwrap();
    let body = |name: &[u8]| {
        rebuilt
            .entries()
            .iter()
            .find(|e| e.path().as_bytes() == name)
            .unwrap()
            .kind()
            .body()
            .unwrap()
    };
    assert_eq!(body(b"src/input"), b"changed by a real process\n");
    assert_eq!(body(b"generated/output"), b"declared output\n");
    assert!(
        !rebuilt
            .entries()
            .iter()
            .any(|e| e.path().as_bytes() == b"src/tool")
    );
    let close_start = Instant::now();
    let receipt = w.close().unwrap();
    match receipt.evidence() {
        TerminalEvidence::Acknowledged(r, _) => {
            assert_eq!(r.copied_bytes, manifest.receipt().payload_bytes() as u64);
            assert_eq!(r.shared_host_bytes, 0);
            assert!(r.removed_entries >= 6);
            eprintln!(
                "host measurement creation_us={} cleanup_us={} copied_bytes={} shared_host_bytes={} imported_bytes={}",
                creation.as_micros(),
                close_start.elapsed().as_micros(),
                r.copied_bytes,
                r.shared_host_bytes,
                r.imported_bytes
            );
        }
        _ => panic!("successful close acknowledges lease"),
    }
    assert!(!scratch.0.join("work").exists());
    quiescent(l);
}

#[test]
fn rebuild_and_parallel_workspaces_share_only_the_immutable_manifest() {
    let s = Scratch::new();
    let (_, _, m) = fixture(&s.0, None);
    let p = plan(m.clone());
    let l = ledger();
    let mut a = create(&s, &l, p.clone(), b"a");
    let mut b = create(&s, &l, p.clone(), b"b");
    assert!(Arc::strong_count(&m) >= 4);
    fs::write(a.tool_directory().join("src/input"), b"private").unwrap();
    assert_eq!(a.import(&capability(), 0, &|_| false).unwrap().len(), 1);
    assert!(b.import(&capability(), 0, &|_| false).unwrap().is_empty());
    let _ = a.close().unwrap();
    let _ = b.close().unwrap();
    let mut c = create(&s, &l, p, b"a");
    assert!(c.import(&capability(), 0, &|_| false).unwrap().is_empty());
    let _ = c.close().unwrap();
    quiescent(l);
}

#[test]
fn traversal_capability_mode_symlink_hardlink_and_budget_refusals_have_positive_twins() {
    let s = Scratch::new();
    let (_, _, m) = fixture(&s.0, None);
    let p = plan(m.clone());
    for invalid in [
        &b"../escape"[..],
        b"/absolute",
        b"a/../../b",
        b".git/config",
    ] {
        assert!(TreePath::parse_default(invalid).is_err());
    }
    let denied = TreeCapability::new(
        capability().workspace_id(),
        capability().repository_id(),
        vec![path(b"README")],
        vec![path(b"src")],
    );
    assert!(matches!(
        SparseWorkspacePlan::new(m.clone(), vec![], &denied, 0, SparseLimits::default()),
        Err(HostRefusal::Capability(_))
    ));
    assert!(
        SparseWorkspacePlan::new(m.clone(), vec![], &capability(), 0, SparseLimits::default())
            .is_ok()
    );
    let l = ledger();
    let mut w = create(&s, &l, p, b"work");
    let input = w.tool_directory().join("src/input");
    let outside = s.0.join("outside");
    fs::write(&outside, b"never read or overwritten").unwrap();
    fs::remove_file(&input).unwrap();
    symlink(&outside, &input).unwrap();
    assert!(w.import(&capability(), 0, &|_| false).is_err());
    fs::remove_file(&input).unwrap();
    fs::hard_link(&outside, &input).unwrap();
    assert!(matches!(
        w.import(&capability(), 0, &|_| false),
        Err(HostRefusal::UnsupportedEntry(_))
    ));
    fs::remove_file(&input).unwrap();
    fs::write(&input, b"permitted").unwrap();
    fs::set_permissions(&input, fs::Permissions::from_mode(0o4755)).unwrap();
    assert!(matches!(
        w.import(&capability(), 0, &|_| false),
        Err(HostRefusal::UnsupportedEntry(_))
    ));
    fs::set_permissions(&input, fs::Permissions::from_mode(0o664)).unwrap();
    assert_eq!(w.import(&capability(), 0, &|_| false).unwrap().len(), 1);
    fs::write(&input, vec![0; 65537]).unwrap();
    assert_eq!(
        w.import(&capability(), 0, &|_| false),
        Err(HostRefusal::ResourceLimit)
    );
    fs::write(&input, vec![0; 65536]).unwrap();
    assert!(w.import(&capability(), 0, &|_| false).is_ok());
    let _ = w.close().unwrap();
    assert_eq!(fs::read(outside).unwrap(), b"never read or overwritten");
    quiescent(l);
}

#[test]
fn byte_exact_case_and_unicode_paths_remain_distinct_on_the_real_host() {
    let s = Scratch::new();
    let (source, base, _) = fixture(&s.0, None);
    let blob = source.put(GitObjectKind::Blob, b"names");
    let names = ["A", "a", "e\u{301}", "é"];
    let subtree = source.tree(
        &names
            .iter()
            .map(|n| entry(b"100644", n.as_bytes(), blob))
            .collect::<Vec<_>>(),
    );
    let tree = source.tree(&[entry(b"40000", b"src", subtree)]);
    let base = BaseView::new(
        base.repository_id(),
        base.base_rcr_id(),
        *base.base_commit_oid(),
        tree,
        ParseLimits::default(),
        PathPolicy::default(),
    );
    let m = Arc::new(
        SparseManifest::build(
            &base,
            &source,
            &mut capability(),
            0,
            SparseLimits::default(),
        )
        .unwrap(),
    );
    let l = ledger();
    let mut w = create(&s, &l, plan(m), b"names");
    for n in names {
        assert_eq!(
            fs::read(w.tool_directory().join("src").join(n)).unwrap(),
            b"names"
        );
    }
    assert!(w.import(&capability(), 0, &|_| false).unwrap().is_empty());
    let _ = w.close().unwrap();
    quiescent(l);
}

#[test]
fn cancelled_materialization_and_import_never_return_partial_publication() {
    let s = Scratch::new();
    let (_, _, m) = fixture(&s.0, None);
    let p = plan(m);
    let l = ledger();
    for epoch in [
        HostEpoch::Reserved,
        HostEpoch::Staging,
        HostEpoch::Writing(2),
        HostEpoch::Visible,
        HostEpoch::Durable,
    ] {
        let r = reserve(&l, &p);
        assert!(
            matches!(SparseWorkspace::materialize(p.clone(),s.parent(),path(b"cancel"),r,&capability(),0,&|e|e==epoch),Err(HostRefusal::Cancelled(e)) if e==epoch)
        );
        assert!(!s.0.join("cancel").exists());
        assert!(!s.0.join(".fgit-staged-cancel").exists());
    }
    let mut w = create(&s, &l, p, b"cancel");
    fs::write(w.tool_directory().join("src/input"), b"change").unwrap();
    for epoch in [
        HostEpoch::Importing(0),
        HostEpoch::Importing(2),
        HostEpoch::Imported,
    ] {
        assert_eq!(
            w.import(&capability(), 0, &|e| e == epoch),
            Err(HostRefusal::Cancelled(epoch))
        );
    }
    assert_eq!(w.import(&capability(), 0, &|_| false).unwrap().len(), 1);
    let _ = w.close().unwrap();
    quiescent(l);
}

#[test]
fn descriptor_relative_import_refuses_parent_symlink_replacement_and_read_only_edits() {
    let s = Scratch::new();
    let (_, _, m) = fixture(&s.0, None);
    let l = ledger();
    let mut w = create(&s, &l, plan(m), b"race");
    let root = w.tool_directory();
    let external = s.0.join("external");
    fs::create_dir(&external).unwrap();
    fs::write(external.join("input"), b"secret").unwrap();
    // Replace a parent precisely between manifest enumeration and its open.
    let once = std::cell::Cell::new(false);
    assert!(
        w.import(&capability(), 0, &|epoch| {
            if epoch == HostEpoch::Importing(2) && !once.replace(true) {
                fs::rename(root.join("src"), root.join("saved")).unwrap();
                symlink(&external, root.join("src")).unwrap();
            }
            false
        })
        .is_err()
    );
    assert_eq!(fs::read(external.join("input")).unwrap(), b"secret");
    fs::remove_file(root.join("src")).unwrap();
    fs::rename(root.join("saved"), root.join("src")).unwrap();
    assert!(w.import(&capability(), 0, &|_| false).unwrap().is_empty());
    fs::write(root.join("README"), b"unauthorized change").unwrap();
    assert_eq!(
        w.import(&capability(), 0, &|_| false),
        Err(HostRefusal::UndeclaredChange(path(b"README")))
    );
    let _ = w.close().unwrap();
    quiescent(l);
}

#[test]
fn live_lease_wrong_plan_and_dropped_workspace_are_not_successful_reopens() {
    let s = Scratch::new();
    let (_, _, m) = fixture(&s.0, None);
    let p = plan(m.clone());
    let l = ledger();
    let w = create(&s, &l, p.clone(), b"lease");
    assert!(
        SparseWorkspace::reopen(
            p.clone(),
            s.parent(),
            path(b"lease"),
            reserve(&l, &p),
            &capability(),
            0
        )
        .is_err()
    );
    drop(w);
    assert!(matches!(
        l.close(),
        RegionCloseOutcome::ContainmentFailure(_)
    ));
    let l = ledger();
    let wrong = SparseWorkspacePlan::new(
        m,
        vec![],
        &capability(),
        0,
        SparseLimits {
            max_entries: 100,
            max_entry_bytes: 65536,
            max_payload_bytes: 131072,
        },
    )
    .unwrap();
    assert!(matches!(
        SparseWorkspace::reopen(
            wrong.clone(),
            s.parent(),
            path(b"lease"),
            reserve(&l, &wrong),
            &capability(),
            0
        ),
        Err(HostRefusal::IdentityMismatch)
    ));
    let mut recovered = SparseWorkspace::reopen(
        p.clone(),
        s.parent(),
        path(b"lease"),
        reserve(&l, &p),
        &capability(),
        0,
    )
    .unwrap();
    assert!(
        recovered
            .import(&capability(), 0, &|_| false)
            .unwrap()
            .is_empty()
    );
    let _ = recovered.close().unwrap();
    quiescent(l);
}

#[test]
fn plan_and_host_permissions_refuse_before_io_beside_admitted_inputs() {
    let s = Scratch::new();
    let (_, _, m) = fixture(&s.0, None);
    assert!(matches!(
        SparseWorkspacePlan::new(
            m.clone(),
            vec![],
            &capability(),
            0,
            SparseLimits {
                max_entries: 4,
                max_entry_bytes: 9,
                max_payload_bytes: 27
            }
        ),
        Err(HostRefusal::ResourceLimit)
    ));
    assert!(
        SparseWorkspacePlan::new(
            m.clone(),
            vec![],
            &capability(),
            0,
            SparseLimits {
                max_entries: 5,
                max_entry_bytes: 9,
                max_payload_bytes: 27
            }
        )
        .is_ok()
    );
    let p = plan(m);
    let l = ledger();
    fs::set_permissions(&s.0, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        SparseWorkspace::materialize(
            p.clone(),
            s.parent(),
            path(b"private"),
            reserve(&l, &p),
            &capability(),
            0,
            &|_| false
        )
        .is_err()
    );
    assert!(!s.0.join(".fgit-staged-private").exists());
    fs::set_permissions(&s.0, fs::Permissions::from_mode(0o700)).unwrap();
    let mut w = create(&s, &l, p, b"private");
    let mut revoked = capability();
    revoked.revoke();
    assert!(matches!(
        w.import(&revoked, 0, &|_| false),
        Err(HostRefusal::Capability(_))
    ));
    assert!(w.import(&capability(), 0, &|_| false).unwrap().is_empty());
    let _ = w.close().unwrap();
    quiescent(l);
    let symlink_root = Scratch::new();
    let (_, _, m) = fixture(&symlink_root.0, Some((b"link", b"120000")));
    assert!(
        matches!(SparseWorkspacePlan::new(m,vec![],&capability(),0,SparseLimits::default()),Err(HostRefusal::UnsupportedEntry(p)) if p==path(b"src/link"))
    );
}

#[test]
fn cleanup_excess_and_root_replacement_report_containment_without_escaped_deletion() {
    let s = Scratch::new();
    let (_, _, m) = fixture(&s.0, None);
    let p = plan(m);
    let l = ledger();
    let w = create(&s, &l, p, b"owned");
    fs::rename(s.0.join("owned"), s.0.join("displaced")).unwrap();
    fs::create_dir(s.0.join("owned")).unwrap();
    fs::write(s.0.join("owned/protected"), b"different directory").unwrap();
    assert!(matches!(w.close(), Err(HostRefusal::Containment { .. })));
    assert_eq!(
        fs::read(s.0.join("owned/protected")).unwrap(),
        b"different directory"
    );
    assert!(matches!(
        l.close(),
        RegionCloseOutcome::ContainmentFailure(_)
    ));
    let s = Scratch::new();
    let (_, _, m) = fixture(&s.0, None);
    let l = ledger();
    let w = create(&s, &l, plan(m), b"excess");
    for n in 0..101 {
        fs::write(w.tool_directory().join(format!("extra-{n}")), b"").unwrap();
    }
    assert!(matches!(w.close(), Err(HostRefusal::Containment { .. })));
    assert!(s.0.join("excess").exists());
    assert!(matches!(
        l.close(),
        RegionCloseOutcome::ContainmentFailure(_)
    ));
}

#[test]
fn fresh_process_crash_windows_recover_complete_or_explicitly_incomplete_roots() {
    for epoch in ["staging", "writing", "visible", "durable"] {
        let s = Scratch::new();
        run_child(&s.0, epoch, None);
        let (_, _, m) = fixture(&s.0, None);
        let p = plan(m);
        let l = ledger();
        if matches!(epoch, "staging" | "writing") {
            assert!(matches!(
                SparseWorkspace::reopen(
                    p.clone(),
                    s.parent(),
                    path(b"crash"),
                    reserve(&l, &p),
                    &capability(),
                    0
                ),
                Err(HostRefusal::IncompleteWorkspace)
            ));
            let _ = SparseWorkspace::discard_incomplete(
                p.clone(),
                s.parent(),
                path(b"crash"),
                reserve(&l, &p),
            )
            .unwrap();
        } else {
            let mut w = SparseWorkspace::reopen(
                p.clone(),
                s.parent(),
                path(b"crash"),
                reserve(&l, &p),
                &capability(),
                0,
            )
            .unwrap();
            assert!(w.import(&capability(), 0, &|_| false).unwrap().is_empty());
            let _ = w.close().unwrap();
        }
        assert!(!s.0.join("crash").exists());
        assert!(!s.0.join(".fgit-staged-crash").exists());
        quiescent(l);
    }
}

fn run_child(root: &Path, mode: &str, workspace: Option<&Path>) {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--ignored",
            "--exact",
            "host_subprocess_driver",
            "--nocapture",
        ])
        .env_clear()
        .env("FGIT_HOST_TEST_ROOT", root)
        .env("FGIT_HOST_TEST_MODE", mode)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    if let Some(workspace) = workspace {
        command.env("FGIT_HOST_TEST_WORKSPACE", workspace);
    }
    let mut child = command.spawn().unwrap();
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert_eq!(status.code(), Some(77));
            break;
        }
        if start.elapsed() > Duration::from_secs(10) {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("bounded host subprocess exceeded deadline");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
#[ignore = "subprocess driver; the parent tests execute it with an exact mode and deadline"]
fn host_subprocess_driver() {
    let mode = std::env::var("FGIT_HOST_TEST_MODE").expect("parent supplies mode");
    if mode == "tool" {
        let root = PathBuf::from(std::env::var_os("FGIT_HOST_TEST_WORKSPACE").unwrap());
        fs::write(root.join("src/input"), b"changed by a real process\n").unwrap();
        fs::write(root.join("generated/output"), b"declared output\n").unwrap();
        fs::remove_file(root.join("src/tool")).unwrap();
        std::process::exit(77);
    }
    let root = PathBuf::from(std::env::var_os("FGIT_HOST_TEST_ROOT").unwrap());
    let (_, _, m) = fixture(&root, None);
    let p = plan(m);
    let l = ledger();
    let r = reserve(&l, &p);
    let epoch = match mode.as_str() {
        "staging" => HostEpoch::Staging,
        "writing" => HostEpoch::Writing(2),
        "visible" => HostEpoch::Visible,
        "durable" => HostEpoch::Durable,
        _ => panic!("unknown crash mode"),
    };
    let _workspace = SparseWorkspace::materialize(
        p,
        File::open(&root).unwrap(),
        path(b"crash"),
        r,
        &capability(),
        0,
        &|e| {
            if e == epoch {
                std::process::exit(77);
            }
            false
        },
    )
    .unwrap();
    panic!("requested crash epoch was not reached");
}
