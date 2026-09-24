#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]
//! Native two-parent inputs through the real descriptor-relative host writer.
use fgit_crypto::{GitHashAlgorithm, GitObjectKind, GitOid, NativeObjectIdentity, Sha1, Sha256};
use fgit_git_object::ParseLimits;
use fgit_resource::{LeakDisposition, ObligationLedger, RegionCloseOutcome, RegionId};
use fgit_runner::sparse_workspace::{HostEpoch, HostRefusal, SparseWorkspace, SparseWorkspacePlan};
use fgit_treefs::{
    BaseView, CandidateManifestRefusal, ObjectSource, ObjectSourceError, PathPolicy, ReadGrant,
    SparseCandidateManifest, SparseLimits, TreeCapability, TreePath, WorkspaceId,
};
use fgit_types::{
    ByteCount, CodecVersion, DigestAlgorithmId, DigestBytes, RepositoryCommitId, RepositoryId,
};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs::{self, File};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

struct Source {
    objects: BTreeMap<Vec<u8>, (GitObjectKind, Vec<u8>)>,
    payload_reads: Cell<usize>,
}
impl Source {
    fn put<A: GitHashAlgorithm>(&mut self, kind: GitObjectKind, bytes: Vec<u8>) -> GitOid<A> {
        let id = GitOid::<A>::of_object(kind, &bytes);
        self.objects
            .insert(id.digest_bytes().to_vec(), (kind, bytes));
        id
    }
    fn tree<A: GitHashAlgorithm>(&mut self, content: &[u8]) -> GitOid<A> {
        let blob = self.put::<A>(GitObjectKind::Blob, content.to_vec());
        self.put::<A>(
            GitObjectKind::Tree,
            [b"100755 result\xff\0".as_slice(), blob.digest_bytes()].concat(),
        )
    }
    fn commit<A: GitHashAlgorithm>(
        &mut self,
        tree: GitOid<A>,
        parents: &[GitOid<A>],
        message: &str,
    ) -> GitOid<A> {
        let mut body = format!("tree {}\n", hex(tree.digest_bytes()));
        for parent in parents {
            let _ = writeln!(body, "parent {}", hex(parent.digest_bytes()));
        }
        let _ = writeln!(
            body,
            "author Test <t@example.invalid> 1 +0000\ncommitter Test <t@example.invalid> 2 +0000\n\n{message}"
        );
        self.put::<A>(GitObjectKind::Commit, body.into_bytes())
    }
}
impl<A: GitHashAlgorithm> ObjectSource<A> for Source {
    fn read_object(
        &self,
        id: &GitOid<A>,
        kind: GitObjectKind,
        _: &ReadGrant,
    ) -> Result<Vec<u8>, ObjectSourceError> {
        if kind != GitObjectKind::Commit {
            self.payload_reads.set(self.payload_reads.get() + 1);
        }
        let (actual, bytes) =
            self.objects
                .get(id.digest_bytes())
                .ok_or_else(|| ObjectSourceError::NotFound {
                    oid_hex: hex(id.digest_bytes()),
                })?;
        if *actual != kind {
            return Err(ObjectSourceError::Refused {
                reason: "wrong fixture kind".into(),
            });
        }
        Ok(bytes.clone())
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn path() -> TreePath {
    TreePath::parse_default(b"result\xff").unwrap()
}
fn limits<A: GitHashAlgorithm>() -> ParseLimits {
    ParseLimits {
        tree_reference_bytes: A::DIGEST_LEN,
        ..Default::default()
    }
}
fn capability() -> TreeCapability {
    TreeCapability::new(
        WorkspaceId::from_bytes([1; 16]),
        RepositoryId::from_bytes([2; 16]),
        vec![path()],
        Vec::new(),
    )
    .with_fetch_budget(ByteCount::try_new("test", 1_000_000, 1_000_000).unwrap())
    .with_file_budget(100)
}
fn fixture<A: GitHashAlgorithm>() -> (Source, BaseView<A>, GitOid<A>, GitOid<A>, GitOid<A>) {
    let mut source = Source {
        objects: BTreeMap::new(),
        payload_reads: Cell::new(0),
    };
    let target_tree = source.tree::<A>(b"target\n");
    let incoming_tree = source.tree::<A>(b"incoming\n");
    let merged_tree = source.tree::<A>(b"resolved\0\xff\n");
    let target = source.commit::<A>(target_tree, &[], "target");
    let incoming = source.commit::<A>(incoming_tree, &[target], "incoming");
    let candidate =
        source.commit::<A>(merged_tree, &[target, incoming], "explicit resolved result");
    let rcr = RepositoryCommitId::from_digest(
        DigestAlgorithmId::try_new(0x8001).unwrap(),
        CodecVersion::new(1, 0),
        DigestBytes::try_new(&[9; 32]).unwrap(),
    );
    let base = BaseView::new(
        RepositoryId::from_bytes([2; 16]),
        rcr,
        target,
        target_tree,
        limits::<A>(),
        PathPolicy::default(),
    );
    (source, base, incoming, candidate, merged_tree)
}
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        loop {
            let path = std::env::temp_dir().join(format!(
                "fg-merge-inputs-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&path) {
                Ok(()) => {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
                    return Self(path);
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => panic!("fixture: {e}"),
            }
        }
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn copied<A: GitHashAlgorithm>(cancel: bool) {
    let (source, base, incoming, candidate, tree) = fixture::<A>();
    let manifest = SparseCandidateManifest::build_merge(
        &base,
        &source,
        candidate,
        incoming,
        &mut capability(),
        0,
        limits::<A>(),
        SparseLimits::default(),
    )
    .unwrap();
    assert_eq!(manifest.parents(), &[*base.base_commit_oid(), incoming]);
    assert_eq!(manifest.base_commit_oid(), base.base_commit_oid());
    assert_eq!(manifest.base_rcr_id(), base.base_rcr_id());
    assert_eq!(manifest.candidate_tree_oid(), &tree);
    assert_eq!(
        manifest.entries()[0].kind().body(),
        Some(b"resolved\0\xff\n".as_slice())
    );
    let plan = SparseWorkspacePlan::for_candidate(
        Arc::new(manifest),
        &capability(),
        0,
        SparseLimits::default(),
    )
    .unwrap();
    let root = Scratch::new();
    let ledger = ObligationLedger::root(
        RegionId::new(1),
        LeakDisposition::RecordAndContinue,
        plan.budget(),
    );
    let obligation = ledger
        .reserve(plan.reservation(), ledger.grant(plan.budget()).unwrap())
        .unwrap();
    let result = SparseWorkspace::materialize(
        plan,
        File::open(&root.0).unwrap(),
        TreePath::parse_default(b"job").unwrap(),
        obligation,
        &capability(),
        0,
        &|epoch| cancel && matches!(epoch, HostEpoch::Writing(_)),
    );
    if cancel {
        assert!(matches!(
            result,
            Err(HostRefusal::Cancelled(HostEpoch::Writing(_)))
        ));
    } else {
        let mut workspace = result.unwrap();
        let file = workspace
            .tool_directory()
            .join(std::ffi::OsStr::from_bytes(b"result\xff"));
        assert_eq!(fs::read(file).unwrap(), b"resolved\0\xff\n");
        assert!(matches!(
            workspace.import(&capability(), 0, &|_| false),
            Err(HostRefusal::IdentityMismatch)
        ));
        let _ = workspace.close().unwrap();
    }
    assert!(matches!(ledger.close(), RegionCloseOutcome::Quiescent(_)));
    assert_eq!(fs::read_dir(&root.0).unwrap().count(), 0);
}
#[test]
fn both_formats_copy_the_actual_merge_result_and_refuse_canonical_import() {
    copied::<Sha1>(false);
    copied::<Sha256>(false);
}
#[test]
fn merge_copy_cancellation_drains_the_same_host_obligation() {
    copied::<Sha1>(true);
    copied::<Sha256>(true);
}

fn wrong_parents<A: GitHashAlgorithm>() {
    let (mut source, base, incoming, candidate, tree) = fixture::<A>();
    assert!(matches!(
        SparseCandidateManifest::build(
            &base,
            &source,
            candidate,
            &mut capability(),
            0,
            limits::<A>(),
            SparseLimits::default()
        ),
        Err(CandidateManifestRefusal::InvalidCandidate(_))
    ));
    for parents in [
        vec![incoming, *base.base_commit_oid()],
        vec![*base.base_commit_oid()],
        vec![*base.base_commit_oid(), incoming, *base.base_commit_oid()],
        vec![*base.base_commit_oid(), *base.base_commit_oid()],
    ] {
        let id = source.commit::<A>(tree, &parents, "bad parent binding");
        assert!(matches!(
            SparseCandidateManifest::build_merge(
                &base,
                &source,
                id,
                incoming,
                &mut capability(),
                0,
                limits::<A>(),
                SparseLimits::default()
            ),
            Err(CandidateManifestRefusal::InvalidCandidate(_))
        ));
    }
    assert_eq!(
        source.payload_reads.get(),
        0,
        "no candidate tree or blob read before ordered parent validation"
    );
    let key = candidate.digest_bytes().to_vec();
    source.objects.get_mut(&key).unwrap().1.push(b'x');
    assert!(matches!(
        SparseCandidateManifest::build_merge(
            &base,
            &source,
            candidate,
            incoming,
            &mut capability(),
            0,
            limits::<A>(),
            SparseLimits::default()
        ),
        Err(CandidateManifestRefusal::Source(
            ObjectSourceError::IdentityMismatch { .. }
        ))
    ));
    assert_eq!(source.payload_reads.get(), 0);
}
#[test]
fn ordered_parent_binding_and_hash_verification_precede_sparse_discovery() {
    wrong_parents::<Sha1>();
    wrong_parents::<Sha256>();
}
