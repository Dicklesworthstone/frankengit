#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]
//! Genuine native object fixtures and the production descriptor-relative writer.
use std::cell::Cell;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Arc, atomic::{AtomicU64, Ordering}};
use fgit_crypto::{GitHashAlgorithm, GitObjectKind, GitOid, NativeObjectIdentity, Sha1, Sha256};
use fgit_git_object::ParseLimits;
use fgit_resource::{LeakDisposition, ObligationLedger, RegionCloseOutcome, RegionId};
use fgit_runner::sparse_workspace::{HostEpoch, HostRefusal, SparseWorkspace, SparseWorkspacePlan};
use fgit_treefs::{BaseView, CandidateManifestRefusal, ObjectSource, ObjectSourceError, PathPolicy,
    ReadGrant, SparseCandidateManifest, SparseLimits, SparseManifest, TreeCapability, TreePath, WorkspaceId};
use fgit_types::{ByteCount, CodecVersion, DigestAlgorithmId, DigestBytes, RepositoryCommitId, RepositoryId};

struct Source { objects: BTreeMap<Vec<u8>, (GitObjectKind, Vec<u8>)>, stop: Cell<bool> }
impl Source {
    fn put<A: GitHashAlgorithm>(&mut self, kind: GitObjectKind, bytes: Vec<u8>) -> GitOid<A> {
        let oid = GitOid::<A>::of_object(kind, &bytes);
        self.objects.insert(oid.digest_bytes().to_vec(), (kind, bytes)); oid
    }
}
impl<A: GitHashAlgorithm> ObjectSource<A> for Source {
    fn read_object(&self, oid: &GitOid<A>, kind: GitObjectKind, _: &ReadGrant) -> Result<Vec<u8>, ObjectSourceError> {
        if self.stop.get() { return Err(ObjectSourceError::Refused { reason: "cancelled fixture source".into() }); }
        let (actual, bytes) = self.objects.get(oid.digest_bytes()).ok_or_else(|| ObjectSourceError::NotFound { oid_hex: hex(oid.digest_bytes()) })?;
        if *actual != kind { return Err(ObjectSourceError::Refused { reason: "wrong kind".into() }); }
        Ok(bytes.clone())
    }
}
fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }
fn path() -> TreePath { TreePath::parse_default(b"input\xff").unwrap() }
fn parse_limits<A: GitHashAlgorithm>() -> ParseLimits { ParseLimits { tree_reference_bytes: A::DIGEST_LEN, ..Default::default() } }
fn capability() -> TreeCapability {
    TreeCapability::new(WorkspaceId::from_bytes([1; 16]), RepositoryId::from_bytes([2; 16]), vec![path()], Vec::new())
        .with_fetch_budget(ByteCount::try_new("fixture", 1_000_000, 1_000_000).unwrap()).with_file_budget(100)
}
fn commit<A: GitHashAlgorithm>(source: &mut Source, tree: GitOid<A>, parents: &[GitOid<A>], message: &str) -> GitOid<A> {
    let mut body = format!("tree {}\n", hex(tree.digest_bytes()));
    for parent in parents { body.push_str(&format!("parent {}\n", hex(parent.digest_bytes()))); }
    body.push_str(&format!("author Test <t@example.invalid> 1 +0000\ncommitter Test <t@example.invalid> 1 +0000\n\n{message}\n"));
    source.put::<A>(GitObjectKind::Commit, body.into_bytes())
}
fn fixture<A: GitHashAlgorithm>() -> (Source, BaseView<A>, GitOid<A>) {
    let mut source = Source { objects: BTreeMap::new(), stop: Cell::new(false) };
    let mut tree = |bytes: &[u8]| {
        let blob = source.put::<A>(GitObjectKind::Blob, bytes.to_vec());
        source.put::<A>(GitObjectKind::Tree, [b"100755 input\xff\0".as_slice(), blob.digest_bytes()].concat())
    };
    let before = tree(b"original\n"); let after = tree(b"\0\xff\r\n");
    let base_commit = commit::<A>(&mut source, before, &[], "base");
    let candidate = commit::<A>(&mut source, after, &[base_commit], "candidate");
    let rcr = RepositoryCommitId::from_digest(DigestAlgorithmId::try_new(0x8001).unwrap(),
        CodecVersion::new(1, 0), DigestBytes::try_new(&[9; 32]).unwrap());
    (source, BaseView::new(RepositoryId::from_bytes([2; 16]), rcr, base_commit, before,
        parse_limits::<A>(), PathPolicy::default()), candidate)
}
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        loop {
            let path = std::env::temp_dir().join(format!("fg-candidate-inputs-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
            match fs::create_dir(&path) {
                Ok(()) => { fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap(); return Self(path); }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => panic!("private fixture: {e}"),
            }
        }
    }
}
impl Drop for Scratch { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }
fn copy_and_close<A: GitHashAlgorithm>() {
    let (source, base, candidate) = fixture::<A>();
    let manifest = SparseCandidateManifest::build(&base, &source, candidate, &mut capability(), 0,
        parse_limits::<A>(), SparseLimits::default()).unwrap();
    assert_eq!(manifest.base_rcr_id(), base.base_rcr_id());
    assert_eq!(manifest.base_commit_oid(), base.base_commit_oid());
    assert_eq!(manifest.candidate_commit_oid(), &candidate);
    assert_ne!(manifest.candidate_tree_oid(), manifest.base_tree_oid());
    assert_eq!(manifest.entries()[0].kind().body().unwrap(), b"\0\xff\r\n");
    let original = SparseManifest::build(&base, &source, &mut capability(), 0, SparseLimits::default()).unwrap();
    let original = SparseWorkspacePlan::new(Arc::new(original), Vec::new(), &capability(), 0, SparseLimits::default()).unwrap();
    let plan = SparseWorkspacePlan::for_candidate(Arc::new(manifest), &capability(), 0, SparseLimits::default()).unwrap();
    assert_ne!(plan.reservation().plan, original.reservation().plan);
    let root = Scratch::new();
    let ledger = ObligationLedger::root(RegionId::new(1), LeakDisposition::RecordAndContinue, plan.budget());
    let granted = ledger.grant(plan.budget()).unwrap(); let reservation = ledger.reserve(plan.reservation(), granted).unwrap();
    let mut workspace = SparseWorkspace::materialize(plan, File::open(&root.0).unwrap(), TreePath::parse_default(b"job").unwrap(),
        reservation, &capability(), 0, &|_| false).unwrap();
    assert_eq!(fs::read(root.0.join("job").join(std::ffi::OsStr::from_bytes(b"input\xff"))).unwrap(), b"\0\xff\r\n");
    assert!(matches!(workspace.import(&capability(), 0, &|_| false), Err(HostRefusal::IdentityMismatch)));
    let _ = workspace.close().unwrap();
    assert!(matches!(ledger.close(), RegionCloseOutcome::Quiescent(_)));
    assert!(!root.0.join("job").exists());
}
#[test]
fn candidate_inputs_keep_base_provenance_and_materialize_without_import_authority() {
    copy_and_close::<Sha1>(); copy_and_close::<Sha256>();
}
#[test]
fn parent_integrity_capabilities_and_payload_limits_are_not_bypassed() {
    let (mut source, base, candidate) = fixture::<Sha1>();
    let good = SparseCandidateManifest::build(&base, &source, candidate, &mut capability(), 0, parse_limits::<Sha1>(), SparseLimits::default()).unwrap();
    let wrong = commit::<Sha1>(&mut source, *good.candidate_tree_oid(), &[candidate], "wrong parent");
    let merged = commit::<Sha1>(&mut source, *good.candidate_tree_oid(), &[*base.base_commit_oid(), candidate], "two parents");
    for id in [wrong, merged, *base.base_commit_oid()] {
        assert!(matches!(SparseCandidateManifest::build(&base, &source, id, &mut capability(), 0, parse_limits::<Sha1>(), SparseLimits::default()), Err(CandidateManifestRefusal::InvalidCandidate(_))));
    }
    let small = SparseLimits { max_entry_bytes: 1, ..Default::default() };
    assert!(SparseCandidateManifest::build(&base, &source, candidate, &mut capability(), 0, parse_limits::<Sha1>(), small).is_err());
    source.stop.set(true);
    assert!(SparseCandidateManifest::build(&base, &source, candidate, &mut capability(), 0, parse_limits::<Sha1>(), SparseLimits::default()).is_err());
    source.stop.set(false);
    source.objects.get_mut(candidate.digest_bytes()).unwrap().1.push(b'x');
    assert!(matches!(SparseCandidateManifest::build(&base, &source, candidate, &mut capability(), 0, parse_limits::<Sha1>(), SparseLimits::default()), Err(CandidateManifestRefusal::Source(ObjectSourceError::IdentityMismatch { .. }))));
}
#[test]
fn candidate_metadata_is_in_the_host_commitment_and_cancelled_copy_settles() {
    let (mut source, base, candidate) = fixture::<Sha256>();
    let first = SparseCandidateManifest::build(&base, &source, candidate, &mut capability(), 0, parse_limits::<Sha256>(), SparseLimits::default()).unwrap();
    let other = commit::<Sha256>(&mut source, *first.candidate_tree_oid(), &[*base.base_commit_oid()], "different metadata");
    let second = SparseCandidateManifest::build(&base, &source, other, &mut capability(), 0, parse_limits::<Sha256>(), SparseLimits::default()).unwrap();
    assert_eq!(first.entries(), second.entries());
    let plan = SparseWorkspacePlan::for_candidate(Arc::new(first), &capability(), 0, SparseLimits::default()).unwrap();
    let other_plan = SparseWorkspacePlan::for_candidate(Arc::new(second), &capability(), 0, SparseLimits::default()).unwrap();
    assert_ne!(plan.reservation().plan, other_plan.reservation().plan);
    let root = Scratch::new();
    let ledger = ObligationLedger::root(RegionId::new(2), LeakDisposition::RecordAndContinue, plan.budget());
    let granted = ledger.grant(plan.budget()).unwrap(); let reservation = ledger.reserve(plan.reservation(), granted).unwrap();
    let result = SparseWorkspace::materialize(plan, File::open(&root.0).unwrap(), TreePath::parse_default(b"cancelled").unwrap(),
        reservation, &capability(), 0, &|epoch| matches!(epoch, HostEpoch::Writing(_)));
    assert!(matches!(result, Err(HostRefusal::Cancelled(_))));
    assert!(matches!(ledger.close(), RegionCloseOutcome::Quiescent(_)));
    assert_eq!(fs::read_dir(&root.0).unwrap().count(), 0);
}
