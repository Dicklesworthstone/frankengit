//! Component lifecycle tests for the production workflow-owned source cache.
//! Native object fixtures follow fgit-runner/tests/shared_workspace.rs.
//! Real clone-or-copy behavior is retained; no filesystem success is simulated.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use super::{SharedInputs, statistics_json};
use fgit_crypto::{GitHashAlgorithm, GitObjectKind, GitOid, NativeObjectIdentity, Sha1, Sha256};
use fgit_git_object::ParseLimits;
use fgit_resource::{
    Grade, LeakDisposition, ObligationLedger, RegionCloseOutcome, RegionId, ResourceVector,
    TerminalEvidence,
};
use fgit_runner::sparse_workspace::{
    HostClosed, HostEpoch, HostRefusal, SparseWorkspace, SparseWorkspacePlan,
};
use fgit_treefs::{
    BaseView, ObjectSource, ObjectSourceError, PathPolicy, ReadGrant, SparseLimits, SparseManifest,
    TreeCapability, TreePath, WorkspaceId,
};
use fgit_types::{CodecVersion, DigestAlgorithmId, DigestBytes, RepositoryCommitId, RepositoryId};

const INPUT: &[u8] = b"input\xff";
const FILE_BYTES: usize = 32 * 1024 + 1;
const LIMITS: SparseLimits = SparseLimits {
    max_entries: 16,
    max_entry_bytes: FILE_BYTES,
    max_payload_bytes: 2 * FILE_BYTES,
};
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let parent = std::env::var_os("FGIT_SHARED_WORKSPACE_TEST_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        assert!(parent.is_absolute() && parent.is_dir());
        let path = parent.join(format!(
            "fgit-node-shared-helper-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }

    fn parent(&self) -> File {
        File::open(&self.0).unwrap()
    }

    fn assert_empty(&self) {
        assert_eq!(
            fs::read_dir(&self.0).unwrap().count(),
            0,
            "the helper must not leave a named source cache or job workspace",
        );
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("remove only this harness's private fixture directory");
    }
}

// This fixture uses real typed native objects and the production manifest
// verifier. Only the object source and authority coordinates are test data.
struct Source(BTreeMap<Vec<u8>, (GitObjectKind, Vec<u8>)>);
impl Source {
    fn put<A: GitHashAlgorithm>(&mut self, kind: GitObjectKind, body: Vec<u8>) -> GitOid<A> {
        let oid = GitOid::<A>::of_object(kind, &body);
        self.0.insert(oid.digest_bytes().to_vec(), (kind, body));
        oid
    }
}
impl<A: GitHashAlgorithm> ObjectSource<A> for Source {
    fn read_object(
        &self,
        oid: &GitOid<A>,
        kind: GitObjectKind,
        _: &ReadGrant,
    ) -> Result<Vec<u8>, ObjectSourceError> {
        let (actual, body) =
            self.0
                .get(oid.digest_bytes())
                .ok_or_else(|| ObjectSourceError::NotFound {
                    oid_hex: hex(oid.digest_bytes()),
                })?;
        if *actual != kind {
            return Err(ObjectSourceError::Refused {
                reason: "fixture object kind".into(),
            });
        }
        Ok(body.clone())
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn path(bytes: &[u8]) -> TreePath {
    TreePath::parse_default(bytes).unwrap()
}

fn fixture<A: GitHashAlgorithm>() -> (SparseWorkspacePlan<A>, TreeCapability, Vec<u8>) {
    let body: Vec<u8> = (0..FILE_BYTES).map(|index| (index % 251) as u8).collect();
    let mut source = Source(BTreeMap::new());
    let blob = source.put::<A>(GitObjectKind::Blob, body.clone());
    let mut tree_body = b"100644 ".to_vec();
    tree_body.extend_from_slice(INPUT);
    tree_body.push(0);
    tree_body.extend_from_slice(blob.digest_bytes());
    let tree = source.put::<A>(GitObjectKind::Tree, tree_body);
    let commit = source.put::<A>(
        GitObjectKind::Commit,
        format!(
            "tree {}\nauthor Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n\nNode helper lifecycle\n",
            hex(tree.digest_bytes()),
        )
        .into_bytes(),
    );
    let repository = RepositoryId::from_bytes([3; 16]);
    let base = BaseView::new(
        repository,
        RepositoryCommitId::from_digest(
            DigestAlgorithmId::try_new(0x8001).unwrap(),
            CodecVersion::new(1, 0),
            DigestBytes::try_new(&[9; 32]).unwrap(),
        ),
        commit,
        tree,
        ParseLimits {
            tree_reference_bytes: A::DIGEST_LEN,
            ..ParseLimits::default()
        },
        PathPolicy::default(),
    );
    let mut capability = TreeCapability::new(
        WorkspaceId::from_bytes([5; 16]),
        repository,
        vec![path(INPUT)],
        Vec::new(),
    );
    let manifest =
        Arc::new(SparseManifest::build(&base, &source, &mut capability, 0, LIMITS).unwrap());
    let plan = SparseWorkspacePlan::new(manifest, Vec::new(), &capability, 0, LIMITS).unwrap();
    (plan, capability, body)
}

fn materialize<A: GitHashAlgorithm>(
    plan: &SparseWorkspacePlan<A>,
    capability: &TreeCapability,
    root: &Scratch,
    slot: &[u8],
    helper: &mut SharedInputs,
) -> (SparseWorkspace<A>, ObligationLedger) {
    let ledger = ObligationLedger::root(
        RegionId::new(1),
        LeakDisposition::RecordAndContinue,
        plan.budget(),
    );
    let reserved = ledger
        .reserve(plan.reservation(), ledger.grant(plan.budget()).unwrap())
        .unwrap();
    let workspace = SparseWorkspace::materialize_with_cache(
        plan.clone(),
        root.parent(),
        path(slot),
        reserved,
        capability,
        0,
        &|_| false,
        helper.cache().unwrap(),
    )
    .unwrap();
    (workspace, ledger)
}

fn close_workspace<A: GitHashAlgorithm>(
    workspace: SparseWorkspace<A>,
    ledger: ObligationLedger,
) -> HostClosed {
    let TerminalEvidence::Acknowledged(receipt, _) = workspace.close().unwrap().into_evidence()
    else {
        panic!("the workspace lease must settle after explicit reaping");
    };
    assert_eq!(
        ledger.snapshot().consumed(),
        ResourceVector::from_grades(&[
            (
                Grade::Bytes,
                receipt.copied_bytes
                    + receipt.shared_host_bytes
                    + receipt.metadata_bytes
                    + receipt.imported_bytes,
            ),
            (
                Grade::Objects,
                receipt.created_entries + receipt.imported_entries,
            ),
        ]),
    );
    assert!(ledger.snapshot().is_conserved());
    assert!(matches!(ledger.close(), RegionCloseOutcome::Quiescent(_)));
    receipt
}

fn lifecycle<A: GitHashAlgorithm>() {
    let root = Scratch::new();
    let (plan, capability, body) = fixture::<A>();
    let mut helper = SharedInputs::open(&plan, &root.parent(), &|| true).unwrap();
    assert_eq!(helper.cache().unwrap().stats().seeded_bytes, 0);
    let (first, first_ledger) = materialize(&plan, &capability, &root, b"job-000", &mut helper);
    let (second, second_ledger) = materialize(&plan, &capability, &root, b"job-001", &mut helper);
    let first_path = first.tool_directory().join(OsStr::from_bytes(INPUT));
    let second_path = second.tool_directory().join(OsStr::from_bytes(INPUT));
    let first_metadata = fs::metadata(&first_path).unwrap();
    let second_metadata = fs::metadata(&second_path).unwrap();
    assert_ne!(
        (first_metadata.dev(), first_metadata.ino()),
        (second_metadata.dev(), second_metadata.ino()),
    );
    assert_eq!(first_metadata.nlink(), 1);
    assert_eq!(second_metadata.nlink(), 1);
    assert_eq!(first_metadata.permissions().mode() & 0o777, 0o600);
    assert_eq!(fs::read(&first_path).unwrap(), body);
    assert_eq!(fs::read(&second_path).unwrap(), body);
    {
        let mut file = OpenOptions::new().write(true).open(&first_path).unwrap();
        file.write_all(b"changed by first job").unwrap();
        file.sync_all().unwrap();
    }
    assert_eq!(fs::read(&second_path).unwrap(), body);
    let first_receipt = close_workspace(first, first_ledger);
    assert_eq!(
        first_receipt.copied_bytes + first_receipt.shared_host_bytes,
        body.len() as u64,
    );
    assert!(!root.0.join("job-000").exists());

    // Cache custody ends independently of an already materialized workspace.
    // The surviving workspace must still own usable immutable original bytes.
    let stats = helper.close().unwrap();
    assert_eq!(stats.resident_bytes, 0);
    assert_eq!(stats.resident_entries, 0);
    assert!(stats.seeded_entries <= 1);
    assert!(stats.seeded_bytes <= body.len() as u64);
    assert_eq!(
        stats.cloned_bytes + stats.fallback_bytes,
        2 * body.len() as u64
    );
    assert_eq!(stats.clone_operations + stats.fallback_files, 2);
    assert_eq!(stats.capacity_files, 0);
    assert!(matches!(
        helper.cache(),
        Err(HostRefusal::SharedInputCacheUnusable)
    ));
    assert_eq!(fs::read(&second_path).unwrap(), body);
    let second_receipt = close_workspace(second, second_ledger);
    assert_eq!(
        second_receipt.copied_bytes + second_receipt.shared_host_bytes,
        body.len() as u64,
    );
    let json = statistics_json(&stats);
    assert!(json.contains("\"cache_closed\":true"));
    assert!(json.contains("\"resident_entries\":0"));
    root.assert_empty();
}

#[test]
fn production_helper_lifecycle_sha1() {
    lifecycle::<Sha1>();
}

#[test]
fn production_helper_lifecycle_sha256() {
    lifecycle::<Sha256>();
}

#[test]
fn production_helper_pre_open_cancellation_settles_and_allows_fresh_open() {
    let root = Scratch::new();
    let (plan, _, _) = fixture::<Sha1>();
    match SharedInputs::open(&plan, &root.parent(), &|| false) {
        Err(error) => assert_eq!(error, HostRefusal::Cancelled(HostEpoch::Staging)),
        Ok(mut helper) => {
            helper.close().unwrap();
            panic!("pre-open cancellation must refuse");
        }
    }
    root.assert_empty();
    // Returning Cancelled rather than CacheUnusable also confirms that the
    // production helper's error branch observed a quiescent cache ledger.
    let mut helper = SharedInputs::open(&plan, &root.parent(), &|| true).unwrap();
    let stats = helper.close().unwrap();
    assert_eq!(stats.seeded_entries, 0);
    assert_eq!(stats.seeded_bytes, 0);
    root.assert_empty();
}

#[test]
fn production_helper_repeat_close_refuses_and_cache_stays_closed() {
    let root = Scratch::new();
    let (plan, _, _) = fixture::<Sha256>();
    let mut helper = SharedInputs::open(&plan, &root.parent(), &|| true).unwrap();
    let stats = helper.close().unwrap();
    assert_eq!(stats.resident_entries, 0);
    assert_eq!(stats.resident_bytes, 0);
    assert_eq!(helper.close(), Err(HostRefusal::SharedInputCacheUnusable));
    assert!(matches!(
        helper.cache(),
        Err(HostRefusal::SharedInputCacheUnusable)
    ));
    root.assert_empty();
}
