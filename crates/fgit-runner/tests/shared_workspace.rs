#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]
//! Native manifests through the production sparse-directory and shared-input
//! adapters. No clone operation is substituted or reported as successful when
//! the host filesystem does not support it. The normal tests verify the path
//! actually selected by PreferReflink; the ignored RequireReflink test is the
//! separate positive copy-on-write obligation on a supporting filesystem.
//!
//! Fixture RCRs identify test bases, not authority publication. Sharing and
//! copied-byte receipts describe logical I/O, never physical disk savings or
//! hostile-process containment. All owning leases are explicitly settled.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use fgit_crypto::{GitHashAlgorithm, GitObjectKind, GitOid, NativeObjectIdentity, Sha1, Sha256};
use fgit_git_object::ParseLimits;
use fgit_resource::{
    Grade, LeakDisposition, ObligationLedger, RegionCloseOutcome, RegionId, ResourceVector,
    TerminalEvidence,
};
use fgit_runner::Commitment;
use fgit_runner::sparse_workspace::{
    HostClosed, HostEpoch, HostRefusal, JobInput, SharedInputCache, SharedInputCacheClosed,
    SharedInputCachePlan, SharedInputCacheStats, SharedInputFallback, SharedInputPolicy,
    SparseWorkspace, SparseWorkspacePlan,
};
use fgit_treefs::{
    BaseView, FileMode, ObjectSource, ObjectSourceError, PathPolicy, ReadGrant, SparseLimits,
    SparseManifest, TreeCapability, TreeEditIntent, TreePath, WorkspaceId,
};
use fgit_types::{CodecVersion, DigestAlgorithmId, DigestBytes, RepositoryCommitId, RepositoryId};

const FILE_BYTES: usize = 128 * 1024;
const NAMES: [&[u8]; 3] = [b"copy.bin", b"input\xff", b"tool.bin"];
const LIMITS: SparseLimits = SparseLimits {
    max_entries: 32,
    max_entry_bytes: FILE_BYTES,
    max_payload_bytes: 4 * FILE_BYTES,
};
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        Self::under(&std::env::temp_dir())
    }

    fn under(parent: &Path) -> Self {
        assert!(
            parent.is_absolute() && parent.is_dir(),
            "existing absolute test root required"
        );
        let path = parent.join(format!(
            "fg-shared-workspace-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }

    fn configured() -> Self {
        Self::under(
            &std::env::var_os("FGIT_SHARED_WORKSPACE_TEST_ROOT")
                .map(PathBuf::from)
                .unwrap_or_else(std::env::temp_dir),
        )
    }

    fn parent(&self) -> File {
        File::open(&self.0).unwrap()
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("remove only this test's private directory");
    }
}

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
        let (actual_kind, body) =
            self.0
                .get(oid.digest_bytes())
                .ok_or_else(|| ObjectSourceError::NotFound {
                    oid_hex: hex(oid.digest_bytes()),
                })?;
        if *actual_kind != kind {
            return Err(ObjectSourceError::Refused {
                reason: "fixture object kind".into(),
            });
        }
        Ok(body.clone())
    }
}

struct Fixture<A: GitHashAlgorithm> {
    source: Source,
    base: BaseView<A>,
    body: Vec<u8>,
    blob: GitOid<A>,
}
impl<A: GitHashAlgorithm> Fixture<A> {
    fn new(repository: u8, content_seed: u8) -> Self {
        let mut state = 0x243f_6a88_85a3_08d3_u64 ^ u64::from(content_seed);
        let body: Vec<u8> = (0..FILE_BYTES)
            .map(|_| {
                state ^= state >> 12;
                state ^= state << 25;
                state ^= state >> 27;
                (state.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 56) as u8
            })
            .collect();
        let mut source = Source(BTreeMap::new());
        let blob = source.put::<A>(GitObjectKind::Blob, body.clone());
        let mut tree_body = Vec::new();
        for (index, name) in NAMES.into_iter().enumerate() {
            tree_body.extend_from_slice(if index == 2 { b"100755 " } else { b"100644 " });
            tree_body.extend_from_slice(name);
            tree_body.push(0);
            tree_body.extend_from_slice(blob.digest_bytes());
        }
        let tree = source.put::<A>(GitObjectKind::Tree, tree_body);
        let commit_body = format!(
            "tree {}\nauthor Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n\nShared workspace\n",
            hex(tree.digest_bytes())
        );
        let commit = source.put::<A>(GitObjectKind::Commit, commit_body.into_bytes());
        let rcr = RepositoryCommitId::from_digest(
            DigestAlgorithmId::try_new(0x8001).unwrap(),
            CodecVersion::new(1, 0),
            DigestBytes::try_new(&[content_seed; 32]).unwrap(),
        );
        Self {
            source,
            base: BaseView::new(
                RepositoryId::from_bytes([repository; 16]),
                rcr,
                commit,
                tree,
                ParseLimits {
                    tree_reference_bytes: A::DIGEST_LEN,
                    ..ParseLimits::default()
                },
                PathPolicy::default(),
            ),
            body,
            blob,
        }
    }

    fn capability(&self, workspace: u8) -> TreeCapability {
        TreeCapability::new(
            WorkspaceId::from_bytes([workspace; 16]),
            self.base.repository_id(),
            NAMES.into_iter().map(path).collect(),
            vec![path(NAMES[1]), path(NAMES[2])],
        )
    }

    fn manifest(&self, capability: &mut TreeCapability) -> Arc<SparseManifest<A>> {
        Arc::new(SparseManifest::build(&self.base, &self.source, capability, 0, LIMITS).unwrap())
    }

    fn plan(&self, workspace: u8, writable: bool) -> (SparseWorkspacePlan<A>, TreeCapability) {
        let mut capability = self.capability(workspace);
        let manifest = self.manifest(&mut capability);
        let outputs = if writable {
            vec![path(NAMES[1]), path(NAMES[2])]
        } else {
            Vec::new()
        };
        let plan = SparseWorkspacePlan::new(manifest, outputs, &capability, 0, LIMITS).unwrap();
        (plan, capability)
    }

    fn assert_original(&self, directory: &Path) {
        for (index, name) in NAMES.into_iter().enumerate() {
            let file = directory.join(OsStr::from_bytes(name));
            assert_eq!(
                fs::read(&file).unwrap(),
                self.body,
                "exact original bytes at {name:?}"
            );
            let metadata = fs::metadata(file).unwrap();
            assert_eq!(
                metadata.nlink(),
                1,
                "reflinks must not become shared writable inodes"
            );
            assert_eq!(
                metadata.permissions().mode() & 0o777,
                if index == 2 { 0o700 } else { 0o600 }
            );
        }
    }

    const fn payload_bytes(&self) -> u64 {
        (NAMES.len() * self.body.len()) as u64
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn path(bytes: &[u8]) -> TreePath {
    TreePath::parse_default(bytes).unwrap()
}
fn ledger(budget: ResourceVector) -> ObligationLedger {
    ObligationLedger::root(RegionId::new(1), LeakDisposition::RecordAndContinue, budget)
}
fn quiescent(ledger: ObligationLedger) {
    assert!(ledger.snapshot().is_conserved());
    assert!(matches!(ledger.close(), RegionCloseOutcome::Quiescent(_)));
}

fn cache<A: GitHashAlgorithm>(
    plan: &SparseWorkspacePlan<A>,
    root: &Scratch,
    policy: SharedInputPolicy,
) -> (SharedInputCache, ObligationLedger) {
    let plan = SharedInputCachePlan::for_workspace(plan, policy);
    let ledger = ledger(plan.budget());
    let reservation = ledger
        .reserve(plan.reservation(), ledger.grant(plan.budget()).unwrap())
        .unwrap();
    let cache = SharedInputCache::create(plan, root.parent(), reservation, &|| false)
        .expect("selected sharing policy must be available on the named fixture filesystem");
    (cache, ledger)
}

fn materialize<A: GitHashAlgorithm>(
    plan: SparseWorkspacePlan<A>,
    capability: &TreeCapability,
    root: &Scratch,
    slot: &[u8],
    cache: Option<&mut SharedInputCache>,
) -> (SparseWorkspace<A>, ObligationLedger) {
    let ledger = ledger(plan.budget());
    let reservation = ledger
        .reserve(plan.reservation(), ledger.grant(plan.budget()).unwrap())
        .unwrap();
    let workspace = match cache {
        Some(cache) => SparseWorkspace::materialize_with_cache(
            plan,
            root.parent(),
            path(slot),
            reservation,
            capability,
            0,
            &|_| false,
            cache,
        ),
        None => SparseWorkspace::materialize(
            plan,
            root.parent(),
            path(slot),
            reservation,
            capability,
            0,
            &|_| false,
        ),
    }
    .unwrap();
    (workspace, ledger)
}

fn close_workspace<A: GitHashAlgorithm>(
    workspace: SparseWorkspace<A>,
    ledger: ObligationLedger,
) -> HostClosed {
    let TerminalEvidence::Acknowledged(receipt, _) = workspace.close().unwrap().into_evidence()
    else {
        panic!("an explicitly reaped workspace must acknowledge its lease");
    };
    assert_eq!(
        ledger.snapshot().consumed(),
        ResourceVector::from_grades(&[
            (
                Grade::Bytes,
                receipt.copied_bytes
                    + receipt.shared_host_bytes
                    + receipt.metadata_bytes
                    + receipt.imported_bytes
            ),
            (
                Grade::Objects,
                receipt.created_entries + receipt.imported_entries
            ),
        ])
    );
    quiescent(ledger);
    receipt
}

fn close_cache(cache: SharedInputCache, ledger: ObligationLedger) -> SharedInputCacheClosed {
    let TerminalEvidence::Acknowledged(receipt, _) = cache.close().unwrap().into_evidence() else {
        panic!("an explicitly reaped source cache must acknowledge its lease");
    };
    assert_eq!(receipt.stats.resident_bytes, 0);
    assert_eq!(receipt.stats.resident_entries, 0);
    assert_eq!(
        ledger.snapshot().consumed(),
        ResourceVector::from_grades(&[
            (Grade::Bytes, receipt.stats.seeded_bytes),
            (
                Grade::Objects,
                receipt.stats.seeded_entries + receipt.stats.probe_entries
            ),
        ])
    );
    quiescent(ledger);
    receipt
}

fn assert_required_refusal<A: GitHashAlgorithm>(
    plan: &SparseWorkspacePlan<A>,
    root: &Scratch,
    probe_entries: u64,
) {
    let plan = SharedInputCachePlan::for_workspace(plan, SharedInputPolicy::RequireReflink);
    let ledger = ledger(plan.budget());
    let reservation = ledger
        .reserve(plan.reservation(), ledger.grant(plan.budget()).unwrap())
        .unwrap();
    assert_eq!(
        SharedInputCache::create(plan, root.parent(), reservation, &|| false).err(),
        Some(HostRefusal::SharedInputUnavailable(
            SharedInputFallback::UnsupportedFilesystem
        )),
        "RequireReflink must refuse this actual unsupported filesystem"
    );
    assert_eq!(
        ledger.snapshot().consumed(),
        ResourceVector::from_grades(&[(Grade::Bytes, 0), (Grade::Objects, probe_entries),])
    );
    quiescent(ledger);
}

fn assert_copy_or_clone_accounting(
    stats: &SharedInputCacheStats,
    receipts: &[HostClosed],
    payload: u64,
) {
    let copied: u64 = receipts.iter().map(|receipt| receipt.copied_bytes).sum();
    let shared: u64 = receipts
        .iter()
        .map(|receipt| receipt.shared_host_bytes)
        .sum();
    assert_eq!(copied + shared, payload * receipts.len() as u64);
    assert_eq!(stats.cloned_bytes, shared);
    assert_eq!(stats.fallback_bytes, copied);
    if stats.reflink_supported {
        assert_eq!(
            copied, 0,
            "this bounded same-filesystem fixture fits its cache"
        );
        assert_eq!(shared, payload * receipts.len() as u64);
        assert!(stats.seeded_bytes > 0 && stats.seeded_bytes <= payload);
        assert!(stats.seeded_entries > 0 && stats.seeded_entries <= NAMES.len() as u64);
        assert_eq!(
            stats.clone_operations,
            (NAMES.len() * receipts.len()) as u64
        );
        assert_eq!(stats.fallback_files, 0);
    } else {
        assert_eq!(
            shared, 0,
            "unsupported must never be reported as successful sharing"
        );
        assert_eq!(
            stats.seeded_bytes, 0,
            "unsupported probe must avoid seed copies"
        );
        assert_eq!(stats.seeded_entries, 0);
        assert_eq!(stats.clone_operations, 0);
        assert_eq!(stats.fallback_files, (NAMES.len() * receipts.len()) as u64);
        assert_eq!(stats.unsupported_files, stats.fallback_files);
        assert_eq!(stats.capacity_files, 0);
    }
}

fn exercise_isolation<A: GitHashAlgorithm>(root: &Scratch, policy: SharedInputPolicy) {
    let fixture = Fixture::<A>::new(9, 1);
    let (plan_a, cap_a) = fixture.plan(1, true);
    let (plan_b, cap_b) = fixture.plan(2, true);
    let (plan_c, cap_c) = fixture.plan(3, false);
    assert_ne!(plan_a.reservation().plan, plan_b.reservation().plan);
    let (mut cache, cache_ledger) = cache(&plan_a, root, policy);
    let initial = cache.stats();
    assert_eq!(initial.seeded_bytes, 0);
    if !initial.reflink_supported {
        assert_required_refusal(&plan_a, root, initial.probe_entries);
    }
    let (mut a, ledger_a) = materialize(plan_a, &cap_a, root, b"a", Some(&mut cache));
    let (mut b, ledger_b) = materialize(plan_b, &cap_b, root, b"b", Some(&mut cache));
    let a_directory = root.0.join("a");
    let b_directory = root.0.join("b");
    fixture.assert_original(&a_directory);
    fixture.assert_original(&b_directory);
    let mut inodes = BTreeSet::new();
    for directory in [&a_directory, &b_directory] {
        for name in NAMES {
            let metadata = fs::metadata(directory.join(OsStr::from_bytes(name))).unwrap();
            assert!(
                inodes.insert((metadata.dev(), metadata.ino())),
                "all writable host inodes are independent"
            );
        }
    }

    let mut expected = fixture.body.clone();
    let mut changed = OpenOptions::new()
        .write(true)
        .open(a_directory.join(OsStr::from_bytes(NAMES[1])))
        .unwrap();
    changed.seek(SeekFrom::Start(4093)).unwrap();
    changed.write_all(b"changed!").unwrap();
    changed.sync_all().unwrap();
    expected[4093..4101].copy_from_slice(b"changed!");
    let shortened = OpenOptions::new()
        .write(true)
        .open(a_directory.join(OsStr::from_bytes(NAMES[2])))
        .unwrap();
    shortened.set_len(73).unwrap();
    shortened.sync_all().unwrap();
    drop((changed, shortened));
    assert_eq!(
        fs::read(a_directory.join(OsStr::from_bytes(NAMES[0]))).unwrap(),
        fixture.body
    );
    fixture.assert_original(&b_directory);
    assert!(b.import(&cap_b, 0, &|_| false).unwrap().is_empty());
    let edits = a.import(&cap_a, 0, &|_| false).unwrap();
    assert!(matches!(edits.intents(), [
        TreeEditIntent::Write { path: input, content, mode: FileMode::Regular, .. },
        TreeEditIntent::Write { path: tool, content: truncated, mode: FileMode::Executable, .. },
    ] if input == &path(NAMES[1]) && content == &expected && tool == &path(NAMES[2]) && truncated == &fixture.body[..73]));

    // C is materialized after both writes. A corrupted shared seed would leak
    // through this new clone even if B happened to remain intact.
    let (c, ledger_c) = materialize(plan_c, &cap_c, root, b"c", Some(&mut cache));
    let c_directory = root.0.join("c");
    fixture.assert_original(&c_directory);
    for name in NAMES {
        let metadata = fs::metadata(c_directory.join(OsStr::from_bytes(name))).unwrap();
        assert!(inodes.insert((metadata.dev(), metadata.ino())));
    }
    assert_eq!(
        fixture.source.0[fixture.blob.digest_bytes()].1,
        fixture.body
    );
    let rebuilt = fixture.manifest(&mut fixture.capability(4));
    for entry in rebuilt.entries() {
        assert_eq!(entry.kind().body().unwrap(), fixture.body);
    }
    let receipts = [
        close_workspace(a, ledger_a),
        close_workspace(b, ledger_b),
        close_workspace(c, ledger_c),
    ];
    assert_eq!(receipts[0].imported_bytes, (FILE_BYTES + 73) as u64);
    assert_eq!(receipts[0].imported_entries, 2);
    assert_eq!(receipts[1].imported_bytes + receipts[2].imported_bytes, 0);
    let stats = cache.stats();
    assert_copy_or_clone_accounting(&stats, &receipts, fixture.payload_bytes());
    eprintln!("shared-input actual host: {stats:?}");
    let closed = close_cache(cache, cache_ledger);
    assert_eq!(closed.stats.seeded_bytes, stats.seeded_bytes);
    assert_eq!(closed.stats.cloned_bytes, stats.cloned_bytes);
    assert_eq!(fs::read_dir(&root.0).unwrap().count(), 0);
}

#[test]
fn actual_host_path_preserves_private_native_inputs_sha1() {
    exercise_isolation::<Sha1>(&Scratch::new(), SharedInputPolicy::PreferReflink);
}

#[test]
fn actual_host_path_preserves_private_native_inputs_sha256() {
    exercise_isolation::<Sha256>(&Scratch::new(), SharedInputPolicy::PreferReflink);
}

#[test]
fn cache_scope_and_capabilities_are_rechecked_and_job_inputs_stay_separate() {
    let root = Scratch::new();
    let fixture = Fixture::<Sha256>::new(9, 1);
    let (plan, capability) = fixture.plan(1, false);
    let (mut cache, cache_ledger) = cache(&plan, &root, SharedInputPolicy::PreferReflink);
    let foreign_repository = Fixture::<Sha256>::new(8, 1);
    let different_source = Fixture::<Sha256>::new(9, 2);
    let mut subset_capability = TreeCapability::new(
        WorkspaceId::from_bytes([4; 16]),
        fixture.base.repository_id(),
        vec![path(NAMES[0])],
        Vec::new(),
    );
    let subset = SparseWorkspacePlan::new(
        fixture.manifest(&mut subset_capability),
        Vec::new(),
        &subset_capability,
        0,
        LIMITS,
    )
    .unwrap();
    let (other_plan, other_capability) = fixture.plan(2, false);
    let mut cases = vec![
        (other_plan, capability, HostRefusal::IdentityMismatch),
        (
            subset,
            subset_capability,
            HostRefusal::SharedInputScopeMismatch,
        ),
    ];
    for changed in [&foreign_repository, &different_source] {
        let (plan, capability) = changed.plan(3, false);
        cases.push((plan, capability, HostRefusal::SharedInputScopeMismatch));
    }
    for (plan, capability, expected) in cases {
        let before = cache.stats();
        let ledger = ledger(plan.budget());
        let reservation = ledger
            .reserve(plan.reservation(), ledger.grant(plan.budget()).unwrap())
            .unwrap();
        let refused = SparseWorkspace::materialize_with_cache(
            plan,
            root.parent(),
            path(b"refused"),
            reservation,
            &capability,
            0,
            &|_| false,
            &mut cache,
        );
        assert_eq!(refused.err(), Some(expected));
        assert_eq!(ledger.snapshot().consumed(), ResourceVector::ZERO);
        quiescent(ledger);
        assert_eq!(
            cache.stats(),
            before,
            "a refused scope must not probe or seed source bytes"
        );
        assert!(!root.0.join("refused").exists());
        assert!(!root.0.join(".fgit-staged-refused").exists());
    }
    // The permitted twin has a different workspace ID and supplemental input,
    // neither of which may widen or contaminate the shared source inventory.
    let (plan, cap) = fixture.plan(2, false);
    assert_eq!(cap.workspace_id(), other_capability.workspace_id());
    let job_body = b"verified producing-job artifact";
    let plan = plan
        .with_job_inputs(vec![
            JobInput::new(
                b"build/input.bin",
                job_body.to_vec(),
                FileMode::Regular,
                Commitment::of_bytes(b"producer observation"),
            )
            .unwrap(),
        ])
        .unwrap();
    let (mut workspace, workspace_ledger) =
        materialize(plan, &cap, &root, b"with-input", Some(&mut cache));
    fixture.assert_original(&root.0.join("with-input"));
    assert_eq!(
        fs::read(root.0.join("with-input/.fgit-artifacts/build/input.bin")).unwrap(),
        job_body
    );
    assert_eq!(
        workspace.import(&cap, 0, &|_| false),
        Err(HostRefusal::IdentityMismatch)
    );
    let receipt = close_workspace(workspace, workspace_ledger);
    let stats = cache.stats();
    assert_eq!(
        receipt.copied_bytes + receipt.shared_host_bytes,
        fixture.payload_bytes() + job_body.len() as u64
    );
    assert_eq!(stats.cloned_bytes, receipt.shared_host_bytes);
    assert_eq!(
        stats.fallback_bytes + job_body.len() as u64,
        receipt.copied_bytes
    );
    close_cache(cache, cache_ledger);
    assert_eq!(fs::read_dir(&root.0).unwrap().count(), 0);
}

#[test]
fn underfunded_cache_reservations_refuse_before_any_host_work() {
    let root = Scratch::new();
    let fixture = Fixture::<Sha256>::new(9, 1);
    let (plan, _) = fixture.plan(1, false);
    let plan = SharedInputCachePlan::for_workspace(&plan, SharedInputPolicy::PreferReflink);
    let grades = [Grade::Bytes, Grade::Objects, Grade::FileDescriptors];
    for short_grade in grades {
        let budget = ResourceVector::from_grades(&grades.map(|grade| {
            (
                grade,
                plan.budget().get(grade) - u64::from(grade == short_grade),
            )
        }));
        let ledger = ledger(budget);
        let reservation = ledger
            .reserve(plan.reservation(), ledger.grant(budget).unwrap())
            .unwrap();
        assert_eq!(
            SharedInputCache::create(plan.clone(), root.parent(), reservation, &|| false).err(),
            Some(HostRefusal::ReservationMismatch),
            "an underfunded {short_grade:?} reservation cannot create a cache"
        );
        assert_eq!(ledger.snapshot().consumed(), ResourceVector::ZERO);
        quiescent(ledger);
        assert_eq!(fs::read_dir(&root.0).unwrap().count(), 0);
    }
}

#[test]
fn cancellation_cleans_workspace_without_losing_cache_custody_or_reusing_spent_budget() {
    let root = Scratch::new();
    let fixture = Fixture::<Sha1>::new(9, 1);
    let (plan, capability) = fixture.plan(1, false);
    let cache_plan = SharedInputCachePlan::for_workspace(&plan, SharedInputPolicy::PreferReflink);
    let cancelled_ledger = ledger(cache_plan.budget());
    let reservation = cancelled_ledger
        .reserve(
            cache_plan.reservation(),
            cancelled_ledger.grant(cache_plan.budget()).unwrap(),
        )
        .unwrap();
    assert!(matches!(
        SharedInputCache::create(cache_plan, root.parent(), reservation, &|| true),
        Err(HostRefusal::Cancelled(_))
    ));
    assert_eq!(cancelled_ledger.snapshot().consumed(), ResourceVector::ZERO);
    quiescent(cancelled_ledger);
    let (mut cache, cache_ledger) = cache(&plan, &root, SharedInputPolicy::PreferReflink);
    let interrupted_ledger = ledger(plan.budget());
    let reservation = interrupted_ledger
        .reserve(
            plan.reservation(),
            interrupted_ledger.grant(plan.budget()).unwrap(),
        )
        .unwrap();
    let refused = SparseWorkspace::materialize_with_cache(
        plan.clone(),
        root.parent(),
        path(b"cancelled"),
        reservation,
        &capability,
        0,
        &|epoch| epoch == HostEpoch::Writing(1),
        &mut cache,
    );
    assert_eq!(
        refused.err(),
        Some(HostRefusal::Cancelled(HostEpoch::Writing(1)))
    );
    assert!(!root.0.join("cancelled").exists());
    assert!(!root.0.join(".fgit-staged-cancelled").exists());
    assert_eq!(
        interrupted_ledger.snapshot().consumed(),
        plan.budget(),
        "started, interrupted work conservatively spends its original bound"
    );
    quiescent(interrupted_ledger);
    let (workspace, workspace_ledger) =
        materialize(plan, &capability, &root, b"permitted", Some(&mut cache));
    fixture.assert_original(&root.0.join("permitted"));
    close_workspace(workspace, workspace_ledger);
    close_cache(cache, cache_ledger);
    assert_eq!(fs::read_dir(&root.0).unwrap().count(), 0);
}

#[test]
#[ignore = "requires an existing unsupported filesystem, normally /dev/shm; no silent fixture skip"]
fn tmpfs_copy_fallback_and_required_refusal_are_explicit() {
    let parent = std::env::var_os("FGIT_SHARED_WORKSPACE_UNSUPPORTED_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/dev/shm"));
    let root = Scratch::under(&parent);
    let fixture = Fixture::<Sha1>::new(9, 1);
    let (plan, capability) = fixture.plan(1, false);
    let (mut cache, cache_ledger) = cache(&plan, &root, SharedInputPolicy::PreferReflink);
    assert!(
        !cache.stats().reflink_supported,
        "this test requires a filesystem that refuses real reflinks"
    );
    assert_required_refusal(&plan, &root, cache.stats().probe_entries);
    let (workspace, workspace_ledger) =
        materialize(plan, &capability, &root, b"copy", Some(&mut cache));
    fixture.assert_original(&root.0.join("copy"));
    let receipt = close_workspace(workspace, workspace_ledger);
    assert_copy_or_clone_accounting(&cache.stats(), &[receipt], fixture.payload_bytes());
    close_cache(cache, cache_ledger);
}

#[test]
#[ignore = "requires actual FICLONE support at FGIT_SHARED_WORKSPACE_TEST_ROOT; unsupported is a failure"]
fn required_reflink_isolation() {
    exercise_isolation::<Sha1>(&Scratch::configured(), SharedInputPolicy::RequireReflink);
    exercise_isolation::<Sha256>(&Scratch::configured(), SharedInputPolicy::RequireReflink);
}

/// `cargo test -p fgit-runner --test shared_workspace measure_shared_workspace -- --ignored --nocapture`
/// Fixed 384 KiB input per workspace, four workspaces per arm, three A/B/A
/// rounds. No caller-supplied size multiplier exists. Materialization includes
/// seed I/O when needed; verification and cleanup have separate timing. Each
/// B arm has a fresh cache and reports its actual support/fallback counters.
#[test]
#[ignore = "bounded real-filesystem A/B/A measurement; reports fallback honestly, without timing gates"]
fn measure_shared_workspace_materialization() {
    const WORKSPACES: usize = 4;
    let root = Scratch::configured();
    let fixture = Fixture::<Sha256>::new(9, 1);
    let (plan, capability) = fixture.plan(1, false);
    eprintln!(
        "round,arm,workspaces,input_bytes,copied_bytes,shared_bytes,seeded_bytes,reflink_supported,setup_ns,materialize_ns,cleanup_ns"
    );
    for round in 0..3 {
        for (arm, shared) in [("a_before", false), ("b_shared", true), ("a_after", false)] {
            let setup = Instant::now();
            let mut owned_cache =
                shared.then(|| cache(&plan, &root, SharedInputPolicy::PreferReflink));
            let setup_ns = setup.elapsed().as_nanos();
            let mut materialize_ns = 0;
            let mut cleanup_ns = 0;
            let mut receipts = Vec::new();
            for index in 0..WORKSPACES {
                let slot = format!("sample-{index}");
                let started = Instant::now();
                let (workspace, workspace_ledger) = materialize(
                    plan.clone(),
                    &capability,
                    &root,
                    slot.as_bytes(),
                    owned_cache.as_mut().map(|(cache, _)| cache),
                );
                materialize_ns += started.elapsed().as_nanos();
                fixture.assert_original(&root.0.join(&slot));
                let started = Instant::now();
                receipts.push(close_workspace(workspace, workspace_ledger));
                cleanup_ns += started.elapsed().as_nanos();
            }
            let stats = if let Some((cache, cache_ledger)) = owned_cache {
                let stats = cache.stats();
                assert_copy_or_clone_accounting(&stats, &receipts, fixture.payload_bytes());
                let started = Instant::now();
                close_cache(cache, cache_ledger);
                cleanup_ns += started.elapsed().as_nanos();
                Some(stats)
            } else {
                assert!(
                    receipts
                        .iter()
                        .all(|receipt| receipt.shared_host_bytes == 0)
                );
                None
            };
            let copied: u64 = receipts.iter().map(|receipt| receipt.copied_bytes).sum();
            let shared: u64 = receipts
                .iter()
                .map(|receipt| receipt.shared_host_bytes)
                .sum();
            assert_eq!(copied + shared, fixture.payload_bytes() * WORKSPACES as u64);
            eprintln!(
                "{round},{arm},{WORKSPACES},{},{copied},{shared},{},{},{setup_ns},{materialize_ns},{cleanup_ns}",
                fixture.payload_bytes(),
                stats.as_ref().map_or(0, |s| s.seeded_bytes),
                stats.as_ref().is_some_and(|s| s.reflink_supported)
            );
        }
    }
    assert_eq!(fs::read_dir(&root.0).unwrap().count(), 0);
}
