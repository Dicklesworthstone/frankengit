#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]
//! Real sparse host directories, source export, lease recovery and adversarial
//! path replacements. Foreign submodule objects never exist in the source.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_crypto::{GitHashAlgorithm, GitObjectKind, GitOid, NativeObjectIdentity, Sha1, Sha256};
use fgit_git_object::{AcceptanceProfile, ParseLimits, TreeEntry, emit_tree};
use fgit_resource::{
    Grade, LeakDisposition, ObligationLedger, RegionCloseOutcome, RegionId, TerminalEvidence,
};
use fgit_runner::sparse_workspace::{
    HostEpoch, HostRefusal, SharedInputCache, SharedInputCachePlan, SharedInputPolicy,
    SparseWorkspace, SparseWorkspacePlan,
};
use fgit_treefs::{
    BaseView, ExportLimits, ExportPlanner, ObjectSource, ObjectSourceError, PathPolicy, ReadGrant,
    SparseEntryKind, SparseLimits, SparseManifest, TreeCapability, TreePath, WorkspaceId,
};
use fgit_types::{CodecVersion, DigestAlgorithmId, DigestBytes, RepositoryCommitId, RepositoryId};

const REPOSITORY: RepositoryId = RepositoryId::from_bytes([0x71; 16]);
const LIMITS: SparseLimits = SparseLimits {
    max_entries: 16,
    max_entry_bytes: 256,
    max_payload_bytes: 512,
};
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fg-gitlink-workspace-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn parent(&self) -> File {
        File::open(&self.0).unwrap()
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("remove only this test's private root");
    }
}

#[derive(Default)]
struct Source {
    objects: BTreeMap<Vec<u8>, (GitObjectKind, Vec<u8>)>,
    reads: RefCell<Vec<Vec<u8>>>,
}
impl Source {
    fn put<A: GitHashAlgorithm>(&mut self, kind: GitObjectKind, body: Vec<u8>) -> GitOid<A> {
        let oid = GitOid::<A>::of_object(kind, &body);
        self.objects
            .insert(oid.digest_bytes().to_vec(), (kind, body));
        oid
    }
    fn tree<A: GitHashAlgorithm>(&mut self, entries: &[(&[u8], &[u8], GitOid<A>)]) -> GitOid<A> {
        let entries = entries
            .iter()
            .map(|(mode, name, oid)| TreeEntry {
                mode: mode.to_vec(),
                name: name.to_vec(),
                object_id: oid.digest_bytes().to_vec(),
            })
            .collect::<Vec<_>>();
        self.put::<A>(
            GitObjectKind::Tree,
            emit_tree(
                &entries,
                AcceptanceProfile::GitCompatibleImport,
                &parse_limits::<A>(),
            )
            .unwrap(),
        )
    }
}
impl<A: GitHashAlgorithm> ObjectSource<A> for Source {
    fn read_object(
        &self,
        oid: &GitOid<A>,
        kind: GitObjectKind,
        _: &ReadGrant,
    ) -> Result<Vec<u8>, ObjectSourceError> {
        self.reads.borrow_mut().push(oid.digest_bytes().to_vec());
        let (actual, body) =
            self.objects
                .get(oid.digest_bytes())
                .ok_or_else(|| ObjectSourceError::NotFound {
                    oid_hex: hex(oid.digest_bytes()),
                })?;
        assert_eq!(*actual, kind);
        Ok(body.clone())
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn path(bytes: &[u8]) -> TreePath {
    TreePath::parse_default(bytes).unwrap()
}
fn parse_limits<A: GitHashAlgorithm>() -> ParseLimits {
    ParseLimits {
        tree_reference_bytes: A::DIGEST_LEN,
        ..ParseLimits::default()
    }
}
fn capability() -> TreeCapability {
    TreeCapability::new(
        WorkspaceId::from_bytes([0x72; 16]),
        REPOSITORY,
        vec![path(b"README"), path(b"vendor")],
        vec![path(b"README"), path(b"vendor")],
    )
}

struct Fixture<A: GitHashAlgorithm> {
    source: Source,
    base: BaseView<A>,
    manifest: Arc<SparseManifest<A>>,
    foreign: GitOid<A>,
}
impl<A: GitHashAlgorithm> Fixture<A> {
    fn new(foreign_body: &[u8]) -> Self {
        let mut source = Source::default();
        let foreign = GitOid::<A>::of_object(GitObjectKind::Commit, foreign_body);
        let readme = source.put::<A>(GitObjectKind::Blob, b"original\n".to_vec());
        let tool = source.put::<A>(GitObjectKind::Blob, b"#!/bin/sh\nexit 0\n".to_vec());
        let vendor =
            source.tree::<A>(&[(b"160000", b"module", foreign), (b"100755", b"tool", tool)]);
        let tree = source.tree::<A>(&[
            (b"100644", b"README", readme),
            (b"40000", b"vendor", vendor),
        ]);
        let commit = source.put::<A>(GitObjectKind::Commit, format!(
            "tree {}\nauthor A <a@example.invalid> 1 +0000\ncommitter A <a@example.invalid> 1 +0000\n\nopaque workspace\n",
            hex(tree.digest_bytes()),
        ).into_bytes());
        let base = BaseView::new(
            REPOSITORY,
            RepositoryCommitId::from_digest(
                DigestAlgorithmId::try_new(0x8043).unwrap(),
                CodecVersion::new(1, 0),
                DigestBytes::try_new(&[0x73; 32]).unwrap(),
            ),
            commit,
            tree,
            parse_limits::<A>(),
            PathPolicy::default(),
        );
        let manifest =
            Arc::new(SparseManifest::build(&base, &source, &mut capability(), 0, LIMITS).unwrap());
        Self {
            source,
            base,
            manifest,
            foreign,
        }
    }
    fn plan(&self, outputs: &[&[u8]]) -> SparseWorkspacePlan<A> {
        SparseWorkspacePlan::new(
            self.manifest.clone(),
            outputs.iter().map(|bytes| path(bytes)).collect(),
            &capability(),
            0,
            LIMITS,
        )
        .unwrap()
    }
    fn assert_no_foreign_read(&self) {
        assert!(
            !self
                .source
                .objects
                .contains_key(self.foreign.digest_bytes())
        );
        assert!(
            self.source
                .reads
                .borrow()
                .iter()
                .all(|id| id != self.foreign.digest_bytes())
        );
    }
}
fn ledger<A: GitHashAlgorithm>(plan: &SparseWorkspacePlan<A>) -> ObligationLedger {
    ObligationLedger::root(
        RegionId::new(1),
        LeakDisposition::RecordAndContinue,
        plan.budget(),
    )
}
fn create<A: GitHashAlgorithm>(
    scratch: &Scratch,
    plan: &SparseWorkspacePlan<A>,
    ledger: &ObligationLedger,
    name: &[u8],
) -> SparseWorkspace<A> {
    SparseWorkspace::materialize(
        plan.clone(),
        scratch.parent(),
        path(name),
        ledger
            .reserve(plan.reservation(), ledger.grant(plan.budget()).unwrap())
            .unwrap(),
        &capability(),
        0,
        &|_| false,
    )
    .unwrap()
}
fn quiescent(ledger: ObligationLedger) {
    assert!(matches!(ledger.close(), RegionCloseOutcome::Quiescent(_)));
}

fn materialize_and_export<A: GitHashAlgorithm>() {
    let scratch = Scratch::new();
    let mut fixture = Fixture::<A>::new(b"absent foreign commit");
    let plan = fixture.plan(&[b"README"]);
    assert!(plan.has_opaque_inputs());
    let obligations = ledger(&plan);
    let mut workspace = create(&scratch, &plan, &obligations, b"work");
    let module = workspace.tool_directory().join("vendor/module");
    assert!(fs::symlink_metadata(&module).unwrap().is_dir());
    assert_eq!(fs::read_dir(&module).unwrap().count(), 0);
    assert_eq!(
        fs::metadata(workspace.tool_directory().join("vendor/tool"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    workspace.verify_opaque_inputs(&|_| false).unwrap();
    assert!(
        workspace
            .import(&capability(), 0, &|_| false)
            .unwrap()
            .is_empty()
    );
    fs::write(workspace.tool_directory().join("README"), b"edited\n").unwrap();
    let log = workspace.import(&capability(), 0, &|_| false).unwrap();
    assert_eq!(log.len(), 1);
    let (overlay, evaluation) = log.evaluate(&|name| {
        fixture
            .manifest
            .entries()
            .iter()
            .any(|entry| entry.path() == name)
    });
    assert!(evaluation.errors().is_empty());
    let exported = ExportPlanner::new(ExportLimits::default(), parse_limits::<A>())
        .plan(
            &fixture.base,
            &fixture.source,
            &mut capability(),
            &overlay,
            0,
            &|| false,
        )
        .unwrap();
    assert!(exported.verify_all());
    for object in exported.objects() {
        fixture
            .source
            .put::<A>(object.kind(), object.body().to_vec());
    }
    let exported_base = BaseView::<A>::new(
        REPOSITORY,
        fixture.base.base_rcr_id(),
        *fixture.base.base_commit_oid(),
        *exported.root_tree(),
        parse_limits::<A>(),
        PathPolicy::default(),
    );
    let rebuilt = SparseManifest::build(
        &exported_base,
        &fixture.source,
        &mut capability(),
        0,
        LIMITS,
    )
    .unwrap();
    let module = rebuilt
        .entries()
        .iter()
        .find(|entry| entry.path() == &path(b"vendor/module"))
        .unwrap();
    assert_eq!(module.kind(), &SparseEntryKind::Gitlink);
    assert_eq!(module.source_oid(), &fixture.foreign);
    let readme = rebuilt
        .entries()
        .iter()
        .find(|entry| entry.path() == &path(b"README"))
        .unwrap();
    assert_eq!(readme.kind().body(), Some(b"edited\n".as_slice()));
    fixture.assert_no_foreign_read();
    let receipt = workspace.close().unwrap();
    let TerminalEvidence::Acknowledged(receipt, _) = receipt.into_evidence() else {
        panic!("close must acknowledge cleanup");
    };
    assert_eq!(receipt.created_entries, 5); // Four source entries plus marker.
    assert_eq!(
        receipt.copied_bytes,
        fixture.manifest.receipt().payload_bytes() as u64
    );
    assert_eq!(receipt.imported_entries, 1);
    assert_eq!(receipt.removed_entries, 5);
    assert!(!scratch.0.join("work").exists());
    quiescent(obligations);
}

#[test]
fn ordinary_edits_preserve_uninitialized_gitlinks_through_native_export_in_both_formats() {
    materialize_and_export::<Sha1>();
    materialize_and_export::<Sha256>();
}

fn output_boundaries<A: GitHashAlgorithm>() {
    let fixture = Fixture::<A>::new(b"absent commit");
    for output in [
        b"vendor".as_slice(),
        b"vendor/module",
        b"vendor/module/new",
        b"vendor/module/deep/new",
    ] {
        assert!(
            matches!(SparseWorkspacePlan::new(fixture.manifest.clone(), vec![path(output)],
            &capability(), 0, LIMITS), Err(HostRefusal::UnsupportedEntry(rejected)) if rejected == path(output))
        );
    }
    // Component boundaries matter: neighboring names are ordinary source outputs.
    let plan = fixture.plan(&[b"vendor/module-sibling"]);
    let scratch = Scratch::new();
    let obligations = ledger(&plan);
    let budget = plan.budget().with(
        Grade::FileDescriptors,
        plan.reservation().max_descriptors - 1,
    );
    assert!(matches!(
        SparseWorkspace::materialize(
            plan.clone(),
            scratch.parent(),
            path(b"underfunded"),
            obligations
                .reserve(plan.reservation(), obligations.grant(budget).unwrap())
                .unwrap(),
            &capability(),
            0,
            &|_| false,
        ),
        Err(HostRefusal::ReservationMismatch)
    ));
    assert_eq!(fs::read_dir(&scratch.0).unwrap().count(), 0);
    let workspace = create(&scratch, &plan, &obligations, b"work");
    for output in [b"vendor/module".as_slice(), b"vendor/module/private"] {
        assert!(
            matches!(workspace.read_artifact_output(&path(output), 64, &|_| false),
            Err(HostRefusal::UnsupportedEntry(rejected)) if rejected == path(output))
        );
    }
    assert_eq!(
        workspace
            .read_artifact_output(&path(b"README"), 64, &|_| false)
            .unwrap()
            .unwrap()
            .0,
        b"original\n"
    );
    let narrowed = TreeCapability::new(
        capability().workspace_id(),
        REPOSITORY,
        vec![path(b"README")],
        vec![path(b"README")],
    );
    assert!(matches!(
        SparseWorkspacePlan::new(fixture.manifest.clone(), vec![], &narrowed, 0, LIMITS),
        Err(HostRefusal::Capability(_))
    ));
    let mut revoked = capability();
    revoked.revoke();
    assert!(matches!(
        SparseWorkspacePlan::new(fixture.manifest.clone(), vec![], &revoked, 0, LIMITS),
        Err(HostRefusal::Capability(_))
    ));
    let _ = workspace.close().unwrap();
    quiescent(obligations);
    fixture.assert_no_foreign_read();
}

#[test]
fn gitlink_paths_cannot_become_outputs_or_artifacts_and_still_require_read_authority() {
    output_boundaries::<Sha1>();
    output_boundaries::<Sha256>();
}

fn tampering<A: GitHashAlgorithm>() {
    for mutation in 0..6 {
        let scratch = Scratch::new();
        let fixture = Fixture::<A>::new(b"absent commit");
        let plan = fixture.plan(&[b"README"]);
        let obligations = ledger(&plan);
        let mut workspace = create(&scratch, &plan, &obligations, b"work");
        let module = workspace.tool_directory().join("vendor/module");
        let sentinel = scratch.0.join("untouched");
        fs::create_dir(&sentinel).unwrap();
        fs::write(sentinel.join("secret"), b"outside bytes").unwrap();
        match mutation {
            0 => fs::write(module.join("untracked"), b"foreign bytes").unwrap(),
            1 => {
                fs::remove_dir(&module).unwrap();
                symlink(&sentinel, &module).unwrap();
            }
            2 => fs::remove_dir(&module).unwrap(),
            3 => {
                fs::remove_dir(&module).unwrap();
                fs::write(&module, b"replacement").unwrap();
            }
            4 => {
                fs::remove_dir(&module).unwrap();
                fs::DirBuilder::new().mode(0o700).create(&module).unwrap();
            }
            5 => fs::set_permissions(&module, fs::Permissions::from_mode(0o755)).unwrap(),
            _ => unreachable!(),
        }
        fs::write(
            workspace.tool_directory().join("README"),
            b"a valid sibling edit\n",
        )
        .unwrap();
        assert!(workspace.verify_opaque_inputs(&|_| false).is_err());
        assert!(
            workspace.import(&capability(), 0, &|_| false).is_err(),
            "no partial sibling edit may escape mutation {mutation}"
        );
        assert!(
            workspace
                .read_artifact_output(&path(b"README"), 64, &|_| false)
                .is_err()
        );
        let receipt = workspace.close().unwrap();
        let TerminalEvidence::Acknowledged(receipt, _) = receipt.into_evidence() else {
            panic!("cleanup must settle");
        };
        assert_eq!(receipt.imported_entries, 0);
        assert_eq!(fs::read(sentinel.join("secret")).unwrap(), b"outside bytes");
        quiescent(obligations);
        fixture.assert_no_foreign_read();
    }
}

#[test]
fn populated_replaced_deleted_symlinked_and_repermissioned_gitlinks_refuse_and_cleanup_safely() {
    tampering::<Sha1>();
    tampering::<Sha256>();
}

fn interruption_and_reopen<A: GitHashAlgorithm>() {
    let scratch = Scratch::new();
    let fixture = Fixture::<A>::new(b"absent commit");
    let plan = fixture.plan(&[b"README"]);
    for epoch in [
        HostEpoch::CreatingParent(1),
        HostEpoch::ValidatingGitlink(0),
        HostEpoch::Visible,
    ] {
        let obligations = ledger(&plan);
        let result = SparseWorkspace::materialize(
            plan.clone(),
            scratch.parent(),
            path(b"work"),
            obligations
                .reserve(
                    plan.reservation(),
                    obligations.grant(plan.budget()).unwrap(),
                )
                .unwrap(),
            &capability(),
            0,
            &|observed| observed == epoch,
        );
        assert!(matches!(result, Err(HostRefusal::Cancelled(observed)) if observed == epoch));
        assert_eq!(fs::read_dir(&scratch.0).unwrap().count(), 0);
        quiescent(obligations);
    }
    let obligations = ledger(&plan);
    let mut workspace = create(&scratch, &plan, &obligations, b"work");
    assert!(matches!(
        workspace.import(&capability(), 0, &|epoch| epoch
            == HostEpoch::ValidatingGitlink(0)),
        Err(HostRefusal::Cancelled(HostEpoch::ValidatingGitlink(0)))
    ));
    assert!(
        workspace
            .import(&capability(), 0, &|_| false)
            .unwrap()
            .is_empty()
    );
    fs::write(workspace.tool_directory().join("README"), b"valid\n").unwrap();
    let planted = Cell::new(false);
    let directory = workspace.tool_directory();
    assert!(matches!(workspace.import(&capability(), 0, &|epoch| {
        if epoch == HostEpoch::Imported && !planted.replace(true) {
            fs::write(directory.join("vendor/module/late"), b"late").unwrap();
        }
        false
    }), Err(HostRefusal::UndeclaredChange(rejected)) if rejected == path(b"vendor/module")));
    fs::remove_file(directory.join("vendor/module/late")).unwrap();
    drop(workspace);
    assert!(matches!(
        obligations.close(),
        RegionCloseOutcome::ContainmentFailure(_)
    ));

    let recovery = ledger(&plan);
    let budget = plan.budget().with(
        Grade::FileDescriptors,
        plan.reservation().max_descriptors - 1,
    );
    assert!(matches!(
        SparseWorkspace::reopen(
            plan.clone(),
            scratch.parent(),
            path(b"work"),
            recovery
                .reserve(plan.reservation(), recovery.grant(budget).unwrap())
                .unwrap(),
            &capability(),
            0,
        ),
        Err(HostRefusal::ReservationMismatch)
    ));
    assert!(scratch.0.join("work/vendor/module").is_dir());
    let changed = Fixture::<A>::new(b"different opaque target").plan(&[b"README"]);
    assert_ne!(plan.reservation().plan, changed.reservation().plan);
    let attempt = |selected: &SparseWorkspacePlan<A>| {
        SparseWorkspace::reopen(
            selected.clone(),
            scratch.parent(),
            path(b"work"),
            recovery
                .reserve(
                    selected.reservation(),
                    recovery.grant(selected.budget()).unwrap(),
                )
                .unwrap(),
            &capability(),
            0,
        )
    };
    assert!(matches!(
        attempt(&changed),
        Err(HostRefusal::IdentityMismatch)
    ));
    fs::write(scratch.0.join("work/vendor/module/late"), b"late").unwrap();
    assert!(matches!(
        attempt(&plan),
        Err(HostRefusal::UndeclaredChange(_))
    ));
    fs::remove_file(scratch.0.join("work/vendor/module/late")).unwrap();
    let mut recovered = attempt(&plan).unwrap();
    recovered.verify_opaque_inputs(&|_| false).unwrap();
    assert_eq!(
        recovered
            .import(&capability(), 0, &|_| false)
            .unwrap()
            .len(),
        1
    );
    let _ = recovered.close().unwrap();
    quiescent(recovery);
    fixture.assert_no_foreign_read();
}

#[test]
fn cancellation_races_and_reopen_keep_gitlinks_opaque_without_losing_lease_cleanup() {
    interruption_and_reopen::<Sha1>();
    interruption_and_reopen::<Sha256>();
}

fn shared_inputs<A: GitHashAlgorithm>() {
    let scratch = Scratch::new();
    let fixture = Fixture::<A>::new(b"absent commit");
    let plan = fixture.plan(&[b"README"]);
    let cache_plan = SharedInputCachePlan::for_workspace(&plan, SharedInputPolicy::PreferReflink);
    assert_eq!(
        cache_plan.reservation().max_bytes,
        fixture.manifest.receipt().payload_bytes() as u64
    );
    let cache_ledger = ObligationLedger::root(
        RegionId::new(2),
        LeakDisposition::RecordAndContinue,
        cache_plan.budget(),
    );
    let reservation = cache_ledger
        .reserve(
            cache_plan.reservation(),
            cache_ledger.grant(cache_plan.budget()).unwrap(),
        )
        .unwrap();
    let mut cache =
        SharedInputCache::create(cache_plan.clone(), scratch.parent(), reservation, &|| false)
            .unwrap();
    for name in [b"first".as_slice(), b"second"] {
        let obligations = ledger(&plan);
        let workspace = SparseWorkspace::materialize_with_cache(
            plan.clone(),
            scratch.parent(),
            path(name),
            obligations
                .reserve(
                    plan.reservation(),
                    obligations.grant(plan.budget()).unwrap(),
                )
                .unwrap(),
            &capability(),
            0,
            &|_| false,
            &mut cache,
        )
        .unwrap();
        workspace.verify_opaque_inputs(&|_| false).unwrap();
        assert_eq!(
            fs::read_dir(workspace.tool_directory().join("vendor/module"))
                .unwrap()
                .count(),
            0
        );
        let _ = workspace.close().unwrap();
        quiescent(obligations);
    }
    let changed = Fixture::<A>::new(b"different target").plan(&[b"README"]);
    let changed_cache =
        SharedInputCachePlan::for_workspace(&changed, SharedInputPolicy::PreferReflink);
    assert_ne!(
        cache_plan.reservation().scope,
        changed_cache.reservation().scope
    );
    let obligations = ledger(&changed);
    assert!(matches!(
        SparseWorkspace::materialize_with_cache(
            changed.clone(),
            scratch.parent(),
            path(b"different"),
            obligations
                .reserve(
                    changed.reservation(),
                    obligations.grant(changed.budget()).unwrap()
                )
                .unwrap(),
            &capability(),
            0,
            &|_| false,
            &mut cache
        ),
        Err(HostRefusal::SharedInputScopeMismatch)
    ));
    assert!(!scratch.0.join("different").exists());
    quiescent(obligations);
    let _ = cache.close().unwrap();
    quiescent(cache_ledger);
    fixture.assert_no_foreign_read();
}

#[test]
fn shared_input_cache_handles_gitlinks_without_caching_or_delegating_foreign_bytes() {
    shared_inputs::<Sha1>();
    shared_inputs::<Sha256>();
}
