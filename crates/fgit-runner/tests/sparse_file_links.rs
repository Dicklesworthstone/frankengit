#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]
//! The explicit selected-file projection uses ordinary private files, keeps
//! native Git links exact, and never treats link text as host traversal power.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt, symlink};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_crypto::{GitHashAlgorithm, GitObjectKind, GitOid, NativeObjectIdentity, Sha1, Sha256};
use fgit_git_object::{AcceptanceProfile, ParseLimits, TreeEntry, emit_tree};
use fgit_resource::{
    Grade, LeakDisposition, ObligationLedger, RegionCloseOutcome, RegionId, TerminalEvidence,
};
use fgit_runner::Commitment;
use fgit_runner::sparse_workspace::{
    HostEpoch, HostRefusal, JobInput, SharedInputCache, SharedInputCachePlan, SharedInputPolicy,
    SparseWorkspace, SparseWorkspacePlan, SymlinkInputPolicy,
};
use fgit_treefs::{
    BaseView, ExportLimits, ExportPlanner, FileMode, ObjectSource, ObjectSourceError, PathPolicy,
    ReadGrant, SparseCandidateManifest, SparseEntryKind, SparseLimits, SparseManifest,
    SymlinkPolicy, TreeCapability, TreePath, WorkspaceId,
};
use fgit_types::{CodecVersion, DigestAlgorithmId, DigestBytes, RepositoryCommitId, RepositoryId};

const REPOSITORY: RepositoryId = RepositoryId::from_bytes([0x81; 16]);
const LIMITS: SparseLimits = SparseLimits {
    max_entries: 64,
    max_entry_bytes: 8192,
    max_payload_bytes: 32768,
};
const EDIT: &[u8] = b"original\n";
const TOOL: &[u8] = b"#!/bin/sh\nexit 0\n";
const KEEP: &[u8] = b"nested\n";
const PAYLOAD: &[u8] = b"selected target\n";
const COPY: SymlinkInputPolicy = SymlinkInputPolicy::SelectedFileCopies;
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fg-file-link-inputs-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
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
        fs::remove_dir_all(&self.0).expect("remove only this test's private directory");
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
        let mut entries = entries
            .iter()
            .map(|(mode, name, oid)| TreeEntry {
                mode: mode.to_vec(),
                name: name.to_vec(),
                object_id: oid.digest_bytes().to_vec(),
            })
            .collect::<Vec<_>>();
        entries.sort_by(fgit_git_object::compare_tree_entries);
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
    fn commit<A: GitHashAlgorithm>(
        &mut self,
        tree: GitOid<A>,
        parent: Option<GitOid<A>>,
    ) -> GitOid<A> {
        let parent = parent
            .map(|oid| format!("parent {}\n", hex(oid.digest_bytes())))
            .unwrap_or_default();
        self.put::<A>(GitObjectKind::Commit, format!("tree {}\n{parent}author A <a@example.invalid> 1 +0000\ncommitter A <a@example.invalid> 1 +0000\n\nfile link inputs\n", hex(tree.digest_bytes())).into_bytes())
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
        WorkspaceId::from_bytes([0x82; 16]),
        REPOSITORY,
        vec![path(b"project")],
        vec![path(b"project")],
    )
}

struct Fixture<A: GitHashAlgorithm> {
    source: Source,
    base: BaseView<A>,
    manifest: Arc<SparseManifest<A>>,
    links: BTreeMap<TreePath, (GitOid<A>, Vec<u8>)>,
    regular_bytes: usize,
}
impl<A: GitHashAlgorithm> Fixture<A> {
    fn new(links: &[(&[u8], &[u8])], payload: &[u8], foreign: bool) -> Self {
        let mut source = Source::default();
        let edit = source.put::<A>(GitObjectKind::Blob, EDIT.to_vec());
        let target = source.put::<A>(GitObjectKind::Blob, payload.to_vec());
        let tool = source.put::<A>(GitObjectKind::Blob, TOOL.to_vec());
        let keep = source.put::<A>(GitObjectKind::Blob, KEEP.to_vec());
        let mut dir_entries: Vec<(&[u8], &[u8], GitOid<A>)> = vec![(b"100644", b"keep", keep)];
        let mut recorded = BTreeMap::new();
        for (name, text) in links {
            let oid = source.put::<A>(GitObjectKind::Blob, text.to_vec());
            dir_entries.push((b"120000", name, oid));
            let mut full = b"project/dir/".to_vec();
            full.extend_from_slice(name);
            recorded.insert(path(&full), (oid, text.to_vec()));
        }
        let dir = source.tree::<A>(&dir_entries);
        let empty = source.tree::<A>(&[]);
        let mut entries: Vec<(&[u8], &[u8], GitOid<A>)> = vec![
            (b"40000", b"dir", dir),
            (b"100644", b"edit", edit),
            (b"40000", b"empty", empty),
            (b"100644", b"target", target),
            (b"100755", b"tool", tool),
        ];
        if foreign {
            entries.push((
                b"160000",
                b"foreign",
                GitOid::<A>::of_object(GitObjectKind::Commit, b"unavailable foreign commit"),
            ));
        }
        let project = source.tree::<A>(&entries);
        let root = source.tree::<A>(&[(b"40000", b"project", project)]);
        let commit = source.commit::<A>(root, None);
        let base = BaseView::<A>::new(
            REPOSITORY,
            RepositoryCommitId::from_digest(
                DigestAlgorithmId::try_new(0x8043).unwrap(),
                CodecVersion::new(1, 0),
                DigestBytes::try_new(&[0x83; 32]).unwrap(),
            ),
            commit,
            root,
            parse_limits::<A>(),
            PathPolicy::default(),
        );
        let manifest =
            Arc::new(SparseManifest::build(&base, &source, &mut capability(), 0, LIMITS).unwrap());
        Self {
            source,
            base,
            manifest,
            links: recorded,
            regular_bytes: EDIT.len() + payload.len() + TOOL.len() + KEEP.len(),
        }
    }
    fn plan(&self, outputs: &[&[u8]]) -> SparseWorkspacePlan<A> {
        SparseWorkspacePlan::new_with_symlink_policy(
            self.manifest.clone(),
            outputs.iter().map(|bytes| path(bytes)).collect(),
            &capability(),
            0,
            LIMITS,
            COPY,
        )
        .unwrap()
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
    obligations: &ObligationLedger,
    name: &[u8],
) -> SparseWorkspace<A> {
    SparseWorkspace::materialize(
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
    )
    .unwrap()
}
fn quiescent(obligations: ObligationLedger) {
    assert!(matches!(
        obligations.close(),
        RegionCloseOutcome::Quiescent(_)
    ));
}

fn native_identity<A: GitHashAlgorithm>() {
    let mut fixture = Fixture::<A>::new(
        &[(b"copy", b".././target"), (b"exec", b"../tool")],
        PAYLOAD,
        false,
    );
    let plan = fixture.plan(&[b"project/edit"]);
    assert_eq!(plan.symlink_policy(), COPY);
    assert!(plan.has_opaque_inputs());
    assert_eq!(plan.reservation().max_descriptors, 7); // Four pinned regular files plus inspection headroom.
    let scratch = Scratch::new();
    let obligations = ledger(&plan);
    let reads = fixture.source.reads.borrow().len();
    let mut workspace = create(&scratch, &plan, &obligations, b"work");
    assert_eq!(
        fixture.source.reads.borrow().len(),
        reads,
        "projection must not fetch through link text"
    );
    for (alias, target, expected, permissions) in [
        ("project/dir/copy", "project/target", PAYLOAD, 0o400),
        ("project/dir/exec", "project/tool", TOOL, 0o500),
    ] {
        let link_path = workspace.tool_directory().join(alias);
        let target_path = workspace.tool_directory().join(target);
        let link = fs::symlink_metadata(&link_path).unwrap();
        let source = fs::metadata(&target_path).unwrap();
        assert!(link.is_file() && !link.file_type().is_symlink());
        assert_ne!((link.dev(), link.ino()), (source.dev(), source.ino()));
        assert_eq!(link.nlink(), 1);
        assert_eq!(link.permissions().mode() & 0o7777, permissions);
        assert_eq!(source.permissions().mode() & 0o7777, permissions);
        assert_eq!(fs::read(link_path).unwrap(), expected);
    }
    workspace.verify_opaque_inputs(&|_| false).unwrap();
    assert!(
        workspace
            .import(&capability(), 0, &|_| false)
            .unwrap()
            .is_empty()
    );
    fs::write(
        workspace.tool_directory().join("project/edit"),
        b"changed\n",
    )
    .unwrap();
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
    for (path, (oid, target)) in &fixture.links {
        let entry = rebuilt
            .entries()
            .iter()
            .find(|entry| entry.path() == path)
            .unwrap();
        assert_eq!(
            entry.kind(),
            &SparseEntryKind::Symlink {
                target: target.clone()
            }
        );
        assert_eq!(entry.source_oid(), oid);
    }
    let TerminalEvidence::Acknowledged(receipt, _) = workspace.close().unwrap().into_evidence()
    else {
        panic!("cleanup acknowledgement");
    };
    assert_eq!(
        receipt.copied_bytes,
        (fixture.regular_bytes + PAYLOAD.len() + TOOL.len()) as u64
    );
    assert_eq!(receipt.shared_host_bytes, 0);
    assert_eq!(receipt.imported_entries, 1);
    assert_eq!(
        receipt.created_entries,
        fixture.manifest.entries().len() as u64 + 1
    );
    assert_eq!(
        obligations
            .snapshot()
            .available()
            .get(Grade::FileDescriptors),
        plan.reservation().max_descriptors
    );
    assert_eq!(fs::read_dir(&scratch.0).unwrap().count(), 0);
    quiescent(obligations);
}

#[test]
fn selected_file_copies_are_regular_readonly_private_and_preserve_both_native_link_formats() {
    native_identity::<Sha1>();
    native_identity::<Sha256>();
}

fn resolution_and_authority<A: GitHashAlgorithm>() {
    for text in [
        b"".as_slice(),
        b"/project/target",
        b"../../../outside",
        b"../missing",
        b"../empty",
        b"../foreign",
        b"../target/",
        b"../target/../target",
        b"../missing/../target",
        b"../target\0suffix",
        b"../.git/config",
    ] {
        let fixture = Fixture::<A>::new(&[(b"copy", text)], PAYLOAD, true);
        let reads = fixture.source.reads.borrow().len();
        assert!(
            matches!(
                SparseWorkspacePlan::new_with_symlink_policy(
                    fixture.manifest.clone(),
                    vec![],
                    &capability(),
                    0,
                    LIMITS,
                    COPY
                ),
                Err(HostRefusal::UnsupportedEntry(_))
            ),
            "must reject target {text:?}"
        );
        assert_eq!(fixture.source.reads.borrow().len(), reads);
        let foreign = GitOid::<A>::of_object(GitObjectKind::Commit, b"unavailable foreign commit");
        assert!(!fixture.source.objects.contains_key(foreign.digest_bytes()));
        assert!(
            fixture
                .source
                .reads
                .borrow()
                .iter()
                .all(|oid| oid.as_slice() != foreign.digest_bytes())
        );
    }
    for links in [
        vec![
            (b"copy".as_slice(), b"other".as_slice()),
            (b"other", b"../target"),
        ],
        vec![
            (b"copy".as_slice(), b"other/../keep".as_slice()),
            (b"other", b"../target"),
        ],
        vec![
            (b"copy".as_slice(), b"other".as_slice()),
            (b"other", b"copy"),
        ],
    ] {
        let fixture = Fixture::<A>::new(&links, PAYLOAD, false);
        assert!(matches!(
            SparseWorkspacePlan::new_with_symlink_policy(
                fixture.manifest,
                vec![],
                &capability(),
                0,
                LIMITS,
                COPY
            ),
            Err(HostRefusal::UnsupportedEntry(_))
        ));
    }
    let fixture = Fixture::<A>::new(&[(b"copy", b"../dir/.././target")], PAYLOAD, false);
    fixture.plan(&[]); // Positive counterpart traverses only an admitted ordinary directory.
    assert!(matches!(
        SparseWorkspacePlan::new(fixture.manifest.clone(), vec![], &capability(), 0, LIMITS),
        Err(HostRefusal::UnsupportedEntry(_))
    ));
    let narrow = TreeCapability::new(
        capability().workspace_id(),
        REPOSITORY,
        vec![path(b"project/dir")],
        vec![],
    );
    let selected = Arc::new(
        SparseManifest::build(
            &fixture.base,
            &fixture.source,
            &mut narrow.clone(),
            0,
            LIMITS,
        )
        .unwrap(),
    );
    assert!(
        matches!(
            SparseWorkspacePlan::new_with_symlink_policy(
                selected,
                vec![],
                &narrow,
                0,
                LIMITS,
                COPY
            ),
            Err(HostRefusal::UnsupportedEntry(_))
        ),
        "a source object outside the selected manifest is not a target"
    );
    assert!(
        matches!(
            SparseWorkspacePlan::new_with_symlink_policy(
                fixture.manifest.clone(),
                vec![],
                &narrow,
                0,
                LIMITS,
                COPY
            ),
            Err(HostRefusal::Capability(_))
        ),
        "prebuilt broad manifests cannot enlarge current authority"
    );
    let mut revoked = capability();
    revoked.revoke();
    for denied in [
        revoked,
        capability().with_expiry(1),
        capability().with_symlink_policy(SymlinkPolicy::Refuse),
    ] {
        assert!(matches!(
            SparseWorkspacePlan::new_with_symlink_policy(
                fixture.manifest.clone(),
                vec![],
                &denied,
                2,
                LIMITS,
                COPY
            ),
            Err(HostRefusal::Capability(_))
        ));
    }
}

#[test]
fn metadata_resolution_refuses_missing_external_unselected_chained_and_nonfile_targets() {
    resolution_and_authority::<Sha1>();
    resolution_and_authority::<Sha256>();
}

fn output_and_budget_boundaries<A: GitHashAlgorithm>() {
    let fixture = Fixture::<A>::new(&[(b"copy", b"../target")], PAYLOAD, false);
    for output in [
        b"project".as_slice(),
        b"project/dir",
        b"project/dir/copy",
        b"project/dir/copy/child",
        b"project/target",
        b"project/target/child",
    ] {
        assert!(
            matches!(SparseWorkspacePlan::new_with_symlink_policy(fixture.manifest.clone(), vec![path(output)], &capability(), 0, LIMITS, COPY), Err(HostRefusal::UnsupportedEntry(rejected)) if rejected == path(output))
        );
    }
    let plan = fixture.plan(&[b"project/target-sibling"]);
    let scratch = Scratch::new();
    let obligations = ledger(&plan);
    let underfunded = plan.budget().with(
        Grade::FileDescriptors,
        plan.reservation().max_descriptors - 1,
    );
    assert!(matches!(
        SparseWorkspace::materialize(
            plan.clone(),
            scratch.parent(),
            path(b"underfunded"),
            obligations
                .reserve(plan.reservation(), obligations.grant(underfunded).unwrap())
                .unwrap(),
            &capability(),
            0,
            &|_| false
        ),
        Err(HostRefusal::ReservationMismatch)
    ));
    assert_eq!(fs::read_dir(&scratch.0).unwrap().count(), 0);
    let workspace = create(&scratch, &plan, &obligations, b"work");
    assert_eq!(
        obligations
            .snapshot()
            .available()
            .get(Grade::FileDescriptors),
        0
    );
    for output in [
        b"project".as_slice(),
        b"project/dir",
        b"project/dir/copy",
        b"project/dir/copy/child",
        b"project/target",
        b"project/target/child",
    ] {
        assert!(
            matches!(workspace.read_artifact_output(&path(output), 64, &|_| false), Err(HostRefusal::UnsupportedEntry(rejected)) if rejected == path(output))
        );
    }
    assert_eq!(
        workspace
            .read_artifact_output(&path(b"project/edit"), 64, &|_| false)
            .unwrap()
            .unwrap()
            .0,
        EDIT
    );
    let _settled = workspace.close().unwrap();
    assert_eq!(
        obligations
            .snapshot()
            .available()
            .get(Grade::FileDescriptors),
        plan.reservation().max_descriptors
    );
    quiescent(obligations);

    // The source inventory fits, but three host copies of this same selected
    // 1024-byte body require three independent logical write allowances.
    let payload = vec![b'x'; 1024];
    let fixture = Fixture::<A>::new(
        &[
            (b"a", b"../target"),
            (b"b", b"../target"),
            (b"c", b"../target"),
        ],
        &payload,
        false,
    );
    let expanded = fixture.regular_bytes + payload.len() * 3;
    assert!(fixture.manifest.receipt().payload_bytes() < expanded);
    let insufficient = SparseLimits {
        max_payload_bytes: expanded - 1,
        max_entry_bytes: 1024,
        ..LIMITS
    };
    assert!(matches!(
        SparseWorkspacePlan::new_with_symlink_policy(
            fixture.manifest.clone(),
            vec![],
            &capability(),
            0,
            insufficient,
            COPY
        ),
        Err(HostRefusal::ResourceLimit)
    ));
    let exact = SparseLimits {
        max_payload_bytes: expanded,
        ..insufficient
    };
    let exact_plan = SparseWorkspacePlan::new_with_symlink_policy(
        fixture.manifest.clone(),
        vec![],
        &capability(),
        0,
        exact,
        COPY,
    )
    .unwrap();
    let obligations = ledger(&exact_plan);
    let workspace = create(&scratch, &exact_plan, &obligations, b"exact");
    let TerminalEvidence::Acknowledged(receipt, _) = workspace.close().unwrap().into_evidence()
    else {
        panic!("cleanup acknowledgement");
    };
    assert_eq!(receipt.copied_bytes, expanded as u64);
    quiescent(obligations);
    let input = JobInput::new(
        b"dependency/value",
        vec![1],
        FileMode::Regular,
        Commitment::of_bytes(b"authorized upstream artifact"),
    )
    .unwrap();
    assert!(
        matches!(
            exact_plan.with_job_inputs(vec![input]),
            Err(HostRefusal::ResourceLimit)
        ),
        "supplemental inputs cannot reuse the alias expansion allowance"
    );
}

#[test]
fn input_aliases_and_targets_refuse_outputs_and_expanded_bytes_and_descriptors_are_funded() {
    output_and_budget_boundaries::<Sha1>();
    output_and_budget_boundaries::<Sha256>();
}

fn tampering<A: GitHashAlgorithm>() {
    for target in ["project/dir/copy", "project/target"] {
        for mutation in 0..6 {
            let fixture = Fixture::<A>::new(&[(b"copy", b"../target")], PAYLOAD, false);
            let plan = fixture.plan(&[b"project/edit"]);
            let scratch = Scratch::new();
            let obligations = ledger(&plan);
            let mut workspace = create(&scratch, &plan, &obligations, b"work");
            let selected = workspace.tool_directory().join(target);
            let outside = scratch.0.join("outside");
            fs::write(&outside, b"outside sentinel").unwrap();
            match mutation {
                0 => {
                    fs::set_permissions(&selected, fs::Permissions::from_mode(0o600)).unwrap();
                    fs::write(&selected, b"changed").unwrap();
                    fs::set_permissions(&selected, fs::Permissions::from_mode(0o400)).unwrap();
                }
                1 => fs::set_permissions(&selected, fs::Permissions::from_mode(0o600)).unwrap(),
                2 => fs::remove_file(&selected).unwrap(),
                3 => {
                    fs::remove_file(&selected).unwrap();
                    symlink(&outside, &selected).unwrap();
                }
                4 => {
                    fs::remove_file(&selected).unwrap();
                    fs::write(&selected, PAYLOAD).unwrap();
                    fs::set_permissions(&selected, fs::Permissions::from_mode(0o400)).unwrap();
                }
                5 => {
                    fs::remove_file(&selected).unwrap();
                    let other = if target.ends_with("copy") {
                        "project/target"
                    } else {
                        "project/dir/copy"
                    };
                    fs::hard_link(workspace.tool_directory().join(other), &selected).unwrap();
                }
                _ => unreachable!(),
            }
            fs::write(
                workspace.tool_directory().join("project/edit"),
                b"valid sibling edit\n",
            )
            .unwrap();
            assert!(
                workspace.verify_opaque_inputs(&|_| false).is_err(),
                "{target}: mutation {mutation}"
            );
            assert!(workspace.import(&capability(), 0, &|_| false).is_err());
            assert!(
                workspace
                    .read_artifact_output(&path(b"project/edit"), 64, &|_| false)
                    .is_err()
            );
            let TerminalEvidence::Acknowledged(receipt, _) =
                workspace.close().unwrap().into_evidence()
            else {
                panic!("cleanup acknowledgement");
            };
            assert_eq!(receipt.imported_entries, 0);
            assert_eq!(fs::read(&outside).unwrap(), b"outside sentinel");
            assert!(!scratch.0.join("work").exists());
            quiescent(obligations);
        }
    }
}

#[test]
fn mutating_either_projected_copy_or_original_target_refuses_the_whole_result_and_cleans_safely() {
    tampering::<Sha1>();
    tampering::<Sha256>();
}

fn cancellation_and_reopen<A: GitHashAlgorithm>() {
    let fixture = Fixture::<A>::new(&[(b"copy", b"../target")], PAYLOAD, false);
    let plan = fixture.plan(&[b"project/edit"]);
    let copy_index = fixture
        .manifest
        .entries()
        .iter()
        .position(|entry| entry.path() == &path(b"project/dir/copy"))
        .unwrap();
    let scratch = Scratch::new();
    for epoch in [
        HostEpoch::Writing(copy_index),
        HostEpoch::ValidatingLinkCopy(0),
        HostEpoch::Visible,
    ] {
        let obligations = ledger(&plan);
        assert!(
            matches!(SparseWorkspace::materialize(plan.clone(), scratch.parent(), path(b"cancel"), obligations.reserve(plan.reservation(), obligations.grant(plan.budget()).unwrap()).unwrap(), &capability(), 0, &|observed| observed == epoch), Err(HostRefusal::Cancelled(observed)) if observed == epoch)
        );
        assert_eq!(fs::read_dir(&scratch.0).unwrap().count(), 0);
        quiescent(obligations);
    }
    let obligations = ledger(&plan);
    let mut workspace = create(&scratch, &plan, &obligations, b"work");
    assert!(matches!(
        workspace.import(&capability(), 0, &|epoch| epoch
            == HostEpoch::ValidatingLinkCopy(0)),
        Err(HostRefusal::Cancelled(HostEpoch::ValidatingLinkCopy(0)))
    ));
    fs::write(
        workspace.tool_directory().join("project/edit"),
        b"changed\n",
    )
    .unwrap();
    let once = Cell::new(false);
    let selected = workspace.tool_directory().join("project/dir/copy");
    assert!(matches!(
        workspace.import(&capability(), 0, &|epoch| {
            if epoch == HostEpoch::Imported && !once.replace(true) {
                fs::set_permissions(&selected, fs::Permissions::from_mode(0o600)).unwrap();
            }
            false
        }),
        Err(HostRefusal::UndeclaredChange(_))
    ));
    fs::set_permissions(&selected, fs::Permissions::from_mode(0o400)).unwrap();
    drop(workspace);
    assert!(matches!(
        obligations.close(),
        RegionCloseOutcome::ContainmentFailure(_)
    ));
    let recovery = ledger(&plan);
    let underfunded = plan.budget().with(
        Grade::FileDescriptors,
        plan.reservation().max_descriptors - 1,
    );
    assert!(matches!(
        SparseWorkspace::reopen(
            plan.clone(),
            scratch.parent(),
            path(b"work"),
            recovery
                .reserve(plan.reservation(), recovery.grant(underfunded).unwrap())
                .unwrap(),
            &capability(),
            0
        ),
        Err(HostRefusal::ReservationMismatch)
    ));
    let changed =
        Fixture::<A>::new(&[(b"copy", b".././target")], PAYLOAD, false).plan(&[b"project/edit"]);
    assert_ne!(plan.reservation().plan, changed.reservation().plan);
    let reopen = |selected: &SparseWorkspacePlan<A>| {
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
        reopen(&changed),
        Err(HostRefusal::IdentityMismatch)
    ));
    let alias = scratch.0.join("work/project/dir/copy");
    fs::set_permissions(&alias, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&alias, b"different bytes").unwrap();
    fs::set_permissions(&alias, fs::Permissions::from_mode(0o400)).unwrap();
    assert!(matches!(
        reopen(&plan),
        Err(HostRefusal::UndeclaredChange(_))
    ));
    fs::set_permissions(&alias, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&alias, PAYLOAD).unwrap();
    fs::set_permissions(&alias, fs::Permissions::from_mode(0o400)).unwrap();
    let mut recovered = reopen(&plan).unwrap();
    recovered.verify_opaque_inputs(&|_| false).unwrap();
    assert_eq!(
        recovered
            .import(&capability(), 0, &|_| false)
            .unwrap()
            .len(),
        1
    );
    let _settled = recovered.close().unwrap();
    quiescent(recovery);
}

#[test]
fn cancellation_late_mutation_and_reopen_preserve_source_bound_immutable_inputs() {
    cancellation_and_reopen::<Sha1>();
    cancellation_and_reopen::<Sha256>();
}

fn policy_identity_and_candidates<A: GitHashAlgorithm>() {
    let plain = Fixture::<A>::new(&[], PAYLOAD, false);
    let old =
        SparseWorkspacePlan::new(plain.manifest.clone(), vec![], &capability(), 0, LIMITS).unwrap();
    let explicit_refuse = SparseWorkspacePlan::new_with_symlink_policy(
        plain.manifest.clone(),
        vec![],
        &capability(),
        0,
        LIMITS,
        SymlinkInputPolicy::Refuse,
    )
    .unwrap();
    assert_eq!(old.reservation(), explicit_refuse.reservation());
    assert_eq!(old.budget(), explicit_refuse.budget());
    let explicit_copy = plain.plan(&[]);
    assert!(!explicit_copy.has_opaque_inputs());
    assert_ne!(old.reservation().plan, explicit_copy.reservation().plan);
    let cache_scope = |plan: &SparseWorkspacePlan<A>| {
        SharedInputCachePlan::for_workspace(plan, SharedInputPolicy::PreferReflink)
            .reservation()
            .scope
    };
    assert_eq!(cache_scope(&old), cache_scope(&explicit_refuse));
    assert_ne!(cache_scope(&old), cache_scope(&explicit_copy));

    let mut fixture = Fixture::<A>::new(&[(b"copy", b"../target")], PAYLOAD, false);
    let candidate = fixture.source.commit::<A>(
        *fixture.base.base_tree_oid(),
        Some(*fixture.base.base_commit_oid()),
    );
    let manifest = Arc::new(
        SparseCandidateManifest::build(
            &fixture.base,
            &fixture.source,
            candidate,
            &mut capability(),
            0,
            parse_limits::<A>(),
            LIMITS,
        )
        .unwrap(),
    );
    assert!(matches!(
        SparseWorkspacePlan::for_candidate(manifest.clone(), &capability(), 0, LIMITS),
        Err(HostRefusal::UnsupportedEntry(_))
    ));
    let plan = SparseWorkspacePlan::for_candidate_with_symlink_policy(
        manifest,
        &capability(),
        0,
        LIMITS,
        COPY,
    )
    .unwrap();
    assert_ne!(
        plan.reservation().plan,
        fixture.plan(&[]).reservation().plan
    );
    let scratch = Scratch::new();
    let obligations = ledger(&plan);
    let mut workspace = create(&scratch, &plan, &obligations, b"candidate");
    assert_eq!(
        fs::read(workspace.tool_directory().join("project/dir/copy")).unwrap(),
        PAYLOAD
    );
    workspace.verify_opaque_inputs(&|_| false).unwrap();
    assert!(matches!(
        workspace.import(&capability(), 0, &|_| false),
        Err(HostRefusal::IdentityMismatch)
    ));
    let _settled = workspace.close().unwrap();
    quiescent(obligations);
}

#[test]
fn explicit_profile_has_separate_plan_and_cache_identity_and_candidates_remain_input_only() {
    policy_identity_and_candidates::<Sha1>();
    policy_identity_and_candidates::<Sha256>();
}

fn shared_inputs<A: GitHashAlgorithm>() {
    let fixture = Fixture::<A>::new(
        &[(b"a", b"../target"), (b"b", b"../target")],
        PAYLOAD,
        false,
    );
    let plan = fixture.plan(&[]);
    let cache_plan = SharedInputCachePlan::for_workspace(&plan, SharedInputPolicy::PreferReflink);
    assert_eq!(
        cache_plan.reservation().max_bytes,
        fixture.regular_bytes as u64,
        "cache retains selected regular bodies, not expanded alias copies or link text"
    );
    let scratch = Scratch::new();
    let cache_ledger = ObligationLedger::root(
        RegionId::new(2),
        LeakDisposition::RecordAndContinue,
        cache_plan.budget(),
    );
    let mut cache = SharedInputCache::create(
        cache_plan.clone(),
        scratch.parent(),
        cache_ledger
            .reserve(
                cache_plan.reservation(),
                cache_ledger.grant(cache_plan.budget()).unwrap(),
            )
            .unwrap(),
        &|| false,
    )
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
        for alias in ["project/dir/a", "project/dir/b"] {
            assert_eq!(
                fs::read(workspace.tool_directory().join(alias)).unwrap(),
                PAYLOAD
            );
        }
        if name == b"first" {
            let alias = workspace.tool_directory().join("project/dir/a");
            fs::set_permissions(&alias, fs::Permissions::from_mode(0o600)).unwrap();
            fs::write(&alias, b"private change").unwrap();
            assert!(workspace.verify_opaque_inputs(&|_| false).is_err());
            assert_eq!(
                fs::read(workspace.tool_directory().join("project/dir/b")).unwrap(),
                PAYLOAD
            );
            assert_eq!(
                fs::read(workspace.tool_directory().join("project/target")).unwrap(),
                PAYLOAD
            );
        }
        let TerminalEvidence::Acknowledged(receipt, _) = workspace.close().unwrap().into_evidence()
        else {
            panic!("cleanup acknowledgement");
        };
        assert_eq!(
            receipt.copied_bytes + receipt.shared_host_bytes,
            (fixture.regular_bytes + 2 * PAYLOAD.len()) as u64
        );
        quiescent(obligations);
    }
    let changed = Fixture::<A>::new(
        &[(b"a", b".././target"), (b"b", b"../target")],
        PAYLOAD,
        false,
    )
    .plan(&[]);
    let obligations = ledger(&changed);
    assert!(matches!(
        SparseWorkspace::materialize_with_cache(
            changed.clone(),
            scratch.parent(),
            path(b"mismatch"),
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
    assert!(!scratch.0.join("mismatch").exists());
    quiescent(obligations);
    let _settled = cache.close().unwrap();
    quiescent(cache_ledger);
}

#[test]
fn shared_source_cache_keeps_private_alias_inodes_and_accounts_for_all_expanded_workspace_bytes() {
    shared_inputs::<Sha1>();
    shared_inputs::<Sha256>();
}
