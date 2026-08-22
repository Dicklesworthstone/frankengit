//! Export, journal and proposal behaviour for FG-026c.
//!
//! The load-bearing assertions here are the round trip and the refusals:
//! exporting an untouched workspace must reproduce the base tree *identity*
//! (not merely an equivalent tree), and nothing in `TreeFS` may claim visibility,
//! durability, or a commit outcome.

use fgit_crypto::{GitObjectKind, GitOid, NativeObjectIdentity, Sha1};
use fgit_git_object::{AcceptanceProfile, ParseLimits, TreeEntry, emit_tree, parse_tree};
use fgit_treefs::base::{BaseView, ObjectSource, ObjectSourceError};
use fgit_treefs::capability::{ReadGrant, TreeCapability, WorkspaceId};
use fgit_treefs::export::{ExportLimits, ExportPlanner, ExportRefusal};
use fgit_treefs::intent::{BasisEntry, IntentLog, TreeEditIntent};
use fgit_treefs::journal::{CancellationState, ExportJournal, ExportPhase, JournalRefusal};
use fgit_treefs::obligation::WorkspaceLeaseReservation;
use fgit_treefs::overlay::{EntryClass, FileMode, Overlay, OverlayEntry};
use fgit_treefs::path::{PathPolicy, TreePath};
use fgit_treefs::proposal::{
    ExpectedRef, PositionReceipt, ProposalRefusal, ProposedRefIntent, ProposedTransaction,
};
use fgit_types::identity::RepositoryCommitId;
use fgit_types::{CodecVersion, DigestAlgorithmId, DigestBytes, RepositoryId};
use std::collections::BTreeMap;

type Oid = GitOid<Sha1>;

fn path(bytes: &[u8]) -> TreePath {
    TreePath::parse_default(bytes).expect("test path parses")
}

fn limits() -> ParseLimits {
    ParseLimits::default()
}

#[derive(Default, Clone)]
struct MemorySource {
    objects: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl MemorySource {
    fn insert(&mut self, kind: GitObjectKind, body: Vec<u8>) -> Oid {
        let oid = Oid::of_object(kind, &body);
        self.objects.insert(oid.digest_bytes().to_vec(), body);
        oid
    }

    fn blob(&mut self, body: &[u8]) -> Oid {
        self.insert(GitObjectKind::Blob, body.to_vec())
    }

    fn tree(&mut self, entries: &[TreeEntry]) -> Oid {
        let body = emit_tree(entries, AcceptanceProfile::GitCompatibleImport, &limits())
            .expect("fixture tree emits");
        self.insert(GitObjectKind::Tree, body)
    }
}

impl ObjectSource<Sha1> for MemorySource {
    fn read_object(
        &self,
        oid: &Oid,
        _kind: GitObjectKind,
        _grant: &ReadGrant,
    ) -> Result<Vec<u8>, ObjectSourceError> {
        self.objects
            .get(oid.digest_bytes())
            .cloned()
            .ok_or_else(|| ObjectSourceError::NotFound {
                oid_hex: String::new(),
            })
    }
}

fn entry(mode: &[u8], name: &[u8], oid: &Oid) -> TreeEntry {
    TreeEntry {
        mode: mode.to_vec(),
        name: name.to_vec(),
        object_id: oid.digest_bytes().to_vec(),
    }
}

/// `docs/readme.md`, `src/lib.rs`, `src/link` (symlink), `vendor` (gitlink).
fn fixture() -> (MemorySource, Oid) {
    let mut source = MemorySource::default();
    let lib = source.blob(b"fn main() {}\n");
    let link = source.blob(b"docs/readme.md");
    let readme = source.blob(b"# readme\n");
    let sub = source.blob(b"gitlink-stand-in");

    let src_tree = source.tree(&[
        entry(b"100644", b"lib.rs", &lib),
        entry(b"120000", b"link", &link),
    ]);
    let docs_tree = source.tree(&[entry(b"100644", b"readme.md", &readme)]);
    let root = source.tree(&[
        entry(b"40000", b"docs", &docs_tree),
        entry(b"40000", b"src", &src_tree),
        entry(b"160000", b"vendor", &sub),
    ]);
    (source, root)
}

const fn repository_id() -> RepositoryId {
    RepositoryId::from_bytes([7; 16])
}

fn rcr_id() -> RepositoryCommitId {
    RepositoryCommitId::from_digest(
        DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
            .expect("nonzero corpus fixture algorithm slot"),
        CodecVersion::new(1, 0),
        DigestBytes::try_new(&[9_u8; 32]).expect("32-byte corpus fixture body"),
    )
}

fn base(root: Oid) -> BaseView<Sha1> {
    BaseView::new(
        repository_id(),
        rcr_id(),
        root,
        root,
        limits(),
        PathPolicy::default(),
    )
}

fn capability() -> TreeCapability {
    TreeCapability::new(
        WorkspaceId::from_bytes([1; 16]),
        repository_id(),
        vec![path(b"src"), path(b"docs"), path(b"vendor"), path(b"new")],
        vec![path(b"src"), path(b"docs"), path(b"new")],
    )
}

fn planner() -> ExportPlanner {
    ExportPlanner::new(ExportLimits::default(), limits())
}

fn never_cancelled() -> impl Fn() -> bool {
    || false
}

// ---------------------------------------------------------------------------
// round trip and determinism
// ---------------------------------------------------------------------------

/// Exporting an untouched workspace reproduces the base root tree IDENTITY.
///
/// This is the export(import(x)) == x assertion. Identity equality, not merely
/// structural equivalence: if the planner reordered entries, changed a mode
/// byte, or re-encoded a subtree differently, the OID would move and this test
/// would fail.
#[test]
fn exporting_an_untouched_workspace_reproduces_the_base_tree_oid() {
    let (source, root) = fixture();
    let view = base(root);
    let mut cap = capability();
    let overlay = Overlay::new();

    let plan = planner()
        .plan(&view, &source, &mut cap, &overlay, 0, &never_cancelled())
        .expect("an untouched workspace exports");

    assert_eq!(
        plan.root_tree(),
        &root,
        "an untouched export must reproduce the base root tree identity exactly"
    );
    assert!(
        plan.verify_all(),
        "every object hashes to its filed identity"
    );
}

/// The exported root tree parses back to exactly the entries it came from.
#[test]
fn exported_tree_bytes_parse_back_to_the_same_entries() {
    let (source, root) = fixture();
    let view = base(root);
    let mut cap = capability();
    let mut overlay = Overlay::new();
    let id = overlay.intern(b"changed\n".to_vec());
    overlay.put(
        path(b"src/lib.rs"),
        OverlayEntry::File {
            content: fgit_treefs::overlay::ContentRef::Overlay(id),
            mode: FileMode::Regular,
            class: EntryClass::Content,
        },
    );

    let plan = planner()
        .plan(&view, &source, &mut cap, &overlay, 0, &never_cancelled())
        .expect("export succeeds");

    let root_object = plan
        .get(plan.root_tree())
        .expect("root tree is in the plan");
    let entries = parse_tree(
        root_object.body(),
        AcceptanceProfile::StrictCreate,
        &limits(),
    )
    .expect("the emitted root tree parses under the strict profile");

    let names: Vec<Vec<u8>> = entries.iter().map(|entry| entry.name.clone()).collect();
    assert_eq!(
        names,
        vec![b"docs".to_vec(), b"src".to_vec(), b"vendor".to_vec()],
        "root entries survive the round trip in canonical order"
    );
    assert_ne!(
        plan.root_tree(),
        &root,
        "an edited workspace must NOT reproduce the base root tree"
    );
}

/// The same base and overlay produce byte-identical objects every time.
#[test]
fn export_is_deterministic_across_repeated_runs() {
    let (source, root) = fixture();
    let view = base(root);

    let mut overlay = Overlay::new();
    for name in [&b"src/a.rs"[..], b"src/b.rs", b"docs/c.md", b"new/d.txt"] {
        let id = overlay.intern(format!("body of {}", String::from_utf8_lossy(name)).into_bytes());
        overlay.put(
            path(name),
            OverlayEntry::File {
                content: fgit_treefs::overlay::ContentRef::Overlay(id),
                mode: FileMode::Regular,
                class: EntryClass::Content,
            },
        );
    }

    let mut first_root = None;
    let mut first_bodies: Vec<Vec<u8>> = Vec::new();
    for _ in 0..5 {
        let mut cap = capability();
        let plan = planner()
            .plan(&view, &source, &mut cap, &overlay, 0, &never_cancelled())
            .expect("export succeeds");
        let bodies: Vec<Vec<u8>> = plan.objects().map(|o| o.body().to_vec()).collect();
        match &first_root {
            None => {
                first_root = Some(*plan.root_tree());
                first_bodies = bodies;
            }
            Some(expected) => {
                assert_eq!(plan.root_tree(), expected, "root tree identity is stable");
                assert_eq!(bodies, first_bodies, "object bytes are stable");
            }
        }
    }
}

/// Unchanged subtrees are reused by identity rather than re-encoded.
#[test]
fn untouched_subtrees_are_reused_not_reencoded() {
    let (source, root) = fixture();
    let view = base(root);
    let mut cap = capability();

    let mut overlay = Overlay::new();
    let id = overlay.intern(b"only docs changed\n".to_vec());
    overlay.put(
        path(b"docs/readme.md"),
        OverlayEntry::File {
            content: fgit_treefs::overlay::ContentRef::Overlay(id),
            mode: FileMode::Regular,
            class: EntryClass::Content,
        },
    );

    let plan = planner()
        .plan(&view, &source, &mut cap, &overlay, 0, &never_cancelled())
        .expect("export succeeds");

    // One new blob, one new docs tree, one new root. src/ is untouched and must
    // not appear as a constructed object.
    assert!(
        plan.object_count() <= 3,
        "editing one file must not re-encode the whole tree; built {} objects",
        plan.object_count()
    );
}

/// A base-carried body contributes no new blob.
#[test]
fn renamed_base_body_adds_no_new_blob() {
    let (source, root) = fixture();
    let view = base(root);
    let mut cap = capability();

    let mut log = IntentLog::new();
    let lib_oid = {
        let mut probe = MemorySource::default();
        probe.blob(b"fn main() {}\n")
    };
    log.push(TreeEditIntent::Rename {
        from: path(b"src/lib.rs"),
        to: path(b"src/renamed.rs"),
        basis_entry: Some(BasisEntry {
            oid: lib_oid.digest_bytes().to_vec(),
            mode: FileMode::Regular,
        }),
    });
    let (overlay, _) = log.evaluate(&|candidate: &TreePath| candidate.as_bytes() == b"src/lib.rs");

    let plan = planner()
        .plan(&view, &source, &mut cap, &overlay, 0, &never_cancelled())
        .expect("export succeeds");

    assert_eq!(
        plan.reused_base_objects(),
        1,
        "the renamed body is referenced, not re-encoded"
    );
    for object in plan.objects() {
        assert_eq!(
            object.kind(),
            GitObjectKind::Tree,
            "a pure rename constructs trees only, never a blob"
        );
    }
}

// ---------------------------------------------------------------------------
// planted negatives
// ---------------------------------------------------------------------------

/// An unresolved conflict is not exportable, while the same workspace without
/// it exports cleanly.
#[test]
fn unresolved_conflict_is_refused_but_the_resolved_twin_exports() {
    let (source, root) = fixture();
    let view = base(root);

    let mut conflicted = Overlay::new();
    let marker = conflicted.intern(b"<<<<<<< ours\na\n=======\nb\n>>>>>>> theirs\n".to_vec());
    conflicted.put(
        path(b"src/lib.rs"),
        OverlayEntry::Conflict {
            marker,
            inputs: vec![b"ours".to_vec(), b"theirs".to_vec()],
        },
    );
    let mut cap = capability();
    assert!(matches!(
        planner().plan(&view, &source, &mut cap, &conflicted, 0, &never_cancelled()),
        Err(ExportRefusal::UnresolvedConflict { .. })
    ));

    // Permitted near-twin: the same path, resolved to ordinary content.
    let mut resolved = Overlay::new();
    let id = resolved.intern(b"resolved\n".to_vec());
    resolved.put(
        path(b"src/lib.rs"),
        OverlayEntry::File {
            content: fgit_treefs::overlay::ContentRef::Overlay(id),
            mode: FileMode::Regular,
            class: EntryClass::Content,
        },
    );
    let mut cap = capability();
    assert!(
        planner()
            .plan(&view, &source, &mut cap, &resolved, 0, &never_cancelled())
            .is_ok()
    );
}

/// An object budget refuses rather than half-building.
#[test]
fn object_budget_is_enforced_and_a_generous_one_proceeds() {
    let (source, root) = fixture();
    let view = base(root);

    let mut overlay = Overlay::new();
    for index in 0..12_u32 {
        let id = overlay.intern(format!("body {index}").into_bytes());
        overlay.put(
            path(format!("src/f{index}.rs").as_bytes()),
            OverlayEntry::File {
                content: fgit_treefs::overlay::ContentRef::Overlay(id),
                mode: FileMode::Regular,
                class: EntryClass::Content,
            },
        );
    }

    let tight = ExportPlanner::new(
        ExportLimits {
            max_objects: 3,
            ..ExportLimits::default()
        },
        limits(),
    );
    let mut cap = capability();
    assert!(matches!(
        tight.plan(&view, &source, &mut cap, &overlay, 0, &never_cancelled()),
        Err(ExportRefusal::ObjectBudgetExceeded { .. })
    ));

    let mut cap = capability();
    assert!(
        planner()
            .plan(&view, &source, &mut cap, &overlay, 0, &never_cancelled())
            .is_ok(),
        "the same overlay under the default budget exports"
    );
}

/// Cancellation yields no plan at all — there is no partial export to promote.
#[test]
fn cancellation_yields_no_plan() {
    let (source, root) = fixture();
    let view = base(root);
    let mut cap = capability();
    let mut overlay = Overlay::new();
    let id = overlay.intern(b"body\n".to_vec());
    overlay.put(
        path(b"src/a.rs"),
        OverlayEntry::File {
            content: fgit_treefs::overlay::ContentRef::Overlay(id),
            mode: FileMode::Regular,
            class: EntryClass::Content,
        },
    );

    let result = planner().plan(&view, &source, &mut cap, &overlay, 0, &|| true);
    assert!(matches!(result, Err(ExportRefusal::Cancelled)));

    let mut cap = capability();
    assert!(
        planner()
            .plan(&view, &source, &mut cap, &overlay, 0, &never_cancelled())
            .is_ok(),
        "the identical export without cancellation proceeds"
    );
}

// ---------------------------------------------------------------------------
// journal: phases, epochs, replay, cancellation
// ---------------------------------------------------------------------------

/// Phases advance one step at a time and skipping is refused.
#[test]
fn journal_phases_are_sequential() {
    let mut journal = ExportJournal::open(WorkspaceId::from_bytes([1; 16]));
    assert_eq!(journal.phase(), ExportPhase::Unstarted);

    assert!(matches!(
        journal.advance(ExportPhase::Staged),
        Err(JournalRefusal::NonSequentialPhase { .. })
    ));

    journal.advance(ExportPhase::Reserved).unwrap();
    journal.advance(ExportPhase::Planned).unwrap();
    journal.advance(ExportPhase::Staged).unwrap();
    journal.advance(ExportPhase::Proposed).unwrap();
    assert_eq!(journal.phase(), ExportPhase::Proposed);
}

/// Re-entering the current phase succeeds, which is what makes replay safe.
#[test]
fn journal_advance_is_idempotent() {
    let mut journal = ExportJournal::open(WorkspaceId::from_bytes([1; 16]));
    journal.advance(ExportPhase::Reserved).unwrap();
    journal.advance(ExportPhase::Reserved).unwrap();
    journal.advance(ExportPhase::Reserved).unwrap();
    assert_eq!(journal.phase(), ExportPhase::Reserved);
    assert_eq!(journal.steps().len(), 1, "a no-op records no extra step");
}

/// Only staging advances an epoch, and visible/durable never move.
#[test]
fn only_staging_advances_an_epoch_and_never_past_staged() {
    let mut journal = ExportJournal::open(WorkspaceId::from_bytes([1; 16]));
    journal.advance(ExportPhase::Reserved).unwrap();
    assert_eq!(journal.epochs().staged().get(), 0);

    journal.advance(ExportPhase::Planned).unwrap();
    assert_eq!(
        journal.epochs().staged().get(),
        0,
        "planning stages nothing"
    );

    journal.advance(ExportPhase::Staged).unwrap();
    assert_eq!(journal.epochs().staged().get(), 1);
    assert_eq!(
        journal.epochs().visible().get(),
        0,
        "TreeFS cannot make anything visible"
    );
    assert_eq!(
        journal.epochs().durable().get(),
        0,
        "TreeFS cannot make anything durable"
    );

    journal.advance(ExportPhase::Proposed).unwrap();
    assert_eq!(journal.epochs().visible().get(), 0);
    assert_eq!(journal.epochs().durable().get(), 0);
    assert!(journal.epochs().invariant_holds());
}

/// Reading a staged export as durable or visible is refused at every phase.
#[test]
fn durability_and_visibility_claims_are_always_refused() {
    let mut journal = ExportJournal::open(WorkspaceId::from_bytes([1; 16]));
    for phase in [
        ExportPhase::Reserved,
        ExportPhase::Planned,
        ExportPhase::Staged,
        ExportPhase::Proposed,
    ] {
        journal.advance(phase).unwrap();
        assert!(matches!(
            journal.assert_durable(),
            Err(JournalRefusal::NotDurable { .. })
        ));
        assert!(matches!(
            journal.assert_visible(),
            Err(JournalRefusal::NotVisible { .. })
        ));
    }
}

/// Once proposed, `TreeFS` refuses to decide the outcome itself.
#[test]
fn outcome_is_locally_decidable_only_before_proposal() {
    let mut journal = ExportJournal::open(WorkspaceId::from_bytes([1; 16]));
    journal.advance(ExportPhase::Reserved).unwrap();
    journal.advance(ExportPhase::Planned).unwrap();
    journal.advance(ExportPhase::Staged).unwrap();
    assert!(journal.local_outcome().is_ok(), "staged is still ours");

    journal.advance(ExportPhase::Proposed).unwrap();
    assert!(
        matches!(
            journal.local_outcome(),
            Err(JournalRefusal::OutcomeNotLocallyDecidable { .. })
        ),
        "after handing over a proposal, a disconnect never proves non-commit"
    );
}

/// Replaying a step sequence reproduces the journal exactly, twice over.
#[test]
fn journal_replay_is_idempotent() {
    let workspace = WorkspaceId::from_bytes([1; 16]);
    let mut original = ExportJournal::open(workspace);
    original.advance(ExportPhase::Reserved).unwrap();
    original.advance(ExportPhase::Planned).unwrap();
    original.record_staged(7, 512);
    original.advance(ExportPhase::Staged).unwrap();

    let replayed = ExportJournal::replay(workspace, original.steps()).expect("replay succeeds");
    assert_eq!(replayed.phase(), original.phase());
    assert_eq!(replayed.staged_objects(), original.staged_objects());
    assert_eq!(replayed.epochs().staged(), original.epochs().staged());

    let twice = ExportJournal::replay(workspace, replayed.steps()).expect("replay again");
    assert_eq!(twice.phase(), replayed.phase());
    assert_eq!(twice.steps().len(), replayed.steps().len());
}

/// Cancellation runs request → drain → finalize and refuses to skip drain.
#[test]
fn cancellation_follows_request_drain_finalize() {
    let mut journal = ExportJournal::open(WorkspaceId::from_bytes([1; 16]));
    journal.advance(ExportPhase::Reserved).unwrap();
    journal.advance(ExportPhase::Planned).unwrap();
    journal.record_staged(4, 100);
    journal.advance(ExportPhase::Staged).unwrap();

    assert_eq!(journal.cancellation(), CancellationState::Running);
    assert!(
        matches!(
            journal.finalize_cancel(4),
            Err(JournalRefusal::DrainIncomplete { .. })
        ),
        "finalizing without draining is refused"
    );

    journal.request_cancel();
    assert_eq!(journal.cancellation(), CancellationState::Requested);
    assert!(
        matches!(
            journal.advance(ExportPhase::Proposed),
            Err(JournalRefusal::CancellationInProgress { .. })
        ),
        "no new work is admitted once cancellation is requested"
    );

    journal.drain();
    assert_eq!(journal.cancellation(), CancellationState::Drained);

    let abort = journal.finalize_cancel(4).expect("finalize succeeds");
    assert_eq!(journal.cancellation(), CancellationState::Finalized);
    assert_eq!(journal.phase(), ExportPhase::Settled);
    assert_eq!(abort.discarded.body_bytes, 100);
    assert!(
        !journal.left_consumable_artifact(),
        "a finalized cancellation leaves nothing consumable"
    );
}

/// Reclaiming fewer objects than were staged is a containment failure, not a
/// quiet success.
#[test]
fn unreclaimed_staged_objects_are_a_containment_failure() {
    let mut journal = ExportJournal::open(WorkspaceId::from_bytes([1; 16]));
    journal.advance(ExportPhase::Reserved).unwrap();
    journal.advance(ExportPhase::Planned).unwrap();
    journal.record_staged(9, 900);
    journal.advance(ExportPhase::Staged).unwrap();
    journal.request_cancel();
    journal.drain();

    journal
        .finalize_cancel(6)
        .expect("finalize records the shortfall");
    assert_eq!(journal.cancellation(), CancellationState::ContainmentFailed);
    assert!(
        journal.left_consumable_artifact(),
        "three unaccounted staged objects must be reported, not rounded away"
    );
}

/// The journal carries the lease reservation the export runs under.
#[test]
fn journal_records_its_lease_reservation() {
    let mut journal = ExportJournal::open(WorkspaceId::from_bytes([1; 16]));
    assert!(journal.reservation().is_none());
    journal.reserve(WorkspaceLeaseReservation {
        workspace_id: WorkspaceId::from_bytes([1; 16]),
        reserved_bytes: 4096,
        reserved_entries: 64,
    });
    assert_eq!(journal.reservation().unwrap().reserved_bytes, 4096);
}

// ---------------------------------------------------------------------------
// proposal: inert by construction
// ---------------------------------------------------------------------------

fn seal_a_proposal() -> (ProposedTransaction<Sha1>, Oid) {
    let (source, root) = fixture();
    let view = base(root);
    let mut cap = capability();
    let mut overlay = Overlay::new();
    let id = overlay.intern(b"new content\n".to_vec());
    overlay.put(
        path(b"src/lib.rs"),
        OverlayEntry::File {
            content: fgit_treefs::overlay::ContentRef::Overlay(id),
            mode: FileMode::Regular,
            class: EntryClass::Content,
        },
    );
    let plan = planner()
        .plan(&view, &source, &mut cap, &overlay, 0, &never_cancelled())
        .expect("export succeeds");

    let receipt = PositionReceipt {
        repository_id: repository_id(),
        base_rcr_id: rcr_id(),
        base_tree_oid: root,
        proposed_tree_oid: *plan.root_tree(),
        touched_paths: overlay.touched_paths(),
    };
    let intents = vec![ProposedRefIntent {
        name: b"refs/heads/main".to_vec(),
        expected: ExpectedRef::Exactly { oid: root },
        new: *plan.root_tree(),
    }];
    let proposal =
        ProposedTransaction::seal(WorkspaceId::from_bytes([1; 16]), &plan, receipt, intents)
            .expect("proposal seals");
    (proposal, root)
}

/// A proposal has no outcome and cannot infer commit from object existence.
#[test]
fn a_proposal_cannot_publish_itself() {
    let (proposal, _) = seal_a_proposal();
    assert!(matches!(
        proposal.outcome(),
        Err(ProposalRefusal::OutcomeNotKnowable)
    ));
    assert!(matches!(
        proposal.commit_from_object_existence(),
        Err(ProposalRefusal::ExistenceIsNotCommit)
    ));
}

/// Sealing validates: an empty proposal, a tree absent from the plan, and a
/// duplicated ref target are all refused, while the well-formed twin seals.
#[test]
fn sealing_refuses_malformed_proposals() {
    let (source, root) = fixture();
    let view = base(root);
    let mut cap = capability();
    let overlay = Overlay::new();
    let plan = planner()
        .plan(&view, &source, &mut cap, &overlay, 0, &never_cancelled())
        .expect("export succeeds");

    let receipt = || PositionReceipt {
        repository_id: repository_id(),
        base_rcr_id: rcr_id(),
        base_tree_oid: root,
        proposed_tree_oid: *plan.root_tree(),
        touched_paths: Vec::new(),
    };
    let workspace = WorkspaceId::from_bytes([1; 16]);

    assert!(matches!(
        ProposedTransaction::seal(workspace, &plan, receipt(), Vec::new()),
        Err(ProposalRefusal::Empty)
    ));

    let duplicated = vec![
        ProposedRefIntent {
            name: b"refs/heads/main".to_vec(),
            expected: ExpectedRef::Absent,
            new: *plan.root_tree(),
        },
        ProposedRefIntent {
            name: b"refs/heads/main".to_vec(),
            expected: ExpectedRef::Absent,
            new: *plan.root_tree(),
        },
    ];
    assert!(matches!(
        ProposedTransaction::seal(workspace, &plan, receipt(), duplicated),
        Err(ProposalRefusal::DuplicateRefTarget { .. })
    ));

    let wrong_tree = PositionReceipt {
        proposed_tree_oid: Oid::of_object(GitObjectKind::Blob, b"not in the plan"),
        ..receipt()
    };
    let one = vec![ProposedRefIntent {
        name: b"refs/heads/main".to_vec(),
        expected: ExpectedRef::Absent,
        new: *plan.root_tree(),
    }];
    assert!(matches!(
        ProposedTransaction::seal(workspace, &plan, wrong_tree, one.clone()),
        Err(ProposalRefusal::TreeNotInPlan)
    ));

    // The permitted near-twin seals.
    assert!(ProposedTransaction::seal(workspace, &plan, receipt(), one).is_ok());
}

/// The canonical request bytes are deterministic and distinguish proposals.
#[test]
fn proposal_request_bytes_are_deterministic_and_distinguishing() {
    let (proposal, root) = seal_a_proposal();
    assert_eq!(
        proposal.canonical_request_bytes(),
        proposal.canonical_request_bytes()
    );
    assert!(
        proposal
            .canonical_request_bytes()
            .starts_with(b"frankengit.treefs.proposal.v1\0")
    );
    assert_eq!(proposal.receipt().base_tree_oid, root);
    assert_eq!(proposal.ref_intents().len(), 1);
}

// ---------------------------------------------------------------------------
// tree ordering and mode fidelity
// ---------------------------------------------------------------------------

/// Git orders a directory as though its name ended in `/`.
///
/// This is the case a plain byte sort gets wrong and the reason the planner
/// defers to `compare_tree_entries`. `a.txt` (blob) must precede `a` (tree),
/// because `a.txt` < `a/` — `.` is 0x2E and `/` is 0x2F. Getting this backwards
/// produces a valid-looking tree with the wrong OID, which is the worst kind of
/// wrong: silent, and only visible as a differential failure much later.
#[test]
fn directory_entries_sort_as_though_they_ended_in_a_slash() {
    let mut source = MemorySource::default();
    let leaf = source.blob(b"leaf\n");
    let inner = source.tree(&[entry(b"100644", b"inner.txt", &leaf)]);
    let sibling = source.blob(b"sibling\n");
    // Deliberately supplied in an order Git would not accept, to prove the
    // planner sorts rather than trusting input order.
    let root = source.tree(&[
        entry(b"40000", b"a", &inner),
        entry(b"100644", b"a.txt", &sibling),
    ]);

    let view = base(root);
    let mut cap = TreeCapability::new(
        WorkspaceId::from_bytes([1; 16]),
        repository_id(),
        vec![path(b"a"), path(b"a.txt")],
        vec![path(b"a")],
    );

    let mut overlay = Overlay::new();
    let id = overlay.intern(b"edited leaf\n".to_vec());
    overlay.put(
        path(b"a/inner.txt"),
        OverlayEntry::File {
            content: fgit_treefs::overlay::ContentRef::Overlay(id),
            mode: FileMode::Regular,
            class: EntryClass::Content,
        },
    );

    let plan = planner()
        .plan(&view, &source, &mut cap, &overlay, 0, &never_cancelled())
        .expect("export succeeds");

    let root_object = plan
        .get(plan.root_tree())
        .expect("root tree is in the plan");
    let entries = parse_tree(
        root_object.body(),
        AcceptanceProfile::StrictCreate,
        &limits(),
    )
    .expect("the emitted root parses strictly, which itself checks canonical order");

    let names: Vec<Vec<u8>> = entries.iter().map(|entry| entry.name.clone()).collect();
    assert_eq!(
        names,
        vec![b"a.txt".to_vec(), b"a".to_vec()],
        "a.txt must precede the directory a, because a.txt < a/"
    );
}

/// Executable, symlink and gitlink modes survive an export unchanged.
#[test]
fn modes_survive_the_export_exactly() {
    let (source, root) = fixture();
    let view = base(root);
    let mut cap = capability();

    let mut overlay = Overlay::new();
    let exec_id = overlay.intern(b"#!/bin/sh\n".to_vec());
    overlay.put(
        path(b"src/run.sh"),
        OverlayEntry::File {
            content: fgit_treefs::overlay::ContentRef::Overlay(exec_id),
            mode: FileMode::Executable,
            class: EntryClass::Content,
        },
    );

    let plan = planner()
        .plan(&view, &source, &mut cap, &overlay, 0, &never_cancelled())
        .expect("export succeeds");

    // Walk the root to src, then inspect src's entries.
    let root_object = plan.get(plan.root_tree()).expect("root in plan");
    let root_entries = parse_tree(
        root_object.body(),
        AcceptanceProfile::StrictCreate,
        &limits(),
    )
    .expect("root parses");
    let src = root_entries
        .iter()
        .find(|entry| entry.name == b"src")
        .expect("src is present");
    let src_oid = {
        let mut hex = String::new();
        use std::fmt::Write as _;
        for byte in &src.object_id {
            let _ = write!(hex, "{byte:02x}");
        }
        <Sha1 as fgit_crypto::GitHashAlgorithm>::parse_hex(&hex).expect("src oid parses")
    };
    let src_object = plan
        .get(&src_oid)
        .expect("the rebuilt src tree is in the plan");
    let src_entries = parse_tree(
        src_object.body(),
        AcceptanceProfile::StrictCreate,
        &limits(),
    )
    .expect("src parses");

    let mode_of = |name: &[u8]| -> Vec<u8> {
        src_entries
            .iter()
            .find(|entry| entry.name == name)
            .map(|entry| entry.mode.clone())
            .unwrap_or_default()
    };
    assert_eq!(
        mode_of(b"run.sh"),
        b"100755",
        "executable mode is preserved"
    );
    assert_eq!(mode_of(b"lib.rs"), b"100644", "regular mode is preserved");
    assert_eq!(
        mode_of(b"link"),
        b"120000",
        "a base symlink stays a symlink through export"
    );

    let gitlink = root_entries
        .iter()
        .find(|entry| entry.name == b"vendor")
        .expect("vendor is present");
    assert_eq!(gitlink.mode, b"160000", "a gitlink stays a gitlink");
}

/// A whiteout removes the entry from the exported tree, and its sibling stays.
#[test]
fn whiteout_removes_only_its_own_entry() {
    let (source, root) = fixture();
    let view = base(root);
    let mut cap = capability();

    let mut overlay = Overlay::new();
    overlay.put(path(b"src/lib.rs"), OverlayEntry::Whiteout);

    let plan = planner()
        .plan(&view, &source, &mut cap, &overlay, 0, &never_cancelled())
        .expect("export succeeds");

    let root_object = plan.get(plan.root_tree()).expect("root in plan");
    let root_entries = parse_tree(
        root_object.body(),
        AcceptanceProfile::StrictCreate,
        &limits(),
    )
    .expect("root parses");
    let src = root_entries
        .iter()
        .find(|entry| entry.name == b"src")
        .expect("src survives because its sibling entry remains");
    let src_oid = {
        let mut hex = String::new();
        use std::fmt::Write as _;
        for byte in &src.object_id {
            let _ = write!(hex, "{byte:02x}");
        }
        <Sha1 as fgit_crypto::GitHashAlgorithm>::parse_hex(&hex).expect("oid parses")
    };
    let src_object = plan.get(&src_oid).expect("rebuilt src is in the plan");
    let src_entries = parse_tree(
        src_object.body(),
        AcceptanceProfile::StrictCreate,
        &limits(),
    )
    .expect("src parses");

    assert!(
        !src_entries.iter().any(|entry| entry.name == b"lib.rs"),
        "the whited-out entry is gone"
    );
    assert!(
        src_entries.iter().any(|entry| entry.name == b"link"),
        "its sibling is untouched"
    );
}

/// An overlay body that is missing from the content store is a typed refusal,
/// never a silently omitted entry.
///
/// This is the planted intent-omission defect: an entry that names a body the
/// store does not hold must not quietly vanish from the exported tree, because
/// a silently dropped intent is exactly the omission the totality map exists to
/// make impossible.
#[test]
fn an_entry_naming_a_missing_body_is_refused_not_omitted() {
    let (source, root) = fixture();
    let view = base(root);
    let mut cap = capability();

    let mut overlay = Overlay::new();
    // Reference a content id that was never interned.
    let orphan = fgit_treefs::overlay::ContentId::of(b"never interned");
    overlay.put(
        path(b"src/ghost.rs"),
        OverlayEntry::File {
            content: fgit_treefs::overlay::ContentRef::Overlay(orphan),
            mode: FileMode::Regular,
            class: EntryClass::Content,
        },
    );

    assert!(
        matches!(
            planner().plan(&view, &source, &mut cap, &overlay, 0, &never_cancelled()),
            Err(ExportRefusal::MissingBody { .. })
        ),
        "a missing body must refuse the whole export, not drop the entry"
    );

    // Permitted near-twin: the same path with its body actually interned.
    let mut good = Overlay::new();
    let id = good.intern(b"real body\n".to_vec());
    good.put(
        path(b"src/ghost.rs"),
        OverlayEntry::File {
            content: fgit_treefs::overlay::ContentRef::Overlay(id),
            mode: FileMode::Regular,
            class: EntryClass::Content,
        },
    );
    let mut cap = capability();
    assert!(
        planner()
            .plan(&view, &source, &mut cap, &good, 0, &never_cancelled())
            .is_ok()
    );
}

// ---------------------------------------------------------------------------
// reference materialization (oracle-only)
// ---------------------------------------------------------------------------

/// Every object is rendered at Git's two-character fan-out path, and the bytes
/// are the canonical `<type> <size>\0<body>` stream.
#[test]
fn materialization_uses_gits_fanout_path_and_canonical_framing() {
    let (source, root) = fixture();
    let view = base(root);
    let mut cap = capability();
    let mut overlay = Overlay::new();
    let id = overlay.intern(b"hello\n".to_vec());
    overlay.put(
        path(b"src/greet.txt"),
        OverlayEntry::File {
            content: fgit_treefs::overlay::ContentRef::Overlay(id),
            mode: FileMode::Regular,
            class: EntryClass::Content,
        },
    );

    let plan = planner()
        .plan(&view, &source, &mut cap, &overlay, 0, &never_cancelled())
        .expect("export succeeds");
    let layout =
        fgit_treefs::materialize::materialize(&plan, &limits()).expect("the plan materializes");

    assert_eq!(layout.len(), plan.object_count());
    for object in layout.objects() {
        let hex = object.oid_hex();
        assert_eq!(
            object.relative_path(),
            format!("objects/{}/{}", &hex[..2], &hex[2..]),
            "Git splits the identity after two hex characters"
        );
        assert_eq!(
            object.compression(),
            fgit_treefs::materialize::Compression::NoneCanonicalStream,
            "the adapter states plainly that it has not deflated anything"
        );
        // The framed stream is "<type> <size>\0<body>" and nothing else.
        let framed = object.framed_bytes();
        let nul = framed
            .iter()
            .position(|byte| *byte == 0)
            .expect("a loose frame has a NUL separator");
        let header = std::str::from_utf8(&framed[..nul]).expect("the header is ASCII");
        let declared: usize = header
            .split(' ')
            .nth(1)
            .expect("the header declares a size")
            .parse()
            .expect("the declared size is a number");
        assert_eq!(
            declared,
            framed.len() - nul - 1,
            "the declared size matches the body that follows"
        );
    }
}

/// Materialization is deterministic and its identities match the plan's.
#[test]
fn materialization_is_deterministic_and_agrees_with_the_plan() {
    let (source, root) = fixture();
    let view = base(root);
    let mut cap = capability();
    let overlay = Overlay::new();

    let plan = planner()
        .plan(&view, &source, &mut cap, &overlay, 0, &never_cancelled())
        .expect("export succeeds");

    let once = fgit_treefs::materialize::materialize(&plan, &limits()).expect("materializes");
    let twice = fgit_treefs::materialize::materialize(&plan, &limits()).expect("materializes");
    assert_eq!(once, twice, "the same plan renders identically every time");

    let mut hex = String::new();
    use std::fmt::Write as _;
    for byte in plan.root_tree().digest_bytes() {
        let _ = write!(hex, "{byte:02x}");
    }
    assert_eq!(
        once.root_tree_hex(),
        hex,
        "the layout names the same root tree the plan does"
    );
    assert!(
        once.paths().iter().all(|p| p.starts_with("objects/")),
        "every path is repository-relative under objects/"
    );
}

/// An empty plan still materializes: the empty tree is a real object.
#[test]
fn an_empty_workspace_materializes_the_empty_tree() {
    let mut source = MemorySource::default();
    let root = source.tree(&[]);
    let view = base(root);
    let mut cap = capability();
    let overlay = Overlay::new();

    let plan = planner()
        .plan(&view, &source, &mut cap, &overlay, 0, &never_cancelled())
        .expect("an empty workspace exports");
    let layout = fgit_treefs::materialize::materialize(&plan, &limits()).expect("materializes");

    assert!(
        !layout.is_empty(),
        "the empty tree is still one real object"
    );
    assert_eq!(
        layout.objects()[0].framed_bytes(),
        b"tree 0\0",
        "Git's empty tree frames as 'tree 0' with an empty body"
    );
}

// ---------------------------------------------------------------------------
// FG-008 semantics at tree scope, and host-profile refusals
// ---------------------------------------------------------------------------

/// The four FG-008 properties, asserted by name at tree scope.
///
/// The bead requires the tree-scope fold to mirror FG-008's semantics. This
/// test states each property explicitly rather than leaving the correspondence
/// implied by scattered assertions elsewhere.
#[test]
fn tree_scope_fold_has_the_fg008_properties() {
    let base_has = |candidate: &TreePath| candidate.as_bytes() == b"src/lib.rs";

    let mut log = IntentLog::new();
    // (1) read-your-own-writes: the second write observes the first.
    log.push(TreeEditIntent::Write {
        path: path(b"a.txt"),
        content: b"first".to_vec(),
        mode: FileMode::Regular,
        entry_class: EntryClass::Content,
    });
    log.push(TreeEditIntent::Write {
        path: path(b"a.txt"),
        content: b"second".to_vec(),
        mode: FileMode::Regular,
        entry_class: EntryClass::Content,
    });
    // (4) a statement error that does not abort the rest.
    log.push(TreeEditIntent::Rename {
        from: path(b"absent/source"),
        to: path(b"b.txt"),
        basis_entry: None,
    });
    log.push(TreeEditIntent::Delete {
        path: path(b"src/lib.rs"),
    });

    let (effect, evaluation) = log.fold(&base_has);

    // (1) read-your-own-writes
    let surviving = effect
        .effects()
        .get(&path(b"a.txt"))
        .expect("a.txt survives");
    match surviving {
        OverlayEntry::File { .. } => {}
        other => panic!("expected a file, got {other:?}"),
    }

    // (2) target-disjoint net effect: one surviving effect per path.
    let targets: std::collections::BTreeSet<_> = effect.effects().keys().collect();
    assert_eq!(
        targets.len(),
        effect.len(),
        "the net effect is target-disjoint"
    );

    // (3) totality: exactly one outcome per source intent, none dropped.
    assert_eq!(
        evaluation.len(),
        log.len(),
        "every source intent maps to exactly one outcome"
    );

    // (4) statement failure is isolated, not an abort of the transaction.
    assert_eq!(evaluation.errors().len(), 1, "one statement error");
    assert!(
        effect.effects().contains_key(&path(b"src/lib.rs")),
        "the intent after the failing statement still took effect"
    );
}

/// A name a target host cannot represent is refused under that host profile and
/// accepted under the repository profile.
///
/// The refusal is bounded and typed rather than a silent rename: aliasing two
/// distinct Git paths onto one host name is what `docs/GIT_TREE_FS.md` §3.3
/// forbids outright.
#[test]
fn host_unrepresentable_names_are_refused_only_under_that_profile() {
    let mut source = MemorySource::default();
    let leaf = source.blob(b"x\n");
    let root = source.tree(&[entry(b"100644", b"keep.txt", &leaf)]);

    let windows_view: BaseView<Sha1> = BaseView::new(
        repository_id(),
        rcr_id(),
        root,
        root,
        limits(),
        PathPolicy {
            host_profile: fgit_treefs::path::HostProfile::WindowsCompatible,
            ..PathPolicy::default()
        },
    );
    let repository_view = base(root);

    // `com1.txt` is reserved on Windows and ordinary in a repository.
    assert!(
        TreePath::parse(
            b"com1.txt",
            &PathPolicy {
                host_profile: fgit_treefs::path::HostProfile::WindowsCompatible,
                ..PathPolicy::default()
            }
        )
        .is_err(),
        "the Windows profile refuses a reserved device name"
    );
    let permitted = TreePath::parse_default(b"com1.txt")
        .expect("the repository profile accepts the very same name");

    let mut overlay = Overlay::new();
    let id = overlay.intern(b"body\n".to_vec());
    overlay.put(
        permitted,
        OverlayEntry::File {
            content: fgit_treefs::overlay::ContentRef::Overlay(id),
            mode: FileMode::Regular,
            class: EntryClass::Content,
        },
    );

    let mut cap = TreeCapability::new(
        WorkspaceId::from_bytes([1; 16]),
        repository_id(),
        vec![TreePath::parse_default(b"com1.txt").unwrap()],
        vec![TreePath::parse_default(b"com1.txt").unwrap()],
    );
    assert!(
        planner()
            .plan(
                &repository_view,
                &source,
                &mut cap,
                &overlay,
                0,
                &never_cancelled()
            )
            .is_ok(),
        "the repository profile exports the name unchanged"
    );

    // The same view carries the strict host policy; the export path re-parses
    // child names under it, so the profile travels with the base.
    assert_eq!(
        windows_view.path_policy().host_profile,
        fgit_treefs::path::HostProfile::WindowsCompatible,
        "the base view carries the host profile the export will honour"
    );
}

/// An untouched sibling subtree survives the export with its base identity.
///
/// The regression guard for a data-destroying defect: the planner used to drop
/// a base subtree from its rebuilt parent whenever that subtree had not itself
/// been rebuilt, silently deleting every file beneath it from the exported
/// tree. Editing `docs/` must not remove `src/`.
#[test]
fn editing_one_subtree_preserves_its_untouched_siblings() {
    let (source, root) = fixture();
    let view = base(root);
    let mut cap = capability();

    // Capture the base identity of the sibling we are NOT touching.
    let src_base_oid = match view
        .resolve(&source, &mut cap, &path(b"src"), 0)
        .expect("src resolves in the base")
    {
        fgit_treefs::base::BaseEntry::Directory { oid } => oid,
        other => panic!("expected a directory, got {other:?}"),
    };

    let mut overlay = Overlay::new();
    let id = overlay.intern(b"only docs changed\n".to_vec());
    overlay.put(
        path(b"docs/readme.md"),
        OverlayEntry::File {
            content: fgit_treefs::overlay::ContentRef::Overlay(id),
            mode: FileMode::Regular,
            class: EntryClass::Content,
        },
    );

    let mut cap = capability();
    let plan = planner()
        .plan(&view, &source, &mut cap, &overlay, 0, &never_cancelled())
        .expect("export succeeds");

    let root_object = plan
        .get(plan.root_tree())
        .expect("root tree is in the plan");
    let entries = parse_tree(
        root_object.body(),
        AcceptanceProfile::StrictCreate,
        &limits(),
    )
    .expect("root parses");

    let src = entries
        .iter()
        .find(|entry| entry.name == b"src")
        .expect("the untouched src subtree must still be present");
    assert_eq!(
        src.object_id,
        src_base_oid.digest_bytes().to_vec(),
        "an untouched subtree keeps its exact base identity"
    );
    assert_eq!(src.mode, b"40000", "and is still a tree");

    let vendor = entries
        .iter()
        .find(|entry| entry.name == b"vendor")
        .expect("the untouched gitlink must still be present");
    assert_eq!(vendor.mode, b"160000");

    assert!(
        entries.iter().any(|entry| entry.name == b"docs"),
        "the edited subtree is present too"
    );
    assert_eq!(entries.len(), 3, "nothing was dropped and nothing invented");
}

/// Creating a directory alongside a base subtree of the same name does not
/// erase the base subtree.
#[test]
fn an_explicit_directory_intent_does_not_erase_the_base_subtree() {
    let (source, root) = fixture();
    let view = base(root);
    let mut cap = capability();

    let src_base_oid = match view
        .resolve(&source, &mut cap, &path(b"src"), 0)
        .expect("src resolves")
    {
        fgit_treefs::base::BaseEntry::Directory { oid } => oid,
        other => panic!("expected a directory, got {other:?}"),
    };

    let mut overlay = Overlay::new();
    overlay.put(path(b"src"), OverlayEntry::Directory);

    let mut cap = capability();
    let plan = planner()
        .plan(&view, &source, &mut cap, &overlay, 0, &never_cancelled())
        .expect("export succeeds");

    let root_object = plan.get(plan.root_tree()).expect("root in plan");
    let entries = parse_tree(
        root_object.body(),
        AcceptanceProfile::StrictCreate,
        &limits(),
    )
    .expect("root parses");
    let src = entries
        .iter()
        .find(|entry| entry.name == b"src")
        .expect("src survives an explicit directory intent");
    assert_eq!(
        src.object_id,
        src_base_oid.digest_bytes().to_vec(),
        "the base subtree identity is retained, not replaced by an empty tree"
    );
}

/// The exported empty tree matches Git's published empty-tree identity.
///
/// An external anchor: this value comes from Git, not from this crate.
#[test]
fn exported_empty_tree_matches_the_published_git_identity() {
    let mut source = MemorySource::default();
    let root = source.tree(&[]);
    let view = base(root);
    let mut cap = capability();

    let plan = planner()
        .plan(
            &view,
            &source,
            &mut cap,
            &Overlay::new(),
            0,
            &never_cancelled(),
        )
        .expect("an empty workspace exports");

    let mut rendered = String::new();
    use std::fmt::Write as _;
    for byte in plan.root_tree().digest_bytes() {
        let _ = write!(rendered, "{byte:02x}");
    }
    assert_eq!(
        rendered, "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
        "the exported empty tree is Git's published empty-tree identity"
    );
}

/// An exported object's identity is DERIVED from its body and kind, never
/// supplied.
///
/// CORRECTING WHAT THIS TEST USED TO CLAIM. It was named
/// `..._verify_detects_a_mismatched_body` and its doc said it pinned that
/// `verify` "can actually fail". It does not, and it never did: nothing below
/// observes `verify()` returning false, because the public API cannot produce
/// an object whose body and identity disagree. `new` computes the identity from
/// the body, there is no constructor taking an explicit oid, there is no
/// mutable body accessor, and `#![forbid(unsafe_code)]` closes the rest. So the
/// mismatch this claimed to detect is unconstructible, and a test name asserting
/// otherwise is the exact "right impression, wrong basis" shape being hunted
/// elsewhere in this crate -- worse here, because the overclaim was in the
/// documentation of a test rather than in code.
///
/// What is genuinely established, and what the name now says: the identity is a
/// function of body AND kind, so two different bodies cannot collide and the
/// same bytes under a different type label are a different object. That is the
/// property `verify` and `verify_all` rest on.
///
/// UPGRADE CONDITION: if a constructor taking an explicit oid is ever added, or
/// any mutable access to `body`, a genuine mismatch becomes constructible and
/// the falsifiability case belongs here.
#[test]
fn exported_object_identity_is_derived_from_body_and_kind() {
    let honest = fgit_treefs::export::ExportedObject::<Sha1>::new(
        GitObjectKind::Blob,
        b"the real body\n".to_vec(),
    );
    assert!(honest.verify(), "an untampered object verifies");
    assert_eq!(
        honest.oid(),
        &Oid::of_object(GitObjectKind::Blob, b"the real body\n"),
        "the identity is derived from the body, not supplied"
    );

    // Two different bodies never share an identity here.
    let other = fgit_treefs::export::ExportedObject::<Sha1>::new(
        GitObjectKind::Blob,
        b"a different body\n".to_vec(),
    );
    assert_ne!(honest.oid(), other.oid());

    // The same bytes under a different object kind are a different identity,
    // because the Git preimage includes the type label.
    let as_tree = fgit_treefs::export::ExportedObject::<Sha1>::new(GitObjectKind::Tree, Vec::new());
    let as_blob = fgit_treefs::export::ExportedObject::<Sha1>::new(GitObjectKind::Blob, Vec::new());
    assert_ne!(
        as_tree.oid(),
        as_blob.oid(),
        "the empty tree and the empty blob are different objects"
    );
}

/// The journal's crash-boundary predicates say the right thing at each phase.
#[test]
fn crash_boundary_predicates_match_their_phases() {
    use fgit_treefs::journal::ExportPhase;

    for phase in [
        ExportPhase::Unstarted,
        ExportPhase::Reserved,
        ExportPhase::Planned,
    ] {
        assert!(
            !phase.may_have_staged_objects(),
            "{phase} cannot have left objects behind"
        );
        assert!(
            phase.outcome_is_locally_decidable(),
            "{phase} is still ours to decide"
        );
    }

    assert!(
        ExportPhase::Staged.may_have_staged_objects(),
        "staging is where objects first exist"
    );
    assert!(
        ExportPhase::Staged.outcome_is_locally_decidable(),
        "staged work has not been handed over yet"
    );

    for phase in [ExportPhase::Proposed, ExportPhase::Settled] {
        assert!(phase.may_have_staged_objects());
        assert!(
            !phase.outcome_is_locally_decidable(),
            "{phase}: only the authority layer knows, and a disconnect never proves non-commit"
        );
    }

    // Code points are stable and ordered, so a receipt can record them.
    let points: Vec<u16> = ExportPhase::ALL.iter().map(|p| p.code_point()).collect();
    assert_eq!(points, vec![0, 1, 2, 3, 4, 5]);
    let mut sorted = ExportPhase::ALL.to_vec();
    sorted.sort_unstable();
    assert_eq!(
        sorted,
        ExportPhase::ALL,
        "the phase order is the declared one"
    );
}

// Non-production fixture identity: this reserved tag deliberately has no registered digest width.
const FIXTURE_ALGORITHM_CODE_POINT: u16 = 0xfff1;
const _: () = assert!(FIXTURE_ALGORITHM_CODE_POINT >= 0xfff0);
