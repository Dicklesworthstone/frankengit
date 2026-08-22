//! FG-076: the `GIT_TREE_FS` §14 eleven-point crash and cancellation matrix.
//!
//! WHAT THIS CORPUS CAN AND CANNOT ESTABLISH, stated first because the honest
//! bound is the whole difficulty of this bead.
//!
//! `fgit-treefs` performs no filesystem I/O. `export.rs` builds an in-memory
//! `ExportPlan`, `materialize.rs` returns a `ReferenceLayout` *describing* what a
//! loose-object store would contain without writing it, and `proposal.rs`
//! refuses to publish. So "crash safety" in the on-disk sense cannot be
//! demonstrated here — there is no on-disk state to corrupt — and a test
//! claiming otherwise would prove a tautology.
//!
//! What §14 actually demands is checkable: after interruption at each named
//! point, every intent must land in exactly one of three recovered states, and
//! no orphan resource may survive closure. Both are properties of this crate.
//!
//! ELEVEN POINTS, SIX REACHABLE. Five of the eleven name capability that does
//! not exist in this crate at all. Those are NOT silently skipped and NOT given
//! a fabricated fixture, which would be a mock presented as live proof (§16.3).
//! Each gets a test asserting the STRUCTURAL FACT that makes it unreachable, so
//! the day the capability lands the assertion fails and points at the drill that
//! then has to be written. An absence recorded that way is falsifiable; an
//! absence recorded in prose is not.
//!
//! This is the same set of five recorded as typed non-claims on fg026d, which
//! the orchestrator bounded-closed. They are reproduced here from the spec text
//! rather than from that bead, and the reachability verdicts are re-derived
//! against the current public surface rather than inherited.

use fgit_crypto::{GitObjectKind, GitOid, NativeObjectIdentity, Sha1};
use fgit_git_object::{AcceptanceProfile, ParseLimits, TreeEntry, emit_tree};
use fgit_treefs::base::{BaseView, ObjectSource, ObjectSourceError};
use fgit_treefs::capability::{ReadGrant, TreeCapability, WorkspaceId};
use fgit_treefs::export::{ExportLimits, ExportPlan, ExportPlanner};
use fgit_treefs::journal::{CancellationState, ExportJournal, ExportPhase, JournalRefusal};
use fgit_treefs::materialize::{MaterializeRefusal, ReferenceLayout, materialize};
use fgit_treefs::overlay::{ContentRef, EntryClass, FileMode, Overlay, OverlayEntry};
use fgit_treefs::path::{PathPolicy, TreePath};
use fgit_types::identity::RepositoryCommitId;
use fgit_types::{CodecVersion, DigestAlgorithmId, DigestBytes, RepositoryId};
use std::collections::BTreeMap;
use std::fmt::Write as _;

type Oid = GitOid<Sha1>;

// ---------------------------------------------------------------------------
// the eleven points, named exactly as GIT_TREE_FS.md:236-248 names them
// ---------------------------------------------------------------------------

/// Why a spec point cannot be exercised, when it cannot.
///
/// Carrying the reason in the type keeps a non-claim from degrading into "we
/// did not get to it": every variant below names a specific missing capability,
/// and the tests that use it assert that the capability is still missing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reachability {
    /// A crash at this point can be injected against real code in this crate.
    Reachable,
    /// The point names capability this crate does not contain.
    StructurallyAbsent {
        /// The exact missing thing, in the spec's own vocabulary.
        because: &'static str,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SpecPoint {
    BeforeContentReservation,
    MidStreamWrite,
    AfterBodyBeforeVisiblePointer,
    AfterVisibleBeforeDurableJournal,
    DuringRenameChain,
    WhileLazyFetchInFlight,
    DuringFuseReadWriteback,
    DuringProcessCancellation,
    AfterOutputBeforeManifestImport,
    DuringCommitTreeConstruction,
    AfterObjectsBeforePublication,
}

impl SpecPoint {
    /// All eleven, in the order the specification lists them.
    const ALL: &'static [Self] = &[
        Self::BeforeContentReservation,
        Self::MidStreamWrite,
        Self::AfterBodyBeforeVisiblePointer,
        Self::AfterVisibleBeforeDurableJournal,
        Self::DuringRenameChain,
        Self::WhileLazyFetchInFlight,
        Self::DuringFuseReadWriteback,
        Self::DuringProcessCancellation,
        Self::AfterOutputBeforeManifestImport,
        Self::DuringCommitTreeConstruction,
        Self::AfterObjectsBeforePublication,
    ];

    const fn reachability(self) -> Reachability {
        match self {
            Self::BeforeContentReservation
            | Self::MidStreamWrite
            | Self::AfterBodyBeforeVisiblePointer
            | Self::DuringProcessCancellation
            | Self::DuringCommitTreeConstruction
            | Self::AfterObjectsBeforePublication => Reachability::Reachable,

            Self::AfterVisibleBeforeDurableJournal => Reachability::StructurallyAbsent {
                because: "no durable session journal: ExportJournal is an in-memory value with no \
                          encoder, and assert_durable()/assert_visible() refuse unconditionally",
            },
            Self::DuringRenameChain => Reachability::StructurallyAbsent {
                because: "no host materialization writer: materialize() returns a ReferenceLayout \
                          describing placements and performs no rename",
            },
            Self::WhileLazyFetchInFlight => Reachability::StructurallyAbsent {
                because: "no lazy object fetch: ObjectSource::read_object is synchronous and \
                          returns a complete body, so there is no in-flight state to interrupt",
            },
            Self::DuringFuseReadWriteback => Reachability::StructurallyAbsent {
                because: "no FUSE host adapter exists in fgit-treefs",
            },
            Self::AfterOutputBeforeManifestImport => Reachability::StructurallyAbsent {
                because: "no manifest import path exists in fgit-treefs",
            },
        }
    }
}

// ---------------------------------------------------------------------------
// the recovered-state trichotomy
// ---------------------------------------------------------------------------

/// The only three states §14 permits an intent to be in after restart.
///
/// The classifier below is total over the journal's own state space and has no
/// catch-all arm: a fourth outcome has to be added here deliberately, which is
/// exactly the edit that should be hard to make by accident.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Recovered {
    /// The intent left no trace: nothing staged, nothing to reclaim.
    Absent,
    /// The intent's effect is present in the recovered overlay.
    VisibleInRecoveredOverlay,
    /// The intent is explicitly refused as incomplete, with a typed reason.
    RefusedAsIncomplete,
}

/// Classifies a recovered journal into the trichotomy.
///
/// The ordering matters and is not arbitrary. A journal whose outcome is not
/// locally decidable is REFUSED even if it staged objects, because "`TreeFS`
/// cannot tell whether the transaction layer accepted this" is precisely the
/// incomplete case §14 wants surfaced; reporting it as visible would be a guess,
/// and reporting it as absent would lose staged objects a later GC must know
/// about.
fn classify(journal: &ExportJournal) -> Recovered {
    if journal.left_consumable_artifact() {
        return Recovered::RefusedAsIncomplete;
    }
    // A finalized cancellation is resolved: drain completed, every staged object
    // was reclaimed, nothing survives. It must classify as Absent.
    //
    // This case has to be answered BEFORE local_outcome() because
    // finalize_cancel sets the phase to Settled, and Settled is outside
    // outcome_is_locally_decidable() -- correctly so, since a journal that
    // reached Settled by way of Proposed genuinely does not know whether the
    // authority accepted it. The phase alone therefore cannot distinguish
    // "settled because cancellation reclaimed everything" from "settled after
    // handing a proposal over", and only the cancellation state separates them.
    // Reading the phase alone reported a clean cancellation as incomplete.
    if journal.cancellation() == CancellationState::Finalized {
        return Recovered::Absent;
    }
    match journal.local_outcome() {
        // EVERY refusal is incomplete, not just OutcomeNotLocallyDecidable.
        // That variant is the one §14 is really about -- staged objects whose
        // fate only the authority layer knows -- and it was written as its own
        // arm to say so. The arms are merged because they returned the same
        // value, and a duplicate arm carrying no behaviour is a comment
        // pretending to be code. The distinction it documented is stated here
        // instead, and the classification is unchanged: any refusal at all
        // means TreeFS cannot call this export complete, so guessing either
        // Absent or Visible would be the failure mode.
        Err(_) => Recovered::RefusedAsIncomplete,
        Ok(_) => {
            if journal.staged_objects() == 0 {
                Recovered::Absent
            } else {
                Recovered::VisibleInRecoveredOverlay
            }
        }
    }
}

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[derive(Default)]
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
        let body = emit_tree(
            entries,
            AcceptanceProfile::GitCompatibleImport,
            &ParseLimits::default(),
        )
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
                oid_hex: hex(oid.digest_bytes()),
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

fn fixture() -> (MemorySource, Oid) {
    let mut source = MemorySource::default();
    let a_txt = source.blob(b"a.txt body\n");
    let inner = source.blob(b"inner body\n");
    let readme = source.blob(b"# readme\n");
    let a_tree = source.tree(&[entry(b"100644", b"inner.txt", &inner)]);
    let docs_tree = source.tree(&[entry(b"100644", b"readme.md", &readme)]);
    let root = source.tree(&[
        entry(b"40000", b"a", &a_tree),
        entry(b"100644", b"a.txt", &a_txt),
        entry(b"40000", b"docs", &docs_tree),
    ]);
    (source, root)
}

fn path(bytes: &[u8]) -> TreePath {
    TreePath::parse_default(bytes).expect("fixture path parses")
}

const fn workspace() -> WorkspaceId {
    WorkspaceId::from_bytes([1; 16])
}

const fn repository() -> RepositoryId {
    RepositoryId::from_bytes([7; 16])
}

fn base_view(root: Oid) -> BaseView<Sha1> {
    BaseView::new(
        repository(),
        RepositoryCommitId::from_digest(
            DigestAlgorithmId::try_new(1).expect("algorithm 1 is registered"),
            CodecVersion::new(1, 0),
            DigestBytes::try_new(&[9_u8; 32]).expect("fixture digest is a legal width"),
        ),
        root,
        root,
        ParseLimits::default(),
        PathPolicy::default(),
    )
}

/// A journal driven to `phase`, staging `objects` along the way.
fn journal_at(phase: ExportPhase, objects: usize, bytes: usize) -> ExportJournal {
    let mut journal = ExportJournal::open(workspace());
    // Unstarted is where a fresh journal already is, so it must return here.
    // Without this the loop below never matches its break condition -- it skips
    // Unstarted and then compares every later phase against it -- and runs all
    // the way to Settled. Every caller asking for Unstarted silently got a
    // settled journal instead, which classifies as RefusedAsIncomplete rather
    // than Absent. Found by that assertion failing rather than by reading.
    if phase == ExportPhase::Unstarted {
        return journal;
    }
    for step in ExportPhase::ALL {
        if *step == ExportPhase::Unstarted {
            continue;
        }
        if *step == ExportPhase::Staged {
            journal.record_staged(objects, bytes);
        }
        journal.advance(*step).expect("phase advances in order");
        if *step == phase {
            break;
        }
    }
    journal
}

// ---------------------------------------------------------------------------
// the matrix is complete and every point has a verdict
// ---------------------------------------------------------------------------

/// The corpus covers all eleven points the specification enumerates.
///
/// A count alone would pass if someone deleted a point and duplicated another,
/// so the identity of the set is checked, not its size.
#[test]
fn every_specification_point_is_present_exactly_once() {
    assert_eq!(
        SpecPoint::ALL.len(),
        11,
        "GIT_TREE_FS §14 enumerates eleven interruption points"
    );
    let mut seen = Vec::new();
    for point in SpecPoint::ALL {
        assert!(
            !seen.contains(point),
            "{point:?} appears twice; the matrix must cover each point exactly once"
        );
        seen.push(*point);
    }
}

/// Six reachable, five structurally absent — and the split is asserted, not
/// assumed.
///
/// If a later change makes one of the five reachable without this count being
/// updated, that is a drill someone owes and this fails until it is written.
#[test]
fn the_reachable_and_absent_split_is_pinned() {
    let reachable = SpecPoint::ALL
        .iter()
        .filter(|point| point.reachability() == Reachability::Reachable)
        .count();
    let absent = SpecPoint::ALL.len() - reachable;
    assert_eq!(
        reachable, 6,
        "six points have capability behind them in fgit-treefs today"
    );
    assert_eq!(
        absent, 5,
        "five points name capability this crate does not contain; each is pinned by its own test \
         below, and implementing one must break that test rather than pass silently"
    );
}

/// Every structurally-absent point states a specific missing capability.
///
/// Guards against the reason degrading into something unfalsifiable later.
#[test]
fn every_absent_point_names_the_missing_capability() {
    for point in SpecPoint::ALL {
        if let Reachability::StructurallyAbsent { because } = point.reachability() {
            assert!(
                because.len() > 30,
                "{point:?} must name the exact missing capability, not gesture at it"
            );
            assert!(
                !because.contains("not implemented") && !because.contains("TODO"),
                "{point:?} reason must describe what is absent, not that work is pending"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// trichotomy: every recovered state is one of exactly three
// ---------------------------------------------------------------------------

/// Recovery from every journal phase lands in the trichotomy.
///
/// Driven over `ExportPhase::ALL` rather than a hand-listed subset so a new
/// phase is covered the day it is added.
#[test]
fn every_recovered_phase_lands_in_the_trichotomy() {
    for phase in ExportPhase::ALL {
        let journal = journal_at(*phase, 3, 300);
        let replayed = ExportJournal::replay(workspace(), journal.steps())
            .expect("a recorded step sequence replays");
        let recovered = classify(&replayed);
        assert!(
            matches!(
                recovered,
                Recovered::Absent
                    | Recovered::VisibleInRecoveredOverlay
                    | Recovered::RefusedAsIncomplete
            ),
            "phase {phase} recovered as {recovered:?}, which is outside the §14 trichotomy"
        );
    }
}

/// The trichotomy is not satisfied vacuously: all three outcomes really occur.
///
/// Without this, a classifier that returned `RefusedAsIncomplete` unconditionally
/// would pass the test above while proving nothing at all. This is the presence
/// case for that absence claim.
#[test]
fn all_three_trichotomy_outcomes_are_actually_reachable() {
    let absent = classify(&journal_at(ExportPhase::Planned, 0, 0));
    assert_eq!(
        absent,
        Recovered::Absent,
        "a plan that staged nothing recovers as absent"
    );

    let staged = classify(&journal_at(ExportPhase::Staged, 3, 300));
    assert_eq!(
        staged,
        Recovered::VisibleInRecoveredOverlay,
        "staged objects survive into the recovered overlay"
    );

    let proposed = classify(&journal_at(ExportPhase::Proposed, 3, 300));
    assert_eq!(
        proposed,
        Recovered::RefusedAsIncomplete,
        "a proposed export cannot be decided locally, so it is refused as incomplete rather than \
         guessed either way"
    );
}

/// Replay is idempotent, which is what makes retrying a crashed export safe.
#[test]
fn replay_of_a_crashed_journal_is_idempotent() {
    for phase in ExportPhase::ALL {
        let journal = journal_at(*phase, 2, 200);
        let once =
            ExportJournal::replay(workspace(), journal.steps()).expect("first replay succeeds");
        let twice =
            ExportJournal::replay(workspace(), once.steps()).expect("second replay succeeds");
        assert_eq!(
            classify(&once),
            classify(&twice),
            "replaying phase {phase} twice must not change the recovered classification"
        );
        assert_eq!(
            once.staged_objects(),
            twice.staged_objects(),
            "replay must not double-count staged objects at phase {phase}"
        );
    }
}

// ---------------------------------------------------------------------------
// staged >= visible >= durable (AGENTS.md §5.4)
// ---------------------------------------------------------------------------

/// The epoch invariant holds, and it is pinned to the REASON it holds.
///
/// `staged >= visible >= durable` is trivially true while visible and durable
/// are never claimed — but "trivially true" is exactly how an invariant rots. So
/// this asserts the mechanism: both answers are unconditional typed refusals at
/// every phase. The day someone makes `assert_visible()` return `Ok` because a
/// journal now exists, this fails and the real ordering test has to be written
/// rather than inherited.
#[test]
fn staged_visible_durable_ordering_is_pinned_to_its_mechanism() {
    for phase in ExportPhase::ALL {
        let journal = journal_at(*phase, 4, 400);
        assert!(
            matches!(
                journal.assert_visible(),
                Err(JournalRefusal::NotVisible { .. })
            ),
            "phase {phase}: TreeFS must never claim visibility; publication is the authority's"
        );
        assert!(
            matches!(
                journal.assert_durable(),
                Err(JournalRefusal::NotDurable { .. })
            ),
            "phase {phase}: TreeFS stages and never makes anything durable"
        );
    }
}

/// Staged counts never decrease as an export advances.
#[test]
fn staged_counts_are_monotonic_across_recovery() {
    let journal = journal_at(ExportPhase::Proposed, 5, 500);
    let mut previous = 0_usize;
    for step in journal.steps() {
        assert!(
            step.staged_objects >= previous,
            "staged object count went backwards at {}: {} then {previous}",
            step.phase,
            step.staged_objects
        );
        previous = step.staged_objects;
    }
}

// ---------------------------------------------------------------------------
// point 8: during process cancellation -- request -> drain -> finalize
// ---------------------------------------------------------------------------

/// Cancellation that accounts for everything leaves no consumable artifact.
#[test]
fn point_08_cancellation_accounting_for_everything_is_finalized() {
    let mut journal = journal_at(ExportPhase::Staged, 3, 300);
    journal.request_cancel();
    journal.drain();
    let abort = journal
        .finalize_cancel(3)
        .expect("drained cancel finalizes");
    assert_eq!(abort.workspace_id, workspace());
    assert!(
        !journal.left_consumable_artifact(),
        "a fully reclaimed cancellation leaves nothing a consumer could mistake for a result"
    );
    assert_eq!(classify(&journal), Recovered::Absent);
}

/// Cancellation that loses track of a staged object reports containment failure.
///
/// The paired permitted case above is what makes this meaningful: the same call
/// with a correct count finalizes cleanly, so this is detecting the shortfall
/// rather than refusing everything.
#[test]
fn point_08_cancellation_missing_an_object_reports_containment_failure() {
    let mut journal = journal_at(ExportPhase::Staged, 3, 300);
    journal.request_cancel();
    journal.drain();
    let _ = journal
        .finalize_cancel(2)
        .expect("finalize still returns an abort record");
    assert_eq!(
        journal.cancellation(),
        CancellationState::ContainmentFailed,
        "an unaccounted staged object is a fact a later GC needs, not a detail to round away"
    );
    assert!(journal.left_consumable_artifact());
    assert_eq!(
        classify(&journal),
        Recovered::RefusedAsIncomplete,
        "a containment failure is incomplete, never absent"
    );
}

/// Finalizing before draining is refused rather than silently accepted.
#[test]
fn point_08_finalize_before_drain_is_refused() {
    let mut journal = journal_at(ExportPhase::Staged, 1, 100);
    journal.request_cancel();
    assert!(
        matches!(
            journal.finalize_cancel(1),
            Err(JournalRefusal::DrainIncomplete { .. })
        ),
        "cancellation is request -> drain -> finalize; skipping drain must refuse"
    );
}

// ---------------------------------------------------------------------------
// points 1, 2, 3, 10, 11: the export pipeline
// ---------------------------------------------------------------------------

fn plan_fixture() -> (MemorySource, Oid, TreeCapability) {
    let (source, root) = fixture();
    let capability = TreeCapability::new(
        workspace(),
        repository(),
        vec![
            path(b"a"),
            path(b"a/inner.txt"),
            path(b"a.txt"),
            path(b"docs"),
            path(b"docs/readme.md"),
        ],
        vec![path(b"a"), path(b"a/inner.txt")],
    );
    (source, root, capability)
}

/// Points 1 and 2: nothing is reserved or written before a plan exists.
///
/// "Before content reservation" and "mid-stream write" are the same fact from
/// two directions in a crate that streams nothing: planning is a pure function
/// of base and overlay, so an interruption anywhere inside it leaves the journal
/// at a phase that stages nothing and recovers as absent.
#[test]
fn points_01_and_02_interruption_before_staging_recovers_as_absent() {
    for phase in [
        ExportPhase::Unstarted,
        ExportPhase::Reserved,
        ExportPhase::Planned,
    ] {
        let journal = journal_at(phase, 0, 0);
        assert_eq!(
            journal.staged_objects(),
            0,
            "phase {phase} must not have staged anything"
        );
        assert_eq!(
            classify(&journal),
            Recovered::Absent,
            "an interruption at {phase} leaves no trace to recover"
        );
    }
}

/// Point 3: objects exist but no pointer publishes them.
#[test]
fn point_03_staged_objects_are_not_visible_without_publication() {
    let journal = journal_at(ExportPhase::Staged, 2, 200);
    assert_eq!(journal.staged_objects(), 2);
    assert!(
        matches!(
            journal.assert_visible(),
            Err(JournalRefusal::NotVisible { .. })
        ),
        "a staged body with no overlay pointer is not visible to any reader"
    );
    assert_eq!(classify(&journal), Recovered::VisibleInRecoveredOverlay);
}

/// Point 10: commit-tree construction is deterministic, so interrupting and
/// recomputing yields the identical plan.
///
/// This is the property an interruption during tree construction actually
/// threatens: not corruption, but a rebuild that differs from the original.
#[test]
fn point_10_commit_tree_construction_is_deterministic_across_restarts() {
    let (source, root, mut capability) = plan_fixture();
    let view = base_view(root);
    let mut overlay = Overlay::new();
    let rewritten = overlay.intern(b"rewritten\n".to_vec());
    overlay.put(
        path(b"a/inner.txt"),
        OverlayEntry::File {
            content: ContentRef::Overlay(rewritten),
            mode: FileMode::Regular,
            class: EntryClass::Content,
        },
    );

    let planner = ExportPlanner::new(ExportLimits::default(), ParseLimits::default());
    let first = planner
        .plan(&view, &source, &mut capability, &overlay, 0, &|| false)
        .expect("first plan succeeds");
    let second = planner
        .plan(&view, &source, &mut capability, &overlay, 0, &|| false)
        .expect("recomputed plan succeeds");

    assert_eq!(
        first.root_tree().digest_bytes(),
        second.root_tree().digest_bytes(),
        "rebuilding after an interruption must reproduce the same root identity"
    );
    assert_eq!(
        first.object_count(),
        second.object_count(),
        "a recomputed plan must contain the same object set"
    );
}

/// Point 11: new objects exist, publication has not happened, and `TreeFS`
/// refuses to guess whether it did.
#[test]
fn point_11_objects_staged_before_publication_are_refused_not_guessed() {
    let journal = journal_at(ExportPhase::Proposed, 4, 400);
    assert!(
        matches!(
            journal.local_outcome(),
            Err(JournalRefusal::OutcomeNotLocallyDecidable { .. })
        ),
        "once proposed, TreeFS cannot tell whether the transaction layer accepted it"
    );
    assert_eq!(
        classify(&journal),
        Recovered::RefusedAsIncomplete,
        "an undecidable outcome is reported as incomplete, never as success or absence"
    );
}

// ---------------------------------------------------------------------------
// the five structurally-absent points, each pinned by the fact that makes it so
// ---------------------------------------------------------------------------

/// Point 4 is unreachable because no durable journal exists.
///
/// Falsifiable: implementing a durable journal means `assert_durable` can return
/// `Ok`, and this test fails, demanding the real drill.
#[test]
fn point_04_is_absent_because_nothing_is_ever_durable() {
    for phase in ExportPhase::ALL {
        let journal = journal_at(*phase, 1, 100);
        assert!(
            journal.assert_durable().is_err(),
            "phase {phase} claims durability; a durable journal now exists and point 4 needs a \
             real crash drill"
        );
    }
}

// Point 5's premise, pinned by the type system rather than by prose.
//
// The assertion in the test below cannot carry the claim alone: checking that
// placements sit under `objects/` stays true even if `materialize` gained a
// writer, so a test resting only on that would survive its own premise
// breaking. What actually enforces "writes nothing" is the signature --
// `materialize` is handed a plan and parse limits and no filesystem handle, so
// it has nothing to write through. A writer added as a PARAMETER changes the
// signature, and this binding then fails to compile.
//
// WHAT THIS DOES NOT CATCH, measured rather than assumed. A writer that arrives
// INSIDE an existing type is invisible here: the binding names types, so
// `ParseLimits` gaining a path field, or `ReferenceLayout` gaining one, leaves
// the signature identical. Measured by giving `ReferenceLayout` a `PathBuf`
// field and initialising it -- the crate still compiles clean, exit 0, and this
// binding says nothing. So the pin covers the function's own shape and not the
// reachability of a filesystem through its arguments or its result.
//
// That bound is worth stating because the honest scope is narrower than the
// first version of this comment claimed, and a guard trusted past its scope is
// worse than no guard.
//
// That the detector is the compiler rather than an assertion is the reason to
// state it here. It was true before this binding existed and nothing said so,
// which made point 5 falsifiable by accident.
//
// DELETION CONDITION: goes when point 5 becomes reachable and earns a real
// rename drill -- the same day this binding stops compiling.
const _: fn(&ExportPlan<Sha1>, &ParseLimits) -> Result<ReferenceLayout, MaterializeRefusal> =
    materialize::<Sha1>;

/// Point 5 is unreachable because materialization writes nothing to rename.
///
/// The structural fact is pinned by the signature binding above. This test adds
/// what `materialize` does instead: it describes loose placements. So the point
/// is absent because there is no write to interrupt, not because nothing runs.
#[test]
fn point_05_is_absent_because_materialize_only_describes_placements() {
    let (source, root, mut capability) = plan_fixture();
    let view = base_view(root);
    let overlay = Overlay::new();
    let plan = ExportPlanner::new(ExportLimits::default(), ParseLimits::default())
        .plan(&view, &source, &mut capability, &overlay, 0, &|| false)
        .expect("plan succeeds");

    let layout = materialize(&plan, &ParseLimits::default()).expect("layout is described");
    assert!(
        layout.objects().iter().all(|object| {
            let relative = object.relative_path();
            !relative.is_empty() && relative.starts_with("objects/")
        }),
        "materialize describes loose placements under objects/; it performs no rename because it \
         performs no write at all"
    );
}

/// Point 6 is unreachable because object reads are synchronous and complete.
///
/// A lazy fetch has an in-flight state to interrupt. A synchronous read either
/// returned a whole body or returned a typed error, and there is no third
/// moment at which a crash could land.
#[test]
fn point_06_is_absent_because_object_reads_have_no_in_flight_state() {
    let (source, root) = fixture();
    let capability = TreeCapability::new(
        workspace(),
        repository(),
        vec![path(b"a"), path(b"a.txt"), path(b"docs")],
        vec![],
    );
    let grant = capability
        .authorize_root(0)
        .expect("the fixture capability authorizes a root read");
    let body = source
        .read_object(&root, GitObjectKind::Tree, &grant)
        .expect("a present object reads completely");
    assert!(
        !body.is_empty(),
        "a synchronous read yields the whole body, so there is no partial-fetch state"
    );

    let missing = Oid::of_object(GitObjectKind::Blob, b"never inserted\n");
    assert!(
        matches!(
            source.read_object(&missing, GitObjectKind::Blob, &grant),
            Err(ObjectSourceError::NotFound { .. })
        ),
        "an absent object is a typed refusal, not a pending fetch"
    );
}

/// Points 7 and 9 have no assertable surface in this crate.
///
/// FUSE read/writeback and manifest import name subsystems that do not exist
/// here at all, so unlike points 4, 5 and 6 there is no structural fact to
/// assert against. Rust cannot express "this module contains no FUSE adapter"
/// as a falsifiable runtime check, and inventing one would be ceremony.
///
/// They are therefore recorded as typed non-claims in the e2e receipt, where
/// `fge_unsupported` makes the gap visible and terminal, rather than asserted
/// vacuously here. This test exists to state that split deliberately, so a
/// reader does not conclude the two points were forgotten.
#[test]
fn points_07_and_09_are_recorded_as_typed_non_claims_not_asserted_here() {
    for point in [
        SpecPoint::DuringFuseReadWriteback,
        SpecPoint::AfterOutputBeforeManifestImport,
    ] {
        assert!(
            matches!(
                point.reachability(),
                Reachability::StructurallyAbsent { .. }
            ),
            "{point:?} must stay marked absent while its subsystem does not exist"
        );
    }
}

// ---------------------------------------------------------------------------
// no orphan resource survives closure
// ---------------------------------------------------------------------------

/// A finalized cancellation accounts for every staged object.
///
/// The crate holds no mount, process or credential — those parts of §14's
/// no-orphan rule are asserted by the e2e suite against the real process. What
/// is checkable here is the fourth: no temporary output survives, which in a
/// crate that writes nothing means no staged object goes unaccounted.
#[test]
fn closure_leaves_no_unaccounted_staged_object() {
    for staged in [0_usize, 1, 5] {
        let mut journal = journal_at(ExportPhase::Staged, staged, staged * 100);
        journal.request_cancel();
        journal.drain();
        let abort = journal.finalize_cancel(staged).expect("finalizes");
        assert_eq!(
            abort.discarded.body_count, staged,
            "the abort record must name every staged object it discarded"
        );
        assert!(
            !journal.left_consumable_artifact(),
            "closure with full accounting leaves no orphan output"
        );
    }
}
