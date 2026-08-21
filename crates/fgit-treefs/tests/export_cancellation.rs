//! Cancellation campaign for FG-026d.
//!
//! The bead asks for cancellation "at path fetch, overlay evaluation, object
//! encode/write/sync, proposal seal, and cleanup". `ExportPlanner::plan` does not
//! expose those as named points — it polls one `cancelled()` closure at three
//! sites — so naming five phases here would be inventing a structure the code
//! does not have and asserting against my own fiction.
//!
//! What the code does support is stronger than the list: cancel at EVERY
//! observable poll, swept exhaustively. The campaign first counts how many times
//! an uninterrupted export asks, then re-runs cancelling at each one in turn.
//! That covers every point cancellation can actually be observed, and it stays
//! correct if someone adds a fourth poll site later, because the sweep is
//! derived rather than hard-coded.
//!
//! The load-bearing property is the same one AGENTS.md §5.4 and §3.2 require: a
//! cancelled export yields NO plan. Not a partial plan, not an empty plan a
//! caller could mistake for "nothing to do" — a typed refusal. And per §16.3,
//! every forbidden case is paired with a near-identical permitted one, so a
//! planner that simply always refused would fail this file rather than pass it.

use fgit_crypto::{GitObjectKind, GitOid, NativeObjectIdentity, Sha1};
use fgit_git_object::{AcceptanceProfile, ParseLimits, TreeEntry, emit_tree};
use fgit_treefs::base::{BaseView, ObjectSource, ObjectSourceError};
use fgit_treefs::capability::{ReadGrant, TreeCapability, WorkspaceId};
use fgit_treefs::export::{ExportLimits, ExportPlanner, ExportRefusal};
use fgit_treefs::journal::{CancellationState, ExportJournal, ExportPhase};
use fgit_treefs::obligation::WorkspaceLeaseReservation;
use fgit_treefs::overlay::{ContentRef, EntryClass, FileMode, Overlay, OverlayEntry};
use fgit_treefs::path::{PathPolicy, TreePath};
use fgit_types::identity::RepositoryCommitId;
use fgit_types::{CodecVersion, DigestAlgorithmId, DigestBytes, RepositoryId};
use std::cell::Cell;
use std::collections::BTreeMap;

type Oid = GitOid<Sha1>;

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

fn path(bytes: &[u8]) -> TreePath {
    TreePath::parse_default(bytes).expect("fixture path parses")
}

/// Deep enough that the export polls more than once.
fn fixture() -> (MemorySource, Oid) {
    let mut source = MemorySource::default();
    let inner = source.blob(b"inner\n");
    let deep = source.blob(b"deep\n");
    let readme = source.blob(b"# readme\n");

    let deep_tree = source.tree(&[entry(b"100644", b"deep.txt", &deep)]);
    let src_tree = source.tree(&[
        entry(b"100644", b"inner.txt", &inner),
        entry(b"40000", b"nested", &deep_tree),
    ]);
    let docs_tree = source.tree(&[entry(b"100644", b"readme.md", &readme)]);
    let root = source.tree(&[
        entry(b"40000", b"docs", &docs_tree),
        entry(b"40000", b"src", &src_tree),
    ]);
    (source, root)
}

fn view(root: Oid) -> BaseView<Sha1> {
    BaseView::new(
        RepositoryId::from_bytes([7; 16]),
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

fn capability() -> TreeCapability {
    TreeCapability::new(
        WorkspaceId::from_bytes([1; 16]),
        RepositoryId::from_bytes([7; 16]),
        vec![
            path(b"docs"),
            path(b"docs/readme.md"),
            path(b"src"),
            path(b"src/inner.txt"),
            path(b"src/nested"),
        ],
        vec![path(b"src"), path(b"src/inner.txt"), path(b"docs")],
    )
}

fn overlay() -> Overlay {
    let mut overlay = Overlay::new();
    let changed = overlay.intern(b"inner changed\n".to_vec());
    overlay.put(
        path(b"src/inner.txt"),
        OverlayEntry::File {
            content: ContentRef::Overlay(changed),
            mode: FileMode::Regular,
            class: EntryClass::Content,
        },
    );
    overlay
}

/// Runs an export whose `cancelled()` returns true on the `trip`-th poll.
///
/// `trip == usize::MAX` never cancels, which is how the permitted twin is run
/// through exactly the same code path as the refusals.
fn export_cancelling_at(trip: usize) -> (Result<(), ExportRefusal>, usize) {
    let (source, root) = fixture();
    let base = view(root);
    let mut cap = capability();
    let overlay = overlay();

    let polls = Cell::new(0_usize);
    let cancelled = || {
        let seen = polls.get();
        polls.set(seen + 1);
        seen == trip
    };

    let outcome = ExportPlanner::new(ExportLimits::default(), ParseLimits::default())
        .plan(&base, &source, &mut cap, &overlay, 0, &cancelled)
        .map(|_plan| ());
    (outcome, polls.get())
}

/// The permitted twin: the identical workspace, never cancelled, exports.
///
/// Without this the refusal sweep below would be satisfied by a planner that
/// refused unconditionally.
#[test]
fn the_same_workspace_exports_when_it_is_not_cancelled() {
    let (outcome, polls) = export_cancelling_at(usize::MAX);
    assert!(
        outcome.is_ok(),
        "the uncancelled twin must export; got {outcome:?}"
    );
    assert!(
        polls > 1,
        "the export must poll cancellation more than once, or the sweep below is trivial; \
         observed {polls}"
    );
}

/// Cancelling at every observable poll yields a typed refusal and no plan.
#[test]
fn cancelling_at_every_observable_poll_refuses_and_yields_no_plan() {
    let (_baseline, total_polls) = export_cancelling_at(usize::MAX);
    assert!(
        total_polls > 0,
        "the export polls cancellation at least once"
    );

    for trip in 0..total_polls {
        let (outcome, _polls) = export_cancelling_at(trip);
        assert!(
            matches!(outcome, Err(ExportRefusal::Cancelled)),
            "cancelling at poll {trip} of {total_polls} must yield ExportRefusal::Cancelled, \
             never a partial plan and never a silent success; got {outcome:?}"
        );
    }
}

/// Cancelling one poll after the last one changes nothing.
///
/// The boundary case: a cancellation that arrives after the export has stopped
/// asking must not retroactively fail a completed export, and must not be
/// mistaken for "cancellation was ignored".
#[test]
fn a_cancellation_that_arrives_after_the_last_poll_does_not_undo_the_export() {
    let (_baseline, total_polls) = export_cancelling_at(usize::MAX);
    let (outcome, _polls) = export_cancelling_at(total_polls);
    assert!(
        outcome.is_ok(),
        "an export that finished asking has finished; got {outcome:?}"
    );
}

// ---------------------------------------------------------------------------
// obligation drain
// ---------------------------------------------------------------------------

/// Cancellation is request -> drain -> finalize, and each step is observable.
///
/// AGENTS.md §3.2: dropping a future is not a complete protocol. A caller must
/// be able to tell "asked to stop" from "stopped and cleaned up".
#[test]
fn cancellation_drains_the_lease_to_quiescence_and_leaves_no_artifact() {
    let mut journal = ExportJournal::open(WorkspaceId::from_bytes([1; 16]));
    journal.reserve(WorkspaceLeaseReservation {
        workspace_id: WorkspaceId::from_bytes([1; 16]),
        reserved_bytes: 1 << 20,
        reserved_entries: 1024,
    });
    journal
        .advance(ExportPhase::Reserved)
        .expect("reserve is legal");
    journal
        .advance(ExportPhase::Planned)
        .expect("plan follows reserve");
    journal.record_staged(3, 300);
    journal
        .advance(ExportPhase::Staged)
        .expect("stage follows plan");

    journal.request_cancel();
    assert_eq!(journal.cancellation(), CancellationState::Requested);

    journal.drain();
    assert_eq!(journal.cancellation(), CancellationState::Drained);

    // Every staged object reclaimed: the cancellation is clean.
    let abort = journal
        .finalize_cancel(3)
        .expect("a drained journal can finalize");
    assert_eq!(journal.cancellation(), CancellationState::Finalized);
    assert_eq!(abort.workspace_id, WorkspaceId::from_bytes([1; 16]));
    assert!(
        !journal.left_consumable_artifact(),
        "a finalized cancellation leaves nothing a consumer could mistake for a result"
    );
}

/// The near-identical failing twin: one object unreclaimed is a containment
/// failure, reported rather than swallowed.
///
/// This is what stops the test above from being satisfied by a `finalize_cancel`
/// that always reports success.
#[test]
fn an_unreclaimed_staged_object_is_a_reported_containment_failure() {
    let mut journal = ExportJournal::open(WorkspaceId::from_bytes([1; 16]));
    journal
        .advance(ExportPhase::Reserved)
        .expect("reserve is legal");
    journal
        .advance(ExportPhase::Planned)
        .expect("plan follows reserve");
    journal.record_staged(3, 300);
    journal
        .advance(ExportPhase::Staged)
        .expect("stage follows plan");

    journal.request_cancel();
    journal.drain();
    let _abort = journal
        .finalize_cancel(2)
        .expect("finalize still returns the abort record");

    assert_eq!(
        journal.cancellation(),
        CancellationState::ContainmentFailed,
        "two of three reclaimed is not quiescence"
    );
    assert!(
        journal.left_consumable_artifact(),
        "an unaccounted staged object is exactly what a later GC or export must be told about"
    );
}

/// Finalizing before draining is refused, so the protocol cannot be short-cut.
#[test]
fn finalizing_without_draining_is_refused() {
    let mut journal = ExportJournal::open(WorkspaceId::from_bytes([1; 16]));
    journal
        .advance(ExportPhase::Reserved)
        .expect("reserve is legal");
    journal.request_cancel();

    assert!(
        journal.finalize_cancel(0).is_err(),
        "request -> finalize skipping drain must be refused; dropping the drain step is \
         precisely the incomplete protocol AGENTS.md §3.2 forbids"
    );
}
