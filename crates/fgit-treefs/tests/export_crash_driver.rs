//! Real-process crash driver for FG-026d.
//!
//! WHAT THIS IS FOR, stated precisely so it is not mistaken for more than it is.
//!
//! `fgit-treefs` performs no filesystem I/O at all. `export.rs` builds an
//! in-memory `ExportPlan`; `materialize.rs` returns a `ReferenceLayout`
//! describing what a loose-object store *would* contain without writing it; and
//! `proposal.rs` refuses to publish anything. So a SIGKILL mid-export cannot
//! corrupt on-disk state, because there is no on-disk state. Writing a test that
//! "proves crash safety" against that would be proving a tautology.
//!
//! What a real process kill DOES establish, and what an in-process loop cannot,
//! is determinism across fresh address-space layouts. Each execution gets new
//! ASLR, a fresh allocator, and fresh hash seeds. AGENTS.md §5.3 forbids relying
//! on map iteration order, and §5.4 requires staged/visible/durable to stay
//! distinct; an accidental dependence on pointer or hash-seed ordering would
//! produce a plan that differs between processes while looking perfectly stable
//! inside any single one. That is the defect class this driver exists to catch.
//!
//! The shell suite runs this binary once to get a baseline fingerprint, then once
//! per journal phase with `FGIT_TREEFS_CRASH_AT` set — aborting the process at
//! that phase — and then again to completion, requiring the fingerprint to be
//! identical every time and requiring the aborted runs to have produced no
//! output and left no file behind.
//!
//! Kept `#[ignore]` because it deliberately calls `process::abort()`.

use fgit_crypto::{GitObjectKind, GitOid, NativeObjectIdentity, Sha1};
use fgit_git_object::{AcceptanceProfile, ParseLimits, TreeEntry, emit_tree};
use fgit_treefs::base::{BaseView, ObjectSource, ObjectSourceError};
use fgit_treefs::capability::{ReadGrant, TreeCapability, WorkspaceId};
use fgit_treefs::export::{ExportLimits, ExportPlanner};
use fgit_treefs::journal::{ExportJournal, ExportPhase};
use fgit_treefs::obligation::WorkspaceLeaseReservation;
use fgit_treefs::overlay::{ContentRef, EntryClass, FileMode, Overlay, OverlayEntry};
use fgit_treefs::path::{PathPolicy, TreePath};
use fgit_types::identity::RepositoryCommitId;
use fgit_types::{CodecVersion, DigestAlgorithmId, DigestBytes, RepositoryId};
use std::collections::BTreeMap;
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::process;

type Oid = GitOid<Sha1>;

const CRASH_AT_ENV: &str = "FGIT_TREEFS_CRASH_AT";
const CRASH_OUT_ENV: &str = "FGIT_TREEFS_CRASH_OUT";
/// Optional directory to run inside, so the suite can prove the export creates
/// no file where it runs.
const PROBE_DIR_ENV: &str = "FGIT_TREEFS_PROBE_DIR";

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
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

/// A workspace wide enough that an ordering bug has room to show.
///
/// Deliberately includes the sibling names that stress Git's directory sort
/// (`a.txt` against the tree `a`), several same-prefix siblings, and a nested
/// subtree that stays untouched so the reuse path is exercised too.
fn fixture() -> (MemorySource, Oid) {
    let mut source = MemorySource::default();
    let a_txt = source.blob(b"a.txt body\n");
    let a_b_txt = source.blob(b"a-b.txt body\n");
    let inner = source.blob(b"inner body\n");
    let deep = source.blob(b"deep body\n");
    let readme = source.blob(b"# readme\n");

    let deep_tree = source.tree(&[entry(b"100644", b"deep.txt", &deep)]);
    let a_tree = source.tree(&[
        entry(b"100644", b"inner.txt", &inner),
        entry(b"40000", b"nested", &deep_tree),
    ]);
    let docs_tree = source.tree(&[entry(b"100644", b"readme.md", &readme)]);
    let root = source.tree(&[
        entry(b"40000", b"a", &a_tree),
        entry(b"100644", b"a-b.txt", &a_b_txt),
        entry(b"100644", b"a.txt", &a_txt),
        entry(b"40000", b"docs", &docs_tree),
    ]);
    (source, root)
}

fn path(bytes: &[u8]) -> TreePath {
    TreePath::parse_default(bytes).expect("fixture path parses")
}

fn crash_if_requested(phase: ExportPhase) {
    if let Ok(requested) = env::var(CRASH_AT_ENV)
        && !requested.is_empty()
        && requested == phase.to_string()
    {
        // A real SIGKILL-equivalent: no unwinding, no destructors, no flush.
        // Anything the crate had "in flight" dies exactly as it would in a power
        // loss, which is the point of running this out of process.
        process::abort();
    }
}

#[test]
#[ignore = "aborts the process on purpose; driven by scripts/e2e/suites/treefs/export_crash.sh"]
fn export_plan_fingerprint_is_stable_across_processes() {
    let out_path = env::var(CRASH_OUT_ENV)
        .expect("FGIT_TREEFS_CRASH_OUT must name the fingerprint output file");

    // Cargo runs test binaries with the current directory set to the PACKAGE
    // ROOT, not wherever cargo was invoked. So the containment probe cannot be
    // established by launching cargo from a scratch directory -- the export
    // would run in crates/fgit-treefs while the suite watched an empty
    // directory that nothing was ever going to touch. Moving here explicitly is
    // what makes FG-026D-CONTAIN-001 able to fail.
    if let Ok(probe) = env::var(PROBE_DIR_ENV)
        && !probe.is_empty()
    {
        env::set_current_dir(&probe).expect("probe directory is enterable");
    }

    let (source, root) = fixture();
    let mut journal = ExportJournal::open(WorkspaceId::from_bytes([1; 16]));

    crash_if_requested(ExportPhase::Unstarted);

    journal.reserve(WorkspaceLeaseReservation {
        workspace_id: WorkspaceId::from_bytes([1; 16]),
        reserved_bytes: 1 << 20,
        reserved_entries: 1024,
    });
    journal
        .advance(ExportPhase::Reserved)
        .expect("reserving is the first legal transition");
    crash_if_requested(ExportPhase::Reserved);

    let view = BaseView::new(
        RepositoryId::from_bytes([7; 16]),
        RepositoryCommitId::from_digest(
            DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
                .expect("nonzero corpus fixture algorithm slot"),
            CodecVersion::new(1, 0),
            DigestBytes::try_new(&[9_u8; 32]).expect("32-byte corpus fixture body"),
        ),
        root,
        root,
        ParseLimits::default(),
        PathPolicy::default(),
    );

    let mut overlay = Overlay::new();
    let changed = overlay.intern(b"inner body changed\n".to_vec());
    overlay.put(
        path(b"a/inner.txt"),
        OverlayEntry::File {
            content: ContentRef::Overlay(changed),
            mode: FileMode::Regular,
            class: EntryClass::Content,
        },
    );
    let added = overlay.intern(b"added body\n".to_vec());
    overlay.put(
        path(b"docs/added.md"),
        OverlayEntry::File {
            content: ContentRef::Overlay(added),
            mode: FileMode::Regular,
            class: EntryClass::Content,
        },
    );

    let mut capability = TreeCapability::new(
        WorkspaceId::from_bytes([1; 16]),
        RepositoryId::from_bytes([7; 16]),
        vec![
            path(b"a"),
            path(b"a/inner.txt"),
            path(b"a/nested"),
            path(b"a-b.txt"),
            path(b"a.txt"),
            path(b"docs"),
            path(b"docs/added.md"),
            path(b"docs/readme.md"),
        ],
        vec![
            path(b"a"),
            path(b"a/inner.txt"),
            path(b"docs"),
            path(b"docs/added.md"),
        ],
    );

    let plan = ExportPlanner::new(ExportLimits::default(), ParseLimits::default())
        .plan(&view, &source, &mut capability, &overlay, 0, &|| false)
        .expect("the fixture workspace exports");

    journal
        .advance(ExportPhase::Planned)
        .expect("planning follows reservation");
    crash_if_requested(ExportPhase::Planned);

    journal.record_staged(plan.object_count(), plan.total_bytes());
    journal
        .advance(ExportPhase::Staged)
        .expect("staging follows planning");
    crash_if_requested(ExportPhase::Staged);

    journal
        .advance(ExportPhase::Proposed)
        .expect("proposing follows staging");
    crash_if_requested(ExportPhase::Proposed);

    journal
        .advance(ExportPhase::Settled)
        .expect("settling follows proposing");
    crash_if_requested(ExportPhase::Settled);

    // The fingerprint covers the plan's full observable content in emission
    // order, not just the root identity. A reordering that left the root hash
    // untouched would still move this value.
    let mut transcript = String::new();
    let _ = writeln!(transcript, "root\t{}", hex(plan.root_tree().digest_bytes()));
    let _ = writeln!(transcript, "objects\t{}", plan.object_count());
    let _ = writeln!(transcript, "bytes\t{}", plan.total_bytes());
    let _ = writeln!(transcript, "reused\t{}", plan.reused_base_objects());
    for object in plan.objects() {
        let _ = writeln!(
            transcript,
            "object\t{}\t{:?}\t{}",
            hex(object.oid().digest_bytes()),
            object.kind(),
            object.body().len()
        );
    }
    let _ = writeln!(transcript, "staged_epoch\t{:?}", journal.staged_epoch());
    let _ = writeln!(transcript, "phase\t{}", journal.phase());

    let fingerprint = Oid::of_object(GitObjectKind::Blob, transcript.as_bytes());
    let rendered = format!(
        "fingerprint\t{}\n{transcript}",
        hex(fingerprint.digest_bytes())
    );

    fs::write(&out_path, rendered).expect("fingerprint output is writable");
}

// Non-production fixture identity: this reserved tag deliberately has no registered digest width.
const FIXTURE_ALGORITHM_CODE_POINT: u16 = 0xfff1;
const _: () = assert!(FIXTURE_ALGORITHM_CODE_POINT >= 0xfff0);
