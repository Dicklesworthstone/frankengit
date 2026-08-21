//! Resource and adversarial refusal coverage for FG-026d.
//!
//! Four `ExportRefusal` variants had no test at all: `ByteBudgetExceeded`,
//! `TreeTooWide`, `PathTypeConflict` and `Base`. Three of them are resource
//! bounds, which AGENTS.md §14 asks to be enforced before allocation and work,
//! and the fourth is the propagation path for a base read that fails. An
//! untested refusal is a claim the system makes without evidence it can honour
//! it — the same shape as the two data-loss defects the differential found,
//! which also lived in code no test exercised.
//!
//! Every refusal here is paired with a near-identical PERMITTED case (§16.3), so
//! none of it is satisfiable by an exporter that simply refuses more often.

use fgit_crypto::{GitObjectKind, GitOid, NativeObjectIdentity, Sha1};
use fgit_git_object::{AcceptanceProfile, ParseLimits, TreeEntry, emit_tree};
use fgit_treefs::base::{BaseError, BaseView, ObjectSource, ObjectSourceError};
use fgit_treefs::capability::{ReadGrant, TreeCapability, WorkspaceId};
use fgit_treefs::export::{ExportLimits, ExportPlanner, ExportRefusal};
use fgit_treefs::overlay::{ContentRef, EntryClass, FileMode, Overlay, OverlayEntry};
use fgit_treefs::path::{PathPolicy, TreePath};
use fgit_types::identity::RepositoryCommitId;
use fgit_types::{CodecVersion, DigestAlgorithmId, DigestBytes, RepositoryId};
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

    /// Removes an object so a base read of it fails.
    fn forget(&mut self, oid: &Oid) {
        self.objects.remove(oid.digest_bytes());
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

fn fixture() -> (MemorySource, Oid) {
    let mut source = MemorySource::default();
    let lib = source.blob(b"fn main() {}\n");
    let readme = source.blob(b"# readme\n");
    let src_tree = source.tree(&[entry(b"100644", b"lib.rs", &lib)]);
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

fn wide_capability() -> TreeCapability {
    TreeCapability::new(
        WorkspaceId::from_bytes([1; 16]),
        RepositoryId::from_bytes([7; 16]),
        vec![path(b"docs"), path(b"src"), path(b"wide"), path(b"a")],
        vec![path(b"docs"), path(b"src"), path(b"wide"), path(b"a")],
    )
}

fn file(overlay: &mut Overlay, at: &[u8], body: &[u8]) {
    let id = overlay.intern(body.to_vec());
    overlay.put(
        path(at),
        OverlayEntry::File {
            content: ContentRef::Overlay(id),
            mode: FileMode::Regular,
            class: EntryClass::Content,
        },
    );
}

fn plan_with(
    limits: ExportLimits,
    source: &MemorySource,
    root: Oid,
    overlay: &Overlay,
) -> Result<usize, ExportRefusal> {
    let base = view(root);
    let mut cap = wide_capability();
    ExportPlanner::new(limits, ParseLimits::default())
        .plan(&base, source, &mut cap, overlay, 0, &|| false)
        .map(|plan| plan.object_count())
}

// ---------------------------------------------------------------------------
// byte budget
// ---------------------------------------------------------------------------

#[test]
fn a_byte_budget_is_enforced_and_a_generous_one_proceeds() {
    let (source, root) = fixture();
    let mut overlay = Overlay::new();
    file(&mut overlay, b"src/lib.rs", &vec![b'x'; 4096]);

    let refused = plan_with(
        ExportLimits {
            max_total_bytes: 128,
            ..ExportLimits::default()
        },
        &source,
        root,
        &overlay,
    );
    assert!(
        matches!(refused, Err(ExportRefusal::ByteBudgetExceeded { .. })),
        "a 4 KiB body under a 128 byte ceiling must be refused by byte budget; got {refused:?}"
    );

    // The permitted twin: identical workspace, ceiling that admits it.
    let allowed = plan_with(ExportLimits::default(), &source, root, &overlay);
    assert!(
        allowed.is_ok(),
        "the same export under the default ceiling must proceed; got {allowed:?}"
    );
}

/// The refusal reports the numbers it actually decided on.
///
/// A bound that refuses without naming the observed value and the ceiling
/// cannot be acted on by a caller, and cannot be distinguished from a bug.
#[test]
fn the_byte_budget_refusal_names_the_observed_size_and_the_ceiling() {
    let (source, root) = fixture();
    let mut overlay = Overlay::new();
    file(&mut overlay, b"src/lib.rs", &vec![b'x'; 4096]);

    match plan_with(
        ExportLimits {
            max_total_bytes: 128,
            ..ExportLimits::default()
        },
        &source,
        root,
        &overlay,
    ) {
        Err(ExportRefusal::ByteBudgetExceeded { observed, limit }) => {
            assert_eq!(limit, 128, "the refusal names the configured ceiling");
            assert!(
                observed > limit,
                "the refusal names an observed size that actually exceeds the ceiling; \
                 observed {observed}, limit {limit}"
            );
        }
        other => panic!("expected ByteBudgetExceeded, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// tree width
// ---------------------------------------------------------------------------

#[test]
fn an_over_wide_tree_is_refused_and_a_narrow_one_proceeds() {
    let (source, root) = fixture();
    let mut overlay = Overlay::new();
    for index in 0..16_u32 {
        let name = format!("wide/file{index:03}.txt");
        file(&mut overlay, name.as_bytes(), b"body\n");
    }

    let refused = plan_with(
        ExportLimits {
            max_tree_entries: 4,
            ..ExportLimits::default()
        },
        &source,
        root,
        &overlay,
    );
    assert!(
        matches!(refused, Err(ExportRefusal::TreeTooWide { .. })),
        "16 entries under a 4 entry ceiling must be refused as too wide; got {refused:?}"
    );

    // The permitted twin: the same 16 entries under a ceiling that admits them.
    let allowed = plan_with(
        ExportLimits {
            max_tree_entries: 64,
            ..ExportLimits::default()
        },
        &source,
        root,
        &overlay,
    );
    assert!(
        allowed.is_ok(),
        "the same tree under a 64 entry ceiling must proceed; got {allowed:?}"
    );
}

/// The width refusal names WHERE the tree is, so a caller can act on it.
#[test]
fn the_width_refusal_locates_the_offending_tree() {
    let (source, root) = fixture();
    let mut overlay = Overlay::new();
    for index in 0..16_u32 {
        let name = format!("wide/file{index:03}.txt");
        file(&mut overlay, name.as_bytes(), b"body\n");
    }

    match plan_with(
        ExportLimits {
            max_tree_entries: 4,
            ..ExportLimits::default()
        },
        &source,
        root,
        &overlay,
    ) {
        Err(ExportRefusal::TreeTooWide {
            path: located,
            observed,
            limit,
        }) => {
            assert_eq!(limit, 4, "the refusal names the configured ceiling");
            assert!(
                observed > limit,
                "observed {observed} must exceed limit {limit}"
            );
            // `None` means the root; either is actionable, an absent field is not.
            assert!(
                located.is_none() || located == Some(path(b"wide")),
                "the refusal locates the offending tree; got {located:?}"
            );
        }
        other => panic!("expected TreeTooWide, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// base read failure
// ---------------------------------------------------------------------------

/// An unreadable subtree that the export MUST read is a typed refusal.
///
/// The subtree has to be one the export actually touches. My first version of
/// this test dropped `docs`, which the overlay never edits -- and an untouched
/// subtree is deliberately carried forward by identity WITHOUT being read, so
/// the export succeeded and I nearly filed that correct behaviour as a defect.
/// Reuse-without-reading is the optimisation `untouched_subtrees_are_reused_not_reencoded`
/// exists to protect. `src` is dirty here, so it must be listed, and a store
/// that cannot supply it must refuse rather than emit a tree missing it.
#[test]
fn a_base_read_failure_is_a_typed_refusal_not_a_silent_omission() {
    let (mut source, root) = fixture();

    let src_oid = {
        let lib = Oid::of_object(GitObjectKind::Blob, b"fn main() {}\n");
        let body = emit_tree(
            &[entry(b"100644", b"lib.rs", &lib)],
            AcceptanceProfile::GitCompatibleImport,
            &ParseLimits::default(),
        )
        .expect("fixture tree emits");
        Oid::of_object(GitObjectKind::Tree, &body)
    };
    source.forget(&src_oid);

    let mut overlay = Overlay::new();
    file(&mut overlay, b"src/lib.rs", b"changed\n");

    let refused = plan_with(ExportLimits::default(), &source, root, &overlay);
    assert!(
        refused.is_err(),
        "an unreadable base subtree must refuse, never export a tree without it; got {refused:?}"
    );

    // The permitted twin: the identical export against an intact store.
    let (intact, intact_root) = fixture();
    let allowed = plan_with(ExportLimits::default(), &intact, intact_root, &overlay);
    assert!(
        allowed.is_ok(),
        "the same export against an intact store proceeds; got {allowed:?}"
    );
}

// ---------------------------------------------------------------------------
// path type conflict
// ---------------------------------------------------------------------------

/// A path cannot be both a file and a directory in one exported tree.
///
/// Git has no representation for it, so the export must refuse rather than pick
/// a winner. AGENTS.md §5.3 is explicit that ambiguous duplicate map values are
/// never preserved and map iteration order never decides an outcome; silently
/// dropping one of the two would let iteration order choose which of the user's
/// edits survives.
///
/// `ExportRefusal::PathTypeConflict` exists for exactly this and, at the time
/// this test was written, was declared but never raised anywhere in export.rs.
#[test]
fn a_path_that_is_both_a_file_and_a_directory_is_refused() {
    let (source, root) = fixture();
    let mut overlay = Overlay::new();
    file(&mut overlay, b"a", b"a is a file\n");
    file(&mut overlay, b"a/b", b"a is also a directory\n");

    let outcome = plan_with(ExportLimits::default(), &source, root, &overlay);
    assert!(
        matches!(outcome, Err(ExportRefusal::PathTypeConflict { .. })),
        "`a` as both file and directory must be refused, not silently resolved; got {outcome:?}"
    );

    // The permitted twin: the same two bodies at non-conflicting paths export.
    let mut fine = Overlay::new();
    file(&mut fine, b"a/one", b"a is a file\n");
    file(&mut fine, b"a/b", b"a is also a directory\n");
    let allowed = plan_with(ExportLimits::default(), &source, root, &fine);
    assert!(
        allowed.is_ok(),
        "two bodies under the same directory are perfectly legal; got {allowed:?}"
    );
}

// ---------------------------------------------------------------------------
// object size bound
// ---------------------------------------------------------------------------

/// An object larger than the parse ceiling is refused before it is parsed.
///
/// `BaseView::read_object` checks the length of what the source returned against
/// `ParseLimits::max_object_bytes` and refuses before handing the bytes to the
/// parser. This is the resource bound AGENTS.md §14 asks about — enforced before
/// the work, not after it — and it had no test, so nothing established that a
/// hostile or corrupt source could not simply hand over an enormous tree and have
/// it parsed anyway.
#[test]
fn an_object_over_the_parse_ceiling_is_refused_and_a_generous_ceiling_admits_it() {
    let (source, root) = fixture();

    let tight = BaseView::<Sha1>::new(
        RepositoryId::from_bytes([7; 16]),
        RepositoryCommitId::from_digest(
            DigestAlgorithmId::try_new(1).expect("algorithm 1 is registered"),
            CodecVersion::new(1, 0),
            DigestBytes::try_new(&[9_u8; 32]).expect("fixture digest is a legal width"),
        ),
        root,
        root,
        ParseLimits {
            max_object_bytes: 8,
            ..ParseLimits::default()
        },
        PathPolicy::default(),
    );
    let mut cap = wide_capability();

    let refused = tight.resolve(&source, &mut cap, &path(b"src/lib.rs"), 0);
    assert!(
        matches!(
            refused,
            Err(BaseError::Source(ObjectSourceError::TooLarge { .. }))
        ),
        "a tree larger than the 8 byte ceiling must be refused as too large; got {refused:?}"
    );

    // The permitted twin: the identical read under the default ceiling.
    let roomy = view(root);
    let mut cap2 = wide_capability();
    let allowed = roomy.resolve(&source, &mut cap2, &path(b"src/lib.rs"), 0);
    assert!(
        allowed.is_ok(),
        "the same read under the default ceiling proceeds; got {allowed:?}"
    );
}

/// The size refusal names the observed size and the ceiling.
#[test]
fn the_size_refusal_names_what_it_measured() {
    let (source, root) = fixture();
    let tight = BaseView::<Sha1>::new(
        RepositoryId::from_bytes([7; 16]),
        RepositoryCommitId::from_digest(
            DigestAlgorithmId::try_new(1).expect("algorithm 1 is registered"),
            CodecVersion::new(1, 0),
            DigestBytes::try_new(&[9_u8; 32]).expect("fixture digest is a legal width"),
        ),
        root,
        root,
        ParseLimits {
            max_object_bytes: 8,
            ..ParseLimits::default()
        },
        PathPolicy::default(),
    );
    let mut cap = wide_capability();

    match tight.resolve(&source, &mut cap, &path(b"src/lib.rs"), 0) {
        Err(BaseError::Source(ObjectSourceError::TooLarge { observed, limit })) => {
            assert_eq!(limit, 8, "the refusal names the configured ceiling");
            assert!(
                observed > limit,
                "observed {observed} must actually exceed limit {limit}"
            );
        }
        other => panic!("expected TooLarge, got {other:?}"),
    }
}
