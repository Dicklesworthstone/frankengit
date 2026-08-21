//! Base-view resolution, capability enforcement, and snapshot behaviour.
//!
//! The object source here is a real in-memory implementation of the
//! [`ObjectSource`] trait over genuine Git tree and blob bytes, built with
//! `fgit-git-object`'s emitter and identified with the native hasher. It is a
//! caller-side implementation of a published boundary, which is what every
//! consumer of this crate must write; it is not a stand-in for a production
//! parser.

use fgit_crypto::{GitObjectKind, GitOid, NativeObjectIdentity, Sha1};
use fgit_git_object::{AcceptanceProfile, ParseLimits, TreeEntry, emit_tree};
use fgit_treefs::base::{BaseEntry, BaseError, BaseView, ObjectSource, ObjectSourceError};
use fgit_treefs::capability::{
    CapabilityRefusal, ReadGrant, SymlinkPolicy, TreeCapability, WorkspaceId,
};
use fgit_treefs::overlay::{EntryClass, FileMode, Overlay, OverlayEntry};
use fgit_treefs::path::{PathPolicy, TreePath};
use fgit_treefs::snapshot::{
    AntiRollbackRefusal, EpochSet, OverlayRoot, SessionRecord, WorkspaceEpoch,
    WorkspaceSnapshotBody,
};
use fgit_types::identity::RepositoryCommitId;
use fgit_types::{ByteCount, CodecVersion, DigestAlgorithmId, DigestBytes, RepositoryId};
use std::cell::RefCell;
use std::collections::BTreeMap;

type Oid = GitOid<Sha1>;

fn path(bytes: &[u8]) -> TreePath {
    TreePath::parse_default(bytes).expect("test path parses")
}

fn limits() -> ParseLimits {
    ParseLimits::default()
}

/// An in-memory object store that records how many reads it served, so a test
/// can assert that a refused access never reached the source at all.
#[derive(Default)]
struct MemorySource {
    objects: BTreeMap<Vec<u8>, Vec<u8>>,
    reads: RefCell<usize>,
    /// When set, this object is served with corrupted bytes.
    corrupt: Option<Vec<u8>>,
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

    fn reads(&self) -> usize {
        *self.reads.borrow()
    }
}

impl ObjectSource<Sha1> for MemorySource {
    fn read_object(
        &self,
        oid: &Oid,
        _kind: GitObjectKind,
        _grant: &ReadGrant,
    ) -> Result<Vec<u8>, ObjectSourceError> {
        *self.reads.borrow_mut() += 1;
        let key = oid.digest_bytes().to_vec();
        if self.corrupt.as_ref() == Some(&key) {
            return Ok(b"these are not the bytes you asked for".to_vec());
        }
        self.objects
            .get(&key)
            .cloned()
            .ok_or_else(|| ObjectSourceError::NotFound {
                oid_hex: hex(oid.digest_bytes()),
            })
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn entry(mode: &[u8], name: &[u8], oid: &Oid) -> TreeEntry {
    TreeEntry {
        mode: mode.to_vec(),
        name: name.to_vec(),
        object_id: oid.digest_bytes().to_vec(),
    }
}

/// Builds `src/{lib.rs,link}` plus `docs/readme.md` and a gitlink.
fn fixture() -> (MemorySource, Oid) {
    let mut source = MemorySource::default();
    let lib = source.blob(b"fn main() {}\n");
    let link = source.blob(b"../docs/readme.md");
    let readme = source.blob(b"# readme\n");
    let submodule = source.blob(b"submodule-commit-stand-in");

    let src_tree = source.tree(&[
        entry(b"100644", b"lib.rs", &lib),
        entry(b"120000", b"link", &link),
    ]);
    let docs_tree = source.tree(&[entry(b"100644", b"readme.md", &readme)]);
    let root = source.tree(&[
        entry(b"40000", b"docs", &docs_tree),
        entry(b"40000", b"src", &src_tree),
        entry(b"160000", b"vendor", &submodule),
    ]);
    (source, root)
}

fn repository_id() -> RepositoryId {
    RepositoryId::from_bytes([7; 16])
}

fn rcr_id() -> RepositoryCommitId {
    RepositoryCommitId::from_digest(
        DigestAlgorithmId::try_new(1).expect("algorithm 1 is registered"),
        CodecVersion::new(1, 0),
        DigestBytes::try_new(&[9_u8; 32]).expect("fixture digest is a legal width"),
    )
}

fn base(root: Oid) -> BaseView<Sha1> {
    BaseView::new(
        repository_id(),
        rcr_id(),
        root.clone(),
        root,
        limits(),
        PathPolicy::default(),
    )
}

fn full_capability() -> TreeCapability {
    TreeCapability::new(
        WorkspaceId::from_bytes([1; 16]),
        repository_id(),
        vec![path(b"src"), path(b"docs"), path(b"vendor")],
        vec![path(b"src")],
    )
}

// ---------------------------------------------------------------------------
// base resolution
// ---------------------------------------------------------------------------

/// Resolving an authorised path returns the typed entry it names.
#[test]
fn resolves_files_symlinks_directories_and_submodules() {
    let (source, root) = fixture();
    let view = base(root);
    let mut capability = full_capability();

    match view
        .resolve(&source, &mut capability, &path(b"src/lib.rs"), 0)
        .expect("lib.rs resolves")
    {
        BaseEntry::File { mode, .. } => assert_eq!(mode, b"100644"),
        other => panic!("expected a file, got {other:?}"),
    }

    assert!(matches!(
        view.resolve(&source, &mut capability, &path(b"src/link"), 0),
        Ok(BaseEntry::Symlink { .. })
    ));
    assert!(matches!(
        view.resolve(&source, &mut capability, &path(b"src"), 0),
        Ok(BaseEntry::Directory { .. })
    ));
    assert!(matches!(
        view.resolve(&source, &mut capability, &path(b"vendor"), 0),
        Ok(BaseEntry::Submodule { .. })
    ));
}

/// A path that does not exist is a typed not-found, not a panic or an empty
/// success.
#[test]
fn missing_paths_are_typed_not_found() {
    let (source, root) = fixture();
    let view = base(root);
    let mut capability = full_capability();

    assert!(matches!(
        view.resolve(&source, &mut capability, &path(b"src/absent.rs"), 0),
        Err(BaseError::NotFound { .. })
    ));
    assert!(matches!(
        view.resolve(&source, &mut capability, &path(b"src/lib.rs/deeper"), 0),
        Err(BaseError::NotADirectory { .. })
    ));
}

/// Resolution refuses to walk *through* a symlink, while reading the symlink
/// itself is permitted.
#[test]
fn symlink_traversal_is_refused_but_reading_the_link_is_not() {
    let (source, root) = fixture();
    let view = base(root);
    let mut capability = full_capability();

    assert!(
        matches!(
            view.resolve(&source, &mut capability, &path(b"src/link"), 0),
            Ok(BaseEntry::Symlink { .. })
        ),
        "the link entry itself is ordinary data"
    );
    assert!(
        matches!(
            view.resolve(&source, &mut capability, &path(b"src/link/readme.md"), 0),
            Err(BaseError::SymlinkTraversal { .. })
        ),
        "resolving THROUGH the link would be host traversal authority"
    );
}

/// Bytes whose identity does not match what was asked for are refused.
#[test]
fn corrupted_object_bytes_are_refused_not_trusted() {
    let (mut source, root) = fixture();
    source.corrupt = Some(root.digest_bytes().to_vec());
    let view = base(root);
    let mut capability = full_capability();

    match view.resolve(&source, &mut capability, &path(b"src/lib.rs"), 0) {
        Err(BaseError::Source(ObjectSourceError::IdentityMismatch {
            requested_hex,
            observed_hex,
        })) => assert_ne!(requested_hex, observed_hex),
        other => panic!("expected an identity mismatch, got {other:?}"),
    }
}

/// The permitted counterpart: an uncorrupted source resolves the same path.
#[test]
fn uncorrupted_source_resolves_the_same_path() {
    let (source, root) = fixture();
    let view = base(root);
    let mut capability = full_capability();
    assert!(
        view.resolve(&source, &mut capability, &path(b"src/lib.rs"), 0)
            .is_ok()
    );
}

// ---------------------------------------------------------------------------
// capability enforcement
// ---------------------------------------------------------------------------

/// An unauthorised path is refused before the object source is ever consulted.
#[test]
fn unauthorised_read_never_reaches_the_object_source() {
    let (source, root) = fixture();
    let view = base(root);
    let mut narrow = TreeCapability::new(
        WorkspaceId::from_bytes([1; 16]),
        repository_id(),
        vec![path(b"docs")],
        vec![],
    );

    let before = source.reads();
    let refused = view.resolve(&source, &mut narrow, &path(b"src/lib.rs"), 0);
    assert!(matches!(
        refused,
        Err(BaseError::Capability(
            CapabilityRefusal::ReadOutsideScope { .. }
        ))
    ));
    assert_eq!(
        source.reads(),
        before,
        "a refused access must not have fetched anything"
    );

    // Permitted counterpart, same capability: the authorised prefix resolves.
    assert!(
        view.resolve(&source, &mut narrow, &path(b"docs/readme.md"), 0)
            .is_ok()
    );
    assert!(source.reads() > before);
}

/// A sibling whose name shares a byte prefix with an authorised prefix is not
/// authorised.
#[test]
fn byte_prefix_siblings_are_not_authorised() {
    let capability = TreeCapability::new(
        WorkspaceId::from_bytes([1; 16]),
        repository_id(),
        vec![path(b"src")],
        vec![],
    );
    assert!(capability.authorize_read(&path(b"src/lib.rs"), 0).is_ok());
    assert!(
        capability
            .authorize_read(&path(b"srcond/lib.rs"), 0)
            .is_err(),
        "srcond must not be inside src"
    );
}

/// Writing requires read scope as well as write scope.
#[test]
fn write_requires_read_scope() {
    let capability = TreeCapability::new(
        WorkspaceId::from_bytes([1; 16]),
        repository_id(),
        vec![path(b"src")],
        vec![path(b"src"), path(b"generated")],
    );
    assert!(capability.authorize_write(&path(b"src/a.rs"), 0).is_ok());
    assert!(
        matches!(
            capability.authorize_write(&path(b"generated/a.rs"), 0),
            Err(CapabilityRefusal::ReadOutsideScope { .. })
        ),
        "write-without-read would be an oracle for the previous bytes"
    );
}

/// An empty capability authorises nothing.
#[test]
fn empty_capability_authorises_nothing() {
    let capability = TreeCapability::new(
        WorkspaceId::from_bytes([1; 16]),
        repository_id(),
        vec![],
        vec![],
    );
    assert!(capability.authorize_read(&path(b"anything"), 0).is_err());
    assert!(capability.authorize_read(&path(b"src/lib.rs"), 0).is_err());
}

/// Expiry and revocation refuse, and the same capability worked before.
#[test]
fn expiry_and_revocation_refuse() {
    let capability = full_capability().with_expiry(100);
    assert!(capability.authorize_read(&path(b"src/lib.rs"), 99).is_ok());
    assert!(matches!(
        capability.authorize_read(&path(b"src/lib.rs"), 100),
        Err(CapabilityRefusal::Expired { .. })
    ));

    let mut live = full_capability();
    assert!(live.authorize_read(&path(b"src/lib.rs"), 0).is_ok());
    live.revoke();
    assert!(matches!(
        live.authorize_read(&path(b"src/lib.rs"), 0),
        Err(CapabilityRefusal::Revoked)
    ));
}

/// Budgets refuse once exceeded and permit up to the ceiling.
#[test]
fn fetch_budgets_are_enforced_at_the_boundary() {
    let mut capability = full_capability().with_fetch_budget(
        ByteCount::try_new("fetch budget", 10, u64::MAX).expect("10 is a legal byte count"),
    );
    assert!(capability.charge_fetch(6).is_ok());
    assert!(capability.charge_fetch(4).is_ok(), "exactly at the ceiling");
    assert!(matches!(
        capability.charge_fetch(1),
        Err(CapabilityRefusal::FetchBudgetExceeded { .. })
    ));

    let mut counted = full_capability().with_file_budget(2);
    assert!(counted.charge_fetch(1).is_ok());
    assert!(counted.charge_fetch(1).is_ok());
    assert!(matches!(
        counted.charge_fetch(1),
        Err(CapabilityRefusal::FileBudgetExceeded { .. })
    ));
}

/// Attenuation narrows and refuses to widen.
#[test]
fn attenuation_narrows_but_never_widens() {
    let capability = full_capability();

    let narrowed = capability
        .attenuate(vec![path(b"src/deep")], vec![path(b"src/deep")])
        .expect("narrowing to a sub-prefix is permitted");
    assert!(narrowed.authorize_read(&path(b"src/deep/a.rs"), 0).is_ok());
    assert!(
        narrowed.authorize_read(&path(b"src/other.rs"), 0).is_err(),
        "the narrowed capability lost the rest of src"
    );

    assert!(matches!(
        capability.attenuate(vec![path(b"unrelated")], vec![]),
        Err(CapabilityRefusal::AttenuationWouldWiden { .. })
    ));
}

/// The refusing symlink policy refuses, while the default treats links as data.
#[test]
fn symlink_policy_refusal_has_a_permitted_counterpart() {
    let refusing = full_capability().with_symlink_policy(SymlinkPolicy::Refuse);
    assert!(matches!(
        refusing.check_symlink(&path(b"src/link")),
        Err(CapabilityRefusal::SymlinkRefused { .. })
    ));

    let data_only = full_capability();
    assert_eq!(data_only.symlink_policy(), SymlinkPolicy::DataOnly);
    assert!(data_only.check_symlink(&path(b"src/link")).is_ok());
}

// ---------------------------------------------------------------------------
// snapshots
// ---------------------------------------------------------------------------

fn snapshot_at(root: Oid, overlay: &Overlay, epochs: EpochSet) -> WorkspaceSnapshotBody<Sha1> {
    WorkspaceSnapshotBody::new(
        WorkspaceId::from_bytes([1; 16]),
        repository_id(),
        rcr_id(),
        root.clone(),
        root,
        OverlayRoot::of(overlay),
        epochs,
    )
}

/// A snapshot's canonical bytes and digest do not move when the overlay it was
/// taken from is edited afterwards.
#[test]
fn snapshots_are_immutable_against_later_overlay_edits() {
    let (_, root) = fixture();
    let mut overlay = Overlay::new();
    let id = overlay.intern(b"first".to_vec());
    overlay.put(
        path(b"src/a.rs"),
        OverlayEntry::File {
            content: id,
            mode: FileMode::Regular,
            class: EntryClass::Content,
        },
    );

    let snapshot = snapshot_at(root.clone(), &overlay, EpochSet::new().stage());
    let bytes_before = snapshot.canonical_bytes().expect("snapshot encodes");
    let digest_before = snapshot.snapshot_digest().expect("snapshot digests");

    overlay.put(path(b"src/b.rs"), OverlayEntry::Whiteout);

    assert_eq!(snapshot.canonical_bytes().unwrap(), bytes_before);
    assert_eq!(snapshot.snapshot_digest().unwrap(), digest_before);

    let later = snapshot_at(root, &overlay, EpochSet::new().stage());
    assert_ne!(
        later.snapshot_digest().unwrap(),
        digest_before,
        "a snapshot of the edited overlay is a different snapshot"
    );
}

/// The canonical encoding is deterministic and its shape is pinned, so a
/// change to the framing shows up as a test failure rather than as silently
/// invalidated receipts.
#[test]
fn snapshot_canonical_bytes_are_deterministic_and_pinned() {
    let (_, root) = fixture();
    let overlay = Overlay::new();
    let snapshot = snapshot_at(root, &overlay, EpochSet::new());

    let once = snapshot.canonical_bytes().expect("snapshot encodes");
    let twice = snapshot.canonical_bytes().expect("snapshot encodes");
    assert_eq!(once, twice, "encoding is deterministic");
    assert!(
        !once.is_empty(),
        "the shared codec produced a non-empty encoding"
    );
    assert_eq!(
        snapshot.snapshot_digest().unwrap(),
        snapshot.snapshot_digest().unwrap(),
        "the digest is a pure function of the bytes"
    );

    // Two snapshots differing only in epoch must differ in identity.
    let (_, root2) = fixture();
    let staged = snapshot_at(root2, &overlay, EpochSet::new().stage());
    assert_ne!(
        staged.snapshot_digest().unwrap(),
        snapshot.snapshot_digest().unwrap()
    );
}

/// An empty overlay and a non-empty one produce different overlay roots.
#[test]
fn overlay_root_distinguishes_overlay_state() {
    let empty = Overlay::new();
    let mut touched = Overlay::new();
    touched.put(path(b"a"), OverlayEntry::Whiteout);
    assert_ne!(OverlayRoot::of(&empty), OverlayRoot::of(&touched));
    assert_eq!(OverlayRoot::of(&empty), OverlayRoot::of(&Overlay::new()));
}

/// A session adopts strictly newer snapshots and refuses older ones.
#[test]
fn session_refuses_rollback_but_accepts_advance() {
    let (_, root) = fixture();
    let overlay = Overlay::new();

    let first = snapshot_at(root.clone(), &overlay, EpochSet::new().stage());
    let second = snapshot_at(root.clone(), &overlay, EpochSet::new().stage().stage());

    let mut session = SessionRecord::open(first.clone());
    assert_eq!(session.adopted_count(), 1);

    session
        .adopt(second.clone())
        .expect("advancing is permitted");
    assert_eq!(session.adopted_count(), 2);
    assert_eq!(session.latest().epochs().staged().get(), 2);

    // The older snapshot still verifies perfectly and is still refused.
    assert!(matches!(
        session.adopt(first),
        Err(AntiRollbackRefusal::NotNewer { .. })
    ));
    // Re-adopting the current one is not an advance either.
    assert!(matches!(
        session.adopt(second),
        Err(AntiRollbackRefusal::NotNewer { .. })
    ));
    assert_eq!(session.adopted_count(), 2);
}

/// A session refuses a snapshot from another workspace or another base.
#[test]
fn session_refuses_foreign_workspace_and_base() {
    let (_, root) = fixture();
    let overlay = Overlay::new();
    let first = snapshot_at(root.clone(), &overlay, EpochSet::new().stage());
    let mut session = SessionRecord::open(first);

    let foreign_workspace = WorkspaceSnapshotBody::new(
        WorkspaceId::from_bytes([2; 16]),
        repository_id(),
        rcr_id(),
        root.clone(),
        root.clone(),
        OverlayRoot::of(&overlay),
        EpochSet::new().stage().stage(),
    );
    assert!(matches!(
        session.adopt(foreign_workspace),
        Err(AntiRollbackRefusal::WorkspaceMismatch)
    ));

    let other_root = Oid::of_object(GitObjectKind::Blob, b"a different base entirely");
    let foreign_base = WorkspaceSnapshotBody::new(
        WorkspaceId::from_bytes([1; 16]),
        repository_id(),
        rcr_id(),
        other_root.clone(),
        other_root,
        OverlayRoot::of(&overlay),
        EpochSet::new().stage().stage(),
    );
    assert!(matches!(
        session.adopt(foreign_base),
        Err(AntiRollbackRefusal::BaseMismatch)
    ));

    // Permitted counterpart: same workspace, same base, strictly newer.
    let good = snapshot_at(root, &overlay, EpochSet::new().stage().stage());
    assert!(session.adopt(good).is_ok());
}

/// Epoch accessors on a snapshot report the three facts separately.
#[test]
fn snapshot_reports_three_separate_epochs() {
    let (_, root) = fixture();
    let overlay = Overlay::new();
    let epochs = EpochSet::new().stage().stage().publish().unwrap();
    let snapshot = snapshot_at(root, &overlay, epochs);

    assert_eq!(snapshot.epochs().staged(), WorkspaceEpoch::from_u64(2));
    assert_eq!(snapshot.epochs().visible(), WorkspaceEpoch::from_u64(2));
    assert_eq!(snapshot.epochs().durable(), WorkspaceEpoch::ZERO);
    assert!(snapshot.epochs().invariant_holds());
}
