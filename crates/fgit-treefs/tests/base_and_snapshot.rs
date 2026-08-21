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
use fgit_treefs::overlay::{ContentRef, EntryClass, FileMode, Overlay, OverlayEntry};
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

const fn repository_id() -> RepositoryId {
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
        root,
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

/// Attenuation narrows PATH SCOPE and refuses a prefix outside the parent's.
///
/// Deliberately named for what it checks. It used to be called
/// `attenuation_narrows_but_never_widens`, and the audit caught that: "never
/// widens" is a claim about every dimension of authority — path scope, budget
/// ceilings, spent budget, expiry, revocation, symlink policy — while the body
/// only ever compared path prefixes. A budget-scoped widening lived behind that
/// name for as long as it existed. The other dimensions are covered by
/// `attenuation_does_not_restore_spent_budget`,
/// `attenuation_does_not_restore_liveness`, and
/// `attenuation_preserves_every_widening_relevant_field`.
#[test]
fn attenuation_narrows_path_scope_and_refuses_a_wider_prefix() {
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
        root,
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
            content: ContentRef::Overlay(id),
            mode: FileMode::Regular,
            class: EntryClass::Content,
        },
    );

    let snapshot = snapshot_at(root, &overlay, EpochSet::new().stage());
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

    let first = snapshot_at(root, &overlay, EpochSet::new().stage());
    let second = snapshot_at(root, &overlay, EpochSet::new().stage().stage());

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
    let first = snapshot_at(root, &overlay, EpochSet::new().stage());
    let mut session = SessionRecord::open(first);

    let foreign_workspace = WorkspaceSnapshotBody::new(
        WorkspaceId::from_bytes([2; 16]),
        repository_id(),
        rcr_id(),
        root,
        root,
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
        other_root,
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

// ---------------------------------------------------------------------------
// externally pinned Git identities
// ---------------------------------------------------------------------------

/// Identities are checked against published Git constants, not against this
/// crate's own output.
///
/// Every other identity assertion in this suite compares `FrankenGit` to
/// `FrankenGit`, which cannot detect a systematically wrong hash preimage. These
/// three values are published, widely cited Git SHA-1 identities that exist
/// independently of this codebase: if the object header framing were wrong by
/// even one byte, all three would differ.
#[test]
fn native_identities_match_published_git_constants() {
    // `git hash-object -t tree /dev/null` — the empty tree.
    assert_eq!(
        hex(Oid::of_object(GitObjectKind::Tree, b"").digest_bytes()),
        "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
        "the empty tree identity is a published Git constant"
    );
    // `git hash-object -t blob /dev/null` — the empty blob.
    assert_eq!(
        hex(Oid::of_object(GitObjectKind::Blob, b"").digest_bytes()),
        "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391",
        "the empty blob identity is a published Git constant"
    );
    // `printf 'hello\n' | git hash-object --stdin`.
    assert_eq!(
        hex(Oid::of_object(GitObjectKind::Blob, b"hello\n").digest_bytes()),
        "ce013625030ba8dba906f756967f9e9ca394464a",
        "a non-empty blob identity matches the published value"
    );
}

/// Attenuation must not restore spent budget.
///
/// The regression guard for a real widening defect: `attenuate` used to reset
/// `fetched_bytes`/`fetched_files` to zero, so a capability that had exhausted
/// its allowance could mint unlimited full-allowance children — an operation
/// that WIDENS authority while being named `attenuate`. The previous
/// attenuation test only checked path scope and so never saw it.
#[test]
fn attenuation_does_not_restore_spent_budget() {
    let mut parent = full_capability()
        .with_fetch_budget(ByteCount::try_new("fetch budget", 100, u64::MAX).unwrap())
        .with_file_budget(3);

    parent.charge_fetch(90).expect("first fetch fits");
    assert_eq!(parent.fetched_bytes(), 90);
    assert_eq!(parent.fetched_files(), 1);

    let mut child = parent
        .attenuate(vec![path(b"src")], vec![path(b"src")])
        .expect("narrowing to a sub-prefix is permitted");

    assert_eq!(
        child.fetched_bytes(),
        90,
        "the child inherits what the parent already spent"
    );
    assert_eq!(child.fetched_files(), 1, "file spend carries forward too");

    // The child has 10 bytes left, exactly as the parent did.
    assert!(
        child.charge_fetch(10).is_ok(),
        "the remaining allowance works"
    );
    assert!(
        matches!(
            child.charge_fetch(1),
            Err(CapabilityRefusal::FetchBudgetExceeded { .. })
        ),
        "the child cannot spend past the parent's ceiling"
    );

    // And a chain of attenuations cannot launder the spend either.
    let grandchild = child
        .attenuate(vec![path(b"src")], vec![path(b"src")])
        .expect("attenuating again is permitted");
    assert_eq!(
        grandchild.fetched_bytes(),
        100,
        "spend survives an attenuation chain"
    );
}

/// A revoked or expired capability stays that way through attenuation.
#[test]
fn attenuation_does_not_restore_liveness() {
    let mut parent = full_capability();
    parent.revoke();
    let child = parent
        .attenuate(vec![path(b"src")], vec![path(b"src")])
        .expect("attenuating a revoked capability is structurally allowed");
    assert!(
        matches!(
            child.authorize_read(&path(b"src/lib.rs"), 0),
            Err(CapabilityRefusal::Revoked)
        ),
        "revocation is inherited, not cleared by narrowing"
    );
}

/// The root is authorised as the root, not through a fabricated path.
#[test]
fn root_listing_is_authorised_as_root_and_empty_capabilities_still_refuse() {
    let (source, root) = fixture();
    let view = base(root);
    let mut cap = full_capability();

    let entries = view
        .list(&source, &mut cap, None, 0)
        .expect("a capability with read scope may read the root tree");
    let names: Vec<Vec<u8>> = entries.iter().map(|(name, _)| name.clone()).collect();
    assert!(names.contains(&b"src".to_vec()));

    // The vacuous case still fails closed.
    let mut empty = TreeCapability::new(
        WorkspaceId::from_bytes([1; 16]),
        repository_id(),
        vec![],
        vec![],
    );
    assert!(
        matches!(
            view.list(&source, &mut empty, None, 0),
            Err(BaseError::Capability(
                CapabilityRefusal::ReadOutsideScope { .. }
            ))
        ),
        "a capability granting nothing cannot read the root"
    );
}

/// Attenuation carries every field through which authority could widen.
///
/// This is the assertion the old `never_widens` name implied but did not make.
/// `attenuate` rebuilds the struct field by field, so any field a future edit
/// forgets to carry silently resets to the permissive default — which is how
/// the spent-budget widening happened. Each field below is checked against a
/// parent whose value is deliberately MORE restrictive than the default, so a
/// dropped field shows up as a widening rather than as an equal value.
#[test]
fn attenuation_preserves_every_widening_relevant_field() {
    let mut parent = full_capability()
        .with_symlink_policy(SymlinkPolicy::Refuse)
        .with_fetch_budget(ByteCount::try_new("fetch budget", 64, u64::MAX).unwrap())
        .with_file_budget(2)
        .with_expiry(500);
    parent.charge_fetch(10).expect("parent spends some budget");

    let child = parent
        .attenuate(vec![path(b"src")], vec![path(b"src")])
        .expect("narrowing is permitted");

    // Symlink policy: the restrictive parent policy must survive.
    assert_eq!(
        child.symlink_policy(),
        SymlinkPolicy::Refuse,
        "a permissive default here would let a child traverse links the parent refused"
    );
    assert!(child.check_symlink(&path(b"src/link")).is_err());

    // Expiry: the child must not outlive the parent.
    assert!(
        child.authorize_read(&path(b"src/a.rs"), 499).is_ok(),
        "before expiry the child works"
    );
    assert!(
        matches!(
            child.authorize_read(&path(b"src/a.rs"), 500),
            Err(CapabilityRefusal::Expired { .. })
        ),
        "the child expires exactly when the parent does"
    );

    // Spent budget carries, so the remaining allowance is the parent's.
    assert_eq!(child.fetched_bytes(), 10);
    assert_eq!(child.fetched_files(), 1);

    // File ceiling carries: the parent used 1 of 2, so exactly one slot remains.
    let mut file_probe = child.clone();
    assert!(file_probe.charge_fetch(0).is_ok(), "one file slot remains");
    assert!(
        matches!(
            file_probe.charge_fetch(0),
            Err(CapabilityRefusal::FileBudgetExceeded { .. })
        ),
        "the file ceiling is the parent's, not a reset default"
    );

    // Byte ceiling carries. This needs its own parent with a generous FILE
    // budget: `charge_fetch` checks the file ceiling before the byte ceiling,
    // so a tight file budget trips first and the byte ceiling is never reached.
    // The first version of this test made exactly that mistake and read as a
    // code defect when it was a test defect.
    let mut byte_parent = full_capability()
        .with_fetch_budget(ByteCount::try_new("fetch budget", 64, u64::MAX).unwrap())
        .with_file_budget(u64::MAX);
    byte_parent
        .charge_fetch(10)
        .expect("parent spends some budget");
    let mut byte_child = byte_parent
        .attenuate(vec![path(b"src")], vec![path(b"src")])
        .expect("narrowing is permitted");
    assert!(
        byte_child.charge_fetch(54).is_ok(),
        "the parent's remaining 54 bytes are available"
    );
    assert!(
        matches!(
            byte_child.charge_fetch(1),
            Err(CapabilityRefusal::FetchBudgetExceeded { .. })
        ),
        "the byte ceiling is the parent's 64, not a reset default"
    );

    // Identity is preserved, so a child cannot re-target another workspace.
    assert_eq!(child.workspace_id(), parent.workspace_id());
    assert_eq!(child.repository_id(), parent.repository_id());
}
