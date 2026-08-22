#![forbid(unsafe_code)]
//! FG-085 regression: `TreeFS` treats a gitlink as data, never a foreign tree.

use std::cell::RefCell;
use std::collections::BTreeMap;

use fgit_crypto::{GitObjectKind, GitOid, NativeObjectIdentity, Sha1};
use fgit_git_object::{AcceptanceProfile, ParseLimits, TreeEntry, emit_tree};
use fgit_treefs::base::{BaseEntry, BaseError, BaseView, ObjectSource, ObjectSourceError};
use fgit_treefs::capability::{ReadGrant, TreeCapability, WorkspaceId};
use fgit_treefs::path::{PathPolicy, TreePath};
use fgit_types::identity::RepositoryCommitId;
use fgit_types::{CodecVersion, DigestAlgorithmId, DigestBytes, RepositoryId};

type Oid = GitOid<Sha1>;

#[derive(Default)]
struct RecordingSource {
    objects: BTreeMap<Vec<u8>, Vec<u8>>,
    reads: RefCell<Vec<Vec<u8>>>,
}

impl RecordingSource {
    fn insert(&mut self, kind: GitObjectKind, body: Vec<u8>) -> Oid {
        let oid = Oid::of_object(kind, &body);
        self.objects.insert(oid.digest_bytes().to_vec(), body);
        oid
    }
}

impl ObjectSource<Sha1> for RecordingSource {
    fn read_object(
        &self,
        oid: &Oid,
        _kind: GitObjectKind,
        _grant: &ReadGrant,
    ) -> Result<Vec<u8>, ObjectSourceError> {
        let key = oid.digest_bytes().to_vec();
        self.reads.borrow_mut().push(key.clone());
        self.objects
            .get(&key)
            .cloned()
            .ok_or_else(|| ObjectSourceError::NotFound { oid_hex: hex(&key) })
    }
}

const fn repository_id() -> RepositoryId {
    RepositoryId::from_bytes([7; 16])
}

const fn foreign_repository_id() -> RepositoryId {
    RepositoryId::from_bytes([8; 16])
}

fn rcr_id() -> RepositoryCommitId {
    RepositoryCommitId::from_digest(
        DigestAlgorithmId::try_new(1).expect("algorithm 1 is registered"),
        CodecVersion::new(1, 0),
        DigestBytes::try_new(&[9_u8; 20]).expect("fixture digest is a legal width"),
    )
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(text, "{byte:02x}").expect("writing to a string cannot fail");
    }
    text
}

fn gitlink_tree(source: &mut RecordingSource, foreign_commit: Oid) -> Oid {
    let root_body = emit_tree(
        &[TreeEntry {
            mode: b"160000".to_vec(),
            name: b"vendor".to_vec(),
            object_id: foreign_commit.digest_bytes().to_vec(),
        }],
        AcceptanceProfile::StrictCreate,
        &ParseLimits::default(),
    )
    .expect("a canonical gitlink tree emits");
    source.insert(GitObjectKind::Tree, root_body)
}

fn parent_view(root: Oid) -> BaseView<Sha1> {
    BaseView::new(
        repository_id(),
        rcr_id(),
        root,
        root,
        ParseLimits::default(),
        PathPolicy::default(),
    )
}

fn parent_capability(vendor: TreePath) -> TreeCapability {
    TreeCapability::new(
        WorkspaceId::from_bytes([1; 16]),
        repository_id(),
        vec![vendor],
        Vec::new(),
    )
}

/// Test-only negative control for the exact confused-deputy rule this corpus
/// guards.  The real `BaseView` must never invoke an object source this way:
/// the grant names a parent path while `foreign_commit` belongs to a foreign
/// repository.  Keeping this bad branch local to the corpus makes a future
/// regression observable without adding a production delegation escape hatch.
fn seeded_parent_credential_delegation(
    source: &RecordingSource,
    capability: &TreeCapability,
    parent_path: &TreePath,
    foreign_commit: &Oid,
) -> Result<Vec<u8>, ObjectSourceError> {
    let parent_grant = capability
        .authorize_read(parent_path, 0)
        .expect("the parent capability deliberately grants its own gitlink path");
    source.read_object(foreign_commit, GitObjectKind::Commit, &parent_grant)
}

#[test]
fn recursive_submodule_path_is_refused_without_reading_the_gitlink_oid() {
    let mut source = RecordingSource::default();
    let foreign_commit = source.insert(GitObjectKind::Commit, b"private commit\n".to_vec());
    let root = gitlink_tree(&mut source, foreign_commit);
    let view = parent_view(root);
    let vendor = TreePath::parse_default(b"vendor").expect("fixture path parses");
    let probe = TreePath::parse_default(b"vendor/private.txt").expect("fixture path parses");
    let mut capability = parent_capability(vendor);

    assert!(matches!(
        view.resolve(&source, &mut capability, &probe, 0),
        Err(BaseError::NotADirectory { path }) if path == TreePath::parse_default(b"vendor").expect("fixture path parses")
    ));
    assert_eq!(
        *source.reads.borrow(),
        vec![root.digest_bytes().to_vec()],
        "TreeFS reads only the parent tree; a gitlink never grants a foreign-object read"
    );
    assert!(
        !source
            .reads
            .borrow()
            .contains(&foreign_commit.digest_bytes().to_vec()),
        "the parent capability cannot recurse into the submodule commit"
    );
}

#[test]
fn gitlink_oid_round_trips_as_parent_tree_data() {
    let mut source = RecordingSource::default();
    let foreign_commit = source.insert(GitObjectKind::Commit, b"private commit\n".to_vec());
    let root = gitlink_tree(&mut source, foreign_commit);
    let view = parent_view(root);
    let vendor = TreePath::parse_default(b"vendor").expect("fixture path parses");
    let mut capability = parent_capability(vendor.clone());

    let entry = view
        .resolve(&source, &mut capability, &vendor, 0)
        .expect("a gitlink itself is visible as parent tree data");
    assert!(matches!(&entry, BaseEntry::Submodule { oid } if oid == &foreign_commit));
    assert_eq!(
        foreign_commit.digest_bytes(),
        match &entry {
            BaseEntry::Submodule { oid } => oid.digest_bytes(),
            _ => unreachable!("the resolved mode-160000 entry remains a gitlink"),
        },
        "TreeFS preserves all native gitlink identity bytes without resolving them"
    );
    assert_eq!(
        *source.reads.borrow(),
        vec![root.digest_bytes().to_vec()],
        "preserving a gitlink reads only the superproject tree"
    );
}

#[test]
fn parent_capability_is_refused_by_foreign_repository_before_object_read() {
    let mut source = RecordingSource::default();
    let secret = source.insert(GitObjectKind::Blob, b"other tenant secret\n".to_vec());
    let foreign_tree_body = emit_tree(
        &[TreeEntry {
            mode: b"100644".to_vec(),
            name: b"secret.txt".to_vec(),
            object_id: secret.digest_bytes().to_vec(),
        }],
        AcceptanceProfile::StrictCreate,
        &ParseLimits::default(),
    )
    .expect("a canonical foreign tree emits");
    let foreign_tree = source.insert(GitObjectKind::Tree, foreign_tree_body);
    let foreign_view = BaseView::new(
        foreign_repository_id(),
        rcr_id(),
        foreign_tree,
        foreign_tree,
        ParseLimits::default(),
        PathPolicy::default(),
    );
    let secret_path = TreePath::parse_default(b"secret.txt").expect("fixture path parses");
    let mut parent_credential = TreeCapability::new(
        WorkspaceId::from_bytes([1; 16]),
        repository_id(),
        vec![secret_path.clone()],
        Vec::new(),
    );

    assert!(matches!(
        foreign_view.resolve(&source, &mut parent_credential, &secret_path, 0),
        Err(BaseError::Capability(
            fgit_treefs::capability::CapabilityRefusal::RepositoryMismatch
        ))
    ));
    assert!(
        source.reads.borrow().is_empty(),
        "repository identity is checked before a foreign path or object can be observed"
    );
}

#[test]
fn seeded_parent_credential_delegation_is_detected_by_read_audit() {
    let mut source = RecordingSource::default();
    let foreign_body = b"private commit\n".to_vec();
    let foreign_commit = source.insert(GitObjectKind::Commit, foreign_body.clone());
    let root = gitlink_tree(&mut source, foreign_commit);
    let view = parent_view(root);
    let vendor = TreePath::parse_default(b"vendor").expect("fixture path parses");
    let private_path = TreePath::parse_default(b"vendor/private.txt").expect("fixture path parses");
    let mut capability = parent_capability(vendor.clone());

    assert!(matches!(
        view.resolve(&source, &mut capability, &private_path, 0),
        Err(BaseError::NotADirectory { path }) if path == vendor
    ));
    assert!(
        !source
            .reads
            .borrow()
            .contains(&foreign_commit.digest_bytes().to_vec()),
        "the production path does not delegate the parent capability to the foreign commit"
    );

    source.reads.borrow_mut().clear();
    let leaked =
        seeded_parent_credential_delegation(&source, &capability, &vendor, &foreign_commit)
            .expect("the deliberately unsafe negative control can expose the foreign commit");
    assert_eq!(leaked, foreign_body);
    assert_eq!(
        *source.reads.borrow(),
        vec![foreign_commit.digest_bytes().to_vec()],
        "the corpus catches the seeded parent-credential delegation as a foreign-object read"
    );
}
