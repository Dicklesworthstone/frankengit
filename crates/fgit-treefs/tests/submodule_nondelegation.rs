#![forbid(unsafe_code)]
//! FG-085 regression: `TreeFS` treats a gitlink as data, never a foreign tree.

use std::cell::RefCell;
use std::collections::BTreeMap;

use fgit_crypto::{GitObjectKind, GitOid, NativeObjectIdentity, Sha1};
use fgit_git_object::{AcceptanceProfile, ParseLimits, TreeEntry, emit_tree};
use fgit_treefs::base::{BaseError, BaseView, ObjectSource, ObjectSourceError};
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

fn rcr_id() -> RepositoryCommitId {
    RepositoryCommitId::from_digest(
        DigestAlgorithmId::try_new(1).expect("algorithm 1 is registered"),
        CodecVersion::new(1, 0),
        DigestBytes::try_new(&[9_u8; 32]).expect("fixture digest is a legal width"),
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

#[test]
fn recursive_submodule_path_is_refused_without_reading_the_gitlink_oid() {
    let mut source = RecordingSource::default();
    let foreign_commit = vec![0x33; 20];
    let root_body = emit_tree(
        &[TreeEntry {
            mode: b"160000".to_vec(),
            name: b"vendor".to_vec(),
            object_id: foreign_commit.clone(),
        }],
        AcceptanceProfile::StrictCreate,
        &ParseLimits::default(),
    )
    .expect("a canonical gitlink tree emits");
    let root = source.insert(GitObjectKind::Tree, root_body);
    let view = BaseView::new(
        repository_id(),
        rcr_id(),
        root,
        root,
        ParseLimits::default(),
        PathPolicy::default(),
    );
    let vendor = TreePath::parse_default(b"vendor").expect("fixture path parses");
    let probe = TreePath::parse_default(b"vendor/private.txt").expect("fixture path parses");
    let mut capability = TreeCapability::new(
        WorkspaceId::from_bytes([1; 16]),
        repository_id(),
        vec![vendor],
        Vec::new(),
    );

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
        !source.reads.borrow().contains(&foreign_commit),
        "the parent capability cannot recurse into the submodule commit"
    );
}
