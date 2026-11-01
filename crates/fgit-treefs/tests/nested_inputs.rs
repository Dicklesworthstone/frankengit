//! Narrow nested source grants traverse real verified trees without admitting
//! ancestor payloads or any sibling names or bytes. Both native hash formats
//! exercise canonical and unpublished candidate materialization.

use std::cell::RefCell;
use std::collections::BTreeMap;

use fgit_crypto::{GitHashAlgorithm, GitObjectKind, GitOid, NativeObjectIdentity, Sha1, Sha256};
use fgit_git_object::{AcceptanceProfile, ParseLimits, TreeEntry, emit_tree};
use fgit_treefs::base::BaseError;
use fgit_treefs::capability::{CapabilityRefusal, GrantScope};
use fgit_treefs::{
    BaseView, ObjectSource, ObjectSourceError, PathPolicy, ReadGrant, SparseCandidateManifest,
    SparseLimits, SparseManifest, TreeCapability, TreePath, WorkspaceId,
};
use fgit_types::{CodecVersion, DigestAlgorithmId, DigestBytes, RepositoryCommitId, RepositoryId};

const REPOSITORY: RepositoryId = RepositoryId::from_bytes([0x31; 16]);
const LIMITS: SparseLimits = SparseLimits {
    max_entries: 16,
    max_entry_bytes: 256,
    max_payload_bytes: 512,
};

#[derive(Default)]
struct Source {
    objects: BTreeMap<Vec<u8>, (GitObjectKind, Vec<u8>)>,
    reads: RefCell<Vec<(GitObjectKind, Vec<u8>, ReadGrant)>>,
}

impl Source {
    fn put<A: GitHashAlgorithm>(&mut self, kind: GitObjectKind, bytes: Vec<u8>) -> GitOid<A> {
        let oid = GitOid::<A>::of_object(kind, &bytes);
        self.objects
            .insert(oid.digest_bytes().to_vec(), (kind, bytes));
        oid
    }

    fn tree<A: GitHashAlgorithm>(&mut self, entries: &[(&[u8], &[u8], GitOid<A>)]) -> GitOid<A> {
        let entries = entries
            .iter()
            .map(|(mode, name, oid)| TreeEntry {
                mode: mode.to_vec(),
                name: name.to_vec(),
                object_id: oid.digest_bytes().to_vec(),
            })
            .collect::<Vec<_>>();
        let body = emit_tree(
            &entries,
            AcceptanceProfile::GitCompatibleImport,
            &parse_limits::<A>(),
        )
        .unwrap();
        self.put::<A>(GitObjectKind::Tree, body)
    }

    fn commit<A: GitHashAlgorithm>(
        &mut self,
        tree: GitOid<A>,
        parent: Option<GitOid<A>>,
    ) -> GitOid<A> {
        let parent = parent.map_or_else(String::new, |id| {
            format!("parent {}\n", hex(id.digest_bytes()))
        });
        self.put::<A>(GitObjectKind::Commit, format!(
            "tree {}\n{parent}author Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n\nnested inputs\n",
            hex(tree.digest_bytes()),
        ).into_bytes())
    }
}

impl<A: GitHashAlgorithm> ObjectSource<A> for Source {
    fn read_object(
        &self,
        oid: &GitOid<A>,
        kind: GitObjectKind,
        grant: &ReadGrant,
    ) -> Result<Vec<u8>, ObjectSourceError> {
        self.reads
            .borrow_mut()
            .push((kind, oid.digest_bytes().to_vec(), grant.clone()));
        let (actual, bytes) =
            self.objects
                .get(oid.digest_bytes())
                .ok_or_else(|| ObjectSourceError::NotFound {
                    oid_hex: hex(oid.digest_bytes()),
                })?;
        assert_eq!(*actual, kind);
        Ok(bytes.clone())
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
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
fn base<A: GitHashAlgorithm>(tree: GitOid<A>, commit: GitOid<A>) -> BaseView<A> {
    BaseView::new(
        REPOSITORY,
        RepositoryCommitId::from_digest(
            DigestAlgorithmId::try_new(0x8043).unwrap(),
            CodecVersion::new(1, 0),
            DigestBytes::try_new(&[0x42; 32]).unwrap(),
        ),
        commit,
        tree,
        parse_limits::<A>(),
        PathPolicy::default(),
    )
}
fn capability() -> TreeCapability {
    TreeCapability::new(
        WorkspaceId::from_bytes([0x32; 16]),
        REPOSITORY,
        vec![
            path(b".github/workflows/build.yml"),
            path(b"crates/selected"),
        ],
        Vec::new(),
    )
}

struct Fixture<A: GitHashAlgorithm> {
    source: Source,
    base: BaseView<A>,
    selected: GitOid<A>,
    hidden: GitOid<A>,
    workflow_tree: GitOid<A>,
}
impl<A: GitHashAlgorithm> Fixture<A> {
    fn new() -> Self {
        let mut source = Source::default();
        let selected = source.put::<A>(GitObjectKind::Blob, b"selected source\n".to_vec());
        // Hidden content exceeds the whole retained-payload profile. Even a
        // seemingly harmless eager sibling fetch is observable in the trace.
        let hidden = source.put::<A>(GitObjectKind::Blob, vec![b'x'; 1024]);
        let workflow = source.put::<A>(GitObjectKind::Blob, b"name: selected\n".to_vec());
        let workflows = source.tree::<A>(&[
            (b"100644", b"build.yml", workflow),
            (b"100644", b"private.yml", hidden),
        ]);
        let workflow_tree = source.tree::<A>(&[
            (b"100644", b"private", hidden),
            (b"40000", b"workflows", workflows),
        ]);
        let src = source.tree::<A>(&[(b"100644", b"lib.rs", selected)]);
        let component = source.tree::<A>(&[(b"40000", b"src", src)]);
        let crates = source.tree::<A>(&[
            (b"100644", b"other", hidden),
            (b"40000", b"selected", component),
        ]);
        let tree = source.tree::<A>(&[
            (b"40000", b".github", workflow_tree),
            (b"40000", b"crates", crates),
            (b"100644", b"private", hidden),
        ]);
        let commit = source.commit::<A>(tree, None);
        Self {
            source,
            base: base::<A>(tree, commit),
            selected,
            hidden,
            workflow_tree,
        }
    }
}

fn names<A: GitHashAlgorithm>(fixture: &Fixture<A>, directory: Option<&[u8]>) -> Vec<Vec<u8>> {
    fixture
        .base
        .list(
            &fixture.source,
            &mut capability(),
            directory.map(path).as_ref(),
            0,
        )
        .unwrap()
        .into_iter()
        .map(|(name, _)| name)
        .collect()
}

fn exercise_disclosure<A: GitHashAlgorithm>() {
    let fixture = Fixture::<A>::new();
    assert_eq!(
        names(&fixture, None),
        [b".github".to_vec(), b"crates".to_vec()]
    );
    assert_eq!(names(&fixture, Some(b".github")), [b"workflows".to_vec()]);
    assert_eq!(
        names(&fixture, Some(b".github/workflows")),
        [b"build.yml".to_vec()]
    );
    assert_eq!(names(&fixture, Some(b"crates")), [b"selected".to_vec()]);
    let entry = fixture
        .base
        .resolve(
            &fixture.source,
            &mut capability(),
            &path(b"crates/selected/src/lib.rs"),
            0,
        )
        .unwrap();
    assert_eq!(entry.oid(), &fixture.selected);

    for denied in [
        b"crates".as_slice(),
        b"crates/other",
        b".github/workflows/private.yml",
        b"private",
    ] {
        let before = fixture.source.reads.borrow().len();
        let error = fixture
            .base
            .resolve(&fixture.source, &mut capability(), &path(denied), 0)
            .unwrap_err();
        assert_eq!(
            error,
            BaseError::Capability(CapabilityRefusal::ReadOutsideScope { path: path(denied) })
        );
        assert_eq!(
            fixture.source.reads.borrow().len(),
            before,
            "out-of-scope resolution must refuse before any fetch"
        );
    }
    let directory_grant = fixture
        .source
        .reads
        .borrow()
        .iter()
        .find_map(|(_, _, grant)| {
            matches!(grant.scope(), GrantScope::DirectoryTraversal(_)).then(|| grant.clone())
        })
        .expect("nested listing must carry typed ancestor traversal authority");
    let before = fixture.source.reads.borrow().len();
    assert!(matches!(
        fixture.base.read_object(
            &fixture.source,
            &fixture.hidden,
            GitObjectKind::Blob,
            &directory_grant
        ),
        Err(ObjectSourceError::Refused { .. })
    ));
    assert_eq!(fixture.source.reads.borrow().len(), before);
    assert!(capability().authorize_read(&path(b"crates"), 0).is_err());
    assert!(
        capability()
            .authorize_write(&path(b"crates/selected/src/lib.rs"), 0)
            .is_err()
    );
    assert!(
        fixture
            .source
            .reads
            .borrow()
            .iter()
            .all(|(_, oid, _)| oid != fixture.hidden.digest_bytes())
    );
}

#[test]
fn nested_tree_traversal_never_grants_ancestor_payloads_or_sibling_disclosure() {
    exercise_disclosure::<Sha1>();
    exercise_disclosure::<Sha256>();
}

fn exercise_manifests<A: GitHashAlgorithm>() {
    let mut fixture = Fixture::<A>::new();
    let manifest =
        SparseManifest::build(&fixture.base, &fixture.source, &mut capability(), 0, LIMITS)
            .unwrap();
    let paths = manifest
        .entries()
        .iter()
        .map(|entry| entry.path().as_bytes())
        .collect::<Vec<_>>();
    assert_eq!(
        paths,
        [
            b".github".as_slice(),
            b".github/workflows",
            b".github/workflows/build.yml",
            b"crates",
            b"crates/selected",
            b"crates/selected/src",
            b"crates/selected/src/lib.rs"
        ]
    );
    assert_eq!(
        manifest.receipt().payload_bytes(),
        b"name: selected\n".len() + b"selected source\n".len()
    );

    let replacement = fixture
        .source
        .put::<A>(GitObjectKind::Blob, b"candidate source\n".to_vec());
    let src = fixture
        .source
        .tree::<A>(&[(b"100644", b"lib.rs", replacement)]);
    let selected = fixture.source.tree::<A>(&[(b"40000", b"src", src)]);
    let crates = fixture.source.tree::<A>(&[
        (b"100644", b"other", fixture.hidden),
        (b"40000", b"selected", selected),
    ]);
    let tree = fixture.source.tree::<A>(&[
        (b"40000", b".github", fixture.workflow_tree),
        (b"40000", b"crates", crates),
        (b"100644", b"private", fixture.hidden),
    ]);
    let candidate = fixture
        .source
        .commit::<A>(tree, Some(*fixture.base.base_commit_oid()));
    let manifest = SparseCandidateManifest::build(
        &fixture.base,
        &fixture.source,
        candidate,
        &mut capability(),
        0,
        parse_limits::<A>(),
        LIMITS,
    )
    .unwrap();
    assert_eq!(
        manifest
            .entries()
            .iter()
            .map(|entry| entry.path().as_bytes())
            .collect::<Vec<_>>(),
        paths
    );
    let entry = manifest
        .entries()
        .iter()
        .find(|entry| entry.path() == &path(b"crates/selected/src/lib.rs"))
        .unwrap();
    assert_eq!(entry.kind().body(), Some(b"candidate source\n".as_slice()));
    assert_eq!(entry.source_oid(), &replacement);
    assert!(
        fixture
            .source
            .reads
            .borrow()
            .iter()
            .all(|(_, oid, _)| oid != fixture.hidden.digest_bytes())
    );
}

#[test]
fn canonical_and_candidate_manifests_materialize_only_nested_inputs() {
    exercise_manifests::<Sha1>();
    exercise_manifests::<Sha256>();
}

fn exercise_ancestor_kinds<A: GitHashAlgorithm>() {
    for mode in [b"100644".as_slice(), b"120000", b"160000"] {
        let mut source = Source::default();
        let body = source.put::<A>(GitObjectKind::Blob, b"unreadable ancestor payload".to_vec());
        let tree = source.tree::<A>(&[(mode, b"crates", body)]);
        let commit = source.commit::<A>(tree, None);
        let base = base::<A>(tree, commit);
        assert!(
            matches!(base.list(&source, &mut capability(), None, 0), Err(BaseError::NotADirectory { path: denied }) if denied == path(b"crates"))
        );
        assert!(SparseManifest::build(&base, &source, &mut capability(), 0, LIMITS).is_err());
        assert!(
            source
                .reads
                .borrow()
                .iter()
                .all(|(kind, _, _)| *kind == GitObjectKind::Tree)
        );
    }
}

#[test]
fn files_symlinks_and_gitlinks_cannot_impersonate_traversal_directories() {
    exercise_ancestor_kinds::<Sha1>();
    exercise_ancestor_kinds::<Sha256>();
}

#[test]
fn directory_traversal_still_obeys_expiry_and_revocation_before_source_reads() {
    let fixture = Fixture::<Sha1>::new();
    for revoke in [false, true] {
        let mut cap = capability().with_expiry(1);
        if revoke {
            cap.revoke();
        }
        let expected = if revoke {
            CapabilityRefusal::Revoked
        } else {
            CapabilityRefusal::Expired {
                expires_at: 1,
                observed: 2,
            }
        };
        assert_eq!(
            fixture
                .base
                .list(&fixture.source, &mut cap, Some(&path(b"crates")), 2)
                .unwrap_err(),
            BaseError::Capability(expected)
        );
        assert!(fixture.source.reads.borrow().is_empty());
    }
}
