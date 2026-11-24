//! Real parent-tree verification and capability filtering for opaque submodule
//! inputs. Foreign commit bytes are deliberately absent in both hash domains.

use std::cell::RefCell;
use std::collections::BTreeMap;

use fgit_crypto::{GitHashAlgorithm, GitObjectKind, GitOid, NativeObjectIdentity, Sha1, Sha256};
use fgit_git_object::{AcceptanceProfile, ParseLimits, TreeEntry, emit_tree};
use fgit_treefs::base::BaseError;
use fgit_treefs::{
    BaseView, ObjectSource, ObjectSourceError, PathPolicy, ReadGrant, SparseCandidateManifest,
    SparseEntryKind, SparseLimits, SparseManifest, SparseRefusal, TreeCapability, TreePath,
    WorkspaceId,
};
use fgit_types::{CodecVersion, DigestAlgorithmId, DigestBytes, RepositoryCommitId, RepositoryId};

const REPOSITORY: RepositoryId = RepositoryId::from_bytes([0x61; 16]);
const LIMITS: SparseLimits = SparseLimits {
    max_entries: 8,
    max_entry_bytes: 256,
    max_payload_bytes: 512,
};
const MODULES: &[u8] =
    b"[submodule \"module\"]\n\tpath = vendor/module\n\turl = ssh://private.invalid/secret\n";

#[derive(Default)]
struct Source {
    objects: BTreeMap<Vec<u8>, (GitObjectKind, Vec<u8>)>,
    reads: RefCell<Vec<Vec<u8>>>,
}

impl Source {
    fn put<A: GitHashAlgorithm>(&mut self, kind: GitObjectKind, body: Vec<u8>) -> GitOid<A> {
        let id = GitOid::<A>::of_object(kind, &body);
        self.objects
            .insert(id.digest_bytes().to_vec(), (kind, body));
        id
    }

    fn tree<A: GitHashAlgorithm>(&mut self, entries: &[(&[u8], &[u8], GitOid<A>)]) -> GitOid<A> {
        let entries = entries
            .iter()
            .map(|(mode, name, id)| TreeEntry {
                mode: mode.to_vec(),
                name: name.to_vec(),
                object_id: id.digest_bytes().to_vec(),
            })
            .collect::<Vec<_>>();
        self.put::<A>(
            GitObjectKind::Tree,
            emit_tree(
                &entries,
                AcceptanceProfile::GitCompatibleImport,
                &parse_limits::<A>(),
            )
            .unwrap(),
        )
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
            "tree {}\n{parent}author A <a@example.invalid> 1 +0000\ncommitter A <a@example.invalid> 1 +0000\n\nopaque inputs\n",
            hex(tree.digest_bytes()),
        ).into_bytes())
    }
}

impl<A: GitHashAlgorithm> ObjectSource<A> for Source {
    fn read_object(
        &self,
        id: &GitOid<A>,
        kind: GitObjectKind,
        _: &ReadGrant,
    ) -> Result<Vec<u8>, ObjectSourceError> {
        self.reads.borrow_mut().push(id.digest_bytes().to_vec());
        let (actual, body) =
            self.objects
                .get(id.digest_bytes())
                .ok_or_else(|| ObjectSourceError::NotFound {
                    oid_hex: hex(id.digest_bytes()),
                })?;
        assert_eq!(*actual, kind);
        Ok(body.clone())
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
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
fn capability(prefixes: &[&[u8]]) -> TreeCapability {
    TreeCapability::new(
        WorkspaceId::from_bytes([0x62; 16]),
        REPOSITORY,
        prefixes.iter().map(|bytes| path(bytes)).collect(),
        vec![],
    )
}
fn base<A: GitHashAlgorithm>(tree: GitOid<A>, commit: GitOid<A>) -> BaseView<A> {
    BaseView::<A>::new(
        REPOSITORY,
        RepositoryCommitId::from_digest(
            DigestAlgorithmId::try_new(0x8043).unwrap(),
            CodecVersion::new(1, 0),
            DigestBytes::try_new(&[0x63; 32]).unwrap(),
        ),
        commit,
        tree,
        parse_limits::<A>(),
        PathPolicy::default(),
    )
}

fn fixture<A: GitHashAlgorithm>() -> (Source, BaseView<A>, GitOid<A>) {
    let mut source = Source::default();
    let foreign = GitOid::<A>::of_object(GitObjectKind::Commit, b"absent foreign commit");
    let module = source.tree::<A>(&[(b"160000", b"module", foreign)]);
    let modules = source.put::<A>(GitObjectKind::Blob, MODULES.to_vec());
    let file = source.put::<A>(GitObjectKind::Blob, b"readme\n".to_vec());
    let tool = source.put::<A>(GitObjectKind::Blob, b"#!/bin/sh\nexit 0\n".to_vec());
    let tree = source.tree::<A>(&[
        (b"100644", b".gitmodules", modules),
        (b"100644", b"README", file),
        (b"100755", b"tool", tool),
        (b"40000", b"vendor", module),
    ]);
    let commit = source.commit::<A>(tree, None);
    (source, base::<A>(tree, commit), foreign)
}

fn opaque_manifests<A: GitHashAlgorithm>() {
    let (mut source, base, foreign) = fixture::<A>();
    let prefixes: &[&[u8]] = &[b".gitmodules", b"README", b"tool", b"vendor"];
    let first =
        SparseManifest::build(&base, &source, &mut capability(prefixes), 0, LIMITS).unwrap();
    assert_eq!(
        first,
        SparseManifest::build(&base, &source, &mut capability(prefixes), 0, LIMITS).unwrap()
    );
    assert_eq!(first.receipt().entry_count(), 5);
    assert_eq!(first.receipt().payload_bytes(), MODULES.len() + 7 + 17);
    let entry = first
        .entries()
        .iter()
        .find(|entry| entry.path() == &path(b"vendor/module"))
        .unwrap();
    assert_eq!(entry.kind(), &SparseEntryKind::Gitlink);
    assert_eq!(entry.source_oid(), &foreign);
    assert_eq!(entry.kind().body(), None);
    assert_eq!(entry.kind().file_mode(), None);

    // A separately identified unpublished candidate uses the same opaque
    // representation; no canonical source receipt is forged for its tree.
    let next_foreign = GitOid::<A>::of_object(GitObjectKind::Commit, b"another absent commit");
    let candidate_tree = source.tree::<A>(&[(b"160000", b"module", next_foreign)]);
    let candidate = source.commit::<A>(candidate_tree, Some(*base.base_commit_oid()));
    let input = SparseCandidateManifest::build(
        &base,
        &source,
        candidate,
        &mut capability(&[b"module"]),
        0,
        parse_limits::<A>(),
        LIMITS,
    )
    .unwrap();
    assert_eq!(input.entries().len(), 1);
    assert_eq!(input.entries()[0].kind(), &SparseEntryKind::Gitlink);
    assert_eq!(input.entries()[0].source_oid(), &next_foreign);
    assert_eq!(input.payload_bytes(), 0);
    assert!(!source.objects.contains_key(foreign.digest_bytes()));
    assert!(!source.objects.contains_key(next_foreign.digest_bytes()));
    assert!(
        source
            .reads
            .borrow()
            .iter()
            .all(|id| id != foreign.digest_bytes() && id != next_foreign.digest_bytes())
    );
}

#[test]
fn canonical_and_candidate_gitlinks_preserve_identity_without_foreign_reads() {
    opaque_manifests::<Sha1>();
    opaque_manifests::<Sha256>();
}

fn scoped_and_bounded<A: GitHashAlgorithm>() {
    let (source, base, foreign) = fixture::<A>();
    let hidden =
        SparseManifest::build(&base, &source, &mut capability(&[b"README"]), 0, LIMITS).unwrap();
    assert_eq!(hidden.entries().len(), 1);
    assert_eq!(hidden.entries()[0].path(), &path(b"README"));
    let narrow = SparseManifest::build(
        &base,
        &source,
        &mut capability(&[b"vendor/module"]),
        0,
        LIMITS,
    )
    .unwrap();
    assert_eq!(narrow.entries().len(), 2);
    assert_eq!(narrow.entries()[1].kind(), &SparseEntryKind::Gitlink);
    assert_eq!(narrow.receipt().payload_bytes(), 0);

    assert!(matches!(SparseManifest::build(
        &base, &source, &mut capability(&[b"vendor/module/private"]), 0, LIMITS,
    ), Err(SparseRefusal::Base(BaseError::NotADirectory { path: rejected }))
        if rejected == path(b"vendor/module")));
    assert!(matches!(
        SparseManifest::build(
            &base,
            &source,
            &mut capability(&[b"vendor"]),
            0,
            SparseLimits {
                max_entries: 1,
                ..LIMITS
            },
        ),
        Err(SparseRefusal::EntryLimitExceeded {
            observed: 2,
            limit: 1
        })
    ));
    assert!(
        SparseManifest::build(
            &base,
            &source,
            &mut capability(&[b"vendor"]),
            0,
            SparseLimits {
                max_entries: 2,
                max_payload_bytes: 0,
                max_entry_bytes: 0
            },
        )
        .is_ok()
    );
    for revoked in [false, true] {
        let mut cap = capability(&[b"vendor"]).with_expiry(1);
        if revoked {
            cap.revoke();
        }
        let before = source.reads.borrow().len();
        assert!(SparseManifest::build(&base, &source, &mut cap, 2, LIMITS).is_err());
        assert_eq!(source.reads.borrow().len(), before);
    }
    assert!(
        source
            .reads
            .borrow()
            .iter()
            .all(|id| id != foreign.digest_bytes())
    );
}

#[test]
fn gitlink_visibility_never_grants_traversal_or_bypasses_resource_and_capability_limits() {
    scoped_and_bounded::<Sha1>();
    scoped_and_bounded::<Sha256>();
}

fn invalid_pointer<A: GitHashAlgorithm>() {
    let mut source = Source::default();
    let null = A::parse_hex(&"0".repeat(A::DIGEST_LEN * 2)).unwrap();
    let tree = source.tree::<A>(&[(b"160000", b"module", null)]);
    let commit = source.commit::<A>(tree, None);
    assert!(matches!(SparseManifest::build(
        &base::<A>(tree, commit), &source, &mut capability(&[b"module"]), 0, LIMITS,
    ), Err(SparseRefusal::InvalidGitlink { path: rejected }) if rejected == path(b"module")));
    assert!(
        source
            .reads
            .borrow()
            .iter()
            .all(|id| id != null.digest_bytes())
    );
}

#[test]
fn all_zero_gitlink_targets_refuse_without_becoming_empty_directories() {
    invalid_pointer::<Sha1>();
    invalid_pointer::<Sha256>();
}
