//! Sparse-directory manifest behaviour for FG-052.
//!
//! The manifest is intentionally host-independent.  These tests exercise a
//! real `BaseView` and object-source boundary so capability filtering, source
//! identity checks, and link-as-data behaviour are not supplied by a fixture
//! shortcut.

use fgit_crypto::{GitObjectKind, GitOid, NativeObjectIdentity, Sha1};
use fgit_git_object::{AcceptanceProfile, ParseLimits, TreeEntry, emit_tree};
use fgit_treefs::base::{BaseView, ObjectSource, ObjectSourceError};
use fgit_treefs::capability::{ReadGrant, SymlinkPolicy, TreeCapability, WorkspaceId};
use fgit_treefs::overlay::FileMode;
use fgit_treefs::path::{PathPolicy, TreePath};
use fgit_treefs::sparse::{
    SparseCompleteness, SparseEntryKind, SparseLimits, SparseManifest, SparseProfile,
    SparseRefusal, SparseVerification,
};
use fgit_types::identity::RepositoryCommitId;
use fgit_types::{CodecVersion, DigestAlgorithmId, DigestBytes, RepositoryId};
use std::collections::BTreeMap;

type Oid = GitOid<Sha1>;

const FIXTURE_ALGORITHM_CODE_POINT: u16 = 0x8043;

#[derive(Clone, Default)]
struct MemorySource {
    objects: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl MemorySource {
    fn insert(&mut self, kind: GitObjectKind, body: &[u8]) -> Oid {
        let oid = Oid::of_object(kind, body);
        self.objects
            .insert(oid.digest_bytes().to_vec(), body.to_vec());
        oid
    }

    fn blob(&mut self, body: &[u8]) -> Oid {
        self.insert(GitObjectKind::Blob, body)
    }

    fn tree(&mut self, entries: &[TreeEntry]) -> Oid {
        let body = emit_tree(
            entries,
            AcceptanceProfile::GitCompatibleImport,
            &ParseLimits::default(),
        )
        .expect("fixture trees are valid Git trees");
        self.insert(GitObjectKind::Tree, &body)
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
                oid_hex: "fixture object missing".to_owned(),
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

fn fixture() -> (MemorySource, Oid, Oid) {
    let mut source = MemorySource::default();
    let readme = source.blob(b"# sparse input\n");
    let tool = source.blob(b"#!/bin/sh\necho sparse\n");
    let link = source.blob(b"../../outside-the-workspace");
    let docs = source.tree(&[entry(b"100644", b"readme.md", &readme)]);
    let src = source.tree(&[
        entry(b"120000", b"link", &link),
        entry(b"100755", b"tool", &tool),
    ]);
    let root = source.tree(&[
        entry(b"40000", b"docs", &docs),
        entry(b"40000", b"src", &src),
    ]);
    let commit = source.blob(b"fixture source-commit identity");
    (source, root, commit)
}

const fn repository_id() -> RepositoryId {
    RepositoryId::from_bytes([0x73; 16])
}

fn rcr_id() -> RepositoryCommitId {
    RepositoryCommitId::from_digest(
        DigestAlgorithmId::try_new(FIXTURE_ALGORITHM_CODE_POINT)
            .expect("fixture code point is nonzero"),
        CodecVersion::new(1, 0),
        DigestBytes::try_new(&[0x42; 32]).expect("fixture digest is long enough"),
    )
}

fn base(root: Oid, commit: Oid) -> BaseView<Sha1> {
    BaseView::new(
        repository_id(),
        rcr_id(),
        commit,
        root,
        ParseLimits::default(),
        PathPolicy::default(),
    )
}

fn path(bytes: &[u8]) -> TreePath {
    TreePath::parse_default(bytes).expect("fixture path is valid")
}

fn capability(prefixes: &[&[u8]], policy: SymlinkPolicy) -> TreeCapability {
    TreeCapability::new(
        WorkspaceId::from_bytes([0x91; 16]),
        repository_id(),
        prefixes.iter().map(|prefix| path(prefix)).collect(),
        Vec::new(),
    )
    .with_symlink_policy(policy)
}

#[test]
fn sparse_manifest_is_canonical_and_keeps_symlinks_as_data() {
    let (source, root, commit) = fixture();
    let view = base(root, commit);
    let mut first_capability = capability(&[b"docs", b"src"], SymlinkPolicy::DataOnly);
    let first = SparseManifest::build(
        &view,
        &source,
        &mut first_capability,
        7,
        SparseLimits::default(),
    )
    .expect("capability-visible authenticated entries build a sparse manifest");
    let mut second_capability = capability(&[b"docs", b"src"], SymlinkPolicy::DataOnly);
    let second = SparseManifest::build(
        &view,
        &source,
        &mut second_capability,
        7,
        SparseLimits::default(),
    )
    .expect("the same source and capability reproduce a manifest");

    assert_eq!(first, second);
    assert_eq!(first.receipt().repository_id(), repository_id());
    assert_eq!(first.receipt().source_rcr_id(), rcr_id());
    assert_eq!(first.receipt().source_commit_oid(), &commit);
    assert_eq!(first.receipt().source_tree_oid(), &root);
    assert_eq!(first.receipt().profile(), SparseProfile::ManifestV1);
    assert_eq!(
        first.receipt().completeness(),
        SparseCompleteness::CapabilityVisibleTreeV1
    );
    assert_eq!(
        first.receipt().verification(),
        SparseVerification::SourceObjectIdentitiesVerifiedV1
    );
    assert_eq!(first.receipt().entry_count(), 5);
    assert_eq!(
        first
            .entries()
            .iter()
            .map(|entry| entry.path().as_bytes())
            .collect::<Vec<_>>(),
        vec![
            b"docs".as_slice(),
            b"docs/readme.md".as_slice(),
            b"src".as_slice(),
            b"src/link".as_slice(),
            b"src/tool".as_slice(),
        ]
    );
    assert_eq!(first.entries()[0].kind(), &SparseEntryKind::Directory);
    assert_eq!(
        first.entries()[1].kind(),
        &SparseEntryKind::File {
            mode: FileMode::Regular,
            body: b"# sparse input\n".to_vec(),
        }
    );
    assert_eq!(
        first.entries()[3].kind(),
        &SparseEntryKind::Symlink {
            target: b"../../outside-the-workspace".to_vec(),
        },
        "the manifest records repository link-text; it never follows it"
    );
    assert_eq!(
        first.entries()[4].kind(),
        &SparseEntryKind::File {
            mode: FileMode::Executable,
            body: b"#!/bin/sh\necho sparse\n".to_vec(),
        }
    );
    assert_eq!(
        first.receipt().payload_bytes(),
        b"# sparse input\n".len()
            + b"../../outside-the-workspace".len()
            + b"#!/bin/sh\necho sparse\n".len()
    );
}

#[test]
fn sparse_manifest_refuses_a_tight_entry_limit_but_allows_its_near_twin() {
    let (source, root, commit) = fixture();
    let view = base(root, commit);
    let mut too_small = capability(&[b"docs", b"src"], SymlinkPolicy::DataOnly);
    assert_eq!(
        SparseManifest::build(
            &view,
            &source,
            &mut too_small,
            7,
            SparseLimits {
                max_entries: 4,
                ..SparseLimits::default()
            },
        ),
        Err(SparseRefusal::EntryLimitExceeded {
            observed: 5,
            limit: 4,
        })
    );

    let mut enough = capability(&[b"docs", b"src"], SymlinkPolicy::DataOnly);
    let manifest = SparseManifest::build(
        &view,
        &source,
        &mut enough,
        7,
        SparseLimits {
            max_entries: 5,
            ..SparseLimits::default()
        },
    )
    .expect("the one-entry-larger twin proceeds");
    assert_eq!(manifest.entries().len(), 5);
}

#[test]
fn sparse_manifest_refuses_symlinks_when_the_capability_forbids_them() {
    let (source, root, commit) = fixture();
    let view = base(root, commit);
    let mut refused = capability(&[b"docs", b"src"], SymlinkPolicy::Refuse);
    assert!(matches!(
        SparseManifest::build(
            &view,
            &source,
            &mut refused,
            7,
            SparseLimits::default(),
        ),
        Err(SparseRefusal::Capability(
            fgit_treefs::capability::CapabilityRefusal::SymlinkRefused { path }
        )) if path.as_bytes() == b"src/link"
    ));

    let mut data_only = capability(&[b"docs", b"src"], SymlinkPolicy::DataOnly);
    assert!(
        SparseManifest::build(&view, &source, &mut data_only, 7, SparseLimits::default(),).is_ok(),
        "the adjacent data-only policy permits the same link as inert data"
    );
}

#[test]
fn sparse_manifest_refuses_a_wrong_source_body_before_retaining_it() {
    let (mut source, root, commit) = fixture();
    let target = source
        .objects
        .values_mut()
        .find(|body| body.as_slice() == b"# sparse input\n")
        .expect("fixture readme exists");
    *target = b"changed bytes at the same claimed oid".to_vec();
    let view = base(root, commit);
    let mut granted = capability(&[b"docs", b"src"], SymlinkPolicy::DataOnly);
    assert!(matches!(
        SparseManifest::build(&view, &source, &mut granted, 7, SparseLimits::default(),),
        Err(SparseRefusal::Source(
            ObjectSourceError::IdentityMismatch { .. }
        ))
    ));
}
