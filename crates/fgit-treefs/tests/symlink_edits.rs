//! Typed, body-free symlink moves and compatibility of existing overlay roots.

use fgit_crypto::{GitHashAlgorithm, GitObjectKind, GitOid, NativeObjectIdentity, Sha1, Sha256};
use fgit_git_object::ParseLimits;
use fgit_treefs::{
    BaseEntry, BaseView, BasisEntry, ContentRef, ExportLimits, ExportPlanner, FileMode,
    IntentError, IntentLog, ObjectSource, ObjectSourceError, Overlay, OverlayEntry, OverlayRoot,
    PathPolicy, ReadGrant, TreeCapability, TreeEditIntent, TreePath, WorkspaceId,
};
use fgit_types::{CodecVersion, DigestAlgorithmId, DigestBytes, RepositoryCommitId, RepositoryId};

fn path(value: &str) -> TreePath {
    TreePath::parse_default(value.as_bytes()).unwrap()
}

fn renamed(from: &str, to: &str) -> TreeEditIntent {
    TreeEditIntent::Rename {
        from: path(from),
        to: path(to),
        basis_entry: None,
    }
}

fn log(intents: impl IntoIterator<Item = TreeEditIntent>) -> IntentLog {
    let mut result = IntentLog::new();
    for intent in intents {
        result.push(intent);
    }
    result
}

fn tree<A: GitHashAlgorithm>(name: &[u8], mode: &[u8], oid: GitOid<A>) -> Vec<u8> {
    [mode, b" ", name, b"\0", oid.digest_bytes()].concat()
}

/// The only readable body is the root tree. A blob fetch fails the test even
/// when the symlink's link-text body is absent from this source entirely.
struct TreeOnlySource<A: GitHashAlgorithm> {
    root: GitOid<A>,
    body: Vec<u8>,
}

impl<A: GitHashAlgorithm> ObjectSource<A> for TreeOnlySource<A> {
    fn read_object(
        &self,
        oid: &GitOid<A>,
        kind: GitObjectKind,
        _grant: &ReadGrant,
    ) -> Result<Vec<u8>, ObjectSourceError> {
        assert_eq!(
            kind,
            GitObjectKind::Tree,
            "a symlink move must never fetch link text"
        );
        assert_eq!(*oid, self.root);
        Ok(self.body.clone())
    }
}

fn carried_symlink<A: GitHashAlgorithm>() {
    let link_oid = GitOid::<A>::of_object(GitObjectKind::Blob, b"../../outside/never-read");
    let body = tree::<A>(b"link", b"120000", link_oid);
    let root = GitOid::<A>::of_object(GitObjectKind::Tree, &body);
    let source = TreeOnlySource::<A> { root, body };
    let repository = RepositoryId::from_bytes([0xd1; 16]);
    let parse_limits = ParseLimits {
        tree_reference_bytes: A::DIGEST_LEN,
        ..ParseLimits::default()
    };
    let base = BaseView::<A>::new(
        repository,
        RepositoryCommitId::from_digest(
            DigestAlgorithmId::try_new(0xfff1).unwrap(),
            CodecVersion::new(1, 0),
            DigestBytes::try_new(&[0xd2; 32]).unwrap(),
        ),
        root,
        root,
        parse_limits.clone(),
        PathPolicy::default(),
    );
    let scope = vec![path("link"), path("moved"), path("final")];
    let mut capability = TreeCapability::new(
        WorkspaceId::from_bytes([0xd3; 16]),
        repository,
        scope.clone(),
        scope,
    );
    let resolved = base
        .resolve(&source, &mut capability, &path("link"), 0)
        .unwrap();
    let edits = log([renamed("link", "moved"), renamed("moved", "final")]);
    let resolver = |target: &TreePath| (target == &path("link")).then(|| resolved.clone());
    let (overlay, evaluation) = edits.evaluate_with_base_entries::<A>(&resolver);
    assert!(evaluation.errors().is_empty());
    assert_eq!(overlay.stats().body_bytes, 0);
    let final_entry = &overlay.entries()[&path("final")];
    assert!(matches!(
        final_entry,
        OverlayEntry::Symlink {
            target: ContentRef::Base { .. }
        }
    ));
    assert_eq!(
        final_entry.base_carry(),
        Some((&link_oid.digest_bytes().to_vec(), &path("link")))
    );
    assert_eq!(final_entry.content_id(), None);
    let (replayed, _) = edits.evaluate_with_base_entries::<A>(&resolver);
    assert_eq!(OverlayRoot::of(&overlay), OverlayRoot::of(&replayed));

    let plan = ExportPlanner::new(ExportLimits::default(), parse_limits)
        .plan(&base, &source, &mut capability, &overlay, 0, &|| false)
        .unwrap();
    let expected = tree::<A>(b"final", b"120000", link_oid);
    assert_eq!(
        *plan.root_tree(),
        GitOid::<A>::of_object(GitObjectKind::Tree, &expected)
    );
    assert_eq!(plan.reused_base_objects(), 1);
    assert_eq!(plan.object_count(), 1);
    assert!(
        plan.objects()
            .all(|object| object.kind() == GitObjectKind::Tree)
    );
    assert!(plan.verify_all());
}

#[test]
fn base_symlink_rename_chains_reuse_native_identity_without_reading_target_bytes() {
    carried_symlink::<Sha1>();
    carried_symlink::<Sha256>();
}

#[test]
fn preexisting_staged_symlink_overlay_root_encoding_is_unchanged() {
    let edits = log([TreeEditIntent::CreateSymlink {
        path: path("link"),
        link_target: b"../target".to_vec(),
    }]);
    let (overlay, evaluation) = edits.evaluate(&|_| false);
    assert!(evaluation.errors().is_empty());
    // Independently calculated from the original v1 content and overlay
    // preimages: no ContentRef tag may be inserted into this old encoding.
    assert_eq!(
        OverlayRoot::of(&overlay).to_string(),
        "a451a876424070396eedddf44ac76b2c9ac9bbf2bf2c265401101bf987531778"
    );
}

fn carried_overlay(oid: Vec<u8>, from: &str) -> Overlay {
    let mut overlay = Overlay::new();
    overlay.put(
        path("destination"),
        OverlayEntry::Symlink {
            target: ContentRef::Base {
                oid,
                from: path(from),
            },
        },
    );
    overlay
}

#[test]
fn carried_symlink_snapshot_binds_native_domain_identity_and_source_lineage() {
    let original = OverlayRoot::of(&carried_overlay(vec![1; 20], "source"));
    for changed in [
        carried_overlay(vec![2; 20], "source"),
        carried_overlay(vec![1; 32], "source"),
        carried_overlay(vec![1; 20], "another-source"),
    ] {
        assert_ne!(original, OverlayRoot::of(&changed));
    }
}

#[test]
fn typed_sources_reject_file_hints_on_symlinks_and_mismatched_file_identities() {
    let oid = GitOid::<Sha1>::of_object(GitObjectKind::Blob, b"source");
    let hint = BasisEntry {
        oid: oid.digest_bytes().to_vec(),
        mode: FileMode::Regular,
    };
    let forged = log([TreeEditIntent::Rename {
        from: path("link"),
        to: path("moved"),
        basis_entry: Some(hint.clone()),
    }]);
    let resolver = |target: &TreePath| -> Option<BaseEntry<Sha1>> {
        (target == &path("link")).then_some(BaseEntry::Symlink { oid })
    };
    let (_, refused) = forged.evaluate_with_base_entries(&resolver);
    assert!(matches!(
        refused.errors()[0].1,
        IntentError::BasisEntryMismatch { .. }
    ));
    let (_, permitted) = log([renamed("link", "moved")]).evaluate_with_base_entries(&resolver);
    assert!(permitted.errors().is_empty());
    let (_, refused) = log([TreeEditIntent::Chmod {
        path: path("link"),
        basis_entry: Some(hint.clone()),
        after: FileMode::Regular,
    }])
    .evaluate_with_base_entries(&resolver);
    assert!(matches!(
        refused.errors()[0].1,
        IntentError::NotAFile { .. }
    ));

    let file = |target: &TreePath| -> Option<BaseEntry<Sha1>> {
        (target == &path("link")).then_some(BaseEntry::File {
            oid,
            mode: b"100755".to_vec(),
        })
    };
    let (_, refused) = forged.evaluate_with_base_entries(&file);
    assert!(matches!(
        refused.errors()[0].1,
        IntentError::BasisEntryMismatch { .. }
    ));
    let (_, permitted) = forged.evaluate_with_base_entries::<Sha1>(&|target| {
        (target == &path("link")).then_some(BaseEntry::File {
            oid,
            mode: b"100644".to_vec(),
        })
    });
    assert!(permitted.errors().is_empty());
}
