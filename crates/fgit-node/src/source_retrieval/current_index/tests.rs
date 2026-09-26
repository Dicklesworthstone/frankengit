//! Equality-policy tests; persisted native-node campaigns are integration tests.
use super::*;
use fgit_crypto::{
    GitObjectKind, IdentityDomain, git_object_id, internal_algorithm_id, internal_digest_value,
    internal_object_id,
};
use fgit_types::{
    CodecVersion, Digest, GitHashAlgorithm, RepositoryCommitId, RepositoryId,
    RepositoryIncarnationId, SchemaFamily, SchemaId, TenantId,
};

fn source(label: &[u8]) -> LexicalSource {
    let schema = |family| SchemaId::new(SchemaFamily::from_static(family), 1, 0);
    let id = |domain, family| {
        internal_object_id(domain, schema(family), CodecVersion::new(1, 0), label)
    };
    LexicalSource {
        namespace: LexicalNamespace {
            tenant: TenantId::from_bytes([1; 16]),
            repository: RepositoryId::from_bytes([2; 16]),
            incarnation: RepositoryIncarnationId::from_bytes([3; 16]),
            object_format: GitHashAlgorithm::Sha1,
        },
        reference: RefName::try_new(b"refs/heads/main").unwrap(),
        source_head: RepositoryAuthorityHeadId::from_internal_object_id(id(
            IdentityDomain::RepositoryAuthorityHead,
            "repository-authority-head",
        ))
        .unwrap(),
        source_rcr: RepositoryCommitId::from_internal_object_id(id(
            IdentityDomain::RepositoryCommitRecord,
            "repository-commit-record",
        ))
        .unwrap(),
        forge_position_root: Digest::new(
            internal_algorithm_id(IdentityDomain::MerkleLeaf),
            internal_digest_value(IdentityDomain::MerkleLeaf, schema("test"), label),
        ),
        commit: git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Commit, b"commit"),
        tree: git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Tree, b"tree"),
    }
}

#[test]
fn different_repository_metadata_does_not_change_exact_native_source() {
    let indexed = source(b"indexed");
    let current = source(b"current");
    assert_ne!(indexed.source_head, current.source_head);
    assert_ne!(indexed.source_rcr, current.source_rcr);
    assert_ne!(indexed.forge_position_root, current.forge_position_root);
    same_native_source(&indexed, &current).unwrap();
    same_native_source(&indexed, &indexed).unwrap();
    // The comparison promises content equivalence, not an unverified temporal
    // ordering between the two heads.
    same_native_source(&current, &indexed).unwrap();
}

#[test]
fn tenant_repository_incarnation_format_and_reference_are_not_interchangeable() {
    let indexed = source(b"indexed");
    for variant in 0..5 {
        let mut current = source(b"current");
        match variant {
            0 => current.namespace.tenant = TenantId::from_bytes([9; 16]),
            1 => current.namespace.repository = RepositoryId::from_bytes([9; 16]),
            2 => current.namespace.incarnation = RepositoryIncarnationId::from_bytes([9; 16]),
            3 => current.namespace.object_format = GitHashAlgorithm::Sha256,
            _ => current.reference = RefName::try_new(b"refs/heads/other").unwrap(),
        }
        assert!(matches!(
            same_native_source(&indexed, &current),
            Err(NodeWorkspaceRefusal::SourceIndex(error))
                if matches!(*error, IndexError::SourceMismatch)
        ));
    }
}

#[test]
fn same_tree_does_not_excuse_a_different_commit_or_vice_versa() {
    let indexed = source(b"indexed");
    for change_tree in [false, true] {
        let mut current = source(b"current");
        if change_tree {
            current.tree = git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Tree, b"other");
        } else {
            current.commit = git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Commit, b"other");
        }
        assert!(matches!(
            same_native_source(&indexed, &current),
            Err(NodeWorkspaceRefusal::SourceIndexStale)
        ));
    }
}

#[test]
fn equal_head_with_contradictory_selected_roots_is_not_metadata_reuse() {
    let indexed = source(b"indexed");
    let other = source(b"other");
    for change_forge in [false, true] {
        let mut current = indexed.clone();
        if change_forge {
            current.forge_position_root = other.forge_position_root;
        } else {
            current.source_rcr = other.source_rcr;
        }
        assert!(matches!(
            same_native_source(&indexed, &current),
            Err(NodeWorkspaceRefusal::SourceIndex(error))
                if matches!(*error, IndexError::SourceMismatch)
        ));
    }
}
