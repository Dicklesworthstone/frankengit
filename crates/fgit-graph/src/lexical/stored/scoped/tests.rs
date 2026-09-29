//! Real lexical codecs and the reference in-memory authority store. These are
//! not native-node, disk-durability or process-crash evidence.
use super::*;
use crate::lexical::{LexicalChannel, SourceDocument};
use fgit_authority::{MemoryAuthorityStore, StoreInstanceId};
use fgit_crypto::{GitObjectKind, IdentityDomain, git_object_id, internal_object_id};
use fgit_types::{
    CodecVersion, Digest, GitHashAlgorithm, RepositoryAuthorityHeadId, RepositoryCommitId,
    RepositoryId, RepositoryIncarnationId, SchemaFamily, SchemaId, TenantId,
};

fn scope(paths: &[&[u8]]) -> LexicalScope {
    LexicalScope::new(&paths.iter().map(|p| p.to_vec()).collect::<Vec<_>>()).unwrap()
}
fn source(format: GitHashAlgorithm) -> LexicalSource {
    let id = |domain, family| {
        internal_object_id(
            domain,
            SchemaId::new(SchemaFamily::from_static(family), 1, 0),
            CodecVersion::new(1, 0),
            b"scoped index fixture",
        )
    };
    let forge = id(IdentityDomain::MerkleLeaf, "scope-test");
    LexicalSource {
        namespace: LexicalNamespace {
            tenant: TenantId::from_bytes([1; 16]),
            repository: RepositoryId::from_bytes([2; 16]),
            incarnation: RepositoryIncarnationId::from_bytes([3; 16]),
            object_format: format,
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
        forge_position_root: Digest::new(forge.algorithm(), *forge.digest()),
        commit: git_object_id(format, GitObjectKind::Commit, b"commit fixture"),
        tree: git_object_id(format, GitObjectKind::Tree, b"tree fixture"),
    }
}
fn prepared(
    format: GitHashAlgorithm,
    coverage: &LexicalScope,
    paths: &[&[u8]],
) -> PreparedScopedLexicalIndex {
    let source = source(format);
    let content = b"Needle needle other";
    let segments = if paths.is_empty() {
        vec![]
    } else {
        vec![
            LexicalSegment::build(
                source.namespace,
                1,
                paths.iter().map(|path| SourceDocument {
                    path,
                    blob: git_object_id(format, GitObjectKind::Blob, content),
                    content,
                }),
                &mut || true,
            )
            .unwrap(),
        ]
    };
    PreparedScopedLexicalIndex::new(source, coverage.clone(), segments, 0, &mut || true).unwrap()
}
fn store<'a>(
    memory: &'a MemoryAuthorityStore,
    format: GitHashAlgorithm,
    coverage: &LexicalScope,
) -> ScopedLexicalIndexStore<'a, MemoryAuthorityStore> {
    let source = source(format);
    ScopedLexicalIndexStore::new(memory, source.namespace, source.reference, coverage.clone())
        .unwrap()
}
fn query(channel: LexicalChannel, word: &[u8], filters: &[Vec<u8>]) -> LexicalQuery {
    LexicalQuery::new(channel, &[word.to_vec()], filters).unwrap()
}

#[test]
fn canonical_union_collapses_descendants_even_with_interleaved_sibling_names() {
    let mut input = vec![
        b"src/a".to_vec(),
        b"src-b".to_vec(),
        b"src".to_vec(),
        b"src".to_vec(),
    ];
    let a = LexicalScope::new(&input).unwrap();
    assert_eq!(a.prefixes(), &[b"src".to_vec(), b"src-b".to_vec()]);
    input.reverse();
    assert_eq!(a, LexicalScope::new(&input).unwrap());
    input[0].clear();
    assert_eq!(a, scope(&[b"src-b", b"src"]));
    assert!(a.includes(b"src/a"));
    assert!(!a.includes(b"src2/a"));
    assert!(!a.includes(b"SRC/a"));
}
#[test]
fn complete_scope_digest_has_a_fixed_domain_and_untruncated_canonical_view() {
    let a = scope(&[b"docs", b"crates/fgit-node"]);
    let digest: String = a.digest().iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        digest,
        "06b5005b12484ba5a48fdb9abc420a76d1bc86064df3eaa800dbe365f80820e3"
    );
    assert_eq!(
        a.view().unwrap().as_bytes(),
        b"lx-a22qawysjbf2ljep3onlyqqko3i3zbqgjxz6vkaa3prwl6aiedrq"
    );
    assert_eq!(a.view().unwrap().as_bytes().len(), 55);
    assert_ne!(a.view().unwrap(), scope(&[b"docs"]).view().unwrap());
}
#[test]
fn malformed_unbounded_and_implicit_whole_tree_scopes_refuse() {
    for paths in [
        vec![],
        vec![vec![]],
        vec![b"/".to_vec()],
        vec![b"a/..".to_vec()],
        vec![b"a//b".to_vec()],
        vec![b"a\0b".to_vec()],
        vec![b".GiT/x".to_vec()],
        vec![vec![b'a'; 4097]],
        vec![b"a".to_vec(); 129],
        vec![vec![b'a'; 4096]; 9],
        vec![format!("{}a", "a/".repeat(64)).into_bytes()],
    ] {
        assert!(LexicalScope::new(&paths).is_err(), "{paths:?}");
    }
    assert!(LexicalScope::new(&vec![vec![b'a'; 4096]; 8]).is_ok());
    assert!(LexicalScope::new(&vec![b"a".to_vec(); 128]).is_ok());
    assert!(scope(&[b"raw\xff"]).includes(b"raw\xff/x"));
    assert!(!scope(&[b"raw\xff"]).includes(b"raw\xfe/x"));
}
#[test]
fn scoped_preparation_rejects_outside_documents_without_dropping_them() {
    let s = source(GitHashAlgorithm::Sha1);
    let body = b"needle";
    let segment = LexicalSegment::build(
        s.namespace,
        1,
        [SourceDocument {
            path: b"src2/a",
            blob: git_object_id(s.namespace.object_format, GitObjectKind::Blob, body),
            content: body,
        }],
        &mut || true,
    )
    .unwrap();
    assert!(
        PreparedScopedLexicalIndex::new(s, scope(&[b"src"]), vec![segment], 0, &mut || true)
            .is_err()
    );
    assert_eq!(
        prepared(GitHashAlgorithm::Sha1, &scope(&[b"src"]), &[b"src/a"]).document_count(),
        1
    );
}
#[test]
fn empty_scopes_have_distinct_candidates_heads_and_rollback_floors_in_both_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let memory = MemoryAuthorityStore::new(StoreInstanceId::from_raw(70));
        let a = scope(&[b"src"]);
        let b = scope(&[b"docs"]);
        let sa = store(&memory, format, &a);
        let sb = store(&memory, format, &b);
        let pa = prepared(format, &a, &[]);
        let pb = prepared(format, &b, &[]);
        assert_ne!(
            sa.candidate_id(&pa, None).unwrap(),
            sb.candidate_id(&pb, None).unwrap()
        );
        let first = sa.publish(&pa, None, &mut || true).unwrap();
        assert!(matches!(
            sb.select(None, None, Default::default(), &mut || true),
            Err(IndexError::Uninitialized)
        ));
        let source = source(format);
        let full = LexicalIndexStore::new(&memory, source.namespace, source.reference).unwrap();
        assert!(matches!(
            full.select(None, None, Default::default(), &mut || true),
            Err(IndexError::Uninitialized)
        ));
        let second_scope = sb.publish(&pb, None, &mut || true).unwrap();
        assert_eq!(first.authority_generation.get(), 1);
        assert_eq!(second_scope.authority_generation.get(), 1);
        assert!(
            sa.select(None, Some(&second_scope), Default::default(), &mut || true)
                .is_err()
        );
        assert!(matches!(
            sa.recover(
                second_scope.generation_id,
                None,
                Default::default(),
                &mut || true
            )
            .unwrap(),
            crate::GenerationRecovery::NotInSelectedHistory { .. }
        ));
        assert!(
            sa.publish(&pa, Some(second_scope.generation_id), &mut || true)
                .is_err()
        );
    }
}
#[test]
fn prepared_values_and_selections_cannot_cross_coverage_boundaries() {
    let format = GitHashAlgorithm::Sha1;
    let memory = MemoryAuthorityStore::new(StoreInstanceId::from_raw(71));
    let a = scope(&[b"src"]);
    let b = scope(&[b"docs"]);
    let sa = store(&memory, format, &a);
    let sb = store(&memory, format, &b);
    let pa = prepared(format, &a, &[b"src/a"]);
    assert!(sb.candidate_id(&pa, None).is_err());
    assert!(sb.publish(&pa, None, &mut || true).is_err());
    sa.publish(&pa, None, &mut || true).unwrap();
    let selected = sa
        .select(None, None, Default::default(), &mut || true)
        .unwrap();
    assert!(
        sb.search(
            &selected,
            &query(LexicalChannel::Content, b"needle", &[]),
            None,
            Default::default(),
            Default::default(),
            &mut || true
        )
        .is_err()
    );
}
#[test]
fn scoped_content_path_and_pagination_preserve_original_bytes_and_ids() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let memory = MemoryAuthorityStore::new(StoreInstanceId::from_raw(72));
        let coverage = scope(&[b"src"]);
        let store = store(&memory, format, &coverage);
        let prepared = prepared(format, &coverage, &[b"src/a", b"src/z"]);
        store.publish(&prepared, None, &mut || true).unwrap();
        let selected = store
            .select(None, None, Default::default(), &mut || true)
            .unwrap();
        let q = query(LexicalChannel::Content, b"NEEDLE", &[]);
        let first = store
            .search(
                &selected,
                &q,
                None,
                Default::default(),
                LexicalQueryLimits {
                    max_results: 1,
                    ..Default::default()
                },
                &mut || true,
            )
            .unwrap();
        assert_eq!(first.scope, coverage);
        assert_eq!(first.index.indexed_documents, 2);
        assert_eq!(first.index.results.hits[0].document_id, 1);
        assert_eq!(first.index.results.hits[0].spans[0].byte_offset, 0);
        assert_eq!(first.index.results.next_after, Some(1));
        assert!(!first.index.results.complete);
        let second = store
            .search(
                &selected,
                &q,
                Some(1),
                Default::default(),
                Default::default(),
                &mut || true,
            )
            .unwrap();
        assert_eq!(second.index.results.hits[0].document_id, 2);
        assert!(second.index.results.complete);
        let path = store
            .search(
                &selected,
                &query(LexicalChannel::Path, b"src", &[]),
                None,
                Default::default(),
                Default::default(),
                &mut || true,
            )
            .unwrap();
        assert_eq!(path.index.results.hits.len(), 2);
        let outside = store
            .search(
                &selected,
                &query(LexicalChannel::Content, b"needle", &[b"src2".to_vec()]),
                None,
                Default::default(),
                Default::default(),
                &mut || true,
            )
            .unwrap();
        assert!(outside.index.results.complete && outside.index.results.hits.is_empty());
        assert_eq!(outside.scope, coverage);
    }
}
#[test]
fn rebuild_and_original_candidate_recovery_retain_exact_scoped_generations() {
    let memory = MemoryAuthorityStore::new(StoreInstanceId::from_raw(73));
    let coverage = scope(&[b"src"]);
    let store = store(&memory, GitHashAlgorithm::Sha256, &coverage);
    let prepared = prepared(GitHashAlgorithm::Sha256, &coverage, &[b"src/a"]);
    let first = store.publish(&prepared, None, &mut || true).unwrap();
    let second = store
        .publish(&prepared, Some(first.generation_id), &mut || true)
        .unwrap();
    let old = store
        .select(Some(&first), Some(&second), Default::default(), &mut || {
            true
        })
        .unwrap();
    assert_eq!(old.activation(), &first);
    assert_eq!(old.selected_head(), &second);
    assert!(
        matches!(store.recover(first.generation_id, Some(&second), Default::default(), &mut || true).unwrap(),
        crate::GenerationRecovery::Superseded { activation, .. } if activation == first)
    );
}
#[test]
fn cancellation_and_exact_payload_bounds_are_not_empty_success() {
    let memory = MemoryAuthorityStore::new(StoreInstanceId::from_raw(74));
    let coverage = scope(&[b"src"]);
    let store = store(&memory, GitHashAlgorithm::Sha1, &coverage);
    let prepared = prepared(GitHashAlgorithm::Sha1, &coverage, &[b"src/a"]);
    assert!(store.publish(&prepared, None, &mut || false).is_err());
    assert!(matches!(
        store.select(None, None, Default::default(), &mut || true),
        Err(IndexError::Uninitialized)
    ));
    store.publish(&prepared, None, &mut || true).unwrap();
    let selected = store
        .select(None, None, Default::default(), &mut || true)
        .unwrap();
    let q = query(LexicalChannel::Content, b"needle", &[]);
    let full = store
        .search(
            &selected,
            &q,
            None,
            Default::default(),
            Default::default(),
            &mut || true,
        )
        .unwrap();
    let limit = LexicalReadLimits {
        max_payload_bytes: full.index.payload_bytes_read,
        ..Default::default()
    };
    assert!(
        store
            .search(&selected, &q, None, limit, Default::default(), &mut || true)
            .is_ok()
    );
    assert!(
        store
            .search(
                &selected,
                &q,
                None,
                LexicalReadLimits {
                    max_payload_bytes: limit.max_payload_bytes - 1,
                    ..limit
                },
                Default::default(),
                &mut || true
            )
            .is_err()
    );
    assert!(
        store
            .search(&selected, &q, None, limit, Default::default(), &mut || {
                false
            })
            .is_err()
    );
}
