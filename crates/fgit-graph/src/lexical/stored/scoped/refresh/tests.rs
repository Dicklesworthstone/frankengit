//! Real codecs, postings and generation CAS over the memory authority. These
//! tests do not claim native TreeFS enumeration or disk durability coverage.
use super::*;
use crate::lexical::{LexicalChannel, LexicalQuery, LexicalQueryLimits, LexicalSegment, SourceDocument};
use fgit_authority::{MemoryAuthorityStore, StoreInstanceId};
use fgit_crypto::{
    GitObjectKind, IdentityDomain, git_object_id, internal_algorithm_id, internal_digest_value,
    internal_object_id,
};
use fgit_types::{
    CodecVersion, Digest, GitHashAlgorithm, RefName, RepositoryAuthorityHeadId,
    RepositoryCommitId, RepositoryId, RepositoryIncarnationId, SchemaFamily, SchemaId, TenantId,
};

fn source(format: GitHashAlgorithm, position: u8) -> LexicalSource {
    let id = |domain, family: &'static str| {
        internal_object_id(
            domain,
            SchemaId::new(SchemaFamily::from_static(family), 1, 0),
            CodecVersion::new(1, 0),
            &[position],
        )
    };
    LexicalSource {
        namespace: crate::lexical::LexicalNamespace {
            tenant: TenantId::from_bytes([1; 16]),
            repository: RepositoryId::from_bytes([2; 16]),
            incarnation: RepositoryIncarnationId::from_bytes([3; 16]),
            object_format: format,
        },
        reference: RefName::try_new(b"refs/heads/main").unwrap(),
        source_head: RepositoryAuthorityHeadId::from_internal_object_id(id(
            IdentityDomain::RepositoryAuthorityHead, "repository-authority-head",
        )).unwrap(),
        source_rcr: RepositoryCommitId::from_internal_object_id(id(
            IdentityDomain::RepositoryCommitRecord, "repository-commit-record",
        )).unwrap(),
        forge_position_root: Digest::new(
            internal_algorithm_id(IdentityDomain::MerkleLeaf),
            internal_digest_value(
                IdentityDomain::MerkleLeaf,
                SchemaId::new(SchemaFamily::from_static("lexical-test"), 1, 0),
                &[position],
            ),
        ),
        commit: git_object_id(format, GitObjectKind::Commit, &[position]),
        tree: git_object_id(format, GitObjectKind::Tree, &[position]),
    }
}

fn prepared(source: &LexicalSource, scope: &LexicalScope) -> PreparedScopedLexicalIndex {
    let content = b"needle original";
    let segment = LexicalSegment::build(
        source.namespace,
        1,
        [b"src/a.rs".as_slice(), b"src/b.rs".as_slice()].map(|path| SourceDocument {
            path,
            blob: git_object_id(source.namespace.object_format, GitObjectKind::Blob, content),
            content,
        }),
        &mut || true,
    ).unwrap();
    PreparedScopedLexicalIndex::new(source.clone(), scope.clone(), vec![segment], 0, &mut || true)
        .unwrap()
}

fn paths(store: &ScopedLexicalIndexStore<'_, MemoryAuthorityStore>, term: &[u8]) -> Vec<Vec<u8>> {
    let selected = store.select(None, None, LexicalReadLimits::default(), &mut || true).unwrap();
    let query = LexicalQuery::new(LexicalChannel::Content, &[term.to_vec()], &[]).unwrap();
    store.search(&selected, &query, None, LexicalReadLimits::default(),
        LexicalQueryLimits::default(), &mut || true).unwrap()
        .index.results.hits.into_iter().map(|hit| hit.path).collect()
}

#[test]
fn scoped_refresh_reuses_unchanged_rows_and_removes_deleted_rows_in_both_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let memory = MemoryAuthorityStore::new(StoreInstanceId::from_raw(981));
        let old = source(format, 1);
        let next = source(format, 2);
        let scope = LexicalScope::new(&[b"src".to_vec()]).unwrap();
        let store = ScopedLexicalIndexStore::new(&memory, old.namespace, old.reference.clone(), scope.clone()).unwrap();
        let first = store.publish(&prepared(&old, &scope), None, &mut || true).unwrap();
        let selected = store.select(None, None, LexicalReadLimits::default(), &mut || true).unwrap();
        let reuse = store.load_refresh_base(&selected, LexicalReadLimits::default(), &mut || true).unwrap();
        let blob = git_object_id(format, GitObjectKind::Blob, b"needle original");
        assert_eq!(reuse.document_bytes(b"src/a.rs", blob), Some(15));
        assert_eq!(reuse.document_bytes(b"src-other/a.rs", blob), None);
        let fresh = b"changed fresh";
        let rows = [
            RefreshDocument { path: b"src/a.rs", blob, content: None },
            RefreshDocument { path: b"src/c.rs", blob: git_object_id(format, GitObjectKind::Blob, fresh), content: Some(fresh) },
        ];
        let (replacement, stats) = reuse.prepare(next.clone(), &rows, 1, &mut || true).unwrap();
        assert_eq!(replacement.scope(), &scope);
        assert_eq!(replacement.source(), &next);
        assert_eq!((stats.reused_documents, stats.rebuilt_documents, stats.prior_documents_not_reused), (1, 1, 1));
        assert_eq!((stats.reused_source_bytes, stats.rebuilt_source_bytes), (15, fresh.len()));
        let second = store.publish(&replacement, Some(first.generation_id), &mut || true).unwrap();
        assert_ne!(second.generation_id, first.generation_id);
        assert_eq!(paths(&store, b"needle"), vec![b"src/a.rs".to_vec()]);
        assert_eq!(paths(&store, b"fresh"), vec![b"src/c.rs".to_vec()]);
        // Repeating the stale predecessor cannot overwrite the published root.
        let (stale, _) = reuse.prepare(source(format, 3), &rows, 1, &mut || true).unwrap();
        assert!(store.publish(&stale, Some(first.generation_id), &mut || true).is_err());
        assert_eq!(store.select(None, None, LexicalReadLimits::default(), &mut || true).unwrap().activation(), &second);
    }
}

#[test]
fn scoped_refresh_cannot_change_coverage_namespace_or_claim_a_changed_blob_as_reused() {
    let memory = MemoryAuthorityStore::new(StoreInstanceId::from_raw(982));
    let source = source(GitHashAlgorithm::Sha256, 1);
    let scope = LexicalScope::new(&[b"src".to_vec()]).unwrap();
    let store = ScopedLexicalIndexStore::new(&memory, source.namespace, source.reference.clone(), scope.clone()).unwrap();
    store.publish(&prepared(&source, &scope), None, &mut || true).unwrap();
    let selected = store.select(None, None, LexicalReadLimits::default(), &mut || true).unwrap();
    let other = ScopedLexicalIndexStore::new(&memory, source.namespace, source.reference.clone(),
        LexicalScope::new(&[b"tests".to_vec()]).unwrap()).unwrap();
    assert!(matches!(other.load_refresh_base(&selected, LexicalReadLimits::default(), &mut || true), Err(IndexError::SourceMismatch)));
    let reuse = store.load_refresh_base(&selected, LexicalReadLimits::default(), &mut || true).unwrap();
    let blob = git_object_id(source.namespace.object_format, GitObjectKind::Blob, b"different");
    for path in [b"tests/a.rs".as_slice(), b"src-other/a.rs".as_slice()] {
        assert!(reuse.prepare(source.clone(), &[RefreshDocument { path, blob, content: Some(b"different") }], 0, &mut || true).is_err());
    }
    assert!(reuse.prepare(source.clone(), &[RefreshDocument { path: b"src/a.rs", blob, content: None }], 0, &mut || true).is_err());
    let mut foreign = source.clone();
    foreign.namespace.tenant = TenantId::from_bytes([9; 16]);
    assert!(matches!(reuse.prepare(foreign, &[], 0, &mut || true), Err(IndexError::SourceMismatch)));
    let other_memory = MemoryAuthorityStore::new(StoreInstanceId::from_raw(983));
    let other_instance = ScopedLexicalIndexStore::new(&other_memory, source.namespace, source.reference.clone(), scope).unwrap();
    assert!(matches!(other_instance.load_refresh_base(&selected, LexicalReadLimits::default(), &mut || true), Err(IndexError::SourceMismatch)));
}

#[test]
fn scoped_refresh_preserves_cancellation_read_budgets_and_explicit_empty_coverage() {
    let memory = MemoryAuthorityStore::new(StoreInstanceId::from_raw(984));
    let source = source(GitHashAlgorithm::Sha1, 1);
    let scope = LexicalScope::new(&[b"src".to_vec()]).unwrap();
    let store = ScopedLexicalIndexStore::new(&memory, source.namespace, source.reference.clone(), scope.clone()).unwrap();
    let first = store.publish(&prepared(&source, &scope), None, &mut || true).unwrap();
    let selected = store.select(None, None, LexicalReadLimits::default(), &mut || true).unwrap();
    assert!(matches!(store.load_refresh_base(&selected, LexicalReadLimits::default(), &mut || false), Err(IndexError::Lexical(LexicalError::Cancelled))));
    assert!(store.load_refresh_base(&selected, LexicalReadLimits { max_payload_bytes: 1, ..Default::default() }, &mut || true).is_err());
    let reuse = store.load_refresh_base(&selected, LexicalReadLimits::default(), &mut || true).unwrap();
    assert!(matches!(reuse.prepare(source.clone(), &[], 0, &mut || false), Err(IndexError::Lexical(LexicalError::Cancelled))));
    let (empty, stats) = reuse.prepare(source, &[], 0, &mut || true).unwrap();
    assert_eq!(empty.scope(), &scope);
    assert_eq!(empty.document_count(), 0);
    assert_eq!(stats.prior_documents_not_reused, 2);
    store.publish(&empty, Some(first.generation_id), &mut || true).unwrap();
    assert!(paths(&store, b"needle").is_empty());
}
