//! Reference-store/codecs are real; source stamps and the async adapter below
//! are explicit fixtures. These tests do not establish durable-backend behavior.
use super::*;
use crate::GenerationAuthority;
use crate::lexical::{LexicalChannel, LexicalNamespace, LexicalQuery};
use fgit_authority::{
    AuthenticatedHead, AuthorityFailure, AuthorityLimits, AuthorityVersionToken, CasOutcome,
    HeadInit, HeadKey, HeadRead, HeadReadReceipt, ImmutableKey, MemoryAuthorityStore, PutOutcome,
};
use fgit_crypto::{
    GitObjectKind, IdentityDomain, git_object_id, internal_algorithm_id, internal_digest_value,
    internal_object_id,
};
use fgit_types::{
    CodecVersion, Digest, GitHashAlgorithm, HeadGeneration, RefName, RepositoryAuthorityHeadId,
    RepositoryCommitId, RepositoryId, RepositoryIncarnationId, SchemaFamily, SchemaId, TenantId,
};
use std::future::{Future, poll_fn};
use std::pin::pin;
use std::sync::Mutex;
use std::task::{Context, Poll, Waker};

type Corpus = Vec<(Vec<u8>, Vec<u8>)>;
fn source(format: GitHashAlgorithm, version: u8) -> LexicalSource {
    let id = |domain, family: &'static str| {
        internal_object_id(
            domain,
            SchemaId::new(SchemaFamily::from_static(family), 1, 0),
            CodecVersion::new(1, 0),
            &[version],
        )
    };
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
        forge_position_root: Digest::new(
            internal_algorithm_id(IdentityDomain::MerkleLeaf),
            internal_digest_value(
                IdentityDomain::MerkleLeaf,
                SchemaId::new(SchemaFamily::from_static("refresh-test"), 1, 0),
                &[version],
            ),
        ),
        commit: git_object_id(format, GitObjectKind::Commit, &[version]),
        tree: git_object_id(format, GitObjectKind::Tree, &[version]),
    }
}
fn blob(format: GitHashAlgorithm, bytes: &[u8]) -> GitOid {
    git_object_id(format, GitObjectKind::Blob, bytes)
}
fn corpus(values: &[(&[u8], &[u8])]) -> Corpus {
    values
        .iter()
        .map(|(p, b)| (p.to_vec(), b.to_vec()))
        .collect()
}
fn fresh(source: LexicalSource, values: &Corpus) -> PreparedLexicalIndex {
    let parts = if values.is_empty() {
        Vec::new()
    } else {
        vec![
            LexicalSegment::build(
                source.namespace,
                1,
                values.iter().map(|(path, bytes)| SourceDocument {
                    path,
                    blob: blob(source.namespace.object_format, bytes),
                    content: bytes,
                }),
                &mut || true,
            )
            .unwrap(),
        ]
    };
    PreparedLexicalIndex::new(source, parts, 2, &mut || true).unwrap()
}
fn assert_same(actual: &PreparedLexicalIndex, expected: &PreparedLexicalIndex) {
    assert_eq!(actual.source(), expected.source());
    assert_eq!(actual.document_count(), expected.document_count());
    let bodies = |p: &PreparedLexicalIndex| {
        p.segments
            .iter()
            .chain(&p.metadata)
            .map(|b| (b.kind, b.root, b.bytes.clone()))
            .collect::<Vec<_>>()
    };
    assert_eq!(bodies(actual), bodies(expected));
}
fn inputs<'a>(base: &LexicalReuse, values: &'a Corpus) -> Vec<RefreshDocument<'a>> {
    values
        .iter()
        .map(|(path, bytes)| {
            let blob = blob(base.source.namespace.object_format, bytes);
            RefreshDocument {
                path,
                blob,
                content: if base.document_bytes(path, blob).is_some() {
                    None
                } else {
                    Some(bytes)
                },
            }
        })
        .collect()
}
fn memory() -> MemoryAuthorityStore {
    MemoryAuthorityStore::new(StoreInstanceId::from_raw(930))
}
fn base(
    index: &LexicalIndexStore<'_, MemoryAuthorityStore>,
    prepared: &PreparedLexicalIndex,
) -> LexicalReuse {
    index.publish(prepared, None, &mut || true).unwrap();
    let selection = index
        .select(None, None, Default::default(), &mut || true)
        .unwrap();
    index
        .load_refresh_base(&selection, Default::default(), &mut || true)
        .unwrap()
}

#[test]
fn refreshed_insert_delete_replace_and_rename_equal_full_rebuild_in_both_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let store = memory();
        let old = source(format, 1);
        let new = source(format, 2);
        let index = LexicalIndexStore::new(&store, old.namespace, old.reference.clone()).unwrap();
        let before = corpus(&[
            (b"a", b"Alpha alpha"),
            (b"b", b"delete"),
            (b"c", b"old"),
            (b"z", b"rename"),
        ]);
        let reuse = base(&index, &fresh(old, &before));
        let after = corpus(&[
            (b"00", b"insert"),
            (b"a", b"Alpha alpha"),
            (b"c", b"new"),
            (b"zz", b"rename"),
        ]);
        let (candidate, stats) = reuse
            .prepare(new.clone(), &inputs(&reuse, &after), 2, &mut || true)
            .unwrap();
        assert_same(&candidate, &fresh(new, &after));
        assert_eq!(
            (
                stats.reused_documents,
                stats.rebuilt_documents,
                stats.prior_documents_not_reused
            ),
            (1, 3, 3)
        );
        assert_eq!(stats.reused_source_bytes, 11);
        assert_eq!(stats.rebuilt_source_bytes, 15);
        let published = index
            .publish(
                &candidate,
                Some(reuse.activation.generation_id),
                &mut || true,
            )
            .unwrap();
        let selection = index
            .select(Some(&published), None, Default::default(), &mut || true)
            .unwrap();
        let query = LexicalQuery::new(LexicalChannel::Content, &[b"alpha".to_vec()], &[]).unwrap();
        let hits = index
            .search(
                &selection,
                &query,
                None,
                Default::default(),
                Default::default(),
                &mut || true,
            )
            .unwrap();
        assert_eq!(hits.results.hits[0].document_id, 2);
        assert_eq!(hits.results.hits[0].spans[0].byte_offset, 0);
        assert_eq!(hits.results.hits[0].path, b"a");
    }
}

#[test]
fn same_content_refresh_changes_source_metadata_without_changing_segment_bytes() {
    let store = memory();
    let old = source(GitHashAlgorithm::Sha256, 1);
    let index = LexicalIndexStore::new(&store, old.namespace, old.reference.clone()).unwrap();
    let values = corpus(&[(b"a.rs", b"Token token\r\n"), (b"b", b"")]);
    let prepared = fresh(old.clone(), &values);
    let reuse = base(&index, &prepared);
    let mut new = source(old.namespace.object_format, 2);
    new.commit = old.commit;
    new.tree = old.tree;
    let (candidate, stats) = reuse
        .prepare(new.clone(), &inputs(&reuse, &values), 2, &mut || true)
        .unwrap();
    assert_same(&candidate, &fresh(new, &values));
    assert_eq!(candidate.segments[0].root, prepared.segments[0].root);
    assert_eq!(stats.rebuilt_documents, 0);
    assert_eq!(stats.rebuilt_source_bytes, 0);
    assert_eq!(stats.reused_documents, 2);
    assert_ne!(
        index
            .candidate_id(&candidate, Some(reuse.activation.generation_id))
            .unwrap(),
        reuse.activation.generation_id
    );
}

#[test]
fn byte_paths_empty_files_repeated_blobs_and_both_channels_preserve_exact_spans() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let store = memory();
        let old = source(format, 1);
        let index = LexicalIndexStore::new(&store, old.namespace, old.reference.clone()).unwrap();
        let values = corpus(&[
            (b"a\xff/data", b"\0TOKEN\xfftoken"),
            (b"b/data", b"\0TOKEN\xfftoken"),
            (b"empty.rs", b""),
        ]);
        let reuse = base(&index, &fresh(old, &values));
        let (prepared, stats) = reuse
            .prepare(source(format, 2), &inputs(&reuse, &values), 2, &mut || true)
            .unwrap();
        assert_same(&prepared, &fresh(source(format, 2), &values));
        assert_eq!(stats.reused_documents, 3);
        assert_eq!(stats.rebuilt_documents, 0);
        assert!(
            reuse
                .document_bytes(b"renamed/data", blob(format, &values[0].1))
                .is_none()
        );
    }
}

#[test]
fn deleting_every_file_creates_a_complete_empty_generation() {
    let store = memory();
    let old = source(GitHashAlgorithm::Sha1, 1);
    let index = LexicalIndexStore::new(&store, old.namespace, old.reference.clone()).unwrap();
    let reuse = base(&index, &fresh(old, &corpus(&[(b"old", b"content")])));
    let (prepared, stats) = reuse
        .prepare(source(GitHashAlgorithm::Sha1, 2), &[], 2, &mut || true)
        .unwrap();
    assert_same(
        &prepared,
        &fresh(source(GitHashAlgorithm::Sha1, 2), &Vec::new()),
    );
    assert_eq!(stats.prior_documents_not_reused, 1);
    let activation = index
        .publish(&prepared, Some(reuse.activation.generation_id), &mut || {
            true
        })
        .unwrap();
    assert_eq!(activation.authority_generation.get(), 2);
}

#[test]
fn incomplete_reuse_requests_wrong_blob_paths_order_and_bad_fresh_input_refuse() {
    let store = memory();
    let src = source(GitHashAlgorithm::Sha1, 1);
    let index = LexicalIndexStore::new(&store, src.namespace, src.reference.clone()).unwrap();
    let values = corpus(&[(b"a", b"good")]);
    let reuse = base(&index, &fresh(src.clone(), &values));
    let known = RefreshDocument {
        path: b"a",
        blob: blob(src.namespace.object_format, b"good"),
        content: None,
    };
    for rows in [
        vec![RefreshDocument {
            path: b"b",
            ..known
        }],
        vec![RefreshDocument {
            blob: blob(src.namespace.object_format, b"changed"),
            ..known
        }],
        vec![known, known],
        vec![RefreshDocument {
            content: Some(b"changed"),
            ..known
        }],
        vec![RefreshDocument {
            path: b"../a",
            ..known
        }],
    ] {
        assert!(reuse.prepare(src.clone(), &rows, 2, &mut || true).is_err());
    }
    // A fresh word longer than MAX_TERM_BYTES is retained, not refused
    // (c7679132): the refresh prepares exactly what a fresh build would.
    let long = vec![b'x'; 129];
    let rows = [RefreshDocument {
        path: b"a",
        blob: blob(src.namespace.object_format, &long),
        content: Some(&long),
    }];
    let (prepared, _) = reuse.prepare(src.clone(), &rows, 2, &mut || true).unwrap();
    assert_same(&prepared, &fresh(src.clone(), &corpus(&[(b"a", &long)])));
    assert!(reuse.prepare(src, &[known], 2, &mut || true).is_ok());
    assert_eq!(
        index
            .select(None, None, Default::default(), &mut || true)
            .unwrap()
            .activation(),
        reuse.activation()
    );
}

#[test]
fn source_scope_and_selection_store_are_not_replaceable_by_equal_bytes() {
    let store = memory();
    let src = source(GitHashAlgorithm::Sha1, 1);
    let index = LexicalIndexStore::new(&store, src.namespace, src.reference.clone()).unwrap();
    let values = corpus(&[(b"a", b"good")]);
    let reuse = base(&index, &fresh(src.clone(), &values));
    for altered in 0..3 {
        let mut other = src.clone();
        match altered {
            0 => other.namespace.tenant = TenantId::from_bytes([9; 16]),
            1 => other.reference = RefName::try_new(b"refs/heads/elsewhere").unwrap(),
            _ => other.namespace.object_format = GitHashAlgorithm::Sha256,
        }
        assert!(matches!(
            reuse.prepare(other, &inputs(&reuse, &values), 2, &mut || true),
            Err(IndexError::SourceMismatch)
        ));
    }
    let selection = index
        .select(None, None, Default::default(), &mut || true)
        .unwrap();
    let foreign = MemoryAuthorityStore::new(StoreInstanceId::from_raw(931));
    let other = LexicalIndexStore::new(&foreign, src.namespace, src.reference).unwrap();
    assert!(matches!(
        other.load_refresh_base(&selection, Default::default(), &mut || true),
        Err(IndexError::SourceMismatch)
    ));
}

#[test]
fn all_old_segments_must_verify_even_if_the_new_inventory_would_delete_them() {
    for missing in [true, false] {
        let store = memory();
        let src = source(GitHashAlgorithm::Sha1, 1);
        let index = LexicalIndexStore::new(&store, src.namespace, src.reference.clone()).unwrap();
        let prepared = fresh(src.clone(), &corpus(&[(b"a", b"good")]));
        for body in &prepared.metadata {
            store
                .put_if_absent(
                    &payload_key(src.namespace, body.kind, body.root).unwrap(),
                    &body.bytes,
                )
                .unwrap();
        }
        if !missing {
            let body = &prepared.segments[0];
            let mut bytes = body.bytes.clone();
            let last = bytes.len() - 1;
            bytes[last] ^= 1;
            store
                .put_if_absent(
                    &payload_key(src.namespace, "segment", body.root).unwrap(),
                    &bytes,
                )
                .unwrap();
        }
        // Deliberately malformed storage fixture: root exists but payload is
        // absent/substituted. Normal publish never creates this state.
        GenerationAuthority::new(&store, index.head_key.clone())
            .stage_and_activate(&index.generation(&prepared, None).unwrap())
            .unwrap();
        let selection = index
            .select(None, None, Default::default(), &mut || true)
            .unwrap();
        assert!(
            index
                .load_refresh_base(&selection, Default::default(), &mut || true)
                .is_err()
        );
    }
}

#[test]
fn exact_read_budget_is_shared_with_catalog_selection() {
    let store = memory();
    let src = source(GitHashAlgorithm::Sha1, 1);
    let index = LexicalIndexStore::new(&store, src.namespace, src.reference.clone()).unwrap();
    let reuse = base(&index, &fresh(src, &corpus(&[(b"a", b"good")])));
    let selection = index
        .select(None, None, Default::default(), &mut || true)
        .unwrap();
    let exact = LexicalReadLimits {
        max_payload_bytes: reuse.payload_bytes,
        ..Default::default()
    };
    assert_eq!(
        index
            .load_refresh_base(&selection, exact, &mut || true)
            .unwrap()
            .payload_bytes,
        reuse.payload_bytes
    );
    assert!(
        index
            .load_refresh_base(
                &selection,
                LexicalReadLimits {
                    max_payload_bytes: exact.max_payload_bytes - 1,
                    ..exact
                },
                &mut || true
            )
            .is_err()
    );
    assert!(
        index
            .load_refresh_base(&selection, exact, &mut || false)
            .is_err()
    );
}

#[test]
fn a_new_head_never_changes_the_old_reuse_base_and_stale_publication_loses() {
    let store = memory();
    let src = source(GitHashAlgorithm::Sha1, 1);
    let index = LexicalIndexStore::new(&store, src.namespace, src.reference.clone()).unwrap();
    let values = corpus(&[(b"a", b"old")]);
    let reuse = base(&index, &fresh(src, &values));
    let selection = index
        .select(None, None, Default::default(), &mut || true)
        .unwrap();
    let newer = fresh(
        source(GitHashAlgorithm::Sha1, 2),
        &corpus(&[(b"a", b"new")]),
    );
    let winner = index
        .publish(&newer, Some(reuse.activation.generation_id), &mut || true)
        .unwrap();
    let old = index
        .load_refresh_base(&selection, Default::default(), &mut || true)
        .unwrap();
    assert!(
        old.document_bytes(b"a", blob(GitHashAlgorithm::Sha1, b"old"))
            .is_some()
    );
    let (candidate, _) = old
        .prepare(
            source(GitHashAlgorithm::Sha1, 3),
            &inputs(&old, &values),
            2,
            &mut || true,
        )
        .unwrap();
    assert!(
        index
            .publish(&candidate, Some(old.activation.generation_id), &mut || true)
            .is_err()
    );
    assert_eq!(
        index
            .select(None, None, Default::default(), &mut || true)
            .unwrap()
            .activation(),
        &winner
    );
}

// Test-only forwarding adapter with a genuine Pending before every read.
struct AsyncView<'a> {
    inner: &'a MemoryAuthorityStore,
    contexts: Mutex<Vec<usize>>,
}
impl AsyncView<'_> {
    async fn wait(&self, value: usize) {
        self.contexts.lock().unwrap().push(value);
        let mut pending = true;
        poll_fn(move |cx| {
            if pending {
                pending = false;
                cx.waker().wake_by_ref();
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        })
        .await;
    }
}
impl AsyncAuthorityStore for AsyncView<'_> {
    type Context = usize;
    fn instance_id(&self) -> StoreInstanceId {
        self.inner.instance_id()
    }
    fn limits(&self) -> AuthorityLimits {
        self.inner.limits()
    }
    fn put_if_absent(
        &self,
        _: &usize,
        key: &ImmutableKey,
        bytes: &[u8],
    ) -> impl Future<Output = Result<PutOutcome, AuthorityFailure>> + Send {
        std::future::ready(self.inner.put_if_absent(key, bytes))
    }
    async fn read_immutable(
        &self,
        cx: &usize,
        key: &ImmutableKey,
    ) -> Result<ImmutableRead, AuthorityFailure> {
        self.wait(*cx).await;
        self.inner.read_immutable(key)
    }
    fn initialize_head(
        &self,
        _: &usize,
        key: &HeadKey,
        n: HeadGeneration,
        bytes: &[u8],
    ) -> impl Future<Output = Result<HeadInit, AuthorityFailure>> + Send {
        std::future::ready(self.inner.initialize_head(key, n, bytes))
    }
    async fn read_head(&self, cx: &usize, key: &HeadKey) -> Result<HeadRead, AuthorityFailure> {
        self.wait(*cx).await;
        self.inner.read_head(key)
    }
    fn compare_exchange_head(
        &self,
        _: &usize,
        key: &HeadKey,
        token: AuthorityVersionToken,
        n: HeadGeneration,
        bytes: &[u8],
    ) -> impl Future<Output = Result<CasOutcome, AuthorityFailure>> + Send {
        std::future::ready(self.inner.compare_exchange_head(key, token, n, bytes))
    }
    async fn authenticate_head_receipt(
        &self,
        cx: &usize,
        receipt: &HeadReadReceipt,
    ) -> Result<AuthenticatedHead, AuthorityFailure> {
        self.wait(*cx).await;
        self.inner.authenticate_head_receipt(receipt)
    }
}
fn drive<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..10_000 {
        if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
            return value;
        }
    }
    panic!("reference future did not finish")
}

#[test]
fn async_loader_suspends_uses_this_context_and_matches_the_sync_bytes() {
    let store = memory();
    let src = source(GitHashAlgorithm::Sha256, 1);
    let index = LexicalIndexStore::new(&store, src.namespace, src.reference.clone()).unwrap();
    let values = corpus(&[(b"a", b"foo bar")]);
    let sync = base(&index, &fresh(src.clone(), &values));
    let view = AsyncView {
        inner: &store,
        contexts: Mutex::new(Vec::new()),
    };
    let index = LexicalIndexStore::new(&view, src.namespace, src.reference.clone()).unwrap();
    let selection =
        drive(index.select_async(&8, None, None, Default::default(), &mut || true)).unwrap();
    view.contexts.lock().unwrap().clear();
    let loaded =
        drive(index.load_refresh_base_async(&9, &selection, Default::default(), &mut || true))
            .unwrap();
    assert!(!view.contexts.lock().unwrap().is_empty());
    assert!(
        view.contexts
            .lock()
            .unwrap()
            .iter()
            .all(|value| *value == 9)
    );
    let (left, _) = sync
        .prepare(src.clone(), &inputs(&sync, &values), 2, &mut || true)
        .unwrap();
    let (right, _) = loaded
        .prepare(src, &inputs(&loaded, &values), 2, &mut || true)
        .unwrap();
    assert_same(&left, &right);
}

#[test]
fn cancelled_and_unpolled_async_reuse_loads_cannot_return_partial_postings() {
    let store = memory();
    let src = source(GitHashAlgorithm::Sha1, 1);
    let index = LexicalIndexStore::new(&store, src.namespace, src.reference.clone()).unwrap();
    base(&index, &fresh(src.clone(), &corpus(&[(b"a", b"foo bar")])));
    let selection = index
        .select(None, None, Default::default(), &mut || true)
        .unwrap();
    let view = AsyncView {
        inner: &store,
        contexts: Mutex::new(Vec::new()),
    };
    let index = LexicalIndexStore::new(&view, src.namespace, src.reference).unwrap();
    let mut live = || true;
    drop(index.load_refresh_base_async(&10, &selection, Default::default(), &mut live));
    assert!(view.contexts.lock().unwrap().is_empty());
    let mut calls = 0;
    let mut live = || {
        calls += 1;
        calls <= 2
    };
    assert!(matches!(
        drive(index.load_refresh_base_async(&11, &selection, Default::default(), &mut live)),
        Err(IndexError::Lexical(LexicalError::Cancelled))
    ));
    assert_eq!(*view.contexts.lock().unwrap(), vec![11]);
}
