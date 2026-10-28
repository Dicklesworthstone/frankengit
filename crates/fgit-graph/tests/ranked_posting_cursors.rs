#![forbid(unsafe_code)]
//! Real persisted lexical codecs and reference authority, with synthetic source
//! coordinates. These tests do not establish node authorization or durability.
use fgit_authority::{MemoryAuthorityStore, StoreInstanceId};
use fgit_crypto::{
    GitObjectKind, IdentityDomain, git_object_id, internal_algorithm_id,
    internal_digest_value, internal_object_id,
};
use fgit_graph::lexical::{
    IndexError, LexicalChannel, LexicalError, LexicalHit, LexicalIndexStore,
    LexicalNamespace, LexicalQuery, LexicalQueryLimits, LexicalSegment, LexicalSource,
    LexicalSpan, PreparedLexicalIndex, RARITY_SCALE, RankedLexicalScore, SourceDocument,
};
use fgit_types::{
    CodecVersion, Digest, GitHashAlgorithm, RefName, RepositoryAuthorityHeadId,
    RepositoryCommitId, RepositoryId, RepositoryIncarnationId, SchemaFamily, SchemaId, TenantId,
};

fn source(format: GitHashAlgorithm) -> LexicalSource {
    let id = |domain, family: &'static str| {
        internal_object_id(
            domain,
            SchemaId::new(SchemaFamily::from_static(family), 1, 0),
            CodecVersion::new(1, 0),
            b"ranked-cursor-tests",
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
                SchemaId::new(SchemaFamily::from_static("ranked-cursor-test"), 1, 0),
                b"forge",
            ),
        ),
        commit: git_object_id(format, GitObjectKind::Commit, b"fixture"),
        tree: git_object_id(format, GitObjectKind::Tree, b"fixture"),
    }
}

fn prepare(
    format: GitHashAlgorithm,
    docs: &[(Vec<u8>, Vec<u8>)],
    chunk: usize,
) -> PreparedLexicalIndex {
    let selected = source(format);
    let segments = docs
        .chunks(chunk)
        .enumerate()
        .map(|(index, rows)| {
            LexicalSegment::build(
                selected.namespace,
                (index * chunk + 1) as u64,
                rows.iter().map(|(path, body)| SourceDocument {
                    path,
                    content: body,
                    blob: git_object_id(format, GitObjectKind::Blob, body),
                }),
                &mut || true,
            )
            .unwrap()
        })
        .collect();
    PreparedLexicalIndex::new(selected, segments, 0, &mut || true).unwrap()
}

#[test]
fn dense_ranked_queries_fit_the_unchanged_budget_without_repeated_binary_searches() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let words: Vec<_> = (0..16).map(|n| format!("t{n:02}")).collect();
        let content = words.join(" ").into_bytes();
        let terms: Vec<_> = words.into_iter().map(String::into_bytes).collect();
        let docs: Vec<_> = (0..2000)
            .map(|n| (format!("src/{n:05}.rs").into_bytes(), content.clone()))
            .collect();
        let prepared = prepare(format, &docs, 2000);
        let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(931));
        let source = prepared.source();
        let index =
            LexicalIndexStore::new(&store, source.namespace, source.reference.clone()).unwrap();
        index.publish(&prepared, None, &mut || true).unwrap();
        let selected = index
            .select(None, None, Default::default(), &mut || true)
            .unwrap();
        let query = LexicalQuery::new(LexicalChannel::Content, &terms, &[]).unwrap();
        let limits = LexicalQueryLimits {
            max_results: 10,
            max_work: 450_000,
        };
        let report = index
            .search_ranked(&selected, &query, Default::default(), limits, &mut || true)
            .unwrap();
        assert_eq!(report.scoped_documents, 2000);
        assert_eq!(report.matched_documents, 2000);
        assert_eq!(report.term_document_frequencies, vec![2000; 16]);
        assert_eq!(report.index.results.hits.len(), 10);
        assert!(!report.index.results.complete);
        assert_eq!(report.index.results.next_after, None);
        for (ordinal, (hit, score)) in report
            .index
            .results
            .hits
            .iter()
            .zip(&report.scores)
            .enumerate()
        {
            assert_eq!(hit.path, docs[ordinal].0);
            assert_eq!(
                *score,
                RankedLexicalScore {
                    matched_terms: 16,
                    rarity_q16: 16 * RARITY_SCALE,
                }
            );
        }
        let exact = LexicalQueryLimits {
            max_work: report.index.results.work_units,
            ..limits
        };
        assert_eq!(
            index
                .search_ranked(&selected, &query, Default::default(), exact, &mut || true)
                .unwrap()
                .index
                .results,
            report.index.results
        );
        assert!(matches!(
            index.search_ranked(
                &selected,
                &query,
                Default::default(),
                LexicalQueryLimits {
                    max_work: exact.max_work - 1,
                    ..exact
                },
                &mut || true,
            ),
            Err(IndexError::Lexical(LexicalError::Limit("query work")))
        ));
    }
}

fn first_offset(bytes: &[u8], term: &[u8]) -> Option<u32> {
    let is_word = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_';
    let mut at = 0;
    while at < bytes.len() {
        if !is_word(bytes[at]) {
            at += 1;
            continue;
        }
        let from = at;
        while at < bytes.len() && is_word(bytes[at]) {
            at += 1;
        }
        if bytes[from..at].eq_ignore_ascii_case(term) {
            return Some(from as u32);
        }
    }
    None
}

#[test]
fn both_channels_and_sparse_path_scopes_match_an_independent_full_corpus_oracle() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut docs = Vec::new();
        for n in 0..96 {
            let group = ["a", "b", "c"][n % 3];
            let word = ["alpha", "beta", "gamma", "none"][n % 4];
            let content = format!(
                "prefix {} {} {} tail",
                if n % 2 == 0 { "ALPHA" } else { "other" },
                if n % 5 == 0 { "beta" } else { "other" },
                if n % 7 == 0 { "alpha" } else { "other" },
            );
            docs.push((
                format!("src/{group}/{word}/{n:03}.rs").into_bytes(),
                content.into_bytes(),
            ));
        }
        docs.sort_by(|a, b| a.0.cmp(&b.0));
        let prepared = prepare(format, &docs, 17);
        let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(932));
        let source = prepared.source();
        let index =
            LexicalIndexStore::new(&store, source.namespace, source.reference.clone()).unwrap();
        index.publish(&prepared, None, &mut || true).unwrap();
        let selected = index
            .select(None, None, Default::default(), &mut || true)
            .unwrap();
        for channel in [LexicalChannel::Content, LexicalChannel::Path] {
            let terms = vec![
                b"alpha".to_vec(),
                b"BETA".to_vec(),
                b"rs".to_vec(),
                b"absent".to_vec(),
            ];
            for prefixes in [
                vec![],
                vec![b"src/a".to_vec()],
                vec![b"src/a".to_vec(), b"src/c".to_vec()],
                vec![b"src/absent".to_vec()],
            ] {
                let query = LexicalQuery::new(channel, &terms, &prefixes).unwrap();
                let mut corpus = 0usize;
                let mut frequencies = vec![0usize; query.terms().len()];
                let mut hits = Vec::new();
                for (ordinal, (path, body)) in docs.iter().enumerate() {
                    if !prefixes.is_empty()
                        && !prefixes.iter().any(|prefix| {
                            path == prefix
                                || (path.starts_with(prefix)
                                    && path.get(prefix.len()) == Some(&b'/'))
                        })
                    {
                        continue;
                    }
                    corpus += 1;
                    let bytes = if channel == LexicalChannel::Path { path } else { body };
                    let spans: Vec<_> = query
                        .terms()
                        .iter()
                        .enumerate()
                        .filter_map(|(query_index, term)| {
                            let byte_offset = first_offset(bytes, term)?;
                            frequencies[query_index] += 1;
                            Some(LexicalSpan {
                                query_index,
                                byte_offset,
                                byte_length: term.len() as u16,
                            })
                        })
                        .collect();
                    if !spans.is_empty() {
                        hits.push(LexicalHit {
                            document_id: ordinal as u64 + 1,
                            path: path.clone(),
                            blob: git_object_id(format, GitObjectKind::Blob, body),
                            content_bytes: body.len() as u32,
                            spans,
                        });
                    }
                }
                let mut expected: Vec<_> = hits
                    .into_iter()
                    .map(|hit| {
                        let score = RankedLexicalScore {
                            matched_terms: hit.spans.len(),
                            rarity_q16: hit
                                .spans
                                .iter()
                                .map(|span| {
                                    (corpus as u64 + 1) * RARITY_SCALE
                                        / (frequencies[span.query_index] as u64 + 1)
                                })
                                .sum(),
                        };
                        (hit, score)
                    })
                    .collect();
                expected.sort_by(|a, b| {
                    b.1.matched_terms
                        .cmp(&a.1.matched_terms)
                        .then_with(|| b.1.rarity_q16.cmp(&a.1.rarity_q16))
                        .then_with(|| a.0.path.cmp(&b.0.path))
                });
                let report = index
                    .search_ranked(
                        &selected,
                        &query,
                        Default::default(),
                        LexicalQueryLimits {
                            max_results: 7,
                            ..Default::default()
                        },
                        &mut || true,
                    )
                    .unwrap();
                assert_eq!(report.scoped_documents, corpus);
                assert_eq!(report.matched_documents, expected.len());
                assert_eq!(report.term_document_frequencies, frequencies);
                assert_eq!(report.index.results.complete, expected.len() <= 7);
                assert_eq!(report.index.segments_read, 6);
                assert_eq!(
                    report.index.results.hits,
                    expected.iter().take(7).map(|x| x.0.clone()).collect::<Vec<_>>()
                );
                assert_eq!(
                    report.scores,
                    expected.iter().take(7).map(|x| x.1).collect::<Vec<_>>()
                );
            }
        }
    }
}
